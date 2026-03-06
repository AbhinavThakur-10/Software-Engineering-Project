"""Security provider clients with retry/timeout/rate-limit handling."""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import requests

from src.utils.virustotal import scan_file_hash_with_virustotal


def _severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _request_with_retries(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    auth: Optional[Any] = None,
    timeout: int = 12,
    retries: int = 2,
) -> Dict[str, Any]:
    last_error: Optional[str] = None
    for attempt in range(retries + 1):
        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_body,
                auth=auth,
                timeout=timeout,
            )
        except requests.RequestException as ex:
            last_error = str(ex)
            if attempt < retries:
                time.sleep(0.4 * (attempt + 1))
                continue
            return {"ok": False, "status": "error", "error": last_error}

        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "1")
            try:
                wait_seconds = max(1, min(5, int(retry_after)))
            except ValueError:
                wait_seconds = 1
            if attempt < retries:
                time.sleep(wait_seconds)
                continue
            return {"ok": False, "status": "rate_limited", "error": response.text}

        if response.status_code >= 500 and attempt < retries:
            time.sleep(0.4 * (attempt + 1))
            continue

        if response.status_code >= 400:
            return {
                "ok": False,
                "status": "error",
                "http_status": response.status_code,
                "error": response.text,
            }

        try:
            return {"ok": True, "status": "ok", "payload": response.json()}
        except Exception:
            return {"ok": False, "status": "error", "error": "Invalid JSON response"}

    return {"ok": False, "status": "error", "error": last_error or "Unknown request error"}


def manager_to_ecosystem(manager: str) -> Optional[str]:
    manager_lower = manager.lower()
    if manager_lower in {"npm", "yarn", "pnpm"}:
        return "npm"
    if manager_lower in {"pip", "pip3", "poetry", "pipx"}:
        return "PyPI"
    return None


def manager_to_github_ecosystem(manager: str) -> Optional[str]:
    manager_lower = manager.lower()
    if manager_lower in {"npm", "yarn", "pnpm"}:
        return "npm"
    if manager_lower in {"pip", "pip3", "poetry", "pipx"}:
        return "pip"
    return None


def scan_with_osv(package_name: str, manager: str, version: Optional[str] = None) -> Dict[str, Any]:
    ecosystem = manager_to_ecosystem(manager)
    if not ecosystem:
        return {"provider": "osv", "status": "unavailable", "findings": [], "error": "Unsupported ecosystem"}

    body: Dict[str, Any] = {"package": {"name": package_name, "ecosystem": ecosystem}}
    if version:
        body["version"] = version

    response = _request_with_retries("POST", "https://api.osv.dev/v1/query", json_body=body)
    if not response.get("ok"):
        return {
            "provider": "osv",
            "status": response.get("status", "error"),
            "findings": [],
            "error": response.get("error", "Request failed"),
        }

    payload = response.get("payload", {})
    vulnerabilities = payload.get("vulns", []) if isinstance(payload, dict) else []

    findings: List[Dict[str, Any]] = []
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        vuln_id = vuln.get("id", "unknown")
        summary = vuln.get("summary") or vuln.get("details") or "OSV vulnerability"
        severity = "unknown"

        sev_items = vuln.get("severity", [])
        if isinstance(sev_items, list) and sev_items:
            first = sev_items[0]
            if isinstance(first, dict):
                score = first.get("score")
                if isinstance(score, str) and score.startswith("CVSS"):
                    try:
                        cvss = float(score.split("/")[-1])
                        severity = _severity_from_cvss(cvss)
                    except Exception:
                        severity = "unknown"

        findings.append({
            "id": vuln_id,
            "severity": severity,
            "summary": str(summary)[:200],
            "source": "osv",
        })

    return {"provider": "osv", "status": "ok", "findings": findings}


def scan_with_github_advisory(package_name: str, manager: str) -> Dict[str, Any]:
    ecosystem = manager_to_github_ecosystem(manager)
    if not ecosystem:
        return {"provider": "github_advisory", "status": "unavailable", "findings": [], "error": "Unsupported ecosystem"}

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Public endpoint; may return limited results/rate limits without token.
    response = _request_with_retries(
        "GET",
        "https://api.github.com/advisories",
        headers=headers,
        params={"ecosystem": ecosystem, "affects": package_name, "per_page": 20},
    )

    if not response.get("ok"):
        error_text = str(response.get("error", "Request failed"))
        status = response.get("status", "error")
        if "429" in error_text:
            status = "rate_limited"
        return {
            "provider": "github_advisory",
            "status": status,
            "findings": [],
            "error": error_text,
        }

    payload = response.get("payload", [])
    advisories = payload if isinstance(payload, list) else []
    findings: List[Dict[str, Any]] = []
    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue
        severity = str(advisory.get("severity", "unknown")).lower()
        findings.append(
            {
                "id": advisory.get("ghsa_id") or advisory.get("cve_id") or "unknown",
                "severity": severity if severity in {"critical", "high", "medium", "low"} else "unknown",
                "summary": str(advisory.get("summary") or advisory.get("description") or "GitHub advisory")[:200],
                "source": "github_advisory",
            }
        )

    return {"provider": "github_advisory", "status": "ok", "findings": findings}


def _to_package_url(package_name: str, manager: str, version: Optional[str]) -> Optional[str]:
    ecosystem = manager_to_ecosystem(manager)
    if ecosystem == "npm":
        return f"pkg:npm/{package_name}{'@' + version if version else ''}"
    if ecosystem == "PyPI":
        return f"pkg:pypi/{package_name}{'@' + version if version else ''}"
    return None


def scan_with_oss_index(package_name: str, manager: str, version: Optional[str] = None) -> Dict[str, Any]:
    coordinate = _to_package_url(package_name, manager, version)
    if not coordinate:
        return {"provider": "oss_index", "status": "unavailable", "findings": [], "error": "Unsupported ecosystem"}

    username = os.environ.get("OSSINDEX_USERNAME")
    token = os.environ.get("OSSINDEX_TOKEN")
    auth = (username, token) if username and token else None

    response = _request_with_retries(
        "POST",
        "https://ossindex.sonatype.org/api/v3/component-report",
        json_body={"coordinates": [coordinate]},
        auth=auth,
    )

    if not response.get("ok"):
        error_text = str(response.get("error", "Request failed"))
        status = response.get("status", "error")
        if "401" in error_text and not auth:
            status = "unavailable"
            error_text = "OSS Index authentication required (set OSSINDEX_USERNAME/OSSINDEX_TOKEN)."
        return {
            "provider": "oss_index",
            "status": status,
            "findings": [],
            "error": error_text,
        }

    payload = response.get("payload", {})
    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    findings: List[Dict[str, Any]] = []

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        score = vuln.get("cvssScore")
        severity = _severity_from_cvss(float(score)) if isinstance(score, (int, float)) else "unknown"
        findings.append(
            {
                "id": vuln.get("cve") or vuln.get("id") or "unknown",
                "severity": severity,
                "summary": str(vuln.get("title") or vuln.get("description") or "OSS Index vulnerability")[:200],
                "source": "oss_index",
            }
        )

    return {"provider": "oss_index", "status": "ok", "findings": findings}


def scan_with_virustotal(file_hash: Optional[str], api_key: str) -> Dict[str, Any]:
    if not file_hash:
        return {
            "provider": "virustotal",
            "status": "unavailable",
            "findings": [],
            "metadata": {"reason": "No file hash"},
        }

    result = scan_file_hash_with_virustotal(file_hash, api_key)
    if not isinstance(result, dict) or result.get("error"):
        return {
            "provider": "virustotal",
            "status": "error",
            "findings": [],
            "error": str(result.get("message") if isinstance(result, dict) else "Unknown error"),
        }

    attributes = ((result.get("data") or {}).get("attributes") or {}) if isinstance(result.get("data"), dict) else {}
    stats = attributes.get("last_analysis_stats", {}) if isinstance(attributes, dict) else {}

    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))

    findings: List[Dict[str, Any]] = []
    if malicious > 0:
        findings.append({"id": "vt-malicious", "severity": "critical", "summary": f"{malicious} engines flagged malicious", "source": "virustotal"})
    elif suspicious > 0:
        findings.append({"id": "vt-suspicious", "severity": "medium", "summary": f"{suspicious} engines flagged suspicious", "source": "virustotal"})

    return {
        "provider": "virustotal",
        "status": "ok",
        "findings": findings,
        "metadata": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
        },
    }
