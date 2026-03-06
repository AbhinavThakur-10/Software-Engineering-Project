"""Multi-provider security aggregator with scoring and fallback."""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from src.utils.security_cache import SecurityScanCache
from src.utils.security_providers import (
    scan_with_osv,
    scan_with_github_advisory,
    scan_with_oss_index,
    scan_with_virustotal,
)


class SecurityAggregator:
    """Aggregate findings from OSV, GitHub Advisory, OSS Index and optional VirusTotal."""

    def __init__(self, api_key: str, cache_ttl_seconds: int = 600) -> None:
        cache_file = os.path.join(os.getcwd(), ".security_scan_cache.json")
        self.api_key = api_key
        self.cache = SecurityScanCache(cache_file=cache_file, ttl_seconds=cache_ttl_seconds)
        self.cache_schema_version = "v3"

    def _provider_config_fingerprint(self) -> str:
        """Return cache fingerprint for provider auth-related configuration."""
        github_token_set = "1" if os.environ.get("GITHUB_TOKEN") else "0"
        oss_auth_set = "1" if (os.environ.get("OSSINDEX_USERNAME") and os.environ.get("OSSINDEX_TOKEN")) else "0"
        vt_key_set = "1" if self.api_key else "0"
        return f"gh:{github_token_set}|oss:{oss_auth_set}|vt:{vt_key_set}"

    def _cache_key(self, package_name: str, manager: str, version: Optional[str], file_hash: Optional[str]) -> str:
        provider_fingerprint = self._provider_config_fingerprint()
        return (
            f"{self.cache_schema_version}::{manager.lower()}::{package_name.lower()}::"
            f"{version or ''}::{file_hash or ''}::{provider_fingerprint}"
        )

    def _collect_provider_results(
        self,
        package_name: str,
        manager: str,
        version: Optional[str],
        file_hash: Optional[str],
    ) -> Dict[str, Dict[str, Any]]:
        providers: Dict[str, Dict[str, Any]] = {
            "osv": scan_with_osv(package_name, manager, version),
            "github_advisory": scan_with_github_advisory(package_name, manager),
            "oss_index": scan_with_oss_index(package_name, manager, version),
            "virustotal": scan_with_virustotal(file_hash, self.api_key),
        }
        return providers

    def _score(self, providers: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        all_findings: List[Dict[str, Any]] = []
        coverage = 0
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        malicious_count = 0

        for provider_name, result in providers.items():
            if result.get("status") == "ok":
                coverage += 1
            findings = result.get("findings", [])
            if isinstance(findings, list):
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    severity = str(finding.get("severity", "unknown")).lower()
                    if severity not in counts:
                        severity = "unknown"
                    counts[severity] += 1
                    if provider_name == "virustotal" and finding.get("id") == "vt-malicious":
                        malicious_count += 1
                    all_findings.append(finding)

        if malicious_count > 0 or counts["critical"] > 0:
            decision = "block"
            reason = "Critical or confirmed malicious findings detected"
        elif counts["high"] > 0 or counts["medium"] > 0:
            decision = "warn"
            reason = "Medium/high severity findings detected"
        elif len(all_findings) == 0 and coverage >= 2:
            decision = "allow"
            reason = "No findings with sufficient provider coverage"
        else:
            decision = "warn"
            reason = "Insufficient provider coverage to confidently allow"

        return {
            "decision": decision,
            "reason": reason,
            "coverage": coverage,
            "counts": counts,
            "findings": all_findings,
        }

    def analyze(
        self,
        package_name: str,
        manager: str,
        version: Optional[str] = None,
        file_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        key = self._cache_key(package_name, manager, version, file_hash)
        cached = self.cache.get(key)
        if cached:
            cached["from_cache"] = True
            return cached

        providers = self._collect_provider_results(package_name, manager, version, file_hash)
        score = self._score(providers)

        result: Dict[str, Any] = {
            "package": package_name,
            "manager": manager,
            "version": version,
            "file_hash": file_hash,
            "decision": score["decision"],
            "reason": score["reason"],
            "coverage": score["coverage"],
            "counts": score["counts"],
            "findings": score["findings"],
            "providers": providers,
            "from_cache": False,
        }

        self.cache.set(key, result)
        return result
