"""Security report writer for install/upgrade actions."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Any, Dict, Optional


def _safe_slug(value: str) -> str:
    """Convert string to safe filename by removing special chars."""
    return re.sub(r"[^a-zA-Z0-9_.@-]+", "_", value.strip())


def write_security_report(
    action: str,
    package_name: str,
    manager_name: str,
    scan_result: Dict[str, Any],
    operation_status: str,
    operation_success: bool,
    output_dir: Optional[str] = None,
) -> Optional[str]:
    """Write a JSON report for an install/upgrade security decision."""
    directory = output_dir or os.path.join(os.getcwd(), "security_reports")
    os.makedirs(directory, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"{_safe_slug(action)}_{_safe_slug(package_name)}_{timestamp}.json"
    path = os.path.join(directory, file_name)

    payload = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "package": package_name,
        "manager": manager_name,
        "operation": {
            "status": operation_status,
            "success": operation_success,
        },
        "security": scan_result,
    }

    try:
        with open(path, "w", encoding="utf-8") as report_file:
            json.dump(payload, report_file, indent=2)
        return path
    except Exception:
        return None


def write_security_report_markdown(
    action: str,
    package_name: str,
    manager_name: str,
    scan_result: Dict[str, Any],
    operation_status: str,
    operation_success: bool,
    output_dir: Optional[str] = None,
) -> Optional[str]:
    """Write a Markdown report for a security decision."""
    directory = output_dir or os.path.join(os.getcwd(), "security_reports")
    os.makedirs(directory, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"{_safe_slug(action)}_{_safe_slug(package_name)}_{timestamp}.md"
    path = os.path.join(directory, file_name)

    counts = scan_result.get("counts", {}) if isinstance(scan_result, dict) else {}
    findings = scan_result.get("findings", []) if isinstance(scan_result, dict) else []

    # build markdown sections
    lines = [
        "# Security Report",
        "",
        f"- **Timestamp:** {datetime.now().isoformat()}",
        f"- **Action:** {action}",
        f"- **Package:** {package_name}",
        f"- **Manager:** {manager_name}",
        f"- **Operation Status:** {operation_status}",
        f"- **Operation Success:** {operation_success}",
        "",
        "## Summary",
        "",
        f"- **Decision:** {scan_result.get('decision', 'unknown')}",
        f"- **Reason:** {scan_result.get('reason', 'No reason provided')}",
        f"- **Coverage:** {scan_result.get('coverage', 0)}",
        f"- **Critical:** {counts.get('critical', 0)}",
        f"- **High:** {counts.get('high', 0)}",
        f"- **Medium:** {counts.get('medium', 0)}",
        f"- **Low:** {counts.get('low', 0)}",
        "",
        "## Findings",
        "",
    ]

    if findings:
        lines.append("| Severity | Source | ID | Summary |")
        lines.append("|---|---|---|---|")
        for finding in findings:
            # escape pipe characters for markdown tables
            severity = str(finding.get("severity", "unknown")).replace("|", "\\|")
            source = str(finding.get("source", "unknown")).replace("|", "\\|")
            finding_id = str(finding.get("id", "unknown")).replace("|", "\\|")
            summary = str(finding.get("summary", "")).replace("|", "\\|")
            lines.append(f"| {severity} | {source} | {finding_id} | {summary} |")
    else:
        lines.append("No findings reported.")

    try:
        with open(path, "w", encoding="utf-8") as report_file:
            report_file.write("\n".join(lines) + "\n")
        return path
    except Exception:
        return None
