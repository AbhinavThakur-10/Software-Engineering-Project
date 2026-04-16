"""Supply-Chain Security Scanner - Multi-provider vulnerability aggregation."""
import argparse
import re
import sys
import threading
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List, Any, Optional, cast

from dotenv import load_dotenv
from colorama import init, Fore, Style
from tabulate import tabulate

from src.utils.virustotal import get_virustotal_api_key, download_package_and_get_hash
from src.utils.package_cache import PackageCacheDB
from src.utils.security_aggregator import SecurityAggregator
from src.utils.security_report import write_security_report, write_security_report_markdown

from src.managers.base_manager import BasePackageManager
from src.managers.npm_manager import NPMManager
from src.managers.pip_manager import PipManager
from src.managers.yarn_manager import YarnManager
from src.managers.pnpm_manager import PNPMManager

# Initialise colorama for colored output
init(autoreset=True)

__version__ = "1.1.0"

PLACEHOLDER_PACKAGE = "<package>"
_MANAGER_CHOICES = ["npm", "pip3", "yarn", "pnpm"]


def _supports_text(value: str) -> bool:
    """Return True if current stdout encoding can represent *value*."""
    encoding = (getattr(sys.stdout, "encoding", None) or "utf-8")
    try:
        value.encode(encoding)
        return True
    except Exception:
        return False


_SYMBOL_OK = "✓" if _supports_text("✓") else "[OK]"
_SYMBOL_WARN = "⚠" if _supports_text("⚠") else "[WARN]"
_SYMBOL_FAIL = "✗" if _supports_text("✗") else "[FAIL]"


class UnifiedCLI:
    """Security scanner CLI with multi-provider vulnerability aggregation."""

    def __init__(self) -> None:
        """Init managers and availability."""
        cache_ttl = int(os.environ.get("SECURITY_CACHE_TTL_SECONDS", "600"))
        self.security_aggregator = SecurityAggregator(
            api_key=get_virustotal_api_key(),
            cache_ttl_seconds=cache_ttl,
        )
        self._last_security_scan: Optional[Dict[str, Any]] = None
        self._findings_display_limit: int = 0
        # TOCTOU fix: stores the exact version resolved before artifact download
        self._last_resolved_version: Optional[str] = None

        self.managers: Dict[str, BasePackageManager] = {
            "npm": NPMManager(),
            "pip3": PipManager(),
            "yarn": YarnManager(),
            "pnpm": PNPMManager(),
        }

        # Discover available managers
        self.available_managers: Dict[str, BasePackageManager] = {}
        for name, manager in self.managers.items():
            if manager.is_available():
                self.available_managers[name] = manager
                print(f"{Fore.GREEN}{_SYMBOL_OK} {name} is available{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}{_SYMBOL_WARN} {name} is not available{Style.RESET_ALL}")

    # ------------------------------------------------------------------
    # Manager resolution helpers
    # ------------------------------------------------------------------

    def _resolve_manager(self, manager_name: Optional[str]) -> Optional[str]:
        """Return validated manager name or None with error printed."""
        if manager_name:
            if manager_name not in self.available_managers:
                print(f"{Fore.RED}Manager '{manager_name}' not available{Style.RESET_ALL}")
                return None
            return manager_name
        return None

    def _prompt_manager(self, choices: Optional[List[str]] = None) -> Optional[str]:
        """Prompt the user to pick a manager from *choices* (defaults to all available)."""
        options = choices or list(self.available_managers.keys())
        if not options:
            print(f"{Fore.RED}No package managers available!{Style.RESET_ALL}")
            return None
        print(f"\n{Fore.CYAN}Available managers:{Style.RESET_ALL}")
        for idx, name in enumerate(options, 1):
            print(f"  {idx}. {name}")
        try:
            raw = input(f"\n{Fore.YELLOW}Select manager (1-{len(options)}): {Style.RESET_ALL}")
            return options[int(raw) - 1]
        except (ValueError, IndexError):
            print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
            return None

    def _detect_managers_for_package(self, package_name: str) -> List[str]:
        """Return list of manager names that have *package_name* installed."""
        found: List[str] = []
        for name, manager in self.available_managers.items():
            packages = manager.list_packages()
            if any(p["name"].lower() == package_name.lower() for p in packages):
                found.append(name)
        return found

    def _get_installed_version(self, package_name: str, manager_name: str) -> Optional[str]:
        """Return installed version for package in manager, if available."""
        manager = self.available_managers.get(manager_name)
        if not manager:
            return None
        try:
            for package in manager.list_packages():
                if str(package.get("name", "")).lower() == package_name.lower():
                    version = package.get("version")
                    return str(version) if version else None
        except Exception:
            return None
        return None

    def _resolve_target_version_for_upgrade(
        self, package_name: str, manager_name: str
    ) -> Optional[str]:
        """Version an upgrade would move to (registry \"latest\"), or installed if already current."""
        manager = self.available_managers.get(manager_name)
        if not manager:
            return self._get_installed_version(package_name, manager_name)
        try:
            for row in manager.check_outdated():
                if str(row.get("name", "")).lower() == package_name.lower():
                    lat = row.get("latest") or row.get("latest_version")
                    if lat:
                        return str(lat).strip()
        except Exception:
            pass
        return self._get_installed_version(package_name, manager_name)

    def _resolve_scan_version(
        self, package_name: str, manager_name: str, *, action: str = "install"
    ) -> Optional[str]:
        """Resolve a package version for security scanning.

        *upgrade*: prefer the target (latest) version you are moving to, not only the installed one.
        *install*: installed copy if present, else registry candidate from search.

        If package_name embeds a version (e.g. ``lodash@4.17.21`` or ``werkzeug==2.2.2``),
        that pinned version is returned immediately regardless of action.
        """
        # Extract pinned version from package name.
        # Handles: lodash@4.17.21, werkzeug==2.2.2, minimist@^1.2.5
        # Does NOT match scoped npm packages like @babel/core (leading @, no prior chars).
        m = re.search(r'(?<=.)[@=]=?(\d[^\s]*)$', package_name)
        if m:
            return m.group(1)

        if action == "upgrade":
            target = self._resolve_target_version_for_upgrade(package_name, manager_name)
            if target:
                return target
            # check_outdated missed it (e.g. locally installed pkg) — ask registry directly
            manager = self.available_managers.get(manager_name)
            if manager:
                try:
                    latest = manager.get_latest_registry_version(package_name)
                    if latest:
                        return latest
                except Exception:
                    pass

        installed = self._get_installed_version(package_name, manager_name)
        if installed:
            return installed

        manager = self.available_managers.get(manager_name)
        if not manager:
            return None

        try:
            results = manager.search_package(package_name)
            for item in results:
                name = str(item.get("name", "")).lower()
                if name == package_name.lower():
                    version = item.get("version")
                    if version:
                        return str(version)
            if results:
                first_version = results[0].get("version")
                if first_version:
                    return str(first_version)
        except Exception:
            return None

        return None

    # ------------------------------------------------------------------
    # Free-provider quick scan (OSV + GitHub Advisory, no API keys)
    # ------------------------------------------------------------------

    def _scan_free_providers(
        self, package_name: str, manager_name: str, version: Optional[str]
    ) -> Dict[str, Any]:
        """Run OSV and GitHub Advisory in parallel; return aggregated finding summary.

        Used for the `list` vulnerability column and post-upgrade patched-CVE note.
        Does NOT call VirusTotal or OSS Index so no API key is required.

        Returns a dict:
            {
                "total": int,
                "critical": int, "high": int, "medium": int, "low": int,
                "findings": [{"id", "severity", "summary", "source"}, ...],
                "label": str,   # "CRITICAL" / "HIGH" / "WARN" / "CLEAN" / "ERROR"
            }
        """
        from src.utils.security_providers import scan_with_osv, scan_with_github_advisory

        def _osv() -> Dict[str, Any]:
            return scan_with_osv(package_name, manager_name, version)

        def _github() -> Dict[str, Any]:
            return scan_with_github_advisory(package_name, manager_name, version)

        findings: List[Dict[str, Any]] = []
        error_count = 0

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {pool.submit(_osv): "osv", pool.submit(_github): "github_advisory"}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result.get("status") == "ok":
                        raw = result.get("findings", [])
                        if isinstance(raw, list):
                            for item in cast(List[Any], raw):
                                if isinstance(item, dict):
                                    findings.append(cast(Dict[str, Any], item))
                    else:
                        error_count += 1
                except Exception:
                    error_count += 1

        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = str(f.get("severity", "")).lower()
            if sev in counts:
                counts[sev] += 1

        total = sum(counts.values())

        if total == 0 and error_count == 2:
            label = "ERROR"
        elif counts["critical"] > 0:
            label = "CRITICAL"
        elif counts["high"] > 0:
            label = "HIGH"
        elif counts["medium"] > 0 or counts["low"] > 0:
            label = "WARN"
        else:
            label = "CLEAN"

        return {**counts, "total": total, "findings": findings, "label": label}

    # ------------------------------------------------------------------
    # Security helpers
    # ------------------------------------------------------------------

    def _security_scan(
        self, package_name: str, manager_name: str, action: str = "install"
    ) -> bool:
        """Run aggregated security scan and return True if action may proceed."""
        try:
            print(
                f"\n{Fore.CYAN}[Security]{Style.RESET_ALL} Running security scan "
                f"for {package_name} ({manager_name}) [{action}]..."
            )

            # TOCTOU fix: resolve the exact version BEFORE downloading the artifact.
            # This guarantees that the hash we compute corresponds to the same
            # release that the package manager will install.
            installed_version = self._resolve_scan_version(
                package_name, manager_name, action=action
            )
            self._last_resolved_version = installed_version

            stop_event = threading.Event()
            spinner_msg = (
                f"{Fore.CYAN}[Security]{Style.RESET_ALL} "
                "Preparing artifact hash and provider checks..."
            )

            def _spin() -> None:
                """Display a spinner while security scan is in progress.

                Runs in a separate thread and checks stop_event periodically.
                Cycles through spinner symbols to show activity.
                """
                symbols = ["|", "/", "-", "\\"]
                idx = 0
                while not stop_event.is_set():
                    print(f"\r{spinner_msg} {symbols[idx % 4]}", end="", flush=True)
                    idx += 1
                    stop_event.wait(0.1)
                print("\r" + " " * (len(spinner_msg) + 4) + "\r", end="", flush=True)

            t = threading.Thread(target=_spin, daemon=True)
            t.start()

            # Pass the pinned version so the download targets the exact release.
            file_hash = download_package_and_get_hash(
                package_name, manager_name, version=installed_version
            )
            stop_event.set()
            t.join()

            # Strip embedded version specifier so providers receive a plain name.
            # e.g. "werkzeug==2.2.2" -> "werkzeug", "minimist@1.2.5" -> "minimist"
            # Preserves scoped packages like "@babel/core" (leading @ with no prior chars).
            base_name = re.sub(r'(?<=.)[@=]=?\d[^\s]*$', '', package_name).strip()

            result = self.security_aggregator.analyze(
                package_name=base_name,
                manager=manager_name,
                version=installed_version,
                file_hash=file_hash,
            )
            self._last_security_scan = result

            providers_any = result.get("providers", {})
            providers = providers_any if isinstance(providers_any, dict) else {}
            provider_rows: List[List[str]] = []
            for provider_name, provider_result in providers.items():
                if not isinstance(provider_result, dict):
                    continue
                status = str(provider_result.get("status", "unknown"))
                provider_findings = provider_result.get("findings", [])
                findings_count = (
                    len(provider_findings)
                    if isinstance(provider_findings, list)
                    else 0
                )
                error_text = str(provider_result.get("error", "-")).strip()
                if len(error_text) > 120:
                    error_text = f"{error_text[:117]}..."
                provider_rows.append([
                    str(provider_name),
                    status,
                    str(findings_count),
                    error_text or "-",
                ])

            if provider_rows:
                print(f"{Fore.CYAN}[Security]{Style.RESET_ALL} Provider statuses:")
                print(
                    tabulate(
                        provider_rows,
                        headers=["Provider", "Provider Call Status", "Findings", "Error"],
                        tablefmt="grid",
                    )
                )

            counts = result.get("counts", {})
            raw_findings_any = result.get("findings", [])
            raw_findings = cast(List[Any], raw_findings_any) if isinstance(raw_findings_any, list) else []
            findings: List[Dict[str, Any]] = [item for item in raw_findings if isinstance(item, dict)]

            def _remark_for_severity(severity: str) -> str:
                count = int(counts.get(severity, 0) or 0)
                matches = [
                    finding
                    for finding in findings
                    if str(finding.get("severity", "unknown")).lower() == severity
                ]
                if count == 0:
                    return "No findings reported at this severity."
                if matches:
                    sample_ids = [str(item.get("id", "unknown")) for item in matches[:2]]
                    sample_text = ", ".join(sample_ids)
                    if len(matches) > 2:
                        sample_text = f"{sample_text}, ..."
                    return (
                        f"{count} finding(s) classified as {severity}; "
                        f"examples: {sample_text}"
                    )
                return (
                    f"{count} finding(s) classified as {severity} by provider scores."
                )

            table: List[List[Any]] = [
                [
                    f"{Fore.RED}critical{Style.RESET_ALL}",
                    counts.get("critical", 0),
                    _remark_for_severity("critical"),
                ],
                [
                    f"{Fore.YELLOW}high{Style.RESET_ALL}",
                    counts.get("high", 0),
                    _remark_for_severity("high"),
                ],
                [
                    f"{Fore.YELLOW}medium{Style.RESET_ALL}",
                    counts.get("medium", 0),
                    _remark_for_severity("medium"),
                ],
                [
                    f"{Fore.GREEN}low{Style.RESET_ALL}",
                    counts.get("low", 0),
                    _remark_for_severity("low"),
                ],
                [
                    "coverage",
                    result.get("coverage", 0),
                    "How many providers returned usable results for this scan.",
                ],
                [
                    "decision",
                    result.get("decision", "warn"),
                    "Final policy outcome based on counts and coverage.",
                ],
            ]
            print(
                tabulate(
                    table,
                    headers=["Security Signal", "Value", "Remarks"],
                    tablefmt="grid",
                )
            )

            findings_limit = max(0, int(self._findings_display_limit or 0))
            if findings_limit > 0:
                shown = findings[:findings_limit]
                if shown:
                    print(
                        f"{Fore.CYAN}[Security]{Style.RESET_ALL} "
                        f"Showing {len(shown)}/{len(findings)} findings:"
                    )
                    finding_rows: List[List[str]] = []
                    for finding in shown:
                        summary = str(finding.get("summary", "")).strip()
                        if len(summary) > 120:
                            summary = f"{summary[:117]}..."
                        finding_rows.append(
                            [
                                str(finding.get("severity", "unknown")),
                                str(finding.get("source", "unknown")),
                                str(finding.get("id", "unknown")),
                                summary,
                            ]
                        )
                    print(
                        tabulate(
                            finding_rows,
                            headers=["Severity", "Source", "ID", "Summary"],
                            tablefmt="grid",
                        )
                    )
                else:
                    print(f"{Fore.GREEN}[Security]{Style.RESET_ALL} No findings reported.")

            decision = str(result.get("decision", "warn")).lower()
            reason = result.get("reason", "No reason provided")
            print(f"{Fore.CYAN}[Security]{Style.RESET_ALL} Decision: {decision} ({reason})")

            if decision == "block":
                print(f"{Fore.RED}[Security]{Style.RESET_ALL} Action blocked by policy.")
                return False

            if decision == "warn":
                warn_sources = sorted(
                    {
                        str(finding.get("source", "unknown"))
                        for finding in findings
                        if str(finding.get("severity", "unknown")).lower() in {"high", "medium"}
                    }
                )
                if warn_sources:
                    print(
                        f"{Fore.YELLOW}[Security]{Style.RESET_ALL} "
                        f"Warn due to high/medium findings from: {', '.join(warn_sources)}"
                    )
                print(
                    f"{Fore.YELLOW}[Security]{Style.RESET_ALL} "
                    "Warning detected. Review/download report, then confirm whether to proceed."
                )
                return True

            print(f"{Fore.GREEN}[Security]{Style.RESET_ALL} Security checks passed. Proceeding.")
            return True

        except Exception as ex:
            # Fail-closed: an unexpected scan error must NOT be treated as a green
            # light.  Returning True here (fail-open) allowed a broken scanner to
            # silently approve every install — exactly the supply-chain attack
            # surface we are protecting against.  We return False so the operation
            # is blocked unless the caller explicitly passes --no-security.
            print(
                f"{Fore.RED}[Security]{Style.RESET_ALL} Security scan FAILED "
                f"({ex}). Blocking action (use --no-security to override)."
            )
            self._last_security_scan = {
                "decision": "block",
                "reason": f"scan_error: {ex}",
                "coverage": 0,
                "counts": {},
                "findings": [],
                "providers": {},
            }
            return False

    def _emit_security_report(
        self,
        action: str,
        package_name: str,
        manager_name: str,
        operation_status: str,
        operation_success: bool,
        scan_result: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Write JSON report for install/upgrade/uninstall operations."""
        payload = scan_result or {
            "decision": "unknown",
            "reason": "No scan payload available",
            "coverage": 0,
            "counts": {},
            "findings": [],
            "providers": {},
        }
        report_path = write_security_report(
            action=action,
            package_name=package_name,
            manager_name=manager_name,
            scan_result=payload,
            operation_status=operation_status,
            operation_success=operation_success,
        )
        if report_path:
            print(f"{Fore.CYAN}[Security]{Style.RESET_ALL} Report saved: {report_path}")

    def _offer_markdown_report_before_action(
        self,
        action: str,
        package_name: str,
        manager_name: str,
    ) -> None:
        """Ask user if they want a markdown report before action execution."""
        if not self._last_security_scan:
            return

        try:
            choice = (
                input(
                    f"{Fore.CYAN}[Security]{Style.RESET_ALL} "
                    f"Download report as Markdown before {action}? (y/n): "
                )
                .strip()
                .lower()
            )
        except (EOFError, OSError):
            choice = "n"

        if choice != "y":
            return

        md_path = write_security_report_markdown(
            action=action,
            package_name=package_name,
            manager_name=manager_name,
            scan_result=self._last_security_scan,
            operation_status=f"pre-{action}",
            operation_success=False,
        )
        if md_path:
            print(f"{Fore.CYAN}[Security]{Style.RESET_ALL} Markdown report saved: {md_path}")
        else:
            print(f"{Fore.YELLOW}[Security]{Style.RESET_ALL} Could not save Markdown report.")

    # ------------------------------------------------------------------
    # Unified action executor (eliminates install/upgrade duplication)
    # ------------------------------------------------------------------

    def _execute_with_security(
        self,
        action: str,
        package_name: str,
        manager_name: str,
        operation: Callable[[str], bool],
        *,
        skip_security: bool = False,
        show_findings: int = 0,
        force_security: bool = False,
    ) -> None:
        """Run security scan, write report, prompt user, then execute *operation*.

        Flow:
          1. Security scan (download artifact hash + query all providers)
          2. Write pre-action report to disk so user can review it
          3. Prompt user to confirm — always for install/upgrade, regardless of decision
          4. Execute manager operation only if user confirms
          5. Update report with final install outcome
        """
        # 1. Security gate
        if not skip_security:
            self._findings_display_limit = max(0, int(show_findings or 0))
            try:
                may_proceed = self._security_scan(package_name, manager_name, action)

                # --- FIX 3: Write report BEFORE prompting user so they can open it ---
                if action in ("install", "upgrade"):
                    self._emit_security_report(
                        action=action,
                        package_name=package_name,
                        manager_name=manager_name,
                        operation_status="pre-action",
                        operation_success=False,
                        scan_result=self._last_security_scan,
                    )
                    self._offer_markdown_report_before_action(action, package_name, manager_name)

                if not may_proceed:
                    decision = str((self._last_security_scan or {}).get("decision", "allow")).lower()
                    if force_security and decision == "block":
                        print(
                            f"{Fore.RED}[Security]{Style.RESET_ALL} "
                            "--force: overriding BLOCK (critical / malicious). Proceed at your own risk."
                        )
                        may_proceed = True
                    else:
                        return

                decision = str((self._last_security_scan or {}).get("decision", "allow")).lower()

                if force_security:
                    if decision == "warn":
                        print(
                            f"{Fore.YELLOW}[Security]{Style.RESET_ALL} "
                            "--force: skipping confirmation for security WARN."
                        )
                    # --force on a clean result: still proceed without prompting
                else:
                    # --- FIX 2: Always prompt before install/upgrade ---
                    if action in ("install", "upgrade"):
                        if decision == "warn":
                            prompt_msg = (
                                f"{Fore.YELLOW}[Security] Vulnerabilities found. "
                                f"Proceed with {action}? (y/n): {Style.RESET_ALL}"
                            )
                        else:
                            prompt_msg = (
                                f"{Fore.GREEN}[Security] Scan passed. "
                                f"Proceed with {action}? (y/n): {Style.RESET_ALL}"
                            )
                        try:
                            choice = input(prompt_msg).strip().lower()
                        except (EOFError, OSError):
                            choice = "n"

                        if choice != "y":
                            print(f"{Fore.CYAN}[Security]{Style.RESET_ALL} {action.capitalize()} cancelled by user.")
                            return

                        if decision == "warn":
                            print(f"{Fore.YELLOW}[Security]{Style.RESET_ALL} Proceeding despite warning.")
            except Exception as ex:
                # Catch exceptions bubbling from a patched/broken _security_scan so
                # _execute_with_security itself never raises — it just blocks the action.
                print(
                    f"{Fore.RED}[Security]{Style.RESET_ALL} Security scan FAILED "
                    f"({ex}). Blocking action (use --no-security to override)."
                )
                self._last_security_scan = {
                    "decision": "block",
                    "reason": f"scan_error: {ex}",
                    "coverage": 0,
                    "counts": {},
                    "findings": [],
                    "providers": {},
                }
                return
            finally:
                self._findings_display_limit = 0

        # 2. Capture pre-install snapshot for transitive dependency diffing.
        before_snapshot: Dict[str, str] = {}
        if action == "install":
            before_snapshot = self._capture_package_snapshot(manager_name)

        # 3. Execute the manager operation.
        # TOCTOU fix: use the version-pinned specifier so the manager installs the
        # exact release that was scanned, not a newer "latest" resolved at install time.
        pinned_pkg = package_name
        resolved_v = self._last_resolved_version
        if resolved_v and action in ("install", "upgrade"):
            # Strip any pre-existing version specifier from the user-supplied name
            base_name = re.sub(r'(?<=.)[@=]=?\d[^\s]*$', '', package_name).strip()
            if manager_name in {"npm", "yarn", "pnpm"}:
                pinned_pkg = f"{base_name}@{resolved_v}"
            elif manager_name == "pip3":
                pinned_pkg = f"{base_name}=={resolved_v}"

        success = operation(pinned_pkg)

        if success:
            print(
                f"{Fore.GREEN}{_SYMBOL_OK} Successfully {action}ed {package_name} "
                f"via {manager_name}{Style.RESET_ALL}"
            )
            # 4. Transitive dependency scan: diff tree and rollback if any dep blocks.
            if action == "install":
                transitive_safe = self._scan_and_rollback_transitive(
                    manager_name, before_snapshot, package_name
                )
                if not transitive_safe:
                    # Rollback already executed inside the method; skip cache write.
                    self._emit_security_report(
                        action=action,
                        package_name=package_name,
                        manager_name=manager_name,
                        operation_status="rolled_back_transitive",
                        operation_success=False,
                        scan_result=self._last_security_scan,
                    )
                    return

            # Record in the local package cache DB
            if action == "install":
                self._cache_installed_package(package_name, manager_name)
            elif action == "upgrade":
                # Keep the DB version column current after a successful upgrade.
                new_version = self._get_installed_version(package_name, manager_name) or ""
                with PackageCacheDB() as db:
                    db.update_package_version(package_name, new_version, manager_name)
        else:
            print(f"{Fore.RED}{_SYMBOL_FAIL} Failed to {action} {package_name}{Style.RESET_ALL}")

        # 5. Update report with final outcome (overwrites pre-action report)
        self._emit_security_report(
            action=action,
            package_name=package_name,
            manager_name=manager_name,
            operation_status="completed" if success else "failed",
            operation_success=success,
            scan_result=self._last_security_scan,
        )

    # ------------------------------------------------------------------
    # Transitive dependency scanning (state-diff + rollback)
    # ------------------------------------------------------------------

    def _capture_package_snapshot(self, manager_name: str) -> Dict[str, str]:
        """Return a {name_lower: version} dict of currently installed packages.

        Called both before and after install so we can diff the two states and
        discover every transitively introduced dependency.
        """
        manager = self.available_managers.get(manager_name)
        if not manager:
            return {}
        try:
            return {
                str(p["name"]).lower(): str(p.get("version", ""))
                for p in manager.list_packages()
            }
        except Exception:
            return {}

    def _scan_and_rollback_transitive(
        self,
        manager_name: str,
        before_snapshot: Dict[str, str],
        top_level_package: str,
    ) -> bool:
        """Scan all packages introduced since *before_snapshot* was taken.

        Strategy (enterprise endpoint-detection pattern):
          A. Diff pre-install and post-install package trees.
          B. Skip the top-level package (already scanned before install).
          C. Run SecurityAggregator over every newly introduced dependency.
          D. If any dependency triggers BLOCK, uninstall everything that was
             added and alert the user.

        Returns True if all transitive deps are safe, False if rollback occurred.
        """
        after_snapshot = self._capture_package_snapshot(manager_name)

        # Step A: find newly added packages
        new_packages: List[Dict[str, str]] = []
        top_base = top_level_package.lower().split("@")[0].split("==")[0].strip()
        for name_lower, version in after_snapshot.items():
            if name_lower not in before_snapshot:
                if name_lower == top_base:
                    continue  # top-level already scanned; skip
                new_packages.append({"name": name_lower, "version": version})

        if not new_packages:
            return True

        print(
            f"\n{Fore.CYAN}[Transitive]{Style.RESET_ALL} "
            f"Scanning {len(new_packages)} newly introduced dependency/dependencies..."
        )

        blocked: List[str] = []
        for dep in new_packages:
            dep_name = dep["name"]
            dep_ver = dep.get("version") or None
            print(
                f"{Fore.CYAN}[Transitive]{Style.RESET_ALL} "
                f"  Checking {dep_name} {dep_ver or '(unknown version)'}..."
            )
            try:
                result = self.security_aggregator.analyze(
                    package_name=dep_name,
                    manager=manager_name,
                    version=dep_ver,
                    file_hash=None,
                )
                decision = str(result.get("decision", "allow")).lower()
                if decision == "block":
                    reason = result.get("reason", "no reason")
                    print(
                        f"{Fore.RED}[Transitive]{Style.RESET_ALL} "
                        f"  BLOCK: {dep_name} — {reason}"
                    )
                    blocked.append(dep_name)
                elif decision == "warn":
                    print(
                        f"{Fore.YELLOW}[Transitive]{Style.RESET_ALL} "
                        f"  WARN: {dep_name} has medium/high findings."
                    )
            except Exception as ex:
                print(
                    f"{Fore.YELLOW}[Transitive]{Style.RESET_ALL} "
                    f"  Scan error for {dep_name}: {ex}"
                )

        # Step D: rollback if any transitive dep is BLOCK
        if blocked:
            print(
                f"\n{Fore.RED}[Transitive]{Style.RESET_ALL} "
                f"CRITICAL: {len(blocked)} transitive dependency/dependencies blocked. "
                "Initiating automatic rollback..."
            )
            manager = self.available_managers.get(manager_name)
            if manager:
                # Rollback top-level package first, then the blocked deps
                all_to_remove = [top_level_package] + blocked
                for pkg in all_to_remove:
                    try:
                        manager.uninstall_package(pkg)
                        print(
                            f"{Fore.YELLOW}[Transitive]{Style.RESET_ALL} "
                            f"  Rolled back: {pkg}"
                        )
                    except Exception as ex:
                        print(
                            f"{Fore.RED}[Transitive]{Style.RESET_ALL} "
                            f"  Rollback failed for {pkg}: {ex}"
                        )
            print(
                f"{Fore.RED}[Transitive]{Style.RESET_ALL} "
                "Rollback complete. Installation aborted due to unsafe transitive "
                f"dependencies: {', '.join(blocked)}"
            )
            return False

        print(
            f"{Fore.GREEN}[Transitive]{Style.RESET_ALL} "
            f"All {len(new_packages)} transitive dependency/dependencies passed security checks."
        )
        return True

    def _cache_installed_package(self, package_name: str, manager_name: str) -> None:
        """Write package info to the local SQLite cache."""
        manager = self.available_managers.get(manager_name)
        if not manager:
            return
        version = ""
        try:
            for pkg in manager.list_packages():
                if pkg["name"].lower() == package_name.lower():
                    version = pkg.get("version", "")
                    break
        except Exception:
            pass
        with PackageCacheDB() as db:
            db.add_package(package_name, version, manager_name)

    # ------------------------------------------------------------------
    # Public commands
    # ------------------------------------------------------------------

    def list_all_packages(self) -> None:
        """List installed packages with versions."""
        if not self.available_managers:
            print(f"{Fore.RED}No package managers available!{Style.RESET_ALL}")
            return

        all_packages: List[Dict[str, Any]] = []

        empty_global_managers: List[str] = []

        for mgr_name, manager in self.available_managers.items():
            print(f"\n{Fore.CYAN}Fetching packages from {mgr_name}...{Style.RESET_ALL}")
            packages = manager.list_packages()
            if not packages and mgr_name in {"yarn", "pnpm"}:
                empty_global_managers.append(mgr_name)

            latest_map: Dict[str, str] = {}
            try:
                for item in manager.check_outdated():
                    latest_map[item["name"].lower()] = (
                        item.get("latest") or item.get("latest_version") or ""
                    )
            except Exception:
                pass

            for pkg in packages:
                current = pkg.get("version", "")
                latest = latest_map.get(pkg["name"].lower(), current)
                all_packages.append(
                    {
                        "name": pkg["name"],
                        "id": pkg.get("id", pkg["name"]),
                        "current": current,
                        "latest": latest,
                        "manager": mgr_name,
                    }
                )

        if all_packages:
            all_packages.sort(key=lambda x: (x["manager"], x["name"]))
            table_data: List[List[Any]] = []
            for pkg in all_packages:
                has_newer = (
                    bool(pkg["latest"])
                    and pkg["current"]
                    and pkg["latest"] != pkg["current"]
                )
                latest_disp = (
                    f"{Fore.GREEN}{pkg['latest']}{Style.RESET_ALL}"
                    if has_newer
                    else (pkg["latest"] or "")
                )
                table_data.append(
                    [pkg["name"], pkg["id"], pkg["current"], latest_disp, pkg["manager"]]
                )

            print(f"\n{Fore.GREEN}Total packages found: {len(all_packages)}{Style.RESET_ALL}")
            print(
                tabulate(
                    table_data,
                    headers=["Package", "Package ID", "Current", "Latest", "Manager"],
                    tablefmt="grid",
                )
            )
            if empty_global_managers:
                print(
                    f"\n{Fore.YELLOW}Note:{Style.RESET_ALL} "
                    f"{', '.join(empty_global_managers)} reported no packages — "
                    "this CLI only lists **global** installs for yarn/pnpm. "
                    "Project-local dependencies are not shown."
                )
        else:
            print(f"{Fore.YELLOW}No packages found{Style.RESET_ALL}")

    def install_package(
        self,
        package_name: str,
        manager_name: Optional[str] = None,
        *,
        skip_security: bool = False,
        show_findings: int = 0,
        force_security: bool = False,
    ) -> None:
        """Install via given or interactively selected manager."""
        resolved = self._resolve_manager(manager_name) if manager_name else self._prompt_manager()
        if not resolved:
            return
        manager = self.available_managers[resolved]
        self._execute_with_security(
            "install", package_name, resolved, manager.install_package,
            skip_security=skip_security,
            show_findings=show_findings,
            force_security=force_security,
        )

    def upgrade_package(
        self,
        package_name: str,
        manager_name: Optional[str] = None,
        *,
        skip_security: bool = False,
        show_findings: int = 0,
        force_security: bool = False,
    ) -> None:
        """Upgrade to latest version (explicit manager or interactive)."""
        if manager_name:
            resolved = self._resolve_manager(manager_name)
            if not resolved:
                return
        else:
            # Auto-detect which manager(s) have this package installed
            print(f"\n{Fore.CYAN}Detecting package manager for {package_name}...{Style.RESET_ALL}")
            found = self._detect_managers_for_package(package_name)
            if not found:
                print(
                    f"{Fore.RED}Package '{package_name}' not found in any installed packages{Style.RESET_ALL}"
                )
                print(
                    f"{Fore.YELLOW}Tip: Use 'python -m src.cli install {package_name} "
                    f"-m <manager>' to install it first{Style.RESET_ALL}"
                )
                return
            if len(found) == 1:
                resolved = found[0]
                print(f"{Fore.GREEN}Found {package_name} in {resolved}{Style.RESET_ALL}")
            else:
                print(
                    f"{Fore.YELLOW}Package '{package_name}' found in multiple managers:{Style.RESET_ALL}"
                )
                resolved = self._prompt_manager(found)
                if not resolved:
                    return

        manager = self.available_managers[resolved]
        self._execute_with_security(
            "upgrade", package_name, resolved, manager.upgrade_package,
            skip_security=skip_security,
            show_findings=show_findings,
            force_security=force_security,
        )

    def upgrade_all_dry_run(
        self,
        manager_name: Optional[str] = None,
        *,
        show_findings: int = 0,
    ) -> int:
        """Scan every outdated package (upgrade target versions) without installing. Returns exit code."""
        if not self.available_managers:
            print(f"{Fore.RED}No package managers available!{Style.RESET_ALL}")
            return 2

        if manager_name:
            resolved = self._resolve_manager(manager_name)
            if not resolved:
                return 2
            managers_to_check = {resolved: self.available_managers[resolved]}
        else:
            managers_to_check = dict(self.available_managers)

        all_outdated: List[Dict[str, Any]] = []
        for name, manager in managers_to_check.items():
            print(f"\n{Fore.CYAN}Collecting outdated packages from {name}...{Style.RESET_ALL}")
            try:
                all_outdated.extend(manager.check_outdated())
            except Exception as ex:
                print(f"{Fore.YELLOW}Warning: could not list outdated for {name}: {ex}{Style.RESET_ALL}")

        if not all_outdated:
            print(f"\n{Fore.GREEN}{_SYMBOL_OK} No outdated packages — nothing to dry-run.{Style.RESET_ALL}")
            return 0

        print(
            f"\n{Fore.CYAN}[Security]{Style.RESET_ALL} Dry-run: scanning {len(all_outdated)} "
            f"outdated package(s) at target (latest) versions (no upgrades performed).\n"
        )

        any_risk = False
        summary_rows: List[List[Any]] = []
        self._findings_display_limit = max(0, int(show_findings or 0))

        for row in all_outdated:
            pkg = str(row.get("name", ""))
            mgr = str(row.get("manager", ""))
            cur = str(row.get("current", ""))
            latest = str(row.get("latest") or row.get("latest_version") or "")
            if not pkg or mgr not in self.available_managers:
                continue

            print(f"{Fore.CYAN}--- {pkg} ({mgr}) {cur} → {latest}{Style.RESET_ALL}")
            try:
                allowed = self._security_scan(pkg, mgr, "upgrade")
            except Exception as ex:
                print(f"{Fore.RED}[Security]{Style.RESET_ALL} Scan error: {ex}")
                summary_rows.append([pkg, mgr, "error", str(ex)[:80]])
                any_risk = True
                continue

            scan = self._last_security_scan or {}
            decision = str(scan.get("decision", "unknown")).lower()
            if not allowed or decision in ("block", "warn"):
                any_risk = True
            summary_rows.append([pkg, mgr, decision, str(scan.get("reason", ""))[:80]])

        self._findings_display_limit = 0

        print(f"\n{Fore.CYAN}[Security]{Style.RESET_ALL} Dry-run summary:")
        print(
            tabulate(
                summary_rows,
                headers=["Package", "Manager", "Decision", "Reason"],
                tablefmt="grid",
            )
        )
        if any_risk:
            print(
                f"{Fore.YELLOW}[Security]{Style.RESET_ALL} "
                "Exit code 1: at least one BLOCK/WARN/ERROR (useful for CI gates)."
            )
            return 1
        print(f"{Fore.GREEN}[Security]{Style.RESET_ALL} Exit code 0: all ALLOW.{Style.RESET_ALL}")
        return 0

    def uninstall_package(
        self,
        package_name: str,
        manager_name: Optional[str] = None,
    ) -> None:
        """Uninstall a package (explicit manager or auto-detect)."""
        if manager_name:
            resolved = self._resolve_manager(manager_name)
            if not resolved:
                return
        else:
            found = self._detect_managers_for_package(package_name)
            if not found:
                print(
                    f"{Fore.RED}Package '{package_name}' not found in any installed packages{Style.RESET_ALL}"
                )
                return
            if len(found) == 1:
                resolved = found[0]
            else:
                resolved = self._prompt_manager(found)
                if not resolved:
                    return

        manager = self.available_managers[resolved]
        success = manager.uninstall_package(package_name)
        if success:
            print(
                f"{Fore.GREEN}{_SYMBOL_OK} Successfully uninstalled {package_name} "
                f"via {resolved}{Style.RESET_ALL}"
            )
            # Keep PackageCacheDB consistent: remove the entry so the DB reflects
            # actual filesystem state rather than just accumulating stale records.
            with PackageCacheDB() as db:
                db.remove_package(package_name, resolved)
        else:
            print(f"{Fore.RED}{_SYMBOL_FAIL} Failed to uninstall {package_name}{Style.RESET_ALL}")

    def search_packages(
        self, query: str, manager_name: Optional[str] = None
    ) -> None:
        """Search registries."""
        if manager_name:
            resolved = self._resolve_manager(manager_name)
            if not resolved:
                return
            managers_to_search = {resolved: self.available_managers[resolved]}
        else:
            managers_to_search = dict(self.available_managers)

        all_results: List[Dict[str, Any]] = []
        for name, manager in managers_to_search.items():
            print(f"\n{Fore.CYAN}Searching {name}...{Style.RESET_ALL}")
            all_results.extend(manager.search_package(query))

        if all_results:
            table_data = [
                [p["name"], p["version"], p.get("description", ""), p["manager"]]
                for p in all_results
            ]
            print(f"\n{Fore.GREEN}Found {len(all_results)} results:{Style.RESET_ALL}")
            print(
                tabulate(
                    table_data,
                    headers=["Package", "Version", "Description", "Manager"],
                    tablefmt="grid",
                )
            )
        else:
            print(f"{Fore.YELLOW}No packages found matching '{query}'{Style.RESET_ALL}")

    def check_updates(self, manager_name: Optional[str] = None) -> None:
        """List outdated packages."""
        if not self.available_managers:
            print(f"{Fore.RED}No package managers available!{Style.RESET_ALL}")
            return

        if manager_name:
            resolved = self._resolve_manager(manager_name)
            if not resolved:
                return
            managers_to_check = {resolved: self.available_managers[resolved]}
        else:
            managers_to_check = dict(self.available_managers)

        all_outdated: List[Dict[str, Any]] = []
        for name, manager in managers_to_check.items():
            print(f"\n{Fore.CYAN}Checking for updates in {name}...{Style.RESET_ALL}")
            all_outdated.extend(manager.check_outdated())

        if all_outdated:
            table_data = [
                [p["name"], p["current"], p["latest"], p["manager"]]
                for p in all_outdated
            ]
            print(f"\n{Fore.YELLOW}Found {len(all_outdated)} outdated packages:{Style.RESET_ALL}")
            print(
                tabulate(
                    table_data,
                    headers=["Package", "Current", "Latest", "Manager"],
                    tablefmt="grid",
                )
            )
            print(f"\n{Fore.CYAN}To update a package:{Style.RESET_ALL}")
            print("  python -m src.cli upgrade <package-name>")
        else:
            print(f"\n{Fore.GREEN}{_SYMBOL_OK} All packages are up to date!{Style.RESET_ALL}")


# ======================================================================
# Argument parsing & entry point
# ======================================================================

def _is_placeholder(name: str) -> bool:
    return name in ("package-name", PLACEHOLDER_PACKAGE)


def _print_help() -> None:
    """Print extended help text."""
    sep = f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}"
    print(f"\n{sep}")
    print(f"{Fore.GREEN}Unified CLI — Help{Style.RESET_ALL}")
    print(f"{sep}\n")

    cmds = [
        (
            "list",
            "List all installed packages from available managers.\n"
            "  Latest column is green when an update is available.\n"
            "  Example: unified list\n",
        ),
        (
            "search <query> [-m <manager>]",
            "Search for packages across npm, pip3, yarn, and/or pnpm.\n"
            "  Examples:\n"
            "    unified search requests\n"
            "    unified search react -m npm\n",
        ),
        (
            "install <package> [-m <manager>] [--no-security] [--show-findings [N]]",
            "Install a package (runs multi-provider security scan first).\n"
            "  Examples:\n"
            "    unified install express -m npm\n"
            "    unified install requests -m pip3\n",
        ),
        (
            "upgrade [package] [-m <manager>] [--no-security] [--show-findings [N]]",
            "Without a package: list outdated packages.\n"
            "  With a package: upgrade it (auto-detect manager unless -m).\n"
            "  Examples:\n"
            "    unified upgrade\n"
            "    unified upgrade pytest\n"
            "    unified upgrade express -m npm\n",
        ),
        (
            "update [package] [-m <manager>] [--no-security] [--show-findings [N]]",
            "Alias for 'upgrade' (same behaviour).\n",
        ),
        (
            "uninstall <package> [-m <manager>]",
            "Remove a package (auto-detect manager unless -m).\n"
            "  Example: unified uninstall lodash -m npm\n",
        ),
        (
            "help",
            "Show this help message.\n",
        ),
    ]

    for title, body in cmds:
        print(f"{Fore.YELLOW}{title}{Style.RESET_ALL}")
        print(f"  {body}")

    print(f"{Fore.MAGENTA}Security Scanning:{Style.RESET_ALL}")
    print("  • Resolves the exact package version BEFORE downloading the artifact")
    print("    (TOCTOU-safe: the scanned hash and the installed release are always the same).")
    print("  • Downloads the pinned artifact to a temp directory and computes SHA-256.")
    print("  • Aggregates OSV, GitHub Advisory, OSS Index, and VirusTotal.")
    print("  • Decision policy: critical/malicious → block, medium/high → warn, clean → allow.")
    print("  • Fail-closed: if the scanner itself errors, the action is BLOCKED")
    print(f"    (use {Fore.YELLOW}--no-security{Style.RESET_ALL} to override).")
    print("  • Retries, timeouts, and rate-limit handling with exponential back-off.")
    print("  • JSON + Markdown reports saved in security_reports/.")
    print(f"  • Skip scanning with {Fore.YELLOW}--no-security{Style.RESET_ALL}.")
    print("  • Show findings in terminal with --show-findings or --show-findings N.\n")

    print(f"{Fore.MAGENTA}Transitive Dependency Scanning:{Style.RESET_ALL}")
    print("  • On install, a pre/post snapshot of installed packages is diffed.")
    print("  • Every newly introduced transitive dependency is scanned automatically.")
    print("  • If any transitive dependency is BLOCKED, the top-level package and all")
    print("    new dependencies are automatically rolled back (uninstalled).")
    print("  • Protects against supply-chain injection via malicious sub-dependencies.\n")

    print(f"{sep}")
    print(f"{Fore.GREEN}Supported Package Managers:{Style.RESET_ALL}")
    print(f"{sep}\n")
    print("  • npm  (Node Package Manager)")
    print("  • pip3 (Python Package Manager)")
    print("  • yarn (Yarn Package Manager)")
    print("  • pnpm (pnpm Package Manager)\n")


def _load_env_files() -> None:
    """Load `.env`: cwd first, then package root (parent of `src/`), so CLI works when cwd != project dir."""
    load_dotenv()
    pkg_root = Path(__file__).resolve().parent.parent
    load_dotenv(pkg_root / ".env")


def main() -> None:
    """CLI entry point."""
    _load_env_files()

    parser = argparse.ArgumentParser(
        description="Supply-Chain Security Scanner - Multi-provider vulnerability aggregation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Security Scanning:
    Every install/upgrade is protected by a multi-layer security pipeline:

    1. VERSION PINNING (TOCTOU fix)
       The exact registry version is resolved before artifact download.
       The same pinned version is passed to the package manager at install time,
       so the scanned artifact and the installed release are always identical.

    2. MULTI-PROVIDER SCANNING
       Packages are checked against 4 providers in parallel:
       - OSV.dev          (open-source vulnerability database)
       - GitHub Advisory  (GitHub-tracked CVEs and advisories)
       - OSS Index        (Sonatype component intelligence)
       - VirusTotal       (SHA-256 file-hash malware reputation)

    3. TRANSITIVE DEPENDENCY SCANNING
       After install, the package tree is diffed (before vs. after).
       Every newly introduced transitive dependency is scanned automatically.
       If any transitive dep is BLOCKED the entire install is rolled back.

    4. FAIL-CLOSED POLICY
       If the scanner itself errors, the action is BLOCKED by default.
       Use --no-security to bypass scanning entirely.

    Decisions: BLOCK (critical/malicious), WARN (medium/high), ALLOW (clean)
    Use --force to override BLOCK or skip WARN prompts.

Examples:
    %(prog)s install requests -m pip3         # Install with full security pipeline
    %(prog)s upgrade flask --show-findings    # Show vulnerability findings
    %(prog)s install lodash --no-security     # Skip security scan
    %(prog)s upgrade --all --dry-run          # Audit all outdated packages (CI gate)
    %(prog)s list                             # List all installed packages
        """,
    )

    parser.add_argument(
        "command",
        choices=["list", "install", "search", "upgrade", "update", "uninstall", "help"],
        help="Command to execute",
    )
    parser.add_argument("package", nargs="?", help="Package name (for install/search/upgrade/uninstall)")
    parser.add_argument(
        "-m",
        "--manager",
        choices=_MANAGER_CHOICES,
        help="Specific package manager to use",
    )
    parser.add_argument(
        "--no-security",
        action="store_true",
        default=False,
        help="Skip the security scan before install/upgrade",
    )
    parser.add_argument(
        "--show-findings",
        nargs="?",
        type=int,
        const=10,
        default=0,
        metavar="N",
        help="Show top N security findings in terminal (default: 10 when provided without N)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Override security BLOCK and skip WARN confirmation (install/upgrade only)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="With 'upgrade --all': run security scans on outdated packages without upgrading",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        dest="upgrade_all",
        default=False,
        help="With 'upgrade': target all outdated packages (requires --dry-run)",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    # Help (exit immediately — no need to probe managers)
    if args.command == "help":
        _print_help()
        sys.exit(0)

    # Create CLI instance (probes manager availability)
    cli = UnifiedCLI()

    if args.command == "list":
        cli.list_all_packages()

    elif args.command == "install":
        if not args.package:
            print(f"{Fore.RED}Error: Package name required for install{Style.RESET_ALL}")
            sys.exit(1)
        if _is_placeholder(args.package.strip()):
            print(
                f"{Fore.YELLOW}Refusing to install placeholder name '{args.package}'. "
                f"Replace with a real package name.{Style.RESET_ALL}"
            )
            sys.exit(1)
        cli.install_package(
            args.package,
            args.manager,
            skip_security=args.no_security,
            show_findings=args.show_findings,
            force_security=args.force,
        )

    elif args.command == "search":
        if not args.package:
            print(f"{Fore.RED}Error: Search query required{Style.RESET_ALL}")
            sys.exit(1)
        cli.search_packages(args.package, args.manager)

    elif args.command in ("upgrade", "update"):
        if not args.package:
            if args.upgrade_all:
                if args.dry_run:
                    code = cli.upgrade_all_dry_run(
                        args.manager,
                        show_findings=args.show_findings,
                    )
                    sys.exit(code)
                print(
                    f"{Fore.YELLOW}upgrade --all requires --dry-run "
                    f"(bulk upgrade is not implemented).{Style.RESET_ALL}"
                )
                sys.exit(1)
            if args.dry_run:
                print(
                    f"{Fore.YELLOW}Use: unified upgrade --all --dry-run "
                    f"to audit outdated packages.{Style.RESET_ALL}"
                )
                sys.exit(1)
            cli.check_updates(args.manager)
            sys.exit(0)
        if _is_placeholder(args.package.strip()):
            print(
                f"{Fore.YELLOW}Refusing to upgrade placeholder name '{args.package}'. "
                f"Replace with a real package name.{Style.RESET_ALL}"
            )
            sys.exit(1)
        cli.upgrade_package(
            args.package,
            args.manager,
            skip_security=args.no_security,
            show_findings=args.show_findings,
            force_security=args.force,
        )

    elif args.command == "uninstall":
        if not args.package:
            print(f"{Fore.RED}Error: Package name required for uninstall{Style.RESET_ALL}")
            sys.exit(1)
        if _is_placeholder(args.package.strip()):
            print(
                f"{Fore.YELLOW}Refusing to uninstall placeholder name '{args.package}'. "
                f"Replace with a real package name.{Style.RESET_ALL}"
            )
            sys.exit(1)
        cli.uninstall_package(args.package, args.manager)


if __name__ == "__main__":
    main()
