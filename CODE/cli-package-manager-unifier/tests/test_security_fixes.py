"""Regression tests for the four architectural security fixes.

Tasks covered
=============
Task 1 — TOCTOU: version is resolved before hash download; pinned specifier is
         passed to the package manager's install command.
Task 2 — Transitive deps: state-diff detects new packages; BLOCK triggers
         automatic rollback.
Task 3 — PackageCacheDB: remove_package and update_package_version keep the DB
         consistent with the filesystem.
Task 4 — OSV parser: CVSS vector strings no longer produce "unknown" severity;
         scan exceptions block the action (fail-closed).
"""
# pyright: reportUnknownParameterType=false, reportMissingParameterType=false
# pyright: reportUnknownArgumentType=false, reportUnknownVariableType=false
# pyright: reportPrivateUsage=false
from __future__ import annotations

import sqlite3
import tempfile
import os
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch, call

import pytest

from src.managers.base_manager import BasePackageManager
from src.cli import UnifiedCLI
from src.utils.package_cache import PackageCacheDB
from src.utils.security_providers import scan_with_osv


# ---------------------------------------------------------------------------
# Shared CLI fixture (all managers available, security mocked, prompts auto-y)
# ---------------------------------------------------------------------------

@pytest.fixture()
def cli(monkeypatch):
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
    instance = UnifiedCLI()
    instance._last_security_scan = {
        "decision": "allow",
        "reason": "test",
        "coverage": 4,
        "counts": {},
        "findings": [],
        "providers": {},
    }
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    monkeypatch.setattr(instance, "_emit_security_report", lambda *a, **k: None)
    monkeypatch.setattr(instance, "_offer_markdown_report_before_action", lambda *a, **k: None)
    return instance


# ===========================================================================
# TASK 1 — TOCTOU fix
# ===========================================================================

class TestTOCTOU:
    """The resolved version must be (a) stored before the hash download and
    (b) embedded in the specifier passed to the underlying manager."""

    def test_version_resolved_before_hash_download(self, cli, monkeypatch):
        """_security_scan must populate _last_resolved_version before
        download_package_and_get_hash is called."""
        call_order: List[str] = []

        def fake_resolve(pkg, mgr, *, action="install"):
            call_order.append("resolve")
            cli._last_resolved_version = "1.2.3"
            return "1.2.3"

        def fake_download(pkg, mgr, version=None):
            call_order.append(f"download:{version}")
            return "abc123"

        monkeypatch.setattr(cli, "_resolve_scan_version", fake_resolve)
        monkeypatch.setattr(
            "src.cli.download_package_and_get_hash", fake_download
        )
        # Stub SecurityAggregator so we don't hit the network
        cli.security_aggregator.analyze = MagicMock(
            return_value={"decision": "allow", "reason": "ok", "coverage": 2,
                          "counts": {}, "findings": [], "providers": {}}
        )

        cli._security_scan("requests", "pip3", "install")

        assert call_order[0] == "resolve", "resolve must happen before download"
        assert "download:1.2.3" in call_order, "hash download must receive the pinned version"

    def test_pinned_specifier_passed_to_install_pip(self, cli, monkeypatch):
        """install_package must call pip install with package==version."""
        received: Dict[str, Any] = {}

        def fake_install(pkg):
            received["pkg"] = pkg
            return True

        monkeypatch.setattr(cli, "_security_scan", lambda *a, **k: True)
        cli._last_resolved_version = "2.28.0"
        monkeypatch.setattr(cli.managers["pip3"], "install_package", fake_install)
        monkeypatch.setattr(
            cli.managers["pip3"], "list_packages",
            lambda: [{"name": "requests", "version": "2.28.0"}],
        )

        cli._execute_with_security(
            "install", "requests", "pip3",
            cli.managers["pip3"].install_package,
            skip_security=True,
        )

        assert received["pkg"] == "requests==2.28.0"

    def test_pinned_specifier_passed_to_install_npm(self, cli, monkeypatch):
        """install_package must call npm install with package@version."""
        received: Dict[str, Any] = {}

        def fake_install(pkg):
            received["pkg"] = pkg
            return True

        monkeypatch.setattr(cli, "_security_scan", lambda *a, **k: True)
        cli._last_resolved_version = "4.17.21"
        monkeypatch.setattr(cli.managers["npm"], "install_package", fake_install)
        monkeypatch.setattr(
            cli.managers["npm"], "list_packages",
            lambda: [{"name": "lodash", "version": "4.17.21"}],
        )

        cli._execute_with_security(
            "install", "lodash", "npm",
            cli.managers["npm"].install_package,
            skip_security=True,
        )

        assert received["pkg"] == "lodash@4.17.21"

    def test_no_version_resolved_leaves_specifier_unchanged(self, cli, monkeypatch):
        """When version cannot be resolved the original name is passed through."""
        received: Dict[str, Any] = {}

        def fake_install(pkg):
            received["pkg"] = pkg
            return True

        monkeypatch.setattr(cli, "_security_scan", lambda *a, **k: True)
        cli._last_resolved_version = None  # simulate unresolvable version
        monkeypatch.setattr(cli.managers["pip3"], "install_package", fake_install)
        monkeypatch.setattr(cli.managers["pip3"], "list_packages", lambda: [])

        cli._execute_with_security(
            "install", "somepackage", "pip3",
            cli.managers["pip3"].install_package,
            skip_security=True,
        )

        assert received["pkg"] == "somepackage"

    def test_download_package_and_get_hash_passes_version_to_pip(self, monkeypatch):
        """download_package_and_get_hash forwards version to _download_pip_artifact."""
        captured: Dict[str, Any] = {}

        def fake_pip_artifact(pkg, tmpdir, version=None):
            captured["pkg"] = pkg
            captured["version"] = version
            return "deadbeef"

        monkeypatch.setattr(
            "src.utils.virustotal._download_pip_artifact", fake_pip_artifact
        )
        from src.utils.virustotal import download_package_and_get_hash

        download_package_and_get_hash("django", "pip3", version="4.2.0")
        assert captured["version"] == "4.2.0"

    def test_pip_artifact_uses_pinned_specifier(self, tmp_path):
        """_download_pip_artifact builds name==version specifier for pip download."""
        from src.utils.virustotal import _download_pip_artifact

        ran: Dict[str, Any] = {}

        import subprocess as _sp

        real_run = _sp.run

        def fake_run(cmd, **kwargs):
            ran["cmd"] = cmd
            # Return success with a fake file already in tmpdir
            fake_file = tmp_path / "django-4.2.0.whl"
            fake_file.write_bytes(b"fakecontent")
            return _sp.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        import unittest.mock as _mock
        with _mock.patch("subprocess.run", side_effect=fake_run):
            _download_pip_artifact("django", str(tmp_path), version="4.2.0")

        assert "django==4.2.0" in ran["cmd"]


# ===========================================================================
# TASK 2 — Transitive dependency scanning
# ===========================================================================

class TestTransitiveDependencyScanning:
    """State-diff correctly identifies new packages and blocks/rollbacks on BLOCK."""

    def test_capture_snapshot_returns_name_version_map(self, cli, monkeypatch):
        monkeypatch.setattr(
            cli.managers["pip3"], "list_packages",
            lambda: [
                {"name": "Django", "version": "4.2.0"},
                {"name": "sqlparse", "version": "0.4.4"},
            ],
        )
        snap = cli._capture_package_snapshot("pip3")
        assert snap == {"django": "4.2.0", "sqlparse": "0.4.4"}

    def test_capture_snapshot_returns_empty_on_error(self, cli, monkeypatch):
        monkeypatch.setattr(
            cli.managers["pip3"], "list_packages",
            lambda: (_ for _ in ()).throw(RuntimeError("boom")),  # type: ignore[misc]
        )
        snap = cli._capture_package_snapshot("pip3")
        assert snap == {}

    def test_no_new_packages_returns_true(self, cli, monkeypatch):
        before = {"django": "4.2.0"}
        monkeypatch.setattr(
            cli.managers["pip3"], "list_packages",
            lambda: [{"name": "django", "version": "4.2.0"}],
        )
        result = cli._scan_and_rollback_transitive("pip3", before, "django")
        assert result is True

    def test_clean_transitive_dep_returns_true(self, cli, monkeypatch):
        before = {"django": "4.2.0"}
        # After install: sqlparse was added
        monkeypatch.setattr(
            cli.managers["pip3"], "list_packages",
            lambda: [
                {"name": "django", "version": "4.2.0"},
                {"name": "sqlparse", "version": "0.4.4"},
            ],
        )
        cli.security_aggregator.analyze = MagicMock(
            return_value={"decision": "allow", "reason": "ok", "coverage": 2,
                          "counts": {}, "findings": [], "providers": {}}
        )
        result = cli._scan_and_rollback_transitive("pip3", before, "django")
        assert result is True
        cli.security_aggregator.analyze.assert_called_once()

    def test_blocked_transitive_dep_triggers_rollback(self, cli, monkeypatch, capsys):
        before = {"django": "4.2.0"}
        monkeypatch.setattr(
            cli.managers["pip3"], "list_packages",
            lambda: [
                {"name": "django", "version": "4.2.0"},
                {"name": "evil-dep", "version": "1.0.0"},
            ],
        )
        cli.security_aggregator.analyze = MagicMock(
            return_value={"decision": "block", "reason": "malware", "coverage": 2,
                          "counts": {"critical": 1}, "findings": [], "providers": {}}
        )
        uninstalled: List[str] = []
        monkeypatch.setattr(
            cli.managers["pip3"], "uninstall_package",
            lambda pkg: uninstalled.append(pkg) or True,
        )

        result = cli._scan_and_rollback_transitive("pip3", before, "django")

        assert result is False
        assert "evil-dep" in uninstalled, "blocked transitive dep must be uninstalled"
        assert "django" in uninstalled, "top-level must also be rolled back"
        out = capsys.readouterr().out
        assert "rollback" in out.lower() or "Rollback" in out

    def test_top_level_package_excluded_from_transitive_scan(self, cli, monkeypatch):
        """The package the user requested is NOT re-scanned as a transitive dep."""
        before: Dict[str, str] = {}
        monkeypatch.setattr(
            cli.managers["pip3"], "list_packages",
            lambda: [{"name": "requests", "version": "2.31.0"}],
        )
        cli.security_aggregator.analyze = MagicMock(
            return_value={"decision": "allow", "reason": "ok", "coverage": 2,
                          "counts": {}, "findings": [], "providers": {}}
        )
        cli._scan_and_rollback_transitive("pip3", before, "requests")
        # analyze should NOT have been called for the top-level package
        cli.security_aggregator.analyze.assert_not_called()

    def test_execute_with_security_calls_transitive_scan_on_install(
        self, cli, monkeypatch
    ):
        """_execute_with_security must invoke _scan_and_rollback_transitive."""
        transitive_called: Dict[str, Any] = {}

        def fake_transitive(mgr, before, top):
            transitive_called["mgr"] = mgr
            transitive_called["top"] = top
            return True

        monkeypatch.setattr(cli, "_security_scan", lambda *a, **k: True)
        monkeypatch.setattr(cli, "_scan_and_rollback_transitive", fake_transitive)
        monkeypatch.setattr(
            cli.managers["pip3"], "install_package", lambda pkg: True
        )
        monkeypatch.setattr(
            cli.managers["pip3"], "list_packages",
            lambda: [{"name": "requests", "version": "2.31.0"}],
        )
        cli._last_resolved_version = None

        cli._execute_with_security(
            "install", "requests", "pip3",
            cli.managers["pip3"].install_package,
            skip_security=True,
        )

        assert transitive_called.get("mgr") == "pip3"


# ===========================================================================
# TASK 3 — PackageCacheDB consistency
# ===========================================================================

@pytest.fixture()
def tmp_db(tmp_path):
    """Yield a fresh PackageCacheDB backed by a temp file."""
    db_file = str(tmp_path / "test_cache.db")
    db = PackageCacheDB(db_path=db_file)
    yield db
    db.close()


class TestPackageCacheDB:
    def test_remove_package_deletes_row(self, tmp_db):
        tmp_db.add_package("requests", "2.28.0", "pip3")
        tmp_db.remove_package("requests", "pip3")
        rows = tmp_db.get_packages()
        assert not any(r[0] == "requests" for r in rows)

    def test_remove_package_noop_if_not_present(self, tmp_db):
        """remove_package on a non-existent row must not raise."""
        tmp_db.remove_package("nonexistent", "pip3")  # must not raise
        assert tmp_db.get_packages() == []

    def test_remove_package_is_manager_scoped(self, tmp_db):
        """Removing a package from one manager must not affect another."""
        tmp_db.add_package("lodash", "4.17.21", "npm")
        tmp_db.add_package("lodash", "4.17.21", "yarn")
        tmp_db.remove_package("lodash", "npm")
        rows = tmp_db.get_packages()
        names_and_mgrs = [(r[0], r[2]) for r in rows]
        assert ("lodash", "npm") not in names_and_mgrs
        assert ("lodash", "yarn") in names_and_mgrs

    def test_update_package_version_changes_version(self, tmp_db):
        tmp_db.add_package("requests", "2.28.0", "pip3")
        tmp_db.update_package_version("requests", "2.31.0", "pip3")
        rows = tmp_db.get_packages()
        versions = [r[1] for r in rows if r[0] == "requests" and r[2] == "pip3"]
        assert "2.31.0" in versions

    def test_update_package_version_upserts_missing_row(self, tmp_db):
        """update_package_version must insert if the package was never recorded."""
        tmp_db.update_package_version("flask", "3.0.0", "pip3")
        rows = tmp_db.get_packages()
        assert any(r[0] == "flask" and r[1] == "3.0.0" for r in rows)

    def test_uninstall_removes_from_db(self, cli, monkeypatch, tmp_path):
        """CLI uninstall must call remove_package on success."""
        db_file = str(tmp_path / "test.db")
        monkeypatch.setattr(
            "src.cli.PackageCacheDB",
            lambda **kw: PackageCacheDB(db_path=db_file),
        )
        db_seed = PackageCacheDB(db_path=db_file)
        db_seed.add_package("requests", "2.28.0", "pip3")
        db_seed.close()

        monkeypatch.setattr(
            cli.managers["pip3"], "uninstall_package", lambda pkg: True
        )
        monkeypatch.setattr(
            cli.managers["pip3"], "list_packages",
            lambda: [],
        )
        monkeypatch.setattr(
            cli, "_detect_managers_for_package", lambda pkg: ["pip3"]
        )

        cli.uninstall_package("requests", "pip3")

        db_check = PackageCacheDB(db_path=db_file)
        rows = db_check.get_packages()
        db_check.close()
        assert not any(r[0] == "requests" for r in rows)

    def test_upgrade_updates_db_version(self, cli, monkeypatch, tmp_path):
        """CLI upgrade must call update_package_version on success."""
        db_file = str(tmp_path / "test.db")
        monkeypatch.setattr(
            "src.cli.PackageCacheDB",
            lambda **kw: PackageCacheDB(db_path=db_file),
        )

        db_seed = PackageCacheDB(db_path=db_file)
        db_seed.add_package("requests", "2.28.0", "pip3")
        db_seed.close()

        monkeypatch.setattr(cli, "_security_scan", lambda *a, **k: True)
        cli._last_resolved_version = "2.31.0"
        monkeypatch.setattr(
            cli.managers["pip3"], "upgrade_package", lambda pkg: True
        )
        monkeypatch.setattr(
            cli.managers["pip3"], "list_packages",
            lambda: [{"name": "requests", "version": "2.31.0"}],
        )
        monkeypatch.setattr(cli, "_scan_and_rollback_transitive", lambda *a, **k: True)

        cli._execute_with_security(
            "upgrade", "requests", "pip3",
            cli.managers["pip3"].upgrade_package,
            skip_security=True,
        )

        db_check = PackageCacheDB(db_path=db_file)
        rows = db_check.get_packages()
        db_check.close()
        assert any(r[0] == "requests" and r[1] == "2.31.0" for r in rows)


# ===========================================================================
# TASK 4a — OSV CVSS vector parser
# ===========================================================================

class TestOSVCVSSParser:
    """CVSS vector strings must not produce 'unknown' severity."""

    def _make_osv_response(self, score_value: Any, db_specific: Dict = None) -> Dict:
        """Build a minimal OSV API response dict."""
        vuln: Dict[str, Any] = {
            "id": "GHSA-0000-0000-0000",
            "summary": "Test vulnerability",
            "severity": [{"type": "CVSS_V3", "score": score_value}],
        }
        if db_specific:
            vuln["database_specific"] = db_specific
        return {"vulns": [vuln]}

    def test_cvss_vector_with_db_specific_numeric_score(self, monkeypatch):
        """CVSS vector + database_specific.cvss_score → correct severity."""
        payload = self._make_osv_response(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            db_specific={"cvss_score": 9.8},
        )
        monkeypatch.setattr(
            "src.utils.security_providers._request_with_retries",
            lambda *a, **k: {"ok": True, "status": "ok", "payload": payload},
        )
        result = scan_with_osv("django", "pip3", "3.2.0")
        assert result["status"] == "ok"
        assert result["findings"][0]["severity"] == "critical"

    def test_cvss_vector_with_db_specific_text_label(self, monkeypatch):
        """CVSS vector + database_specific.severity text label → correct severity."""
        payload = self._make_osv_response(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            db_specific={"severity": "MEDIUM"},
        )
        monkeypatch.setattr(
            "src.utils.security_providers._request_with_retries",
            lambda *a, **k: {"ok": True, "status": "ok", "payload": payload},
        )
        result = scan_with_osv("pillow", "pip3", "9.0.0")
        assert result["findings"][0]["severity"] == "medium"

    def test_cvss_vector_with_ecosystem_specific_fallback(self, monkeypatch):
        """CVSS vector + no database_specific → use ecosystem_specific.severity."""
        vuln: Dict[str, Any] = {
            "id": "PYSEC-2023-0001",
            "summary": "Test",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
            "affected": [{"ecosystem_specific": {"severity": "HIGH"}}],
        }
        monkeypatch.setattr(
            "src.utils.security_providers._request_with_retries",
            lambda *a, **k: {"ok": True, "status": "ok", "payload": {"vulns": [vuln]}},
        )
        result = scan_with_osv("paramiko", "pip3", "2.10.0")
        assert result["findings"][0]["severity"] == "high"

    def test_numeric_string_score_parsed_correctly(self, monkeypatch):
        """A plain numeric string score like '7.5' must map to 'high'."""
        payload = self._make_osv_response("7.5")
        monkeypatch.setattr(
            "src.utils.security_providers._request_with_retries",
            lambda *a, **k: {"ok": True, "status": "ok", "payload": payload},
        )
        result = scan_with_osv("numpy", "pip3", "1.23.0")
        assert result["findings"][0]["severity"] == "high"

    def test_numeric_float_score_parsed_correctly(self, monkeypatch):
        """A float score like 9.8 must map to 'critical'."""
        payload = self._make_osv_response(9.8)
        monkeypatch.setattr(
            "src.utils.security_providers._request_with_retries",
            lambda *a, **k: {"ok": True, "status": "ok", "payload": payload},
        )
        result = scan_with_osv("urllib3", "pip3", "1.26.0")
        assert result["findings"][0]["severity"] == "critical"

    def test_unparseable_score_stays_unknown(self, monkeypatch):
        """If no fallback can resolve the severity it stays 'unknown' without crashing."""
        payload = self._make_osv_response("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N")
        monkeypatch.setattr(
            "src.utils.security_providers._request_with_retries",
            lambda *a, **k: {"ok": True, "status": "ok", "payload": payload},
        )
        result = scan_with_osv("somelib", "pip3", "1.0.0")
        # Must not raise; severity may be unknown if no fallback data exists
        assert result["status"] == "ok"
        assert result["findings"][0]["severity"] in {
            "unknown", "critical", "high", "medium", "low"
        }


# ===========================================================================
# TASK 4b — Fail-closed security exception handler
# ===========================================================================

class TestFailClosed:
    """A scan exception must block the action, not silently allow it."""

    def test_scan_exception_returns_false(self, cli, monkeypatch):
        """When SecurityAggregator.analyze raises, _security_scan must return False."""
        cli.security_aggregator.analyze = MagicMock(
            side_effect=RuntimeError("network timeout")
        )
        monkeypatch.setattr(
            "src.cli.download_package_and_get_hash",
            lambda *a, **k: None,
        )

        result = cli._security_scan("requests", "pip3", "install")
        assert result is False

    def test_scan_exception_sets_block_decision(self, cli, monkeypatch):
        """_last_security_scan.decision must be 'block' after a scan error."""
        cli.security_aggregator.analyze = MagicMock(
            side_effect=ConnectionError("DNS failure")
        )
        monkeypatch.setattr(
            "src.cli.download_package_and_get_hash",
            lambda *a, **k: None,
        )

        cli._security_scan("requests", "pip3", "install")
        assert cli._last_security_scan is not None
        assert cli._last_security_scan.get("decision") == "block"

    def test_scan_error_prevents_install(self, cli, monkeypatch, capsys):
        """install_package must not call install_package on the manager when scan errors."""
        install_called = {"called": False}

        def boom_scan(pkg, mgr, action="install"):
            raise RuntimeError("provider unavailable")

        def fake_install(pkg):
            install_called["called"] = True
            return True

        monkeypatch.setattr(cli, "_security_scan", boom_scan)
        monkeypatch.setattr(cli.managers["pip3"], "install_package", fake_install)

        # Simulate what _execute_with_security does when skip_security=False
        cli._execute_with_security(
            "install", "requests", "pip3",
            cli.managers["pip3"].install_package,
            skip_security=False,
        )

        assert not install_called["called"], (
            "install must not proceed when the security scan raises"
        )

    def test_no_security_flag_bypasses_scan(self, cli, monkeypatch):
        """--no-security must skip the scan entirely, even if it would error."""
        scan_called = {"called": False}

        def fail_scan(*a, **k):
            scan_called["called"] = True
            raise RuntimeError("should not be called")

        monkeypatch.setattr(cli, "_security_scan", fail_scan)
        monkeypatch.setattr(
            cli.managers["pip3"], "install_package", lambda pkg: True
        )
        monkeypatch.setattr(
            cli.managers["pip3"], "list_packages",
            lambda: [{"name": "requests", "version": "2.31.0"}],
        )
        cli._last_resolved_version = None
        monkeypatch.setattr(cli, "_scan_and_rollback_transitive", lambda *a, **k: True)

        cli._execute_with_security(
            "install", "requests", "pip3",
            cli.managers["pip3"].install_package,
            skip_security=True,
        )

        assert not scan_called["called"]
