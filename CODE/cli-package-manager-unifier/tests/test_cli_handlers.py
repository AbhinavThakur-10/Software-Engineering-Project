"""Tests for CLI command handlers (install, upgrade, uninstall, search, list).

All tests mock the underlying manager methods and security scan so no real
subprocess or network calls are made.
"""
# pyright: reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownLambdaType=false, reportPrivateUsage=false
import pytest
from unittest.mock import MagicMock

from src.cli import UnifiedCLI
from src.managers.base_manager import BasePackageManager


@pytest.fixture()
def cli(monkeypatch):
    """Create a UnifiedCLI with all managers marked available but all ops mocked."""
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
    instance = UnifiedCLI()
    # Stub security scan to always allow
    monkeypatch.setattr(instance, "_security_scan", lambda pkg, mgr, *a, **k: True)
    instance._last_security_scan = {"decision": "allow", "reason": "test", "coverage": 4, "counts": {}, "findings": [], "providers": {}}
    return instance


# ------------------------------------------------------------------
# install_package
# ------------------------------------------------------------------

class TestInstallPackage:
    def test_install_with_manager(self, cli, monkeypatch, capsys):
        monkeypatch.setattr(cli.managers["npm"], "install_package", lambda pkg: True)
        monkeypatch.setattr(cli.managers["npm"], "list_packages", lambda: [{"name": "lodash", "version": "4.17.21"}])
        cli.install_package("lodash", "npm")
        out = capsys.readouterr().out
        assert "Successfully installed" in out

    def test_install_unavailable_manager(self, monkeypatch, capsys):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: False)
        cli2 = UnifiedCLI()
        cli2.install_package("lodash", "npm")
        out = capsys.readouterr().out
        assert "not available" in out

    def test_install_failure_reports_error(self, cli, monkeypatch, capsys):
        monkeypatch.setattr(cli.managers["pip3"], "install_package", lambda pkg: False)
        cli.install_package("nonexistent-pkg", "pip3")
        out = capsys.readouterr().out
        assert "Failed to install" in out

    def test_install_blocked_by_security(self, monkeypatch, capsys):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        cli2 = UnifiedCLI()
        monkeypatch.setattr(cli2, "_security_scan", lambda pkg, mgr, *a, **k: False)
        cli2._last_security_scan = {"decision": "block", "reason": "test", "coverage": 0, "counts": {}, "findings": [], "providers": {}}
        cli2.install_package("malicious-pkg", "npm")
        out = capsys.readouterr().out
        # Should not say "Successfully installed"
        assert "Successfully installed" not in out

    def test_install_passes_show_findings(self, cli, monkeypatch):
        called = {}

        def _capture(action, package_name, manager_name, operation, **kwargs):
            called.update(kwargs)

        monkeypatch.setattr(cli, "_execute_with_security", _capture)
        cli.install_package("lodash", "npm", show_findings=7)
        assert called["show_findings"] == 7


# ------------------------------------------------------------------
# upgrade_package
# ------------------------------------------------------------------

class TestUpgradePackage:
    def test_upgrade_with_manager(self, cli, monkeypatch, capsys):
        monkeypatch.setattr(cli.managers["pip3"], "upgrade_package", lambda pkg: True)
        cli.upgrade_package("requests", "pip3")
        out = capsys.readouterr().out
        assert "Successfully upgrade" in out

    def test_upgrade_auto_detect_single(self, cli, monkeypatch, capsys):
        monkeypatch.setattr(cli.managers["pip3"], "list_packages", lambda: [{"name": "requests", "version": "2.31.0"}])
        monkeypatch.setattr(cli.managers["npm"], "list_packages", lambda: [])
        monkeypatch.setattr(cli.managers["yarn"], "list_packages", lambda: [])
        monkeypatch.setattr(cli.managers["pnpm"], "list_packages", lambda: [])
        monkeypatch.setattr(cli.managers["pip3"], "upgrade_package", lambda pkg: True)
        cli.upgrade_package("requests")
        out = capsys.readouterr().out
        assert "Successfully upgrade" in out

    def test_upgrade_not_found(self, cli, monkeypatch, capsys):
        for mgr in cli.managers.values():
            monkeypatch.setattr(mgr, "list_packages", lambda: [])
        cli.upgrade_package("nonexistent-pkg")
        out = capsys.readouterr().out
        assert "not found" in out

    def test_upgrade_passes_show_findings(self, cli, monkeypatch):
        called = {}

        def _capture(action, package_name, manager_name, operation, **kwargs):
            called.update(kwargs)

        monkeypatch.setattr(cli, "_execute_with_security", _capture)
        cli.upgrade_package("requests", "pip3", show_findings=4)
        assert called["show_findings"] == 4


# ------------------------------------------------------------------
# uninstall_package
# ------------------------------------------------------------------

class TestUninstallPackage:
    def test_uninstall_with_manager(self, cli, monkeypatch, capsys):
        monkeypatch.setattr(cli.managers["npm"], "uninstall_package", lambda pkg: True)
        cli.uninstall_package("lodash", "npm")
        out = capsys.readouterr().out
        assert "Successfully uninstalled" in out

    def test_uninstall_failure(self, cli, monkeypatch, capsys):
        monkeypatch.setattr(cli.managers["npm"], "uninstall_package", lambda pkg: False)
        cli.uninstall_package("lodash", "npm")
        out = capsys.readouterr().out
        assert "Failed to uninstall" in out


# ------------------------------------------------------------------
# search_packages
# ------------------------------------------------------------------

class TestSearchPackages:
    def test_search_all_managers(self, cli, monkeypatch, capsys):
        for mgr in cli.managers.values():
            monkeypatch.setattr(mgr, "search_package", lambda q: [{"name": "react", "version": "18.0.0", "description": "React", "manager": "npm"}])
        cli.search_packages("react")
        out = capsys.readouterr().out
        assert "Found" in out

    def test_search_no_results(self, cli, monkeypatch, capsys):
        for mgr in cli.managers.values():
            monkeypatch.setattr(mgr, "search_package", lambda q: [])
        cli.search_packages("zzz_nonexistent")
        out = capsys.readouterr().out
        assert "No packages found" in out


# ------------------------------------------------------------------
# check_updates
# ------------------------------------------------------------------

class TestCheckUpdates:
    def test_check_updates_shows_outdated(self, cli, monkeypatch, capsys):
        monkeypatch.setattr(cli.managers["pip3"], "check_outdated", lambda: [
            {"name": "flask", "current": "2.0.0", "latest": "3.0.0", "manager": "pip3"}
        ])
        for name, mgr in cli.managers.items():
            if name != "pip3":
                monkeypatch.setattr(mgr, "check_outdated", lambda: [])
        cli.check_updates()
        out = capsys.readouterr().out
        assert "flask" in out
        assert "outdated" in out

    def test_check_updates_all_current(self, cli, monkeypatch, capsys):
        for mgr in cli.managers.values():
            monkeypatch.setattr(mgr, "check_outdated", lambda: [])
        cli.check_updates()
        out = capsys.readouterr().out
        assert "up to date" in out


# ------------------------------------------------------------------
# skip_security flag
# ------------------------------------------------------------------

class TestSkipSecurity:
    def test_install_with_no_security(self, monkeypatch, capsys):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        cli2 = UnifiedCLI()
        # _security_scan should NOT be called; if it is, fail
        monkeypatch.setattr(cli2, "_security_scan", lambda *a: (_ for _ in ()).throw(AssertionError("should not be called")))
        monkeypatch.setattr(cli2.managers["npm"], "install_package", lambda pkg: True)
        monkeypatch.setattr(cli2.managers["npm"], "list_packages", lambda: [])
        cli2._last_security_scan = None
        cli2.install_package("lodash", "npm", skip_security=True)
        out = capsys.readouterr().out
        assert "Successfully installed" in out


class TestSecurityOutput:
    def test_security_table_includes_remarks_for_high_medium(self, monkeypatch, capsys):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        cli2 = UnifiedCLI()

        monkeypatch.setattr("src.cli.download_package_and_get_hash", lambda *a, **k: "abc123")

        cli2.security_aggregator = MagicMock()
        cli2.security_aggregator.analyze.return_value = {
            "decision": "allow",
            "reason": "test",
            "coverage": 2,
            "counts": {"critical": 0, "high": 4, "medium": 8, "low": 1},
            "findings": [
                {"id": "GHSA-AAAA", "severity": "high", "summary": "High issue", "source": "github_advisory"},
                {"id": "GHSA-BBBB", "severity": "high", "summary": "High issue 2", "source": "github_advisory"},
                {"id": "GHSA-CCCC", "severity": "medium", "summary": "Medium issue", "source": "github_advisory"},
                {"id": "GHSA-DDDD", "severity": "medium", "summary": "Medium issue 2", "source": "github_advisory"},
            ],
            "providers": {},
        }

        allowed = cli2._security_scan("Werkzeug", "pip3")
        out = capsys.readouterr().out

        assert allowed is True
        assert "Remarks" in out
        assert "4 finding(s) classified as high" in out
        assert "8 finding(s) classified as medium" in out

    def test_security_output_shows_provider_error_sources(self, monkeypatch, capsys):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        cli2 = UnifiedCLI()

        monkeypatch.setattr("src.cli.download_package_and_get_hash", lambda *a, **k: "abc123")

        cli2.security_aggregator = MagicMock()
        cli2.security_aggregator.analyze.return_value = {
            "decision": "allow",
            "reason": "test",
            "coverage": 2,
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "findings": [],
            "providers": {
                "osv": {"status": "ok", "findings": []},
                "virustotal": {
                    "status": "error",
                    "error": "AuthenticationRequiredError: X-Apikey header is missing",
                    "findings": [],
                },
            },
        }

        allowed = cli2._security_scan("Werkzeug", "pip3")
        out = capsys.readouterr().out

        assert allowed is True
        assert "Provider statuses" in out
        assert "Provider Call Status" in out
        assert "Findings" in out
        assert "virustotal" in out
        assert "AuthenticationRequiredError" in out

    def test_warn_output_shows_high_medium_source_providers(self, monkeypatch, capsys):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        cli2 = UnifiedCLI()

        monkeypatch.setattr("src.cli.download_package_and_get_hash", lambda *a, **k: "abc123")

        cli2.security_aggregator = MagicMock()
        cli2.security_aggregator.analyze.return_value = {
            "decision": "warn",
            "reason": "Medium/high severity findings detected",
            "coverage": 3,
            "counts": {"critical": 0, "high": 1, "medium": 1, "low": 0},
            "findings": [
                {"id": "GHSA-H", "severity": "high", "summary": "h", "source": "github_advisory"},
                {"id": "OSV-M", "severity": "medium", "summary": "m", "source": "osv"},
            ],
            "providers": {
                "github_advisory": {"status": "ok", "findings": [{"id": "GHSA-H"}]},
                "osv": {"status": "ok", "findings": [{"id": "OSV-M"}]},
                "virustotal": {"status": "ok", "findings": []},
            },
        }

        allowed = cli2._security_scan("Werkzeug", "pip3")
        out = capsys.readouterr().out

        assert allowed is True
        assert "Warn due to high/medium findings from:" in out
        assert "github_advisory" in out
        assert "osv" in out


class TestMarkdownPrompt:
    def test_install_prompt_yes_saves_markdown_report(self, monkeypatch, capsys):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        cli2 = UnifiedCLI()
        monkeypatch.setattr(cli2, "_security_scan", lambda pkg, mgr, *a, **k: True)
        cli2._last_security_scan = {
            "decision": "warn",
            "reason": "test",
            "coverage": 2,
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "findings": [{"id": "GHSA-1", "severity": "high", "summary": "x", "source": "github_advisory"}],
            "providers": {},
        }
        monkeypatch.setattr("builtins.input", lambda *_: "y")
        monkeypatch.setattr("src.cli.write_security_report_markdown", lambda **kwargs: "security_reports/preinstall.md")
        monkeypatch.setattr(cli2.managers["npm"], "install_package", lambda pkg: True)
        monkeypatch.setattr(cli2.managers["npm"], "list_packages", lambda: [])

        cli2.install_package("lodash", "npm")
        out = capsys.readouterr().out
        assert "Markdown report saved" in out

    def test_install_prompt_no_does_not_save_markdown_report(self, monkeypatch, capsys):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        cli2 = UnifiedCLI()
        monkeypatch.setattr(cli2, "_security_scan", lambda pkg, mgr, *a, **k: True)
        cli2._last_security_scan = {
            "decision": "allow",
            "reason": "test",
            "coverage": 2,
            "counts": {},
            "findings": [],
            "providers": {},
        }
        monkeypatch.setattr("builtins.input", lambda *_: "n")
        writer = MagicMock(return_value="security_reports/preinstall.md")
        monkeypatch.setattr("src.cli.write_security_report_markdown", writer)
        monkeypatch.setattr(cli2.managers["npm"], "install_package", lambda pkg: True)
        monkeypatch.setattr(cli2.managers["npm"], "list_packages", lambda: [])

        cli2.install_package("lodash", "npm")
        _ = capsys.readouterr().out
        writer.assert_not_called()

    def test_upgrade_prompt_yes_saves_markdown_report(self, monkeypatch, capsys):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        cli2 = UnifiedCLI()
        monkeypatch.setattr(cli2, "_security_scan", lambda pkg, mgr, *a, **k: True)
        cli2._last_security_scan = {
            "decision": "warn",
            "reason": "test",
            "coverage": 2,
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "findings": [{"id": "GHSA-1", "severity": "high", "summary": "x", "source": "github_advisory"}],
            "providers": {},
        }
        monkeypatch.setattr("builtins.input", lambda *_: "y")
        writer = MagicMock(return_value="security_reports/preupgrade.md")
        monkeypatch.setattr("src.cli.write_security_report_markdown", writer)
        monkeypatch.setattr(cli2.managers["pip3"], "upgrade_package", lambda pkg: True)

        cli2.upgrade_package("Werkzeug", "pip3")
        out = capsys.readouterr().out

        writer.assert_called_once()
        assert "Markdown report saved" in out

    def test_warn_flow_prompts_download_before_proceed(self, monkeypatch):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        cli2 = UnifiedCLI()

        call_order = []

        def _fake_security_scan(pkg, mgr, *a, **k):
            cli2._last_security_scan = {
                "decision": "warn",
                "reason": "test",
                "coverage": 2,
                "counts": {},
                "findings": [],
                "providers": {},
            }
            return True

        def _fake_offer(action, pkg, mgr):
            call_order.append("download")

        def _fake_input(_prompt):
            call_order.append("proceed")
            return "y"

        monkeypatch.setattr(cli2, "_security_scan", _fake_security_scan)
        monkeypatch.setattr(cli2, "_offer_markdown_report_before_action", _fake_offer)
        monkeypatch.setattr("builtins.input", _fake_input)
        monkeypatch.setattr(cli2.managers["pip3"], "upgrade_package", lambda pkg: True)

        cli2.upgrade_package("Werkzeug", "pip3")
        assert call_order == ["download", "proceed"]
