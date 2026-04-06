"""Phase-1 CLI registration and parser tests."""
# pyright: reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownLambdaType=false
import pytest

from src.cli import UnifiedCLI, main
from src.managers.base_manager import BasePackageManager


def test_unifiedcli_registers_all_managers(monkeypatch):
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: False)
    cli = UnifiedCLI()

    assert "npm" in cli.managers
    assert "pip3" in cli.managers
    assert "yarn" in cli.managers
    assert "pnpm" in cli.managers
    for mgr in cli.managers.values():
        assert isinstance(mgr, BasePackageManager)


def test_search_with_unavailable_manager_shows_message(monkeypatch, capsys):
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: False)
    cli = UnifiedCLI()
    cli.search_packages("react", "yarn")

    captured = capsys.readouterr()
    assert "Manager 'yarn' not available" in captured.out


def test_main_rejects_invalid_manager_choice(monkeypatch):
    monkeypatch.setattr("sys.argv", ["unified", "search", "react", "-m", "invalid"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2


def test_main_accepts_yarn_choice_in_parser(monkeypatch):
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: False)
    monkeypatch.setattr("sys.argv", ["unified", "help", "-m", "yarn"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0


def test_update_command_recognised_in_parser(monkeypatch):
    """'update' is now a valid command (alias for upgrade)."""
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: False)
    monkeypatch.setattr("sys.argv", ["unified", "update"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0


def test_uninstall_command_recognised_in_parser(monkeypatch):
    """'uninstall' is now a valid command."""
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: False)
    monkeypatch.setattr("sys.argv", ["unified", "uninstall", "lodash", "-m", "npm"])
    # Will print "Manager 'npm' not available" but should NOT raise
    main()


def test_version_flag(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["unified", "--version"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "1.1.0" in captured.out


def test_show_findings_flag_defaults_to_10(monkeypatch):
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: False)
    captured = {}

    def _fake_install(
        self, package_name, manager_name=None, *, skip_security=False, show_findings=0, force_security=False
    ):
        captured["package_name"] = package_name
        captured["manager_name"] = manager_name
        captured["skip_security"] = skip_security
        captured["show_findings"] = show_findings
        captured["force_security"] = force_security

    monkeypatch.setattr(UnifiedCLI, "install_package", _fake_install)
    monkeypatch.setattr("sys.argv", ["unified", "install", "requests", "--show-findings"])
    main()

    assert captured["package_name"] == "requests"
    assert captured["show_findings"] == 10


def test_show_findings_flag_with_explicit_value(monkeypatch):
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: False)
    captured = {}

    def _fake_upgrade(
        self, package_name, manager_name=None, *, skip_security=False, show_findings=0, force_security=False
    ):
        captured["package_name"] = package_name
        captured["manager_name"] = manager_name
        captured["skip_security"] = skip_security
        captured["show_findings"] = show_findings
        captured["force_security"] = force_security

    monkeypatch.setattr(UnifiedCLI, "upgrade_package", _fake_upgrade)
    monkeypatch.setattr("sys.argv", ["unified", "upgrade", "requests", "--show-findings", "3"])
    main()

    assert captured["package_name"] == "requests"
    assert captured["show_findings"] == 3
