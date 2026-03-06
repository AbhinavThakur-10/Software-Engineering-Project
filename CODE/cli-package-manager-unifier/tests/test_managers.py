"""Unit tests for all concrete package manager implementations.

Every test mocks _run_command so no real subprocess calls are made.
"""
# pyright: reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownLambdaType=false
import json
import subprocess

import pytest

from src.managers.npm_manager import NPMManager
from src.managers.pip_manager import PipManager
from src.managers.yarn_manager import YarnManager
from src.managers.pnpm_manager import PNPMManager
from src.managers.base_manager import BasePackageManager


def _cp(stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


# ======================================================================
# NPMManager
# ======================================================================

class TestNPMManager:
    @pytest.fixture(autouse=True)
    def _setup(self, monkeypatch):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        self.mgr = NPMManager()

    def test_list_packages(self, monkeypatch):
        payload = json.dumps({"dependencies": {"express": {"version": "4.18.2"}}})
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(payload))
        pkgs = self.mgr.list_packages()
        assert len(pkgs) == 1
        assert pkgs[0]["name"] == "express"
        assert pkgs[0]["version"] == "4.18.2"
        assert pkgs[0]["manager"] == "npm"

    def test_list_packages_empty(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp("{}"))
        assert self.mgr.list_packages() == []

    def test_list_packages_bad_json(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp("not json"))
        assert self.mgr.list_packages() == []

    def test_install_package_success(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp())
        assert self.mgr.install_package("lodash") is True

    def test_install_package_failure(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(rc=1))
        assert self.mgr.install_package("lodash") is False

    def test_upgrade_package_success(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp())
        assert self.mgr.upgrade_package("lodash") is True

    def test_uninstall_package_success(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp())
        assert self.mgr.uninstall_package("lodash") is True

    def test_check_outdated(self, monkeypatch):
        payload = json.dumps({"lodash": {"current": "4.17.20", "latest": "4.17.21", "wanted": "4.17.21"}})
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(payload, rc=1))
        outdated = self.mgr.check_outdated()
        assert len(outdated) == 1
        assert outdated[0]["name"] == "lodash"
        assert outdated[0]["current"] == "4.17.20"

    def test_check_outdated_empty(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(""))
        assert self.mgr.check_outdated() == []

    def test_search_package_json(self, monkeypatch):
        payload = json.dumps([{"name": "react", "version": "18.2.0", "description": "React lib"}])
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(payload))
        results = self.mgr.search_package("react")
        assert len(results) == 1
        assert results[0]["name"] == "react"

    def test_install_defaults_to_global(self, monkeypatch):
        """NPM install now defaults to global (-g flag)."""
        captured_args = []
        def _capture(args, **kw):
            captured_args.extend(args)
            return _cp()
        monkeypatch.setattr(self.mgr, "_run_command", _capture)
        self.mgr.install_package("lodash")
        assert "-g" in captured_args


# ======================================================================
# PipManager
# ======================================================================

class TestPipManager:
    @pytest.fixture(autouse=True)
    def _setup(self, monkeypatch):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        self.mgr = PipManager()

    def test_list_packages(self, monkeypatch):
        payload = json.dumps([{"name": "requests", "version": "2.31.0"}])
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(payload))
        pkgs = self.mgr.list_packages()
        assert len(pkgs) == 1
        assert pkgs[0]["name"] == "requests"

    def test_list_packages_bad_json(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp("{bad"))
        assert self.mgr.list_packages() == []

    def test_install_package_success(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp())
        assert self.mgr.install_package("flask") is True

    def test_install_package_failure(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(rc=1))
        assert self.mgr.install_package("flask") is False

    def test_upgrade_package(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp())
        assert self.mgr.upgrade_package("flask") is True

    def test_uninstall_package(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp())
        assert self.mgr.uninstall_package("flask") is True

    def test_check_outdated(self, monkeypatch):
        payload = json.dumps([
            {"name": "flask", "version": "2.0.0", "latest_version": "3.0.0", "latest_filetype": "wheel"}
        ])
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(payload))
        outdated = self.mgr.check_outdated()
        assert len(outdated) == 1
        assert outdated[0]["latest"] == "3.0.0"

    def test_check_outdated_empty(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(""))
        assert self.mgr.check_outdated() == []


# ======================================================================
# YarnManager
# ======================================================================

class TestYarnManager:
    @pytest.fixture(autouse=True)
    def _setup(self, monkeypatch):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        self.mgr = YarnManager()

    def test_list_packages(self, monkeypatch):
        stdout = '{"type":"info","data":"\\"lodash@4.17.21\\""}\n'
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(stdout))
        pkgs = self.mgr.list_packages()
        assert len(pkgs) == 1
        assert pkgs[0]["name"] == "lodash"
        assert pkgs[0]["version"] == "4.17.21"

    def test_list_packages_empty(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(""))
        assert self.mgr.list_packages() == []

    def test_install_package_success(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp())
        assert self.mgr.install_package("lodash") is True

    def test_install_package_failure(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(rc=1))
        assert self.mgr.install_package("lodash") is False

    def test_upgrade_package(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp())
        assert self.mgr.upgrade_package("lodash") is True

    def test_uninstall_package(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp())
        assert self.mgr.uninstall_package("lodash") is True

    def test_search_delegates_to_base(self, monkeypatch):
        """Yarn search now delegates to _search_npm_registry (base class)."""
        monkeypatch.setattr(
            self.mgr, "_search_npm_registry",
            lambda q, limit=10: [{"name": "react", "version": "18.0.0", "manager": "yarn"}],
        )
        results = self.mgr.search_package("react")
        assert results[0]["manager"] == "yarn"


# ======================================================================
# PNPMManager
# ======================================================================

class TestPNPMManager:
    @pytest.fixture(autouse=True)
    def _setup(self, monkeypatch):
        monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
        self.mgr = PNPMManager()

    def test_list_packages(self, monkeypatch):
        payload = json.dumps([{"dependencies": {"typescript": {"version": "5.0.0"}}}])
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(payload))
        pkgs = self.mgr.list_packages()
        assert len(pkgs) == 1
        assert pkgs[0]["name"] == "typescript"

    def test_list_packages_empty(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp("[{}]"))
        assert self.mgr.list_packages() == []

    def test_install_package_success(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp())
        assert self.mgr.install_package("typescript") is True

    def test_install_package_failure(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp(rc=1))
        assert self.mgr.install_package("typescript") is False

    def test_upgrade_package(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp())
        assert self.mgr.upgrade_package("typescript") is True

    def test_uninstall_package(self, monkeypatch):
        monkeypatch.setattr(self.mgr, "_run_command", lambda args, **kw: _cp())
        assert self.mgr.uninstall_package("typescript") is True

    def test_search_delegates_to_base(self, monkeypatch):
        monkeypatch.setattr(
            self.mgr, "_search_npm_registry",
            lambda q, limit=10: [{"name": "vite", "version": "5.0.0", "manager": "pnpm"}],
        )
        results = self.mgr.search_package("vite")
        assert results[0]["manager"] == "pnpm"
