"""Shared pytest fixtures for the unified CLI test suite."""
# pyright: reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownLambdaType=false
import pytest

from src.managers.base_manager import BasePackageManager
from src.managers.npm_manager import NPMManager
from src.managers.pip_manager import PipManager
from src.managers.yarn_manager import YarnManager
from src.managers.pnpm_manager import PNPMManager


# ---------------------------------------------------------------------------
# Subprocess result factory
# ---------------------------------------------------------------------------

def make_completed_process(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Return a mock subprocess.CompletedProcess."""
    import subprocess
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# Manager instances (availability forced off so they never shell out)
# ---------------------------------------------------------------------------

@pytest.fixture()
def npm_manager(monkeypatch):
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
    return NPMManager()


@pytest.fixture()
def pip_manager(monkeypatch):
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
    return PipManager()


@pytest.fixture()
def yarn_manager(monkeypatch):
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
    return YarnManager()


@pytest.fixture()
def pnpm_manager(monkeypatch):
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: True)
    return PNPMManager()


# ---------------------------------------------------------------------------
# CLI with all managers forced unavailable (safe for unit tests)
# ---------------------------------------------------------------------------

@pytest.fixture()
def cli_no_managers(monkeypatch):
    """Return a UnifiedCLI where every manager reports unavailable."""
    monkeypatch.setattr(BasePackageManager, "is_available", lambda self: False)
    from src.cli import UnifiedCLI
    return UnifiedCLI()
