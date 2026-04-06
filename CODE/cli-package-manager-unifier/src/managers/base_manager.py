"""Common interface for package managers."""
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
import subprocess
import shutil
import sys

import requests


class BasePackageManager(ABC):
    """Abstract base for package managers."""

    def __init__(self, name: str, command: str):
        """Initialize with display name and base command."""
        self.name = name  # friendly name like "npm" or "pip3"
        self.command = command  # actual CLI command to execute

    # ------------------------------------------------------------------
    # Abstract interface — every concrete manager MUST implement these.
    # ------------------------------------------------------------------

    @abstractmethod
    def list_packages(self) -> List[Dict[str, str]]:
        """Return installed packages."""
        pass

    @abstractmethod
    def install_package(self, package_name: str) -> bool:
        """Install a package by name."""
        pass

    @abstractmethod
    def search_package(self, query: str) -> List[Dict[str, str]]:
        """Search for packages by query."""
        pass

    @abstractmethod
    def upgrade_package(self, package_name: str) -> bool:
        """Upgrade a package to its latest version."""
        pass

    @abstractmethod
    def check_outdated(self) -> List[Dict[str, str]]:
        """Return a list of outdated packages."""
        pass

    @abstractmethod
    def uninstall_package(self, package_name: str) -> bool:
        """Uninstall a package by name."""
        pass

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _search_npm_registry(self, query: str, limit: int = 10) -> List[Dict[str, str]]:
        """Search the npm registry — shared by npm, yarn and pnpm managers."""
        try:
            url = "https://registry.npmjs.org/-/v1/search"
            response = requests.get(url, params={'text': query, 'size': limit}, timeout=10)
            if response.status_code != 200:
                return []

            data = response.json()
            packages: List[Dict[str, str]] = []
            for item in data.get('objects', []):
                pkg = item.get('package', {})
                name = pkg.get('name', '')
                if not name:
                    continue
                # trim description to 100 chars for cleaner output
                packages.append({
                    'name': name,
                    'id': name,
                    'version': pkg.get('version', ''),
                    'description': (pkg.get('description') or '')[:100],
                    'manager': self.name,
                })
            return packages
        except Exception as e:
            print(f"Error searching npm registry: {e}")
            return []

    def _run_command(self, args: List[str], capture_output: bool = True) -> subprocess.CompletedProcess[str]:
        """Run the manager command with args."""
        try:
            # Windows needs full path to avoid cmd.exe built-in conflicts
            if sys.platform == 'win32':
                command_path = shutil.which(self.command)
                if command_path is None:
                    raise FileNotFoundError(f"{self.command} is not installed or not in PATH")
                cmd = [command_path] + args
            else:
                cmd = [self.command] + args
            
            result: subprocess.CompletedProcess[str] = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                encoding='utf-8',
                errors='replace',  # handle any encoding issues gracefully
                timeout=30
            )
            return result
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Command timed out: {' '.join([self.command] + args)}")
        except FileNotFoundError:
            raise FileNotFoundError(f"{self.command} is not installed or not in PATH")

    def get_latest_registry_version(self, package_name: str) -> Optional[str]:
        """Return the latest published version from the registry, or None on failure.

        Default implementation queries the npm registry — works for npm, yarn, pnpm.
        pip overrides this to hit PyPI instead.
        """
        try:
            url = f"https://registry.npmjs.org/{package_name}/latest"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                version = str(response.json().get("version", "")).strip()
                return version or None
        except Exception:
            pass
        return None

    def is_available(self) -> bool:
        """Return True if the manager responds to --version."""
        try:
            result = self._run_command(['--version'])
            return result.returncode == 0
        except Exception:
            # manager not installed or not in PATH
            return False
