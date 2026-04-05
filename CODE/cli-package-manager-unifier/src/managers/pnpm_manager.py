"""PNPM package manager implementation."""
from typing import List, Dict
import json
import subprocess
from .base_manager import BasePackageManager


class PNPMManager(BasePackageManager):
    """PNPM manager."""

    def __init__(self) -> None:
        super().__init__(name="pnpm", command="pnpm")

    def list_packages(self) -> List[Dict[str, str]]:
        """Return globally installed pnpm packages."""
        try:
            result: subprocess.CompletedProcess[str] = self._run_command(
                ['list', '-g', '--depth=0', '--json']
            )

            if result.returncode != 0:
                print("Warning: pnpm list returned non-zero exit code")
                return []

            data = json.loads(result.stdout)
            packages: List[Dict[str, str]] = []

            # pnpm wraps data in an array
            nodes = data[0].get('dependencies', {}) if isinstance(data, list) and data else {}
            if isinstance(nodes, dict):
                for name, info in nodes.items():
                    if not isinstance(info, dict):
                        continue
                    packages.append({
                        'name': name,
                        'id': name,
                        'version': info.get('version', 'unknown'),
                        'manager': 'pnpm'
                    })

            return packages
        except json.JSONDecodeError as e:
            print(f"Error parsing pnpm output: {e}")
            return []
        except Exception as e:
            print(f"Error listing pnpm packages: {e}")
            return []

    def install_package(self, package_name: str, global_install: bool = True) -> bool:
        """Install a pnpm package."""
        try:
            args = ['add']
            if global_install:
                args.append('-g')
            args.append(package_name)

            print(f"Installing {package_name} via pnpm...")
            result: subprocess.CompletedProcess[str] = self._run_command(args, capture_output=False)
            if result.returncode == 0:
                print(f"Successfully installed {package_name}")
                return True
            print(f"Failed to install {package_name}")
            return False
        except Exception as e:
            print(f"Error installing package: {e}")
            return False

    def upgrade_package(self, package_name: str, global_upgrade: bool = True) -> bool:
        """Upgrade a pnpm package."""
        try:
            args = ['update']
            if global_upgrade:
                args.append('-g')
            args.append(package_name)

            print(f"Upgrading {package_name} via pnpm...")
            result: subprocess.CompletedProcess[str] = self._run_command(args, capture_output=False)

            if result.returncode == 0:
                print(f"Successfully upgraded {package_name}")
                return True
            print(f"Failed to upgrade {package_name}")
            return False
        except Exception as e:
            print(f"Error upgrading package: {e}")
            return False

    def search_package(self, query: str, limit: int = 10) -> List[Dict[str, str]]:
        """Search package names from npm registry (works for pnpm ecosystem)."""
        return self._search_npm_registry(query, limit)

    def check_outdated(self) -> List[Dict[str, str]]:
        """Return outdated globally installed pnpm packages."""
        try:
            result: subprocess.CompletedProcess[str] = self._run_command(
                ['outdated', '-g', '--format', 'json']
            )

            if result.returncode not in [0, 1]:
                return []

            if not result.stdout.strip():
                return []

            data = json.loads(result.stdout)
            outdated: List[Dict[str, str]] = []

            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    name = item.get('name')
                    if not name:
                        continue
                    outdated.append({
                        'name': name,
                        'id': name,
                        'current': item.get('current', 'unknown'),
                        'latest': item.get('latest', 'unknown'),
                        'wanted': item.get('wanted', 'unknown'),
                        'manager': 'pnpm'
                    })

            return outdated
        except Exception:
            return []

    def uninstall_package(self, package_name: str) -> bool:
        """Uninstall a pnpm package globally."""
        try:
            print(f"Uninstalling {package_name} via pnpm...")
            result: subprocess.CompletedProcess[str] = self._run_command(
                ['remove', '-g', package_name],
                capture_output=False
            )
            return result.returncode == 0
        except Exception as e:
            print(f"Error uninstalling package: {e}")
            return False
