"""Yarn package manager implementation."""
from typing import List, Dict
import json
import subprocess
from .base_manager import BasePackageManager


class YarnManager(BasePackageManager):
    """Yarn manager."""

    def __init__(self) -> None:
        super().__init__(name="yarn", command="yarn")

    def list_packages(self) -> List[Dict[str, str]]:
        """Return globally installed yarn packages."""
        try:
            result: subprocess.CompletedProcess[str] = self._run_command(
                ['global', 'list', '--depth=0', '--json']
            )

            if result.returncode != 0:
                print("Warning: yarn global list returned non-zero exit code")
                return []

            packages: List[Dict[str, str]] = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if item.get('type') != 'info':
                    continue

                data = item.get('data')
                if not isinstance(data, str):
                    continue

                if not data.startswith('"'):
                    continue

                # Example: "package@1.2.3"
                entry = data.strip('"')
                if '@' not in entry:
                    continue
                name, version = entry.rsplit('@', 1)
                if not name:
                    continue

                packages.append({
                    'name': name,
                    'id': name,
                    'version': version or 'unknown',
                    'manager': 'yarn'
                })

            return packages

        except Exception as e:
            print(f"Error listing yarn packages: {e}")
            return []

    def install_package(self, package_name: str) -> bool:
        """Install a yarn package globally."""
        try:
            print(f"Installing {package_name} via yarn...")
            result: subprocess.CompletedProcess[str] = self._run_command(
                ['global', 'add', package_name],
                capture_output=False
            )

            if result.returncode == 0:
                print(f"Successfully installed {package_name}")
                return True

            print(f"Failed to install {package_name}")
            return False
        except Exception as e:
            print(f"Error installing package: {e}")
            return False

    def upgrade_package(self, package_name: str) -> bool:
        """Upgrade a yarn package globally."""
        try:
            print(f"Upgrading {package_name} via yarn...")
            result: subprocess.CompletedProcess[str] = self._run_command(
                ['global', 'upgrade', package_name],
                capture_output=False
            )

            if result.returncode == 0:
                print(f"Successfully upgraded {package_name}")
                return True

            print(f"Failed to upgrade {package_name}")
            return False
        except Exception as e:
            print(f"Error upgrading package: {e}")
            return False

    def search_package(self, query: str, limit: int = 10) -> List[Dict[str, str]]:
        """Search package names from npm registry (works for yarn ecosystem)."""
        return self._search_npm_registry(query, limit)

    def check_outdated(self) -> List[Dict[str, str]]:
        """Return outdated globally installed yarn packages."""
        try:
            result: subprocess.CompletedProcess[str] = self._run_command(
                ['global', 'outdated', '--json']
            )

            # yarn can return non-zero if outdated packages are present
            if result.returncode not in [0, 1]:
                return []

            outdated: List[Dict[str, str]] = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if item.get('type') != 'table':
                    continue

                data = item.get('data', {})
                body = data.get('body', []) if isinstance(data, dict) else []
                for row in body:
                    if not isinstance(row, list) or len(row) < 4:
                        continue
                    name = row[0]
                    current = row[1]
                    wanted = row[2]
                    latest = row[3]
                    outdated.append({
                        'name': name,
                        'id': name,
                        'current': current,
                        'latest': latest or wanted,
                        'wanted': wanted,
                        'manager': 'yarn'
                    })

            return outdated
        except Exception:
            return []

    def uninstall_package(self, package_name: str) -> bool:
        """Uninstall a yarn package globally."""
        try:
            print(f"Uninstalling {package_name} via yarn...")
            result: subprocess.CompletedProcess[str] = self._run_command(
                ['global', 'remove', package_name],
                capture_output=False
            )
            return result.returncode == 0
        except Exception as e:
            print(f"Error uninstalling package: {e}")
            return False