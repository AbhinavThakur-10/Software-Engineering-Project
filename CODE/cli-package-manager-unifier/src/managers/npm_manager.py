"""
NPM Package Manager implementation.
"""
from typing import List, Dict
import json
import subprocess
from .base_manager import BasePackageManager

class NPMManager(BasePackageManager):
    """NPM (Node Package Manager) implementation."""

    def __init__(self) -> None:
        super().__init__(name="npm", command="npm")

    def list_packages(self) -> List[Dict[str, str]]:
        """
        List all globally installed npm packages.
        Returns:
            List of dictionaries with package info (name, id, version, manager)
        """
        try:
            result: subprocess.CompletedProcess[str] = self._run_command(
                ['list', '-g', '--depth=0', '--json']
            )

            if result.returncode != 0:
                print(f"Warning: npm list returned non-zero exit code")
                return []

            data = json.loads(result.stdout)
            packages: List[Dict[str, str]] = []

            if 'dependencies' in data:
                for name, info in data['dependencies'].items():
                    packages.append({
                        'name': name,
                        'id': name,
                        'version': info.get('version', 'unknown'),
                        'manager': 'npm'
                    })
            return packages

        except json.JSONDecodeError as e:
            print(f"Error parsing npm output: {e}")
            return []
        except Exception as e:
            print(f"Error listing npm packages: {e}")
            return []

    def install_package(self, package_name: str, global_install: bool = False) -> bool:
        """
        Install an npm package.
        """
        try:
            args = ['install']
            if global_install:
                args.append('-g')
            args.append(package_name)

            print(f"Installing {package_name} via npm...")
            result: subprocess.CompletedProcess[str] = self._run_command(args, capture_output=False)

            if result.returncode == 0:
                print(f"✓ Successfully installed {package_name}")
                return True
            else:
                print(f"✗ Failed to install {package_name}")
                return False

        except Exception as e:
            print(f"Error installing package: {e}")
            return False
    
    def upgrade_package(self, package_name: str, global_upgrade: bool = True) -> bool:
        """
        Upgrade an npm package to the latest version.
        """
        try:
            args = ['update']
            if global_upgrade:
                args.append('-g')
            args.append(package_name)

            print(f"Upgrading {package_name} via npm...")
            result: subprocess.CompletedProcess[str] = self._run_command(args, capture_output=False)

            if result.returncode == 0:
                print(f"✓ Successfully upgraded {package_name}")
                return True
            else:
                print(f"✗ Failed to upgrade {package_name}")
                return False

        except Exception as e:
            print(f"Error upgrading package: {e}")
            return False

    def search_package(self, query: str, limit: int = 10) -> List[Dict[str, str]]:
        """
        Search for npm packages.
        """
        try:
            result: subprocess.CompletedProcess[str] = self._run_command(['search', query, '--json'])

            if result.returncode != 0:
                print(f"npm search failed with code {result.returncode}")
                return []

            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                return self._parse_search_text(result.stdout, limit)

            packages: List[Dict[str, str]] = []
            for item in data[:limit]:
                packages.append({
                    'name': item.get('name', ''),
                    'id': item.get('name', ''),
                    'version': item.get('version', ''),
                    'description': item.get('description', '')[:100],
                    'manager': 'npm'
                })
            return packages

        except Exception as e:
            print(f"Error searching npm packages: {e}")
            return []

    def _parse_search_text(self, output: str, limit: int) -> List[Dict[str, str]]:
        packages: List[Dict[str, str]] = []
        lines = output.strip().split('\n')

        for line in lines[1:limit + 1]:
            parts = line.split()
            if len(parts) >= 2:
                packages.append({
                    'name': parts[0],
                    'id': parts[0],
                    'version': parts[1] if len(parts) > 1 else 'unknown',
                    'description': ' '.join(parts[2:])[:100] if len(parts) > 2 else '',
                    'manager': 'npm'
                })
        return packages

    def check_outdated(self) -> List[Dict[str, str]]:
        """
        Check for outdated globally installed npm packages.
        Returns:
            List of dictionaries with package update info
        """
        try:
            result: subprocess.CompletedProcess[str] = self._run_command(
                ['outdated', '-g', '--json']
            )

            # npm outdated returns exit code 1 when there are outdated packages
            if result.returncode not in [0, 1]:
                print(f"Warning: npm outdated returned unexpected exit code")
                return []

            if not result.stdout.strip():
                return []

            data = json.loads(result.stdout)
            outdated: List[Dict[str, str]] = []

            for name, info in data.items():
                outdated.append({
                    'name': name,
                    'id': name,
                    'current': info.get('current', 'unknown'),
                    'latest': info.get('latest', 'unknown'),
                    'wanted': info.get('wanted', 'unknown'),
                    'manager': 'npm'
                })
            return outdated

        except json.JSONDecodeError as e:
            print(f"Error parsing npm outdated output: {e}")
            return []
        except Exception as e:
            print(f"Error checking outdated npm packages: {e}")
            return []

    def uninstall_package(self, package_name: str, global_uninstall: bool = False) -> bool:
        """
        Uninstall an npm package.
        """
        try:
            args = ['uninstall']
            if global_uninstall:
                args.append('-g')
            args.append(package_name)

            print(f"Uninstalling {package_name} via npm...")
            result: subprocess.CompletedProcess[str] = self._run_command(args, capture_output=False)

            return result.returncode == 0

        except Exception as e:
            print(f"Error uninstalling package: {e}")
            return False
