"""Pip3 package manager implementation."""
from typing import List, Dict, Optional
import json
import re
import requests
from .base_manager import BasePackageManager

class PipManager(BasePackageManager):
    """Pip3 manager."""
    
    def __init__(self):
        super().__init__(name="pip3", command="pip3")
    
    def list_packages(self) -> List[Dict[str, str]]:
        """Return installed pip packages."""
        try:
            result = self._run_command(['list', '--format=json'])
            
            if result.returncode != 0:
                print("Warning: pip list returned non-zero exit code")
                return []
            
            data = json.loads(result.stdout)
            packages = []
            
            for item in data:
                packages.append({
                    'name': item['name'],
                    'id': item['name'],
                    'version': item['version'],
                    'manager': 'pip3'
                })
            
            return packages
        
        except json.JSONDecodeError as e:
            print(f"Error parsing pip output: {e}")
            return []
        except Exception as e:
            print(f"Error listing pip packages: {e}")
            return []
    
    def install_package(self, package_name: str, upgrade: bool = False) -> bool:
        """Install a pip package; set upgrade=True to force upgrade."""
        try:
            args = ['install']
            if upgrade:
                args.append('--upgrade')
            args.append(package_name)
            
            print(f"Installing {package_name} via pip3...")
            result = self._run_command(args, capture_output=False)
            
            if result.returncode == 0:
                print(f"Successfully installed {package_name}")
                return True
            else:
                print(f"Failed to install {package_name}")
                return False
        
        except Exception as e:
            print(f"Error installing package: {e}")
            return False
    
    def upgrade_package(self, package_name: str) -> bool:
        """Upgrade a pip package to latest."""
        try:
            args = ['install', '--upgrade', package_name]
            
            print(f"Upgrading {package_name} via pip3...")
            result = self._run_command(args, capture_output=False)
            
            if result.returncode == 0:
                print(f"Successfully upgraded {package_name}")
                return True
            else:
                print(f"Failed to upgrade {package_name}")
                return False
        
        except Exception as e:
            print(f"Error upgrading package: {e}")
            return False
    
    def search_package(self, query: str, limit: int = 10) -> List[Dict[str, str]]:
        """Search packages using PyPI APIs (warehouse fallback)."""
        try:
            import requests
            
            # try direct package lookup first (faster)
            url = f"https://pypi.org/pypi/{query}/json"
            
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    return [{
                        'name': data['info']['name'],
                        'id': data['info']['name'],
                        'version': data['info']['version'],
                        'description': data['info']['summary'][:100] if data['info'].get('summary') else '',
                        'manager': 'pip3'
                    }]
                else:
                    # fall back to warehouse search
                    return self._search_pypi_warehouse(query, limit)
            
            except requests.RequestException:
                return self._search_pypi_warehouse(query, limit)
        
        except Exception as e:
            print(f"Error searching pip packages: {e}")
            return []
    
    def _search_pypi_warehouse(self, query: str, limit: int) -> List[Dict[str, str]]:
        """Search PyPI warehouse page and parse results (simple)."""
        try:
            import requests
            
            url = "https://pypi.org/search/"
            params = {'q': query}
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                import re
                
                # extract package names from HTML
                pattern = r'<a class="package-snippet".*?href="/project/(.*?)/"'
                matches = re.findall(pattern, response.text)
                
                packages = []
                for name in matches[:limit]:
                    packages.append({
                        'name': name,
                        'id': name,
                        'version': 'See PyPI for version',
                        'description': f'Python package: {name}',
                        'manager': 'pip3'
                    })
                
                return packages
            
            return []
        
        except Exception as e:
            print(f"Error in PyPI warehouse search: {e}")
            return []
    
    def uninstall_package(self, package_name: str) -> bool:
        """Uninstall a pip package."""
        try:
            args = ['uninstall', '-y', package_name]
            
            print(f"Uninstalling {package_name} via pip3...")
            result = self._run_command(args, capture_output=False)
            
            return result.returncode == 0
        
        except Exception as e:
            print(f"Error uninstalling package: {e}")
            return False
    
    def check_outdated(self) -> List[Dict[str, str]]:
        """Return outdated pip packages."""
        try:
            result = self._run_command(['list', '--outdated', '--format=json'])
            
            if result.returncode != 0:
                print("Warning: pip list --outdated returned non-zero exit code")
                return []
            
            if not result.stdout.strip():
                return []
            
            data = json.loads(result.stdout)
            outdated = []
            
            for item in data:
                outdated.append({
                    'name': item['name'],
                    'id': item['name'],
                    'current': item['version'],
                    'latest': item['latest_version'],
                    'type': item.get('latest_filetype', 'unknown'),
                    'manager': 'pip3'
                })
            
            return outdated
        
        except json.JSONDecodeError as e:
            print(f"Error parsing pip outdated output: {e}")
            return []
        except Exception as e:
            print(f"Error checking outdated pip packages: {e}")
            return []

    def get_latest_registry_version(self, package_name: str) -> Optional[str]:
        """Return the latest version of a pip package from PyPI."""
        try:
            response = requests.get(
                f"https://pypi.org/pypi/{package_name}/json", timeout=10
            )
            if response.status_code == 200:
                version = str(response.json().get("info", {}).get("version", "")).strip()
                return version or None
        except Exception:
            pass
        return None

    def show_package_info(self, package_name: str) -> Dict[str, str]:
        """
        Show detailed information about a package.
        
        Args:
            package_name: Name of the package
            
        Returns:
            Dictionary with package details
        """
        try:
            result = self._run_command(['show', package_name])
            
            if result.returncode != 0:
                return {}
            
            # parse key-value pairs from pip show output
            info = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    info[key.strip().lower()] = value.strip()
            
            return info
        
        except Exception as e:
            print(f"Error getting package info: {e}")
            return {}
