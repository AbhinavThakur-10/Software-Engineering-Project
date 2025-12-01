"""
Pip3 Package Manager implementation.
"""
from typing import List, Dict
import json
import re
from .base_manager import BasePackageManager

class PipManager(BasePackageManager):
    """Pip3 (Python Package Manager) implementation."""
    
    def __init__(self):
        super().__init__(name="pip3", command="pip3")
    
    def list_packages(self) -> List[Dict[str, str]]:
        """
        List all installed pip packages.
        
        Returns:
            List of dictionaries with package info (name, id, version, manager)
        """
        try:
            result = self._run_command(['list', '--format=json'])
            
            if result.returncode != 0:
                print(f"Warning: pip list returned non-zero exit code")
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
        """
        Install a pip package.
        
        Args:
            package_name: Name of the package to install
            upgrade: Whether to upgrade if already installed (default: False)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            args = ['install']
            if upgrade:
                args.append('--upgrade')
            args.append(package_name)
            
            print(f"Installing {package_name} via pip3...")
            result = self._run_command(args, capture_output=False)
            
            if result.returncode == 0:
                print(f"✓ Successfully installed {package_name}")
                return True
            else:
                print(f"✗ Failed to install {package_name}")
                return False
        
        except Exception as e:
            print(f"Error installing package: {e}")
            return False
    
    def upgrade_package(self, package_name: str) -> bool:
        """
        Upgrade a pip package to the latest version.
        
        Args:
            package_name: Name of the package to upgrade
            
        Returns:
            True if successful, False otherwise
        """
        try:
            args = ['install', '--upgrade', package_name]
            
            print(f"Upgrading {package_name} via pip3...")
            result = self._run_command(args, capture_output=False)
            
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
        Search for pip packages using PyPI API.
        Note: pip search was disabled, so we use PyPI API instead.
        
        Args:
            query: Search query string
            limit: Maximum number of results (default: 10)
            
        Returns:
            List of matching packages with name, version, and description
        """
        try:
            import requests
            
            # Use PyPI JSON API for search
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
                    # Fallback: search using PyPI search API
                    return self._search_pypi_warehouse(query, limit)
            
            except requests.RequestException:
                return self._search_pypi_warehouse(query, limit)
        
        except Exception as e:
            print(f"Error searching pip packages: {e}")
            return []
    
    def _search_pypi_warehouse(self, query: str, limit: int) -> List[Dict[str, str]]:
        """
        Search PyPI using the warehouse search API.
        
        Args:
            query: Search query string
            limit: Maximum number of results
            
        Returns:
            List of package dictionaries
        """
        try:
            import requests
            
            url = "https://pypi.org/search/"
            params = {'q': query}
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                # Parse HTML response (simplified)
                # In production, you'd want to use BeautifulSoup for proper parsing
                import re
                
                # Extract package names from search results
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
        """
        Uninstall a pip package.
        
        Args:
            package_name: Name of the package to uninstall
            
        Returns:
            True if successful, False otherwise
        """
        try:
            args = ['uninstall', '-y', package_name]
            
            print(f"Uninstalling {package_name} via pip3...")
            result = self._run_command(args, capture_output=False)
            
            return result.returncode == 0
        
        except Exception as e:
            print(f"Error uninstalling package: {e}")
            return False
    
    def check_outdated(self) -> List[Dict[str, str]]:
        """
        Check for outdated pip packages.
        
        Returns:
            List of dictionaries with package update info
        """
        try:
            result = self._run_command(['list', '--outdated', '--format=json'])
            
            if result.returncode != 0:
                print(f"Warning: pip list --outdated returned non-zero exit code")
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
            
            info = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    info[key.strip().lower()] = value.strip()
            
            return info
        
        except Exception as e:
            print(f"Error getting package info: {e}")
            return {}
