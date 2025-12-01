"""
Main CLI interface for the unified package manager.
"""
import argparse
import sys
from typing import Dict, List, Any, Optional
import threading
import time
from colorama import init, Fore, Style

from tabulate import tabulate

# VirusTotal integration
from src.utils.virustotal import (
    get_virustotal_api_key, 
    scan_file_hash_with_virustotal,
    download_package_and_get_hash
)
from src.utils.package_cache import PackageCacheDB

# Manager base and implementations
from src.managers.base_manager import BasePackageManager
from src.managers.npm_manager import NPMManager
from src.managers.pip_manager import PipManager

# Initialize colorama for cross-platform colored output
init(autoreset=True)


class UnifiedCLI:
    """Unified command-line interface for multiple package managers."""
    
    def __init__(self):
        """Initialize the CLI with available package managers."""
        self.managers: Dict[str, BasePackageManager] = {
            'npm': NPMManager(),
            'pip3': PipManager()
        }
        
        # Check which managers are available
        self.available_managers: Dict[str, BasePackageManager] = {}
        for name, manager in self.managers.items():
            if manager.is_available():
                self.available_managers[name] = manager
                print(f"{Fore.GREEN}✓ {name} is available{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}⚠ {name} is not available{Style.RESET_ALL}")
    
    def list_all_packages(self):
        """List packages from all available managers with ID, current and latest version.
        Colorize outdated packages (name red) and latest versions (green).
        """
        if not self.available_managers:
            print(f"{Fore.RED}No package managers available!{Style.RESET_ALL}")
            return
        
        all_packages: List[Dict[str, Any]] = []
        
        for name, manager in self.available_managers.items():
            print(f"\n{Fore.CYAN}Fetching packages from {name}...{Style.RESET_ALL}")
            packages = manager.list_packages()
            # If manager supports outdated check, fetch to map latest versions
            latest_map = {}
            if hasattr(manager, 'check_outdated'):
                try:
                    outdated = manager.check_outdated()
                    for item in outdated:
                        latest_map[item['name'].lower()] = item.get('latest') or item.get('latest_version') or ''
                except Exception:
                    latest_map = {}

            # enrich each package with id, current, latest
            for pkg in packages:
                name_lower = pkg['name'].lower()
                pkg_id = pkg.get('id', pkg['name'])
                current = pkg.get('version', '')
                latest = latest_map.get(name_lower, current)
                all_packages.append({
                    'name': pkg['name'],
                    'id': pkg_id,
                    'current': current,
                    'latest': latest,
                    'manager': name
                })
        
        if all_packages:
            # Sort by manager then name
            all_packages.sort(key=lambda x: (x['manager'], x['name']))
            
            # Format as table with colors
            table_data: List[List[Any]] = []
            for pkg in all_packages:
                has_newer = bool(pkg['latest']) and pkg['current'] and (pkg['latest'] != pkg['current'])
                name_disp = pkg['name']
                latest_disp = (
                    f"{Fore.GREEN}{pkg['latest']}{Style.RESET_ALL}" if has_newer else (pkg['latest'] or '')
                )
                table_data.append([name_disp, pkg['id'], pkg['current'], latest_disp, pkg['manager']])
            
            print(f"\n{Fore.GREEN}Total packages found: {len(all_packages)}{Style.RESET_ALL}")
            print(tabulate(table_data, 
                          headers=['Package', 'Package ID', 'Current', 'Latest', 'Manager'],
                          tablefmt='grid'))
        else:
            print(f"{Fore.YELLOW}No packages found{Style.RESET_ALL}")

    def _virustotal_scan(self, package_name: str, manager_name: Optional[str]) -> bool:
        """
        Perform a VirusTotal lookup for the given package by downloading it and hashing.
        Prints progress and returns True if safe/unknown, False if flagged malicious.
        """
        try:
            print(f"\n{Fore.CYAN}[Security]{Style.RESET_ALL} Preparing VirusTotal scan for {package_name} ({manager_name or 'auto'})...")

            # Simple spinner for async feels
            spinner_running = True
            spinner_msg = f"{Fore.CYAN}[Security]{Style.RESET_ALL} Downloading package to calculate hash..."
            def _spin():
                seq = ['|', '/', '-', '\\']
                i = 0
                while spinner_running:
                    print(f"\r{spinner_msg} {seq[i % len(seq)]}", end='', flush=True)
                    i += 1
                    time.sleep(0.1)
                print("\r" + ' ' * (len(spinner_msg) + 4) + "\r", end='', flush=True)
            t = threading.Thread(target=_spin, daemon=True)
            t.start()

            file_hash = download_package_and_get_hash(package_name, manager_name or 'pip3')
            spinner_running = False
            t.join()
            
            if not file_hash:
                print(f"{Fore.YELLOW}[Security]{Style.RESET_ALL} Failed to download package for hashing.")
                choice = input(f"{Fore.YELLOW}Proceed with installation anyway? (y/n): {Style.RESET_ALL}").strip().lower()
                if choice != 'y':
                    print(f"{Fore.RED}[Security]{Style.RESET_ALL} Installation cancelled by user.")
                    return False
                print(f"{Fore.YELLOW}[Security]{Style.RESET_ALL} User chose to proceed without hash scan.")
                return True
            
            print(f"{Fore.CYAN}[Security]{Style.RESET_ALL} Package hash: {Fore.YELLOW}{file_hash}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[Security]{Style.RESET_ALL} Querying VirusTotal...")
            
            api_key = get_virustotal_api_key()
            result = scan_file_hash_with_virustotal(file_hash, api_key)

            # Detailed output
            if isinstance(result, dict) and result.get('data') and isinstance(result['data'], dict):
                attrs = result['data'].get('attributes', {}) or {}
                stats = attrs.get('last_analysis_stats', {}) or {}
                malicious = int(stats.get('malicious', 0))
                undetected = int(stats.get('undetected', 0)) if 'undetected' in stats else 0
                suspicious = int(stats.get('suspicious', 0)) if 'suspicious' in stats else 0
                harmless = int(stats.get('harmless', 0)) if 'harmless' in stats else 0
                # Render stats as a table
                table = [
                    [f"{Fore.RED}malicious{Style.RESET_ALL}", malicious],
                    [f"{Fore.YELLOW}suspicious{Style.RESET_ALL}", suspicious],
                    [f"{Fore.GREEN}harmless{Style.RESET_ALL}", harmless],
                    ["undetected", undetected],
                ]
                print(tabulate(table, headers=["Result", "Count"], tablefmt="grid"))
                
                if malicious > 0:
                    print(f"{Fore.RED}[Security]{Style.RESET_ALL} VirusTotal flagged '{package_name}' as MALICIOUS. Aborting for safety.")
                    return False
                
                if suspicious > 0:
                    print(f"{Fore.YELLOW}[Security]{Style.RESET_ALL} Warning: {suspicious} engine(s) flagged '{package_name}' as SUSPICIOUS.")
                    choice = input(f"{Fore.YELLOW}Do you want to install anyway? (y/n): {Style.RESET_ALL}").strip().lower()
                    if choice != 'y':
                        print(f"{Fore.RED}[Security]{Style.RESET_ALL} Installation cancelled by user.")
                        return False
                    print(f"{Fore.YELLOW}[Security]{Style.RESET_ALL} User chose to proceed despite suspicious flag.")
                    return True
                
                print(f"{Fore.GREEN}[Security]{Style.RESET_ALL} VirusTotal scan clean. Proceeding.")
                return True

            # Error path
            if isinstance(result, dict) and result.get('error'):
                print(f"{Fore.YELLOW}[Security]{Style.RESET_ALL} VirusTotal error {result.get('error')}: {result.get('message')}")
                choice = input(f"{Fore.YELLOW}Proceed with installation anyway? (y/n): {Style.RESET_ALL}").strip().lower()
                if choice != 'y':
                    print(f"{Fore.RED}[Security]{Style.RESET_ALL} Installation cancelled by user.")
                    return False
                print(f"{Fore.YELLOW}[Security]{Style.RESET_ALL} User chose to proceed despite VirusTotal error.")
                return True

            # No data path
            print(f"{Fore.YELLOW}[Security]{Style.RESET_ALL} No VirusTotal data for hash. Proceeding.")
            return True
        except Exception as ex:
            print(f"{Fore.YELLOW}[Security]{Style.RESET_ALL} VirusTotal scan skipped due to error: {ex}")
            return True
    
    def install_package(self, package_name: str, manager_name: str = None):
        """
        Install a package using specified or all managers.
        
        Args:
            package_name: Name of the package to install
            manager_name: Specific manager to use (optional)
        """
        if manager_name:
            # Install with specific manager
            if manager_name not in self.available_managers:
                print(f"{Fore.RED}Manager '{manager_name}' not available{Style.RESET_ALL}")
                return
            
            # Security scan before installing
            if not self._virustotal_scan(package_name, manager_name):
                return
            
            manager: BasePackageManager = self.available_managers[manager_name]
            success = manager.install_package(package_name)
            if success:
                print(f"{Fore.GREEN}✓ Successfully installed {package_name} via {manager_name}{Style.RESET_ALL}")
                # --- Cache in SQLite ---
                version = None
                pkgs = manager.list_packages()
                for pkg in pkgs:
                    if pkg['name'].lower() == package_name.lower():
                        version = pkg['version']
                        break
                db = PackageCacheDB()
                db.add_package(package_name, version or '', manager_name)
                db.close()
            else:
                print(f"{Fore.RED}✗ Failed to install {package_name}{Style.RESET_ALL}")
        else:
            # Ask user which manager to use
            print(f"\n{Fore.CYAN}Available managers:{Style.RESET_ALL}")
            for idx, name in enumerate(self.available_managers.keys(), 1):
                print(f"  {idx}. {name}")
            try:
                choice = input(f"\n{Fore.YELLOW}Select manager (1-{len(self.available_managers)}): {Style.RESET_ALL}")
                idx = int(choice) - 1
                manager_name = list(self.available_managers.keys())[idx]
                
                # Security scan before installing
                if not self._virustotal_scan(package_name, manager_name):
                    return
                
                manager: BasePackageManager = self.available_managers[manager_name]
                success = manager.install_package(package_name)
                if success:
                    print(f"{Fore.GREEN}✓ Successfully installed {package_name} via {manager_name}{Style.RESET_ALL}")
                    # --- Cache in SQLite ---
                    version = None
                    pkgs = manager.list_packages()
                    for pkg in pkgs:
                        if pkg['name'].lower() == package_name.lower():
                            version = pkg['version']
                            break
                    db = PackageCacheDB()
                    db.add_package(package_name, version or '', manager_name)
                    db.close()
                else:
                    print(f"{Fore.RED}✗ Failed to install {package_name}{Style.RESET_ALL}")
            except (ValueError, IndexError):
                print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
    
    def search_packages(self, query: str, manager_name: str = None):
        """
        Search for packages across managers.
        
        Args:
            query: Search query
            manager_name: Specific manager to search (optional)
        """
        if manager_name:
            # Search with specific manager
            if manager_name not in self.available_managers:
                print(f"{Fore.RED}Manager '{manager_name}' not available{Style.RESET_ALL}")
                return
            
            managers_to_search: Dict[str, BasePackageManager] = {manager_name: self.available_managers[manager_name]}
        else:
            # Search all managers
            managers_to_search: Dict[str, BasePackageManager] = self.available_managers
        
        all_results: List[Dict[str, Any]] = []
        
        for name, manager in managers_to_search.items():
            print(f"\n{Fore.CYAN}Searching {name}...{Style.RESET_ALL}")
            results = manager.search_package(query)
            all_results.extend(results)
        
        if all_results:
            # Format as table
            table_data: List[List[Any]] = [[pkg['name'], pkg['version'], pkg.get('description', ''), pkg['manager']] 
                         for pkg in all_results]
            
            print(f"\n{Fore.GREEN}Found {len(all_results)} results:{Style.RESET_ALL}")
            print(tabulate(table_data, 
                          headers=['Package', 'Version', 'Description', 'Manager'],
                          tablefmt='grid'))
        else:
            print(f"{Fore.YELLOW}No packages found matching '{query}'{Style.RESET_ALL}")
    
    def check_updates(self, manager_name: Optional[str] = None):
        """
        Check for package updates across managers.
        
        Args:
            manager_name: Specific manager to check (optional)
        """
        if not self.available_managers:
            print(f"{Fore.RED}No package managers available!{Style.RESET_ALL}")
            return
        
        if manager_name:
            # Check specific manager
            if manager_name not in self.available_managers:
                print(f"{Fore.RED}Manager '{manager_name}' not available{Style.RESET_ALL}")
                return
            
            managers_to_check: Dict[str, BasePackageManager] = {manager_name: self.available_managers[manager_name]}
        else:
            # Check all managers
            managers_to_check: Dict[str, BasePackageManager] = self.available_managers
        
        all_outdated: List[Dict[str, Any]] = []
        
        for name, manager in managers_to_check.items():
            print(f"\n{Fore.CYAN}Checking for updates in {name}...{Style.RESET_ALL}")
            
            # Check if manager has check_outdated method
            if hasattr(manager, 'check_outdated'):
                outdated = manager.check_outdated()
                all_outdated.extend(outdated)
            else:
                print(f"{Fore.YELLOW}Update checking not implemented for {name}{Style.RESET_ALL}")
        
        if all_outdated:
            # Format as table
            table_data: List[List[Any]] = [
                [
                    pkg['name'], 
                    pkg['current'], 
                    pkg['latest'],
                    pkg['manager']
                ] 
                for pkg in all_outdated
            ]
            
            print(f"\n{Fore.YELLOW}Found {len(all_outdated)} outdated packages:{Style.RESET_ALL}")
            print(tabulate(table_data, 
                          headers=['Package', 'Current', 'Latest', 'Manager'],
                          tablefmt='grid'))
            
            print(f"\n{Fore.CYAN}To update packages:{Style.RESET_ALL}")
            print("  python -m src.cli update <package-name>")
        else:
            print(f"\n{Fore.GREEN}✓ All packages are up to date!{Style.RESET_ALL}")
    
    def update_package(self, package_name: str):
        """
        Update a package to the latest version by detecting which manager has it installed.
        
        Args:
            package_name: Name of the package to update
        """
        # Auto-detect which manager has the package installed
        print(f"\n{Fore.CYAN}Detecting package manager for {package_name}...{Style.RESET_ALL}")
        
        found_managers: List[str] = []
        
        for name, manager in self.available_managers.items():
            packages = manager.list_packages()
            if any(pkg['name'].lower() == package_name.lower() for pkg in packages):
                found_managers.append(name)
        
        if not found_managers:
            print(f"{Fore.RED}Package '{package_name}' not found in any installed packages{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Tip: Use 'python -m src.cli install {package_name} -m <manager>' to install it first{Style.RESET_ALL}")
            return
        
        if len(found_managers) == 1:
            # Package found in only one manager, use it
            manager_name = found_managers[0]
            print(f"{Fore.GREEN}Found {package_name} in {manager_name}{Style.RESET_ALL}")
            
            manager: BasePackageManager = self.available_managers[manager_name]
            
            # Security scan before updating
            if not self._virustotal_scan(package_name, manager_name):
                return

            if hasattr(manager, 'upgrade_package'):
                success = manager.upgrade_package(package_name)
                
                if success:
                    print(f"{Fore.GREEN}✓ Successfully updated {package_name} via {manager_name}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}✗ Failed to update {package_name}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}Update not implemented for {manager_name}{Style.RESET_ALL}")
        else:
            # Package found in multiple managers, ask user
            print(f"{Fore.YELLOW}Package '{package_name}' found in multiple managers:{Style.RESET_ALL}")
            for idx, name in enumerate(found_managers, 1):
                print(f"  {idx}. {name}")
            
            try:
                choice = input(f"\n{Fore.YELLOW}Select manager (1-{len(found_managers)}): {Style.RESET_ALL}")
                idx = int(choice) - 1
                manager_name = found_managers[idx]
                
                manager: BasePackageManager = self.available_managers[manager_name]
                
                # Security scan before updating
                if not self._virustotal_scan(package_name, manager_name):
                    return

                if hasattr(manager, 'upgrade_package'):
                    manager.upgrade_package(package_name)
                else:
                    print(f"{Fore.YELLOW}Update not implemented for {manager_name}{Style.RESET_ALL}")
            
            except (ValueError, IndexError):
                print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
    
    def upgrade_package(self, package_name: str, manager_name: Optional[str] = None):
        """
        Upgrade a package to the latest version.
        
        Args:
            package_name: Name of the package to upgrade
            manager_name: Specific manager to use (optional)
        """
        if manager_name:
            # Upgrade with specific manager
            if manager_name not in self.available_managers:
                print(f"{Fore.RED}Manager '{manager_name}' not available{Style.RESET_ALL}")
                return
            
            manager: BasePackageManager = self.available_managers[manager_name]
            
            # Security scan before upgrading
            if not self._virustotal_scan(package_name, manager_name):
                return

            # Check if manager has upgrade_package method
            if hasattr(manager, 'upgrade_package'):
                success = manager.upgrade_package(package_name)
                
                if success:
                    print(f"{Fore.GREEN}✓ Successfully upgraded {package_name} via {manager_name}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}✗ Failed to upgrade {package_name}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}Upgrade not implemented for {manager_name}{Style.RESET_ALL}")
        else:
            # Ask user which manager to use
            print(f"\n{Fore.CYAN}Available managers:{Style.RESET_ALL}")
            for idx, name in enumerate(self.available_managers.keys(), 1):
                print(f"  {idx}. {name}")
            
            try:
                choice = input(f"\n{Fore.YELLOW}Select manager (1-{len(self.available_managers)}): {Style.RESET_ALL}")
                idx = int(choice) - 1
                manager_name = list(self.available_managers.keys())[idx]
                
                manager: BasePackageManager = self.available_managers[manager_name]
                
                # Security scan before upgrading
                if not self._virustotal_scan(package_name, manager_name):
                    return

                if hasattr(manager, 'upgrade_package'):
                    manager.upgrade_package(package_name)
                else:
                    print(f"{Fore.YELLOW}Upgrade not implemented for {manager_name}{Style.RESET_ALL}")
            
            except (ValueError, IndexError):
                print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description='Unified Package Manager CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s list                    # List all packages
    %(prog)s install <package>       # Install a package (replace <package>)
    %(prog)s install express -m npm  # Install with specific manager
    %(prog)s search django           # Search for packages
    %(prog)s search react -m npm     # Search in specific manager
    %(prog)s update                  # Check for outdated packages
    %(prog)s update pytest           # Update pytest (auto-detects manager)
    %(prog)s upgrade express -m npm  # Alternative: upgrade with specific manager
                """
    )
    
    parser.add_argument('command', 
                       choices=['list', 'install', 'search', 'update', 'upgrade', 'help'],
                       help='Command to execute')
    
    parser.add_argument('package', 
                       nargs='?',
                       help='Package name (for install/search)')
    
    parser.add_argument('-m', '--manager',
                       choices=['npm', 'pip3'],
                       help='Specific package manager to use')
    

    args = parser.parse_args()
    
    # Create CLI instance
    cli = UnifiedCLI()
    
    # Execute command
    if args.command == 'help':
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Available Commands:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}list{Style.RESET_ALL}")
        print("  List all installed packages from npm and pip3")
        print("  Example: unified list\n")
        print(f"{Fore.YELLOW}search <query> [-m <manager>]{Style.RESET_ALL}")
        print("  Search for packages across npm and/or pip3")
        print("  Examples:")
        print("    unified search requests")
        print("    unified search react -m npm\n")
        print(f"{Fore.YELLOW}install <package> [-m <manager>]{Style.RESET_ALL}")
        print("  Install a package using specified or selected manager")
        print("  Examples:")
        print("    unified install express -m npm")
        print("    unified install requests -m pip3\n")
        print(f"{Fore.YELLOW}update [package]{Style.RESET_ALL}")
        print("  Check for outdated packages or update a specific package")
        print("  Examples:")
        print("    unified update              # Check all outdated packages")
        print("    unified update pytest       # Update pytest (auto-detects manager)\n")
        print(f"{Fore.YELLOW}upgrade <package> -m <manager>{Style.RESET_ALL}")
        print(f"  Upgrade a package using a specific manager")
        print(f"  Examples:")
        print(f"    unified upgrade express -m npm")
        print(f"    unified upgrade requests -m pip3\n")
        print(f"{Fore.YELLOW}help{Style.RESET_ALL}")
        print(f"  Show this help message\n")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Supported Package Managers:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        print(f"  • npm (Node Package Manager)")
        print(f"  • pip3 (Python Package Manager)\n")
        sys.exit(0)
    
    elif args.command == 'list':
        cli.list_all_packages()
    
    elif args.command == 'install':
        if not args.package:
            print(f"{Fore.RED}Error: Package name required for install{Style.RESET_ALL}")
            sys.exit(1)
        # Safety: prevent accidental execution of placeholder examples
        if args.package == 'package-name' or args.package.strip() == '<package>':
            print(f"{Fore.YELLOW}Refusing to install placeholder package name '{args.package}'. Replace with a real package name.{Style.RESET_ALL}")
            sys.exit(1)

        cli.install_package(args.package, args.manager)
    
    elif args.command == 'search':
        if not args.package:
            print(f"{Fore.RED}Error: Search query required{Style.RESET_ALL}")
            sys.exit(1)
        cli.search_packages(args.package, args.manager)
    
    elif args.command == 'update':
        if args.package:
            # Update specific package
            # Safety: prevent accidental execution of placeholder examples
            if args.package == 'package-name' or args.package.strip() == '<package>':
                print(f"{Fore.YELLOW}Refusing to update placeholder package name '{args.package}'. Replace with a real package name.{Style.RESET_ALL}")
                sys.exit(1)
            
            cli.update_package(args.package)
        else:
            # Check for all outdated packages
            cli.check_updates(args.manager)
    
    elif args.command == 'upgrade':
        if not args.package:
            print(f"{Fore.RED}Error: Package name required for upgrade{Style.RESET_ALL}")
            sys.exit(1)
        # Safety: prevent accidental execution of placeholder examples
        if args.package == 'package-name' or args.package.strip() == '<package>':
            print(f"{Fore.YELLOW}Refusing to upgrade placeholder package name '{args.package}'. Replace with a real package name.{Style.RESET_ALL}")
            sys.exit(1)
        
        cli.upgrade_package(args.package, args.manager)

if __name__ == '__main__':
    main()
