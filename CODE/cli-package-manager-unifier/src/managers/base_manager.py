"""
Base manager class providing common interface for all package managers.
"""
from abc import ABC, abstractmethod
from typing import List, Dict
import subprocess
import shutil
import sys
# import json


class BasePackageManager(ABC):
    """Abstract base class for package managers."""

    def __init__(self, name: str, command: str):
        """
        Initialize the package manager.

        Args:
            name: Display name of the package manager
            command: Base command to execute (e.g., 'npm', 'pip3')
        """
        self.name = name
        self.command = command

    @abstractmethod
    def list_packages(self) -> List[Dict[str, str]]:
        """
        List all installed packages.
        Returns:
            List of dictionaries containing package information
        """
        pass

    @abstractmethod
    def install_package(self, package_name: str) -> bool:
        """
        Install a package.
        Args:
            package_name: Name of the package to install
        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def search_package(self, query: str) -> List[Dict[str, str]]:
        """
        Search for packages.
        Args:
            query: Search query string
        Returns:
            List of matching packages
        """
        pass

    def _run_command(self, args: List[str], capture_output: bool = True) -> subprocess.CompletedProcess[str]:
        """
        Execute a command with the package manager.
        Args:
            args: List of command arguments
            capture_output: Whether to capture output
        Returns:
            CompletedProcess[str] object
        """
        try:
            # On Windows, find the full path to the command to handle .cmd files
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
                errors='replace',
                timeout=30
            )
            return result
        except subprocess.TimeoutExpired:
            raise Exception(f"Command timed out: {' '.join([self.command] + args)}")
        except FileNotFoundError:
            raise Exception(f"{self.command} is not installed or not in PATH")

    def is_available(self) -> bool:
        """
        Check if the package manager is available.
        Returns:
            True if available, False otherwise
        """
        try:
            result = self._run_command(['--version'])
            return result.returncode == 0
        except Exception:
            return False
