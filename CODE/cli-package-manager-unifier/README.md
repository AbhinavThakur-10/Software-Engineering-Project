# CLI Package Manager Unifier

A unified command-line interface for managing both npm and pip3 packages from a single tool.

## Features

- **Unified Interface**: Manage npm and pip3 packages with a single CLI
- **Smart Package Detection**: Automatically detects which manager a package belongs to
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Colorful Output**: Clear, color-coded feedback for all operations
- **Update Checking**: Check for outdated packages across both managers

## Installation

### Option 1: Install as a Command (Recommended)

Run the installation script:

**Windows:**
```bash
install.bat
```

**Linux/macOS:**
```bash
chmod +x install.sh
./install.sh
```

Or manually:
```bash
pip install -e .
```

After installation, you can use the `unified` command from anywhere:
```bash
unified list
unified search requests
unified install express -m npm
```

### Option 2: Run Without Installation

You can run directly using Python:
```bash
python unified.py list
python unified.py search requests
python unified.py install express -m npm
```

Or using the module:
```bash
python -m src.cli list
```

## Usage

### List Installed Packages
```bash
unified list
```
Shows all installed packages from both npm (global) and pip3.

### Search for Packages
```bash
# Search across all managers
unified search requests

# Search in specific manager
unified search express -m npm
unified search django -m pip3
```

### Install Packages
```bash
# Install with specific manager
unified install requests -m pip3
unified install express -m npm

# Interactive installation (prompts for manager selection)
unified install lodash
```

### Check for Updates
```bash
# Check all outdated packages
unified update

# Check outdated packages in specific manager
unified update -m npm
unified update -m pip3
```

### Update Packages
```bash
# Auto-detects and updates from correct manager
unified update pytest
unified update express

# If package exists in multiple managers, prompts for selection
```

### Upgrade Packages (Alternative)
```bash
# Upgrade with specific manager
unified upgrade requests -m pip3
unified upgrade express -m npm
```

## Examples

```bash
# List all installed packages
unified list

# Search for a package
unified search react

# Install React via npm
unified install react -m npm

# Check what needs updating
unified update

# Update a specific package
unified update pytest

# Install Python package
unified install requests -m pip3
```

## Requirements

- Python 3.7 or higher
- npm (optional, for npm package management)
- pip3 (optional, for Python package management)

## Dependencies

- `colorama` - Cross-platform colored terminal output
- `tabulate` - Pretty table formatting
- `requests` - HTTP library for PyPI searches

## Architecture

```
cli-package-manager-unifier/
├── src/
│   ├── cli.py                 # Main CLI interface
│   └── managers/
│       ├── base_manager.py    # Abstract base class
│       ├── npm_manager.py     # NPM implementation
│       └── pip_manager.py     # Pip3 implementation
├── unified.py                 # Entry point script
├── setup.py                   # Installation configuration
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## Contributing

Feel free to submit issues and enhancement requests!

## License

MIT License
