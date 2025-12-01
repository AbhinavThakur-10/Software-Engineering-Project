#!/bin/bash
# Installation script for Linux/macOS

echo "Installing unified package manager CLI..."
echo ""

# Check if python3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed or not in PATH"
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
    echo "Error: pip is not installed"
    exit 1
fi

# Install in editable mode
echo "Installing package in editable mode..."
pip3 install -e . || pip install -e .

if [ $? -ne 0 ]; then
    echo ""
    echo "Installation failed!"
    exit 1
fi

echo ""
echo "======================================"
echo "Installation successful!"
echo "======================================"
echo ""
echo "You can now use the following commands:"
echo "  unified list"
echo "  unified search <package>"
echo "  unified install <package> -m <manager>"
echo "  unified update"
echo "  unified update <package>"
echo "  unified upgrade <package> -m <manager>"
echo ""
echo "Note: You may need to restart your terminal for the changes to take effect."
echo ""
