"""Setup script for the unified CLI."""
from setuptools import setup, find_packages

setup(
    name='cli-package-manager-unifier',
    version='1.1.0',
    description='A unified CLI for managing npm, pip3, yarn, and pnpm packages with security scanning',
    author='Your Name',
    packages=find_packages(),
    install_requires=[
        'colorama>=0.4.6',
        'tabulate>=0.9.0',
        'requests>=2.31.0',
    ],
    entry_points={
        'console_scripts': [
            'unified=src.cli:main',
        ],
    },
    python_requires='>=3.7',
)
