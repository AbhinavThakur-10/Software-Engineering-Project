"""Setup script for the Supply-Chain Security Scanner."""
from setuptools import setup, find_packages

setup(
    name='supply-chain-security-scanner',
    version='1.1.0',
    description='Multi-provider vulnerability aggregation tool for supply-chain security',
    long_description='A security scanner that aggregates findings from OSV.dev, GitHub Advisory, OSS Index, and VirusTotal to make intelligent BLOCK/WARN/ALLOW decisions before package installation.',
    author='Your Name',
    packages=find_packages(),
    install_requires=[
        'colorama>=0.4.6',
        'tabulate>=0.9.0',
        'requests>=2.31.0',
        'python-dotenv>=1.0.0',
    ],
    entry_points={
        'console_scripts': [
            'unified=src.cli:main',
        ],
    },
    python_requires='>=3.7',
    keywords='security, vulnerability, scanner, supply-chain, npm, pip, package-manager',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Build Tools',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
)
