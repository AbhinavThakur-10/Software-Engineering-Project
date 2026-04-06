# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Supply-Chain Security Scanner** — a CLI tool (`unified`) that wraps `npm`, `pip3`, `yarn`, and `pnpm` and scans packages against 4 security providers (OSV.dev, GitHub Advisory, OSS Index, VirusTotal) before installation.

All source code lives under `cli-package-manager-unifier/`.

## Commands

All commands should be run from `cli-package-manager-unifier/`.

### Setup
```bash
pip install -e .
# or without installing:
python unified.py <command>
```

### Running tests
```bash
pytest tests/ -v                          # all tests
pytest tests/test_managers.py -v         # manager unit tests only
pytest tests/test_cli_handlers.py -v     # CLI handler tests only
pytest tests/test_cli_integration.py -v  # CLI integration tests
pytest tests/ -v -k "test_install"       # run tests matching a pattern
```

Tests must be run from `cli-package-manager-unifier/` so that `src.*` imports resolve correctly.

### Running the CLI
```bash
unified list
unified install <pkg> -m npm
unified install <pkg> -m pip3 --no-security
unified upgrade <pkg> --show-findings 5
unified search <query>
unified check_updates
unified uninstall <pkg> -m pip3
```

## Architecture

### Data flow for `install`/`upgrade`
1. `src/cli.py` (`UnifiedCLI`) parses args and dispatches to a handler method.
2. The handler resolves the target manager from `self.available_managers` (dict of `BasePackageManager` subclasses).
3. If security is not skipped, `SecurityAggregator.analyze()` is called, which:
   - Checks a file-based TTL cache (`SecurityScanCache`, `.security_scan_cache.json`).
   - Fans out to 4 providers in `src/utils/security_providers.py` (`scan_with_osv`, `scan_with_github_advisory`, `scan_with_oss_index`, `scan_with_virustotal`).
   - Scores findings and returns a `decision`: `"allow"` / `"warn"` / `"block"`.
4. `"block"` aborts installation; `"warn"` prints a warning; `"allow"` proceeds.
5. After installation, `PackageCacheDB` (SQLite, `package_cache.db`) records the package.
6. Reports are written to `security_reports/` (JSON + Markdown) via `src/utils/security_report.py`.

### Manager abstraction
- `BasePackageManager` (ABC) in `src/managers/base_manager.py` defines the interface: `list_packages`, `install_package`, `search_package`, `upgrade_package`, `check_outdated`, `uninstall_package`.
- `_run_command()` handles Windows path resolution via `shutil.which`.
- `_search_npm_registry()` is shared by npm, yarn, and pnpm managers.
- Each concrete manager (`NPMManager`, `PipManager`, `YarnManager`, `PNPMManager`) implements the interface for its ecosystem.

### Security layer
- `SecurityAggregator` (`src/utils/security_aggregator.py`) orchestrates all providers; cache key includes schema version, manager, package, version, file hash, and auth configuration fingerprint.
- `SecurityScanCache` (`src/utils/security_cache.py`) is a file-based JSON cache with configurable TTL (default 600 s, override with `SECURITY_CACHE_TTL_SECONDS`).
- Decision thresholds: critical/malicious → `block`; high/medium → `warn`; no findings + ≥2 providers → `allow`.

### Environment variables
| Variable | Purpose |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal file-hash scanning |
| `OSSINDEX_USERNAME` / `OSSINDEX_TOKEN` | OSS Index auth |
| `GITHUB_TOKEN` | Increases GitHub Advisory rate limits |
| `SECURITY_CACHE_TTL_SECONDS` | Cache TTL (default: 600) |

Copy `.env.example` to `.env` — loaded automatically via `python-dotenv`.

### Test conventions
- `tests/conftest.py` provides fixtures that monkeypatch `BasePackageManager.is_available` to avoid real subprocess calls; use `cli_no_managers` for CLI-level tests.
- Security provider tests mock HTTP calls; do not make real network requests in tests.
- Test files are named by feature: `test_managers`, `test_cli_handlers`, `test_cli_integration`, `test_virustotal`, `test_security_aggregator`, `test_security_cache`, `test_security_providers`, `test_security_report_and_cache`.
