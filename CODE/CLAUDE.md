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
3. If security is not skipped, `_security_scan()` runs the full pipeline:
   a. **Version resolution (TOCTOU fix):** `_resolve_scan_version()` queries the registry for the exact version *before* any download. The result is stored in `self._last_resolved_version`.
   b. **Artifact hash:** `download_package_and_get_hash()` downloads the tarball/wheel for that pinned version and returns its SHA-256.
   c. **Provider fan-out:** `SecurityAggregator.analyze()` checks the file-based TTL cache (`SecurityScanCache`, `.security_scan_cache.json`), then fans out to 4 providers in `src/utils/security_providers.py`.
   d. Returns a `decision`: `"allow"` / `"warn"` / `"block"`.
4. **Fail-closed policy:** if `_security_scan()` raises an exception the decision is `"block"` and the action is aborted (not silently allowed).
5. `"block"` aborts installation; `"warn"` prints a warning and prompts the user; `"allow"` proceeds.
6. The manager is called with the **version-pinned specifier** (`pkg==ver` for pip, `pkg@ver` for npm/yarn/pnpm) so the installed release is always identical to the scanned artifact.
7. **Transitive dependency scan (install only):**
   - `_capture_package_snapshot()` records the installed package tree before the install.
   - After a successful install the tree is captured again and diffed.
   - `_scan_and_rollback_transitive()` runs `SecurityAggregator.analyze()` on every newly introduced dependency.
   - If any transitive dep returns `"block"`, the top-level package and all new deps are uninstalled automatically (rollback).
8. On success, `PackageCacheDB` (SQLite, `package_cache.db`) is updated:
   - `install` → `add_package()`
   - `upgrade` → `update_package_version()` (upsert)
   - `uninstall` → `remove_package()` (delete)
9. Reports are written to `security_reports/` (JSON + Markdown) via `src/utils/security_report.py`.

### Manager abstraction
- `BasePackageManager` (ABC) in `src/managers/base_manager.py` defines the interface: `list_packages`, `install_package`, `search_package`, `upgrade_package`, `check_outdated`, `uninstall_package`.
- `_run_command()` handles Windows path resolution via `shutil.which`.
- `_search_npm_registry()` is shared by npm, yarn, and pnpm managers.
- `get_latest_registry_version()` queries PyPI (pip) or the npm registry; used for TOCTOU-safe version resolution.
- Each concrete manager (`NPMManager`, `PipManager`, `YarnManager`, `PNPMManager`) implements the interface for its ecosystem.

### Security layer
- `SecurityAggregator` (`src/utils/security_aggregator.py`) orchestrates all providers; cache key includes schema version, manager, package, version, file hash, and auth configuration fingerprint.
- `SecurityScanCache` (`src/utils/security_cache.py`) is a file-based JSON cache with configurable TTL (default 600 s, override with `SECURITY_CACHE_TTL_SECONDS`).
- Decision thresholds: critical/malicious → `block`; high/medium → `warn`; no findings + ≥2 providers → `allow`.
- **OSV severity parsing:** CVSS vector strings (e.g. `CVSS:3.1/AV:N/…`) are resolved via `database_specific.cvss_score`, `database_specific.severity` (text label), or `affected[].ecosystem_specific.severity` — in that priority order — rather than trying to parse the vector tail as a float.

### PackageCacheDB
`src/utils/package_cache.py` — SQLite-backed record of packages managed through unified.

| Method | Trigger | Purpose |
|---|---|---|
| `add_package(name, version, manager)` | successful `install` | Insert new record |
| `update_package_version(name, version, manager)` | successful `upgrade` | Upsert to new version |
| `remove_package(name, manager)` | successful `uninstall` | Delete stale record |
| `get_packages()` | `list` (internal) | Return all records |

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
- Test files are named by feature: `test_managers`, `test_cli_handlers`, `test_cli_integration`, `test_virustotal`, `test_security_aggregator`, `test_security_cache`, `test_security_providers`, `test_security_report_and_cache`, `test_security_fixes`.
- `tests/test_security_fixes.py` covers all four architectural fixes: TOCTOU, transitive scanning, PackageCacheDB consistency, OSV parser, and fail-closed policy.
