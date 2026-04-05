# Supply-Chain Security Scanner

A **multi-provider vulnerability aggregation** tool that checks packages against **4 independent security providers** before installation — giving you higher confidence than any single-provider solution.

## Why Multi-Provider?

Single-provider vulnerability scanners miss threats. Each security database has different coverage:

| Provider | Strength |
|----------|----------|
| **OSV.dev** | Comprehensive open-source vulnerability database |
| **GitHub Advisory** | Fast disclosure of GitHub-tracked CVEs |
| **OSS Index** | Sonatype's commercial-grade intelligence |
| **VirusTotal** | File-hash malware reputation (60+ AV engines) |

Our **aggregation strategy** combines all four providers and makes intelligent decisions:
- **BLOCK** — Critical/malicious findings → installation aborted
- **WARN** — Medium/high severity → proceed with caution
- **ALLOW** — Clean + sufficient coverage → safe to install

## Key Features

- **Multi-Provider Aggregation** — combines 4 security providers for maximum coverage
- **Intelligent Decision Policy** — BLOCK/WARN/ALLOW based on severity and coverage
- **Caching** — TTL-based cache avoids redundant API calls
- **Detailed Reports** — JSON + Markdown reports in `security_reports/`
- **Cross-Platform** — works on Windows, Linux, and macOS
- **Multi-Manager Support** — works with `npm`, `pip3`, `yarn`, and `pnpm`

## Installation

### Option 1: Install as a command (recommended)

**Windows:**
```bash
install.bat
```

**Linux / macOS:**
```bash
chmod +x install.sh && ./install.sh
```

Or manually:
```bash
pip install -e .
```

Then use `unified` from anywhere:
```bash
unified list
unified install express -m npm
```

### Option 2: Run without installation

```bash
python unified.py list
python unified.py search requests
```

## Usage

### List installed packages
```bash
unified list                  # all managers
unified list -m pip3          # pip3 only
```

### Search for packages
```bash
unified search react          # search all managers
unified search django -m pip3 # search one manager
```

### Install packages
```bash
unified install express -m npm
unified install requests -m pip3
unified install lodash          # prompts for manager if ambiguous
unified install lodash --no-security   # skip security scan
unified install flask --show-findings   # show top 10 findings in terminal
unified install flask --show-findings 5 # show top 5 findings
```

### Upgrade / update packages
```bash
unified upgrade requests -m pip3
unified update express -m npm     # "update" is an alias for "upgrade"
unified upgrade Werkzeug --show-findings 8
```

### Check for outdated packages
```bash
unified check_updates             # all managers
unified check_updates -m npm      # npm only
```

### Uninstall packages
```bash
unified uninstall requests -m pip3
unified uninstall lodash -m npm
```

### Other flags
```bash
unified --version          # print version and exit
unified install foo --no-security   # skip security scanning
unified upgrade foo --show-findings [N]  # print findings summary table
```

## Security Scanning

Every `install` and `upgrade` command triggers a multi-provider security scan (unless `--no-security` is passed):

| Provider | What it checks |
|---|---|
| **VirusTotal** | File-hash reputation (requires `VIRUSTOTAL_API_KEY` env var) |
| **OSV.dev** | Open-source vulnerability database |
| **GitHub Advisory** | GitHub's advisory database |
| **OSS Index** | Sonatype OSS Index |

**Decision policy:**

| Condition | Action |
|---|---|
| Critical / malicious finding | **Block** — installation aborted |
| Medium / high finding | **Warn** — proceed with caution message |
| Clean + sufficient coverage | **Allow** |

Scan results are cached in `.security_scan_cache.json` (default TTL 600 s) and a JSON report is written to `security_reports/`.

Use `--show-findings` to print findings directly in the terminal during scan:
- `--show-findings` shows top 10 findings
- `--show-findings N` shows top `N` findings

## Environment Variables

Copy `.env.example` to `.env` and configure your API keys:

| Variable | Purpose | Required |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | File-hash reputation checks | Recommended |
| `OSSINDEX_USERNAME` | OSS Index authentication | Recommended |
| `OSSINDEX_TOKEN` | OSS Index authentication | Recommended |
| `GITHUB_TOKEN` | Increases GitHub API rate limits | Optional |
| `SECURITY_CACHE_TTL_SECONDS` | Cache TTL in seconds (default: 600) | Optional |

## Requirements

- Python 3.8+
- At least one of: `npm`, `pip3`, `yarn`, `pnpm`

## Dependencies

- `colorama` — coloured terminal output
- `tabulate` — pretty table formatting
- `requests` — HTTP client for registry / security API calls

## Architecture

```
cli-package-manager-unifier/
├── src/
│   ├── cli.py                       # Main CLI (argparse + handlers)
│   ├── managers/
│   │   ├── base_manager.py          # Abstract base class + shared helpers
│   │   ├── npm_manager.py           # npm implementation
│   │   ├── pip_manager.py           # pip3 implementation
│   │   ├── yarn_manager.py          # yarn implementation
│   │   └── pnpm_manager.py          # pnpm implementation
│   └── utils/
│       ├── virustotal.py            # VirusTotal hash download + API
│       ├── security_providers.py    # OSV / GitHub / OSS Index providers
│       ├── security_aggregator.py   # Multi-provider scoring & decision
│       ├── security_cache.py        # File-based TTL cache
│       ├── security_report.py       # JSON report writer
│       └── package_cache.py         # SQLite installed-package cache
├── tests/                           # 72 pytest tests
│   ├── conftest.py                  # Shared fixtures
│   ├── test_managers.py             # Manager unit tests (31)
│   ├── test_cli_handlers.py         # CLI handler tests (14)
│   ├── test_phase1_cli.py           # CLI integration tests (7)
│   ├── test_phase1_virustotal.py    # VirusTotal tests (3)
│   ├── test_phase2_security_*.py    # Security provider/cache tests (9)
│   └── test_security_report_and_cache.py  # Report & DB tests (6)
├── unified.py                       # Entry-point script
├── setup.py                         # Package configuration
├── requirements.txt                 # Python dependencies
└── .gitignore
```

## Running Tests

```bash
pytest tests/ -v
```

## License

MIT License
