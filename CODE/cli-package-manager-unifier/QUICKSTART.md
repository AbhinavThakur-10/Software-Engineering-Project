# Quick Start Guide

Check if a package is safe before installing it.

## 1. Setup (5 minutes)

### Install the scanner
```bash
pip install -e .
```

### Configure API keys
```bash
# Copy the example file
cp .env.example .env

# Edit .env with your keys (at minimum, set OSSINDEX credentials)
```

Get your API keys:
- **OSS Index**: Free at https://ossindex.sonatype.org/user/register
- **VirusTotal**: Free at https://www.virustotal.com/gui/join-us
- **GitHub Token**: Optional, https://github.com/settings/tokens

### Set environment variables
**Windows (PowerShell):**
```powershell
$env:OSSINDEX_USERNAME="your_email@example.com"
$env:OSSINDEX_TOKEN="your_token"
$env:VIRUSTOTAL_API_KEY="your_key"
```

**Linux/macOS:**
```bash
export OSSINDEX_USERNAME="your_email@example.com"
export OSSINDEX_TOKEN="your_token"
export VIRUSTOTAL_API_KEY="your_key"
```

## 2. Check if a Package is Safe

### Basic security scan
```bash
unified install requests -m pip3
```

Output shows:
- Which providers responded (OSV, GitHub, OSS Index, VirusTotal)
- Any vulnerabilities found
- Final decision: **ALLOW**, **WARN**, or **BLOCK**

### View detailed findings
```bash
unified install flask -m pip3 --show-findings
```

This prints the top 10 findings directly in your terminal.

### Skip security scan (not recommended)
```bash
unified install lodash -m npm --no-security
```

## 3. Understanding Decisions

| Decision | What it means | What to do |
|----------|---------------|------------|
| **ALLOW** | Clean, sufficient coverage | Safe to install |
| **WARN** | Medium/high severity issues | Review findings before proceeding |
| **BLOCK** | Critical or malicious | Do not install |

## 4. View Security Reports

Every scan saves a detailed report:
```
security_reports/
├── requests_2025-04-04_14-30-00.json   # Machine-readable
└── requests_2025-04-04_14-30-00.md     # Human-readable
```

## 5. Common Workflows

### Audit before upgrading
```bash
unified upgrade werkzeug -m pip3 --show-findings 5
```

### Check npm packages
```bash
unified install express -m npm
unified install lodash -m npm --show-findings
```

### Batch audit (PowerShell)
```powershell
@("react", "lodash", "express") | ForEach-Object {
    unified upgrade $_ -m npm --show-findings 1
}
```

## 6. Troubleshooting

### "OSS Index: error"
Set your credentials:
```bash
export OSSINDEX_USERNAME="your_email"
export OSSINDEX_TOKEN="your_token"
```

### "VirusTotal: error"
Get a free API key from https://www.virustotal.com/gui/join-us

### Decision is WARN with no findings
This means insufficient provider coverage. Ensure at least 2 providers are configured.

## Next Steps

- Read [SECURITY_MODEL.md](docs/SECURITY_MODEL.md) to understand how decisions are made
- Check [docs/PROVIDERS.md](docs/PROVIDERS.md) for provider details
- Run experiments with [experiments/EXPERIMENTS.md](experiments/EXPERIMENTS.md)
