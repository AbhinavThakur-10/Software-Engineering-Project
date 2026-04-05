# Security Providers

This document details each security provider integrated into the scanner.

## Overview

| Provider | Type | Auth Required | Rate Limits |
|----------|------|---------------|-------------|
| OSV.dev | Vulnerability DB | No | Generous |
| GitHub Advisory | Vulnerability DB | Optional | 60/hr (5000/hr with token) |
| OSS Index | Vulnerability DB | Yes | 1000/day |
| VirusTotal | Malware Scanner | Yes | 4/min (free tier) |

---

## 1. OSV.dev

**What it detects:** Known vulnerabilities in open-source packages

**Data source:** Google-maintained aggregation of:
- GitHub Security Advisories
- PyPI Advisory Database
- npm Security Advisories
- RustSec
- Go Vulnerability Database

### Example Finding
```json
{
  "id": "GHSA-jfmj-5v4g-7637",
  "summary": "Werkzeug debugger PIN bypass",
  "severity": "high",
  "affected_versions": "<2.2.3"
}
```

### Coverage
| Ecosystem | Status |
|-----------|--------|
| PyPI (pip) | ✅ Excellent |
| npm | ✅ Excellent |
| Go | ✅ Good |
| Cargo (Rust) | ✅ Good |
| Maven (Java) | ⚠️ Partial |

### Configuration
No authentication required.

---

## 2. GitHub Advisory Database

**What it detects:** CVEs tracked by GitHub Security

**Data source:** GitHub-curated security advisories

### Example Finding
```json
{
  "id": "GHSA-r9hx-vwmv-q579",
  "summary": "ReDoS in lodash",
  "severity": "medium",
  "cve": "CVE-2020-28500"
}
```

### Rate Limits
- Without token: 60 requests/hour
- With `GITHUB_TOKEN`: 5000 requests/hour

### Configuration
```bash
# Optional but recommended
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
```

Token doesn't need any special scopes for public advisory data.

---

## 3. OSS Index (Sonatype)

**What it detects:** Vulnerabilities from Sonatype's commercial intelligence

**Data source:** Sonatype's proprietary vulnerability database

### Example Finding
```json
{
  "id": "sonatype-2021-1234",
  "summary": "Prototype pollution in minimist",
  "severity": "high",
  "cvss_score": 7.5
}
```

### Unique Strengths
- Often has findings before public CVE assignment
- Includes commercial intelligence not in free databases
- Quality curation (fewer false positives)

### Configuration (Required)
```bash
export OSSINDEX_USERNAME="your_email@example.com"
export OSSINDEX_TOKEN="your_api_token"
```

Register free at: https://ossindex.sonatype.org/user/register

### Rate Limits
- 1000 requests/day (free tier)

---

## 4. VirusTotal

**What it detects:** Malware, trojans, backdoors in package artifacts

**Data source:** 60+ antivirus engines scanning file hashes

### How It Works
1. Scanner downloads the package tarball/wheel
2. Calculates SHA-256 hash
3. Queries VirusTotal for existing scan results
4. If hash is unknown, optionally uploads for scanning

### Example Finding
```json
{
  "id": "vt-malicious",
  "summary": "Detected as Trojan.Python.Agent by 5 engines",
  "severity": "critical",
  "detection_count": 5
}
```

### What It Catches (CVE scanners miss)
- Typosquatting packages with malware
- Compromised package maintainer accounts
- Supply-chain injection attacks
- Cryptominers, backdoors, RATs

### Configuration (Required)
```bash
export VIRUSTOTAL_API_KEY="your_api_key"
```

Get free key at: https://www.virustotal.com/gui/join-us

### Rate Limits
- Free tier: 4 requests/minute, 1000/day
- Premium: Higher limits

---

## Provider Comparison

### Detection Capabilities

| Threat Type | OSV | GitHub | OSS Index | VirusTotal |
|-------------|-----|--------|-----------|------------|
| Known CVEs | ✅ | ✅ | ✅ | ❌ |
| Zero-day vulns | ❌ | ❌ | ⚠️ | ❌ |
| Malware | ❌ | ❌ | ❌ | ✅ |
| Typosquatting | ❌ | ❌ | ❌ | ✅ |
| Backdoors | ❌ | ❌ | ❌ | ✅ |

### Latency

| Provider | Typical Latency |
|----------|-----------------|
| OSV.dev | 200-500ms |
| GitHub Advisory | 300-800ms |
| OSS Index | 500-1500ms |
| VirusTotal | 1-3s |

### Reliability

| Provider | Uptime | Graceful Degradation |
|----------|--------|---------------------|
| OSV.dev | 99.9% | Scanner continues without it |
| GitHub Advisory | 99.9% | Scanner continues without it |
| OSS Index | 99% | Scanner continues without it |
| VirusTotal | 99.5% | Scanner continues without it |

---

## Why All Four?

**Single-provider blind spots:**

- **OSV.dev only**: Misses malware that isn't a CVE
- **VirusTotal only**: Misses CVEs that don't trigger AV signatures
- **GitHub only**: Misses packages not on GitHub
- **OSS Index only**: May be unavailable if auth fails

**Multi-provider benefits:**

1. **Higher recall**: Catch more threats
2. **Redundancy**: Keep working if one provider is down
3. **Cross-validation**: Multiple sources increase confidence
4. **Comprehensive**: CVEs + Malware + Commercial intel

---

## Provider Status in Reports

Each security report shows provider status:

```
Provider Status:
├── OSV.dev: ✅ ok (2 findings)
├── GitHub Advisory: ✅ ok (1 finding)
├── OSS Index: ✅ ok (0 findings)
└── VirusTotal: ⚠️ error (rate limited)

Coverage: 3/4 providers
```

Even with one provider down, the scanner makes a decision based on available data.
