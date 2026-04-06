# Security Model

This document explains how the Supply-Chain Security Scanner aggregates findings from multiple providers and makes installation decisions.

## Architecture Overview

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│    OSV.dev   │    │   GitHub     │    │  OSS Index   │    │  VirusTotal  │
│              │    │   Advisory   │    │  (Sonatype)  │    │              │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │                   │
       └───────────────────┴───────────────────┴───────────────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │  Security Aggregator  │
                        │  (Scoring & Decision) │
                        └───────────┬───────────┘
                                    │
                                    ▼
                           ┌───────────────┐
                           │   Decision    │
                           │ BLOCK│WARN│ALLOW│
                           └───────────────┘
```

## Provider Capabilities

| Provider | Data Source | Strengths | Limitations |
|----------|-------------|-----------|-------------|
| **OSV.dev** | Open Source Vulnerabilities database | Broad ecosystem coverage, fast updates | May miss commercial intelligence |
| **GitHub Advisory** | GitHub Security Advisories | Quick disclosure of GitHub-tracked CVEs | Limited to GitHub-indexed packages |
| **OSS Index** | Sonatype commercial intelligence | High-quality curated data | Requires authentication |
| **VirusTotal** | 60+ antivirus engines | Malware/trojan detection | Only detects file-based threats |

## Decision Policy

The aggregator makes decisions based on severity levels and coverage:

### Decision Matrix

| Condition | Decision | Behavior |
|-----------|----------|----------|
| **Any critical finding** | `BLOCK` | Installation aborted |
| **Any malicious detection (VirusTotal)** | `BLOCK` | Installation aborted |
| **Medium or high severity findings** | `WARN` | Warning displayed, user can proceed |
| **No findings + coverage ≥ 2 providers** | `ALLOW` | Safe to install |
| **No findings + coverage < 2 providers** | `WARN` | Insufficient coverage warning |

### Severity Mapping

Findings from all providers are normalized to these severity levels:

| Level | Examples |
|-------|----------|
| `critical` | Remote code execution, credential theft |
| `high` | Privilege escalation, data exposure |
| `medium` | Denial of service, information disclosure |
| `low` | Minor issues, best-practice violations |
| `unknown` | Severity not specified by provider |

## Scoring Algorithm

```python
def score(providers):
    coverage = count(provider for provider in providers if provider.status == "ok")
    counts = {critical: 0, high: 0, medium: 0, low: 0, unknown: 0}
    malicious_count = 0
    
    for provider in providers:
        for finding in provider.findings:
            counts[finding.severity] += 1
            if finding.id == "vt-malicious":
                malicious_count += 1
    
    # Decision logic
    if malicious_count > 0 or counts.critical > 0:
        return "BLOCK"
    elif counts.high > 0 or counts.medium > 0:
        return "WARN"
    elif no_findings and coverage >= 2:
        return "ALLOW"
    else:
        return "WARN"  # Insufficient coverage
```

## Coverage Concept

**Coverage** = number of providers that successfully returned results.

- Coverage = 4: All providers responded → highest confidence
- Coverage = 3: One provider failed → still high confidence
- Coverage = 2: Two providers responded → minimum for ALLOW
- Coverage < 2: Insufficient data → WARN even if no findings

This ensures we don't falsely ALLOW a package just because providers are down.

## Caching Strategy

Scan results are cached to avoid redundant API calls:

- **Cache key**: `{schema_version}::{manager}::{package}::{version}::{hash}::{provider_fingerprint}`
- **TTL**: 600 seconds (configurable via `SECURITY_CACHE_TTL_SECONDS`)
- **Provider fingerprint**: Encodes which credentials are configured, so cache invalidates if auth changes

## Report Generation

Every scan generates two report formats:

1. **JSON report** (`security_reports/{package}_{timestamp}.json`)
   - Machine-readable
   - Contains full provider responses
   - Suitable for CI/CD integration

2. **Markdown report** (`security_reports/{package}_{timestamp}.md`)
   - Human-readable summary
   - Decision explanation
   - Finding details in tables

## Integration with Package Managers

The scanner integrates with `install` and `upgrade` commands:

```
unified install <package> -m <manager>
         │
         ├── Download package artifact
         │
         ├── Calculate SHA-256 hash
         │
         ├── Query all 4 security providers
         │
         ├── Aggregate findings → Decision
         │
         ├── Write report to security_reports/
         │
         └── If BLOCK → abort, else proceed with install
```

## Why Multi-Provider?

Single-provider solutions have blind spots:

1. **OSV.dev alone**: May miss VirusTotal malware detections
2. **VirusTotal alone**: Only detects file-based threats, not CVEs
3. **GitHub Advisory alone**: Limited to GitHub-indexed packages
4. **OSS Index alone**: Requires authentication, may be unavailable

By combining all four, we achieve:
- **Higher recall**: More vulnerabilities detected
- **Redundancy**: Graceful degradation if one provider fails
- **Cross-validation**: Multiple sources agreeing increases confidence

## Metrics

The following metrics measure scanner effectiveness:

| Metric | Definition | Target |
|--------|------------|--------|
| **Precision** | TP / (TP + FP) | >75% |
| **Recall** | TP / (TP + FN) | >80% |
| **F1 Score** | Harmonic mean of P and R | >75% |
| **Coverage** | Providers responding / 4 | >75% |
| **Latency (cold)** | Time to first scan | <30s |
| **Latency (warm)** | Time with cache hit | <2s |

See `experiments/RESULTS.md` for measured values.
