# Experiments Protocol

## Goal

Evaluate the **decision quality** of multi-provider vulnerability aggregation by measuring:
1. **Precision/Recall/F1** — How accurate are BLOCK/WARN/ALLOW decisions?
2. **Provider Contribution** — How much does each provider improve F1?
3. **Latency** — Cold vs warm cache performance
4. **Robustness** — Behavior under degraded conditions

## Package Test Set

| Ecosystem | Package | Known Vulnerable? | Notes |
|-----------|---------|-------------------|-------|
| npm | react | No | Stable, well-maintained |
| npm | lodash | Yes | Historical prototype pollution CVEs |
| npm | express | No | Stable, well-maintained |
| pip3 | requests | No | Stable, well-maintained |
| pip3 | flask | No | Stable, well-maintained |
| pip3 | werkzeug | Yes | Historical debugger PIN CVEs |

## Pre-Experiment Setup

### 1. Set Environment Variables

**PowerShell:**
```powershell
$env:OSSINDEX_USERNAME="your_email@example.com"
$env:OSSINDEX_TOKEN="your_token"
$env:VIRUSTOTAL_API_KEY="your_api_key"
```

**Bash:**
```bash
export OSSINDEX_USERNAME="your_email@example.com"
export OSSINDEX_TOKEN="your_token"
export VIRUSTOTAL_API_KEY="your_api_key"
```

### 2. Verify Credentials
```powershell
Write-Output "OSS Index configured: $([bool]$env:OSSINDEX_USERNAME)"
Write-Output "VirusTotal configured: $([bool]$env:VIRUSTOTAL_API_KEY)"
```

### 3. Clear Cache
```powershell
Remove-Item .security_scan_cache.json -ErrorAction SilentlyContinue
```

---

## Experiment 1: Baseline (All Providers)

**Objective:** Measure decision quality with all 4 providers enabled.

### Protocol
```powershell
# Clear cache first
Remove-Item .security_scan_cache.json -ErrorAction SilentlyContinue

# Run scans
unified upgrade react -m npm --show-findings 1
unified upgrade lodash -m npm --show-findings 1
unified upgrade express -m npm --show-findings 1
unified upgrade requests -m pip3 --show-findings 1
unified upgrade flask -m pip3 --show-findings 1
unified upgrade werkzeug -m pip3 --show-findings 1
```

### Record in results.csv
For each package, record:
- `decision`: ALLOW/WARN/BLOCK
- `coverage`: Number of providers that responded
- `osv_status`, `github_status`, `oss_status`, `vt_status`: ok/error
- `critical`, `high`, `medium`, `low`: Finding counts
- `runtime_seconds`: Execution time
- `predicted_positive`: 1 if WARN/BLOCK, 0 if ALLOW

---

## Experiment 2: Ablation Studies

**Objective:** Measure F1 drop when each provider is removed.

### 2a. Ablation: Remove OSS Index
```powershell
# Unset OSS credentials
Remove-Item Env:OSSINDEX_USERNAME -ErrorAction SilentlyContinue
Remove-Item Env:OSSINDEX_TOKEN -ErrorAction SilentlyContinue
Remove-Item .security_scan_cache.json -ErrorAction SilentlyContinue

# Rerun all 6 packages
unified upgrade react -m npm --show-findings 1
# ... (all packages)
```

### 2b. Ablation: Remove VirusTotal
```powershell
Remove-Item Env:VIRUSTOTAL_API_KEY -ErrorAction SilentlyContinue
Remove-Item .security_scan_cache.json -ErrorAction SilentlyContinue
# Rerun all packages
```

### 2c. Ablation: Remove GitHub Token
```powershell
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
Remove-Item .security_scan_cache.json -ErrorAction SilentlyContinue
# Rerun all packages
```

### Analysis
Compare F1 scores:
- `F1_baseline` vs `F1_no_oss`
- `F1_baseline` vs `F1_no_vt`
- `F1_baseline` vs `F1_no_github`

Provider impact = F1_baseline - F1_without_provider

---

## Experiment 3: Latency (Cold vs Warm Cache)

**Objective:** Measure caching effectiveness.

### Protocol
For each package:

```powershell
# Cold run
Remove-Item .security_scan_cache.json -ErrorAction SilentlyContinue
$cold = Measure-Command { unified upgrade requests -m pip3 --show-findings 1 }

# Warm run (cache hit)
$warm = Measure-Command { unified upgrade requests -m pip3 --show-findings 1 }

Write-Output "Cold: $($cold.TotalSeconds)s, Warm: $($warm.TotalSeconds)s"
```

### Metrics
- Mean cold latency
- Mean warm latency
- Cache speedup = (cold - warm) / cold × 100%
- p95 latency (95th percentile)

---

## Experiment 4: Robustness

**Objective:** Verify graceful degradation when providers fail.

### Test Cases
1. **Missing OSS credentials**: Should still make decision with 3 providers
2. **Invalid VirusTotal key**: Should still make decision with 3 providers
3. **All credentials missing**: Should warn about insufficient coverage

### Expected Behavior
- Command completes (doesn't crash)
- Error messages shown for failed providers
- Coverage value reflects available providers
- Decision still made (WARN if coverage < 2)

---

## Ground Truth Labels

Create `experiments/ground_truth.json`:

```json
{
  "packages": [
    {"name": "react", "manager": "npm", "ground_truth_vulnerable": 0},
    {"name": "lodash", "manager": "npm", "ground_truth_vulnerable": 1},
    {"name": "express", "manager": "npm", "ground_truth_vulnerable": 0},
    {"name": "requests", "manager": "pip3", "ground_truth_vulnerable": 0},
    {"name": "flask", "manager": "pip3", "ground_truth_vulnerable": 0},
    {"name": "werkzeug", "manager": "pip3", "ground_truth_vulnerable": 1}
  ]
}
```

### Labeling Sources
- NVD (nvd.nist.gov)
- Snyk Vulnerability DB
- GitHub Security Advisories
- Package changelogs

---

## Metrics Calculation

### From results.csv

```
predicted_positive = 1 if decision in (WARN, BLOCK) else 0

TP = count where predicted_positive=1 AND ground_truth_vulnerable=1
FP = count where predicted_positive=1 AND ground_truth_vulnerable=0
TN = count where predicted_positive=0 AND ground_truth_vulnerable=0
FN = count where predicted_positive=0 AND ground_truth_vulnerable=1

Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
F1 = 2 × (Precision × Recall) / (Precision + Recall)
```

### Target Metrics

| Metric | Target |
|--------|--------|
| Precision | >75% |
| Recall | >80% |
| F1 | >75% |
| Coverage (avg) | >75% |
| Cold latency | <30s |
| Warm latency | <2s |
| Cache speedup | >90% |

---

## Results Documentation

After running experiments, create `RESULTS.md` with:

1. **Decision Quality Table**
   - Precision, Recall, F1 for baseline and each ablation

2. **Provider Contribution Chart**
   - Bar chart showing F1 drop per provider

3. **Latency Comparison**
   - Cold vs warm latency for each package
   - Mean and p95 values

4. **Robustness Summary**
   - Behavior under each degraded condition

---

## Quick Run Script

```powershell
# experiments/run_experiments.ps1

# Baseline
.\run_baseline.ps1

# Ablations
.\run_ablation_oss.ps1
.\run_ablation_vt.ps1
.\run_ablation_github.ps1

# Latency
.\run_latency.ps1

# Generate report
python analyze_results.py
```

---

## Track 1: Installation Overhead (Timing)

**Objective:** Quantify the real-world cost introduced by the security scan step
compared to calling the native package manager directly.

### Four Conditions

| Condition | What it measures |
|---|---|
| `native` | `npm install` / `pip install` directly — pure baseline, no unified tool |
| `unified_no_sec` | Unified CLI with `--no-security` — dispatch + DB write, no scan |
| `scan_cold` | Full security scan via `upgrade` (cache cleared before each rep) |
| `scan_warm` | Full security scan via `upgrade` (cache hit — steady-state overhead) |

Native and `unified_no_sec` install into throwaway temp directories (`$TEMP/unified_timing_*`).
`scan_cold` and `scan_warm` use the `upgrade` path and decline (`n`) the actual upgrade,
so nothing is installed — they measure only the scan pipeline.

### Protocol

Run from `cli-package-manager-unifier/`:

```powershell
# Default: 5 reps per condition
pwsh -File experiments/run_timing.ps1

# Custom rep count
pwsh -File experiments/run_timing.ps1 -Reps 3
```

Then analyse:

```powershell
# Auto-detects the latest timing_raw_*.csv
python experiments/analyze_timing.py

# Or point to a specific file
python experiments/analyze_timing.py experiments/timing_raw_20260405_120000.csv
```

### Package Test Set

| Package | Manager | Rationale |
|---|---|---|
| `react` | npm | Lightweight, stable, no security noise |
| `express` | npm | Lightweight, stable |
| `requests` | pip3 | Lightweight, stable |
| `click` | pip3 | Lightweight, stable |

Small packages are used deliberately to minimise network/disk variance so
timing differences reflect the scanner, not download time.

### Output Files

| File | Contents |
|---|---|
| `timing_raw_<ts>.csv` | One row per rep: `package, manager, condition, rep, time_s` |
| `timing_<ts>_summary.csv` | Per-package medians and derived metrics |
| `timing_<ts>_report.txt` | Formatted tables (also printed to console) |

### Metrics Computed

| Metric | Formula |
|---|---|
| `manager_overhead_s` | `unified_no_sec_median − native_median` |
| `manager_overhead_pct` | `manager_overhead / native × 100` |
| `scan_overhead_s` | `scan_cold_median` (pure scan cost) |
| `total_cold_overhead_s` | `manager_overhead + scan_cold_median` |
| `total_cold_overhead_pct` | `total_cold_overhead / native × 100` |
| `cache_speedup_s` | `scan_cold_median − scan_warm_median` |
| `cache_speedup_pct` | `(scan_cold − scan_warm) / scan_cold × 100` |

### Target Thresholds

| Metric | Target |
|---|---|
| Total cold overhead | < 30 s |
| Total warm overhead | < 3 s |
| Cache speedup | > 85 % |
| Manager dispatch overhead | < 5 % of native |
