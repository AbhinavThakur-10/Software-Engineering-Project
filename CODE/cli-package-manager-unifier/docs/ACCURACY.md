# Accuracy & Decision Quality

This document explains how we measure the scanner's decision quality.

## Metrics Overview

| Metric | Definition | What it tells you |
|--------|------------|-------------------|
| **Precision** | TP / (TP + FP) | "When we warn/block, are we right?" |
| **Recall** | TP / (TP + FN) | "Do we catch all vulnerable packages?" |
| **F1 Score** | 2 × (P × R) / (P + R) | Balanced measure of P and R |
| **Coverage** | Providers responding / 4 | Data quality indicator |

## Confusion Matrix

For each package scan:

|  | Actually Vulnerable | Actually Safe |
|--|---------------------|---------------|
| **Predicted Vulnerable** (WARN/BLOCK) | True Positive (TP) | False Positive (FP) |
| **Predicted Safe** (ALLOW) | False Negative (FN) | True Negative (TN) |

### Mapping Decisions to Predictions

| Scanner Decision | Predicted |
|------------------|-----------|
| `BLOCK` | Vulnerable |
| `WARN` | Vulnerable |
| `ALLOW` | Safe |

## Target Metrics

| Metric | Target | Rationale |
|--------|--------|-----------|
| **Precision** | >75% | Minimize alert fatigue |
| **Recall** | >80% | Don't miss vulnerabilities |
| **F1 Score** | >75% | Balanced performance |
| **Coverage** | >75% (3/4 providers) | Ensure data quality |

## Why These Targets?

### Recall > Precision

In security scanning, **false negatives are worse than false positives**:
- False positive: User sees a warning for a safe package → inconvenience
- False negative: Vulnerable package installed → security breach

We target 80% recall to minimize missed vulnerabilities, accepting some false positives.

### F1 as Primary Metric

F1 score balances precision and recall. A high F1 means:
- We catch most vulnerabilities (high recall)
- We don't cry wolf too often (reasonable precision)

## Measuring Ground Truth

To calculate precision/recall, we need ground truth labels:

### Manual Labeling Process
1. Select test packages (e.g., `requests`, `flask`, `lodash`)
2. Research each package version:
   - Check NVD (nvd.nist.gov) for CVEs
   - Check Snyk vulnerability DB
   - Check npm/PyPI security advisories
3. Label: `ground_truth_vulnerable = 1` if any known vulnerability, else `0`

### Example Ground Truth
```json
{
  "requests": {"version": "2.31.0", "ground_truth_vulnerable": 0},
  "werkzeug": {"version": "2.2.2", "ground_truth_vulnerable": 1},
  "lodash": {"version": "4.17.21", "ground_truth_vulnerable": 1}
}
```

## Calculating Metrics

### From Experiment Results

Given a results table:

| Package | Decision | Ground Truth | Classification |
|---------|----------|--------------|----------------|
| requests | ALLOW | 0 | TN |
| werkzeug | WARN | 1 | TP |
| lodash | WARN | 1 | TP |
| flask | ALLOW | 0 | TN |
| express | ALLOW | 1 | FN |
| react | ALLOW | 0 | TN |

### Formulas

```
TP = 2, FP = 0, TN = 3, FN = 1

Precision = TP / (TP + FP) = 2 / 2 = 1.00 (100%)
Recall    = TP / (TP + FN) = 2 / 3 = 0.67 (67%)
F1        = 2 × (1.0 × 0.67) / (1.0 + 0.67) = 0.80 (80%)
```

## Ablation Studies

To measure each provider's contribution:

1. **Baseline**: Run with all 4 providers → F1_baseline
2. **Ablation-OSV**: Remove OSV → F1_no_osv
3. **Ablation-GitHub**: Remove GitHub → F1_no_github
4. **Ablation-OSS**: Remove OSS Index → F1_no_oss
5. **Ablation-VT**: Remove VirusTotal → F1_no_vt

**Provider impact** = F1_baseline - F1_without_provider

### Expected Results

| Provider Removed | Expected F1 Drop | Why |
|------------------|------------------|-----|
| OSV.dev | 10-15% | Broad CVE coverage |
| GitHub Advisory | 5-10% | Overlaps with OSV |
| OSS Index | 5-10% | Commercial intelligence |
| VirusTotal | 5-10% | Unique malware detection |

## Latency Metrics

| Metric | Definition | Target |
|--------|------------|--------|
| **Cold Latency** | First scan (no cache) | <30s |
| **Warm Latency** | Cached scan | <2s |
| **Cache Speedup** | (cold - warm) / cold | >90% |

### Measurement Protocol
```bash
# Cold run
rm .security_scan_cache.json
time unified upgrade requests -m pip3

# Warm run (immediately after)
time unified upgrade requests -m pip3
```

## Interpreting Results

### Good Results
- F1 > 75%: Scanner is effective
- Recall > Precision: Errs on side of caution (good for security)
- Provider ablation shows >5% drop: Each provider adds value

### Warning Signs
- Precision < 50%: Too many false positives → alert fatigue
- Recall < 70%: Missing too many vulnerabilities
- One provider has 0% impact: May be redundant

## Continuous Improvement

As new vulnerabilities are discovered:
1. Add to ground truth labels
2. Re-run experiments
3. Track F1 over time
4. Identify providers with degrading performance

See `experiments/EXPERIMENTS.md` for detailed protocol.
