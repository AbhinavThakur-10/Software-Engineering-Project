# Experiments Protocol (Demo 2)

## 1) Goal
Evaluate decision quality, provider contribution, latency, and robustness of the security scan workflow.

## 2) Package Set (fixed)
- npm: react, lodash, express
- pip3: requests, flask, werkzeug

Keep this exact set for all runs to ensure fairness.

## 3) Pre-check
In the same terminal you will run commands:

```powershell
$env:OSSINDEX_USERNAME="<your_username>"
$env:OSSINDEX_TOKEN="<your_token>"
```

Optional credential checks:

```powershell
Write-Output ("OSSINDEX_USERNAME missing: " + [string]::IsNullOrWhiteSpace($env:OSSINDEX_USERNAME))
Write-Output ("OSSINDEX_TOKEN missing: " + [string]::IsNullOrWhiteSpace($env:OSSINDEX_TOKEN))
```

## 4) Experiment A — Baseline (all providers enabled)
Run each command once and capture outputs in `security_reports`:

```powershell
unified upgrade react -m npm --show-findings 1
unified upgrade lodash -m npm --show-findings 1
unified upgrade express -m npm --show-findings 1
unified upgrade requests -m pip3 --show-findings 1
unified upgrade flask -m pip3 --show-findings 1
unified upgrade werkzeug -m pip3 --show-findings 1
```

Record in `results_template.csv`:
- provider statuses
- coverage
- decision
- severity counts
- runtime (seconds)

## 5) Experiment B — Ablation (without OSS Index)
Unset OSS variables, clear cache, rerun same package list:

```powershell
Remove-Item Env:OSSINDEX_USERNAME -ErrorAction SilentlyContinue
Remove-Item Env:OSSINDEX_TOKEN -ErrorAction SilentlyContinue
Remove-Item .security_scan_cache.json -ErrorAction SilentlyContinue
```

Rerun all 6 commands and compare:
- decision changes
- coverage drop
- findings count differences

## 6) Experiment C — Performance (cold vs warm cache)
For each package, do:
1. Cold run: clear `.security_scan_cache.json`, run command, measure time.
2. Warm run: run same command immediately again, measure time.

Store both runtimes. Compute mean and p95 cold/warm.

## 7) Experiment D — Robustness
Demonstrate behavior under missing provider credentials:
- missing OSS credentials
- (optional) VT key invalid/missing if you test env-key mode

Expected: command still returns a decision, provider error is visible, coverage adjusts.

## 8) Predicted Positive Mapping
Use this mapping for confusion matrix columns:
- `predicted_positive = 1` if decision is `warn` or `block`
- `predicted_positive = 0` if decision is `allow`

## 9) Ground Truth Labels
For each package run, set `ground_truth_vulnerable` manually from known advisories (0/1).

## 10) Metrics
Compute TP/FP/TN/FN per row and aggregate with formulas in `metrics_formulas.md`.

## 11) Demo Slide Outputs
Prepare 3 result visuals:
1. Decision Quality (precision/recall/F1)
2. Ablation Table (with/without provider)
3. Cold vs Warm latency chart
