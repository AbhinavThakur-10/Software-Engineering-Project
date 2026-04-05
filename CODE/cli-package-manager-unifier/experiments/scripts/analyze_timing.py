"""
analyze_timing.py — Track 1: Installation Overhead Analysis

Reads the raw per-repetition CSV produced by run_timing.ps1, computes summary
statistics, and writes two output files:

    experiments/data/processed/timing_summary_<timestamp>.csv   — per-package metrics table
    experiments/data/processed/timing_report_<timestamp>.txt    — human-readable report

Usage
-----
    # Auto-detect latest timing_raw_*.csv in experiments/data/raw/
    python experiments/scripts/analyze_timing.py

    # Specify a file explicitly
    python experiments/scripts/analyze_timing.py experiments/data/raw/timing_raw_20260405_120000.csv

Metrics computed
----------------
    native_median_s          Median of 5 native-install reps
    unified_no_sec_median_s  Median of 5 unified --no-security reps
    scan_cold_median_s       Median of 5 cold-cache scan reps
    scan_warm_median_s       Median of 5 warm-cache scan reps

    manager_overhead_s       unified_no_sec - native  (CLI dispatch cost)
    manager_overhead_pct     manager_overhead / native × 100
    scan_overhead_s          scan_cold_median  (pure scanning cost over native)
    total_cold_overhead_s    manager_overhead + scan_cold  (worst-case overhead)
    total_cold_overhead_pct  total_cold_overhead / native × 100
    cache_speedup_s          scan_cold - scan_warm
    cache_speedup_pct        (scan_cold - scan_warm) / scan_cold × 100
"""

from __future__ import annotations

import csv
import glob
import math
import os
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ── Path resolution ───────────────────────────────────────────────────────────
SCRIPT_DIR      = Path(__file__).parent
EXPERIMENTS_DIR = SCRIPT_DIR.parent
PROJECT_DIR     = EXPERIMENTS_DIR.parent
RAW_DIR         = EXPERIMENTS_DIR / "data" / "raw"
OUT_DIR         = EXPERIMENTS_DIR / "data" / "processed"

CONDITIONS = ["native", "unified_no_sec", "scan_cold", "scan_warm"]


# ── Utilities ─────────────────────────────────────────────────────────────────

def median(values: list[float]) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def pct(numerator: float, denominator: float) -> float:
    if math.isnan(denominator) or denominator == 0:
        return float("nan")
    return round(numerator / denominator * 100, 1)


def fmt(value: float, decimals: int = 3) -> str:
    if math.isnan(value):
        return "n/a"
    return f"{value:.{decimals}f}"


# ── CSV loading ───────────────────────────────────────────────────────────────

def find_latest_raw_csv() -> Path:
    pattern = str(RAW_DIR / "timing_raw_*.csv")
    files   = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError(
            f"No timing_raw_*.csv found in {RAW_DIR}.\n"
            "Run experiments/scripts/run_timing.ps1 first."
        )
    return Path(files[-1])


def load_raw(csv_path: Path) -> dict[tuple[str, str], dict[str, list[float]]]:
    """Return {(package, manager): {condition: [times]}}."""
    data: dict[tuple[str, str], dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    with open(csv_path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            key  = (row["package"].strip(), row["manager"].strip())
            cond = row["condition"].strip()
            try:
                t = float(row["time_s"])
            except ValueError:
                continue
            data[key][cond].append(t)
    return data


# ── Metrics computation ───────────────────────────────────────────────────────

def compute_metrics(data: dict[tuple[str, str], dict[str, list[float]]]) -> list[dict]:
    rows = []
    for (pkg, mgr), cond_times in sorted(data.items()):
        native_med   = median(cond_times.get("native", []))
        nosec_med    = median(cond_times.get("unified_no_sec", []))
        cold_med     = median(cond_times.get("scan_cold", []))
        warm_med     = median(cond_times.get("scan_warm", []))

        mgr_overhead_s   = nosec_med - native_med
        scan_overhead_s  = cold_med
        total_cold_s     = mgr_overhead_s + cold_med
        cache_speedup_s  = cold_med - warm_med

        rows.append({
            "package":                  pkg,
            "manager":                  mgr,
            "native_median_s":          round(native_med,  3),
            "unified_no_sec_median_s":  round(nosec_med,   3),
            "scan_cold_median_s":       round(cold_med,    3),
            "scan_warm_median_s":       round(warm_med,    3),
            "manager_overhead_s":       round(mgr_overhead_s, 3),
            "manager_overhead_pct":     pct(mgr_overhead_s, native_med),
            "scan_overhead_s":          round(scan_overhead_s, 3),
            "total_cold_overhead_s":    round(total_cold_s, 3),
            "total_cold_overhead_pct":  pct(total_cold_s, native_med),
            "cache_speedup_s":          round(cache_speedup_s, 3),
            "cache_speedup_pct":        pct(cache_speedup_s, cold_med),
            # Raw rep counts for reference
            "reps_native":              len(cond_times.get("native", [])),
            "reps_unified_no_sec":      len(cond_times.get("unified_no_sec", [])),
            "reps_scan_cold":           len(cond_times.get("scan_cold", [])),
            "reps_scan_warm":           len(cond_times.get("scan_warm", [])),
        })
    return rows


# ── Summary CSV ───────────────────────────────────────────────────────────────

SUMMARY_FIELDS = [
    "package", "manager",
    "native_median_s", "unified_no_sec_median_s",
    "scan_cold_median_s", "scan_warm_median_s",
    "manager_overhead_s", "manager_overhead_pct",
    "scan_overhead_s",
    "total_cold_overhead_s", "total_cold_overhead_pct",
    "cache_speedup_s", "cache_speedup_pct",
    "reps_native", "reps_unified_no_sec", "reps_scan_cold", "reps_scan_warm",
]


def write_summary_csv(rows: list[dict], out_path: Path) -> None:
    with open(out_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


# ── Human-readable report ─────────────────────────────────────────────────────

def _col(text: str, width: int) -> str:
    return str(text).ljust(width)


def write_text_report(rows: list[dict], raw_path: Path, out_path: Path) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 72,
        "  Track 1: Installation Overhead — Timing Report",
        f"  Generated : {now}",
        f"  Source    : {raw_path.name}",
        "=" * 72,
        "",
        "Conditions",
        "----------",
        "  native          Raw npm/pip install (pure baseline)",
        "  unified_no_sec  Unified CLI install, --no-security flag (dispatch + DB only)",
        "  scan_cold       Security scan only — cold cache (upgrade, declined)",
        "  scan_warm       Security scan only — warm cache (upgrade, declined)",
        "",
        "All times are MEDIANS in seconds.",
        "",
    ]

    # ── Table 1: raw medians ──────────────────────────────────────────────────
    lines += [
        "Table 1 — Raw Medians (seconds)",
        "-" * 72,
        f"{'Package':<14} {'Mgr':<6} {'native':>8} {'no_sec':>8} {'cold':>8} {'warm':>8}",
        "-" * 72,
    ]
    for r in rows:
        lines.append(
            f"{r['package']:<14} {r['manager']:<6}"
            f" {fmt(r['native_median_s']):>8}"
            f" {fmt(r['unified_no_sec_median_s']):>8}"
            f" {fmt(r['scan_cold_median_s']):>8}"
            f" {fmt(r['scan_warm_median_s']):>8}"
        )

    # ── Table 2: overhead breakdown ───────────────────────────────────────────
    lines += [
        "",
        "Table 2 — Overhead Breakdown",
        "-" * 72,
        f"{'Package':<14} {'Mgr':<6} {'mgr_ovhd_s':>12} {'mgr_ovhd_%':>12} {'scan_ovhd_s':>12} {'total_cold_s':>13} {'total_cold_%':>13}",
        "-" * 72,
    ]
    for r in rows:
        lines.append(
            f"{r['package']:<14} {r['manager']:<6}"
            f" {fmt(r['manager_overhead_s']):>12}"
            f" {fmt(r['manager_overhead_pct'], 1):>12}"
            f" {fmt(r['scan_overhead_s']):>12}"
            f" {fmt(r['total_cold_overhead_s']):>13}"
            f" {fmt(r['total_cold_overhead_pct'], 1):>13}"
        )

    # ── Table 3: cache speedup ────────────────────────────────────────────────
    lines += [
        "",
        "Table 3 — Cache Speedup",
        "-" * 72,
        f"{'Package':<14} {'Mgr':<6} {'cold_s':>8} {'warm_s':>8} {'saved_s':>8} {'speedup_%':>10}",
        "-" * 72,
    ]
    for r in rows:
        lines.append(
            f"{r['package']:<14} {r['manager']:<6}"
            f" {fmt(r['scan_cold_median_s']):>8}"
            f" {fmt(r['scan_warm_median_s']):>8}"
            f" {fmt(r['cache_speedup_s']):>8}"
            f" {fmt(r['cache_speedup_pct'], 1):>10}"
        )

    # ── Aggregates ────────────────────────────────────────────────────────────
    valid_native  = [r["native_median_s"]         for r in rows if not math.isnan(r["native_median_s"])]
    valid_cold    = [r["scan_cold_median_s"]       for r in rows if not math.isnan(r["scan_cold_median_s"])]
    valid_warm    = [r["scan_warm_median_s"]       for r in rows if not math.isnan(r["scan_warm_median_s"])]
    valid_pct     = [r["total_cold_overhead_pct"]  for r in rows if not math.isnan(r["total_cold_overhead_pct"])]
    valid_speedup = [r["cache_speedup_pct"]        for r in rows if not math.isnan(r["cache_speedup_pct"])]

    mean = lambda lst: sum(lst) / len(lst) if lst else float("nan")

    lines += [
        "",
        "Aggregates (mean across all packages)",
        "-" * 72,
        f"  Mean native install time       : {fmt(mean(valid_native))} s",
        f"  Mean cold scan time            : {fmt(mean(valid_cold))} s",
        f"  Mean warm scan time            : {fmt(mean(valid_warm))} s",
        f"  Mean total overhead (cold, %)  : {fmt(mean(valid_pct), 1)} %",
        f"  Mean cache speedup             : {fmt(mean(valid_speedup), 1)} %",
        "",
        "=" * 72,
    ]

    report = "\n".join(lines)
    out_path.write_text(report, encoding="utf-8")
    print(report)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    # Resolve input CSV
    if len(sys.argv) > 1:
        raw_path = Path(sys.argv[1])
    else:
        raw_path = find_latest_raw_csv()

    if not raw_path.exists():
        print(f"[error] File not found: {raw_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[analyze] Reading: {raw_path}")
    data = load_raw(raw_path)

    if not data:
        print("[error] No valid rows found in CSV.", file=sys.stderr)
        sys.exit(1)

    rows = compute_metrics(data)

    # Build timestamped output names based on the raw file's stem
    stem = raw_path.stem.replace("timing_raw", "timing")
    summary_csv  = OUT_DIR / f"{stem}_summary.csv"
    report_txt   = OUT_DIR / f"{stem}_report.txt"

    write_summary_csv(rows, summary_csv)
    print(f"[analyze] Summary CSV  : {summary_csv}")

    write_text_report(rows, raw_path, report_txt)
    print(f"[analyze] Text report  : {report_txt}")


if __name__ == "__main__":
    main()
