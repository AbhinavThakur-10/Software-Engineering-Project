"""
analyze_security.py — Track 2: Security Detection Analysis

Reads the raw per-package CSV produced by run_security_detection.ps1, computes
confusion-matrix metrics, per-provider contribution, and supply-chain-specific
detection rate, then writes:

    experiments/security_<ts>_summary.csv   — per-package scored rows
    experiments/security_<ts>_report.txt    — formatted report (also printed)

Usage
-----
    # Auto-detect latest security_raw_*.csv in experiments/
    python experiments/analyze_security.py

    # Point to a specific file
    python experiments/analyze_security.py experiments/security_raw_20260405_130000.csv
"""

from __future__ import annotations

import csv
import glob
import math
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

SCRIPT_DIR  = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
OUT_DIR     = SCRIPT_DIR

PROVIDERS = ["osv", "github", "oss_index", "virustotal"]


# ── I/O helpers ───────────────────────────────────────────────────────────────

def find_latest_raw_csv() -> Path:
    pattern = str(SCRIPT_DIR / "security_raw_*.csv")
    files   = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError(
            f"No security_raw_*.csv found in {SCRIPT_DIR}.\n"
            "Run experiments/run_security_detection.ps1 first."
        )
    return Path(files[-1])


def load_rows(csv_path: Path) -> list[dict]:
    with open(csv_path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# ── Metrics helpers ───────────────────────────────────────────────────────────

def safe_div(n: float, d: float) -> float:
    return n / d if d else float("nan")


def fmt(v: float, dec: int = 3) -> str:
    return "n/a" if math.isnan(v) else f"{v:.{dec}f}"


def pct(v: float) -> str:
    return "n/a" if math.isnan(v) else f"{v * 100:.1f}%"


# ── Core computation ──────────────────────────────────────────────────────────

def score_rows(rows: list[dict]) -> list[dict]:
    """Add tp/fp/tn/fn fields to each row (in-place copy)."""
    out = []
    for r in rows:
        gt   = int(r.get("ground_truth_vulnerable", 0))
        pred = int(r.get("predicted_positive", 0))
        tp = 1 if gt == 1 and pred == 1 else 0
        fp = 1 if gt == 0 and pred == 1 else 0
        tn = 1 if gt == 0 and pred == 0 else 0
        fn = 1 if gt == 1 and pred == 0 else 0
        out.append({**r, "tp": tp, "fp": fp, "tn": tn, "fn": fn})
    return out


def aggregate(rows: list[dict]) -> dict:
    tp = sum(int(r["tp"]) for r in rows)
    fp = sum(int(r["fp"]) for r in rows)
    tn = sum(int(r["tn"]) for r in rows)
    fn = sum(int(r["fn"]) for r in rows)

    precision = safe_div(tp, tp + fp)
    recall    = safe_div(tp, tp + fn)
    f1        = safe_div(2 * precision * recall, precision + recall) if not math.isnan(precision) and not math.isnan(recall) else float("nan")
    accuracy  = safe_div(tp + tn, tp + fp + tn + fn)

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall,
        "f1": f1, "accuracy": accuracy,
        "total": len(rows),
        "positives": tp + fn,
        "negatives": tn + fp,
    }


def supply_chain_metrics(rows: list[dict]) -> dict:
    sc = [r for r in rows if r.get("test_type") == "supply_chain"]
    if not sc:
        return {"count": 0, "detected": 0, "detection_rate": float("nan")}
    detected = sum(1 for r in sc if int(r["tp"]) == 1)
    return {
        "count": len(sc),
        "detected": detected,
        "detection_rate": safe_div(detected, len(sc)),
        "packages": [r["package"] for r in sc],
        "decisions": {r["package"]: r["decision"] for r in sc},
    }


def provider_coverage(rows: list[dict]) -> dict:
    """How often each provider returned status='ok'."""
    col_map = {
        "osv":        "osv_status",
        "github":     "github_status",
        "oss_index":  "oss_index_status",
        "virustotal": "virustotal_status",
    }
    result = {}
    total = len(rows)
    for name, col in col_map.items():
        ok = sum(1 for r in rows if r.get(col, "").strip().lower() == "ok")
        result[name] = {"ok": ok, "total": total, "rate": safe_div(ok, total)}
    return result


def provider_contribution(rows: list[dict]) -> dict:
    """
    For each provider: among TP rows, how many had this provider with status='ok'?
    Indicates how much each provider contributes to correct detections.
    """
    col_map = {
        "osv":        "osv_status",
        "github":     "github_status",
        "oss_index":  "oss_index_status",
        "virustotal": "virustotal_status",
    }
    tp_rows = [r for r in rows if int(r.get("tp", 0)) == 1]
    result  = {}
    for name, col in col_map.items():
        contrib = sum(1 for r in tp_rows if r.get(col, "").strip().lower() == "ok")
        result[name] = {
            "contributed_to_tp": contrib,
            "tp_total": len(tp_rows),
            "rate": safe_div(contrib, len(tp_rows)),
        }
    return result


# ── CSV output ────────────────────────────────────────────────────────────────

SUMMARY_FIELDS = [
    "package", "manager", "version", "test_type",
    "ground_truth_vulnerable", "decision", "predicted_positive",
    "tp", "fp", "tn", "fn",
    "coverage", "from_cache",
    "osv_status", "github_status", "oss_index_status", "virustotal_status",
    "critical", "high", "medium", "low",
    "runtime_s", "report_file",
]


def write_summary_csv(rows: list[dict], out_path: Path) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=SUMMARY_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ── Text report ───────────────────────────────────────────────────────────────

def write_text_report(
    scored_rows: list[dict],
    agg: dict,
    sc: dict,
    cov: dict,
    contrib: dict,
    raw_path: Path,
    out_path: Path,
) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 72,
        "  Track 2: Security Detection — Results Report",
        f"  Generated : {now}",
        f"  Source    : {raw_path.name}",
        "=" * 72,
        "",
    ]

    # ── Table 1: Per-package decisions ───────────────────────────────────────
    lines += [
        "Table 1 — Per-Package Decisions",
        "-" * 72,
        f"{'Package':<16} {'Mgr':<6} {'Type':<14} {'GT':>3} {'Decision':<8} {'Pred':>5} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}",
        "-" * 72,
    ]
    for r in scored_rows:
        gt   = r.get("ground_truth_vulnerable", "?")
        pred = r.get("predicted_positive", "?")
        dec  = r.get("decision", "?")
        tp, fp, tn, fn = r["tp"], r["fp"], r["tn"], r["fn"]
        lines.append(
            f"{r['package']:<16} {r['manager']:<6} {r.get('test_type','?'):<14}"
            f" {gt:>3} {dec:<8} {pred:>5} {tp:>3} {fp:>3} {tn:>3} {fn:>3}"
        )

    # ── Table 2: Confusion matrix + core metrics ──────────────────────────────
    lines += [
        "",
        "Table 2 — Confusion Matrix & Core Metrics",
        "-" * 72,
        f"  Total packages tested : {agg['total']}",
        f"  True Positives  (TP)  : {agg['tp']}   (vulnerable, correctly flagged)",
        f"  False Positives (FP)  : {agg['fp']}   (clean, incorrectly flagged)",
        f"  True Negatives  (TN)  : {agg['tn']}   (clean, correctly passed)",
        f"  False Negatives (FN)  : {agg['fn']}   (vulnerable, missed)",
        "",
        f"  Precision  : {pct(agg['precision'])}   (of flagged, how many were truly vulnerable)",
        f"  Recall     : {pct(agg['recall'])}   (of vulnerable, how many were caught)",
        f"  F1 Score   : {pct(agg['f1'])}",
        f"  Accuracy   : {pct(agg['accuracy'])}",
    ]

    # ── Table 3: Supply-chain detection ──────────────────────────────────────
    lines += [
        "",
        "Table 3 — Supply-Chain Attack Detection",
        "-" * 72,
    ]
    if sc["count"] == 0:
        lines.append("  No supply-chain packages in test set.")
    else:
        lines += [
            f"  Packages tested  : {sc['count']}  ({', '.join(sc['packages'])})",
            f"  Detected (WARN/BLOCK) : {sc['detected']}",
            f"  Detection rate   : {pct(sc['detection_rate'])}",
            "",
        ]
        for p, dec in sc["decisions"].items():
            marker = "[DETECTED]" if dec in ("warn", "block") else "[MISSED]  "
            lines.append(f"    {marker}  {p}  =>  {dec.upper()}")

    # ── Table 4: Provider coverage ────────────────────────────────────────────
    lines += [
        "",
        "Table 4 — Provider Coverage (status=ok across all scans)",
        "-" * 72,
        f"  {'Provider':<16} {'OK runs':>8}  {'Total':>6}  {'Rate':>8}",
        "  " + "-" * 44,
    ]
    for name, v in cov.items():
        lines.append(f"  {name:<16} {v['ok']:>8}  {v['total']:>6}  {pct(v['rate']):>8}")

    # ── Table 5: Provider contribution to detections ─────────────────────────
    lines += [
        "",
        "Table 5 — Provider Contribution to True Positives",
        "-" * 72,
        f"  {'Provider':<16} {'Contributed':>12}  {'TP total':>9}  {'Rate':>8}",
        "  " + "-" * 50,
    ]
    for name, v in contrib.items():
        lines.append(
            f"  {name:<16} {v['contributed_to_tp']:>12}  {v['tp_total']:>9}  {pct(v['rate']):>8}"
        )

    # ── Target thresholds ────────────────────────────────────────────────────
    lines += [
        "",
        "Target Thresholds",
        "-" * 72,
        f"  Precision  > 75%  : {'PASS' if not math.isnan(agg['precision']) and agg['precision'] > 0.75 else 'FAIL / n/a'}",
        f"  Recall     > 80%  : {'PASS' if not math.isnan(agg['recall']) and agg['recall'] > 0.80 else 'FAIL / n/a'}",
        f"  F1         > 75%  : {'PASS' if not math.isnan(agg['f1']) and agg['f1'] > 0.75 else 'FAIL / n/a'}",
        f"  SC detect  > 80%  : {'PASS' if not math.isnan(sc['detection_rate']) and sc['detection_rate'] > 0.80 else 'FAIL / n/a' if sc['count'] > 0 else 'n/a (no SC packages)'}",
        "",
        "=" * 72,
    ]

    report = "\n".join(lines)
    out_path.write_text(report, encoding="utf-8")
    print(report)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) > 1:
        raw_path = Path(sys.argv[1])
    else:
        raw_path = find_latest_raw_csv()

    if not raw_path.exists():
        print(f"[error] File not found: {raw_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[analyze] Reading: {raw_path}")
    rows        = load_rows(raw_path)
    scored_rows = score_rows(rows)
    agg         = aggregate(scored_rows)
    sc          = supply_chain_metrics(scored_rows)
    cov         = provider_coverage(scored_rows)
    contrib     = provider_contribution(scored_rows)

    stem        = raw_path.stem.replace("security_raw", "security")
    summary_csv = OUT_DIR / f"{stem}_summary.csv"
    report_txt  = OUT_DIR / f"{stem}_report.txt"

    write_summary_csv(scored_rows, summary_csv)
    print(f"[analyze] Summary CSV : {summary_csv}")

    write_text_report(scored_rows, agg, sc, cov, contrib, raw_path, report_txt)
    print(f"[analyze] Text report : {report_txt}")


if __name__ == "__main__":
    main()
