"""
Plotting script for poster results.

Reads benchmark_data.json and generates two clean poster-ready figures:

  poster_chart1_effectiveness.png  — Detection heatmap: old vs new version
  poster_chart2_performance.png    — Cold scan vs cached scan bar chart

Run from cli-package-manager-unifier/:
    python plot_results.py
"""
from __future__ import annotations

import json
import os
from typing import Any
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import LinearSegmentedColormap
import numpy as np

DATA_FILE = os.path.join(os.path.dirname(__file__), "benchmark_data.json")
OUT_DIR   = os.path.dirname(__file__)

PROVIDERS       = ["osv", "github_advisory", "oss_index", "virustotal"]
PROVIDER_LABELS = ["OSV.dev", "GitHub Advisory", "OSS Index", "VirusTotal"]

DECISION_COLOR = {"block": "#D32F2F", "warn": "#F57C00", "allow": "#388E3C", "error": "#9E9E9E", "unknown": "#9E9E9E"}
DECISION_LABEL = {"block": "BLOCK", "warn": "WARN", "allow": "ALLOW", "error": "ERROR"}


# ---------------------------------------------------------------------------
# Chart 1 — Detection Heatmap  (old version vs new version)
# ---------------------------------------------------------------------------

def chart_effectiveness(data: list) -> None:
    """
    A side-by-side heatmap.

    Left panel  — Old (vulnerable) version: cells show detected / not-detected per provider
    Right panel — New (patched) version: same layout

    Rows   = packages (lodash, minimist, …)
    Cols   = providers (OSV, GitHub Advisory, OSS Index, VirusTotal)

    Cell:  red   = threat detected
           light = not detected
    Decision badge appended on right side.
    """
    n_pkg  = len(data)
    n_prov = len(PROVIDERS)

    # Build detection matrices and per-provider count matrices
    old_matrix = np.zeros((n_pkg, n_prov))
    new_matrix = np.zeros((n_pkg, n_prov))
    old_counts = np.zeros((n_pkg, n_prov), dtype=int)
    new_counts = np.zeros((n_pkg, n_prov), dtype=int)
    for i, row in enumerate(data):
        for j, prov in enumerate(PROVIDERS):
            old_matrix[i, j] = 1.0 if row[f"old_{prov}"] else 0.0
            new_matrix[i, j] = 1.0 if row[f"new_{prov}"] else 0.0
            old_counts[i, j] = row.get(f"old_{prov}_count", 0)
            new_counts[i, j] = row.get(f"new_{prov}_count", 0)

    pkg_labels     = [r["display"] for r in data]
    old_ver_labels = [f"v{r['old_version']}" for r in data]
    new_ver_labels = [f"v{r['new_version']}" for r in data]
    old_decisions  = [r["old_decision"] for r in data]
    new_decisions  = [r["new_decision"]  for r in data]
    old_findings   = [r["old_findings"]  for r in data]
    new_findings   = [r["new_findings"]  for r in data]

    # Wrap long provider labels so they fit without crowding
    PROVIDER_LABELS_WRAPPED = ["OSV.dev", "GitHub\nAdvisory", "OSS\nIndex", "VirusTotal"]

    # Colormaps: light grey → red (old) / light grey → green (new)
    cmap_old = LinearSegmentedColormap.from_list("old", ["#EEEEEE", "#C62828"])
    cmap_new = LinearSegmentedColormap.from_list("new", ["#EEEEEE", "#2E7D32"])

    BG = "#FFFFFF"
    PANEL_BG = "#FFFFFF"
    ROW_ALT  = "#F5F5F5"

    fig, (ax_old, ax_new) = plt.subplots(
        1, 2, figsize=(17, 6.5),
        gridspec_kw={"wspace": 0.62},
    )
    fig.patch.set_facecolor(BG)

    def _draw_panel(ax, matrix, counts, decisions, findings, ver_labels, cmap, title, is_old):
        accent = "#EF5350" if is_old else "#66BB6A"

        ax.set_facecolor(PANEL_BG)

        # Alternating row shading drawn before imshow
        for r in range(n_pkg):
            if r % 2 == 1:
                ax.axhspan(r - 0.5, r + 0.5, color=ROW_ALT, zorder=0)

        im = ax.imshow(matrix, cmap=cmap, vmin=0, vmax=1, aspect="auto",
                       alpha=0.92, zorder=1)

        # Cell borders
        ax.set_xticks(np.arange(-0.5, n_prov, 1), minor=True)
        ax.set_yticks(np.arange(-0.5, n_pkg,  1), minor=True)
        ax.grid(which="minor", color=BG, linewidth=2.5, zorder=2)
        ax.tick_params(which="minor", length=0)

        # ── Column headers ──────────────────────────────────────────────────
        ax.set_xticks(np.arange(n_prov))
        ax.set_xticklabels(
            PROVIDER_LABELS_WRAPPED,
            fontsize=9, fontweight="bold",
            color="#333333",
            rotation=0, ha="center", linespacing=1.3,
        )
        ax.xaxis.set_tick_params(pad=6, length=0)

        # ── Row labels (package + version) ──────────────────────────────────
        ax.set_yticks(np.arange(n_pkg))
        y_labels = [f"{pkg}  {ver}" for pkg, ver in zip(pkg_labels, ver_labels)]
        ax.set_yticklabels(y_labels, fontsize=10, fontweight="bold", color="#222222")
        ax.yaxis.set_tick_params(pad=8, length=0)

        # ── Cell values ─────────────────────────────────────────────────────
        for i in range(n_pkg):
            for j in range(n_prov):
                detected = matrix[i, j] > 0
                count    = counts[i, j]
                symbol   = str(count) if detected else "–"
                txt_color = "white" if detected else "#AAAAAA"
                ax.text(j, i, symbol, ha="center", va="center",
                        fontsize=14, fontweight="bold", color=txt_color, zorder=3)

        # ── Decision badges (right spine) ───────────────────────────────────
        ax2 = ax.twinx()
        ax2.set_ylim(ax.get_ylim())
        ax2.set_yticks([])
        ax2.tick_params(length=0)
        ax2.set_facecolor(PANEL_BG)

        for i, (decision, nf) in enumerate(zip(decisions, findings)):
            bc = DECISION_COLOR.get(decision, "#9E9E9E")
            label = DECISION_LABEL.get(decision, decision.upper())
            ax2.text(
                1.03, i, f"{label}  {nf}",
                transform=ax2.get_yaxis_transform(),
                ha="left", va="center",
                fontsize=9, fontweight="bold",
                color="white",
                bbox=dict(
                    boxstyle="round,pad=0.35",
                    fc=bc, ec="none",
                ),
            )

        # ── Panel title ─────────────────────────────────────────────────────
        ax.set_title(
            title,
            fontsize=12, fontweight="bold",
            color=accent, pad=14,
            loc="center",
        )

        # ── Spines ──────────────────────────────────────────────────────────
        for spine in ax.spines.values():
            spine.set_visible(False)
        for spine in ax2.spines.values():
            spine.set_visible(False)

        # Coloured bottom border under the panel title
        ax.axhline(-0.5, color=accent, linewidth=2.5, zorder=4)

    _draw_panel(
        ax_old, old_matrix, old_counts, old_decisions, old_findings,
        old_ver_labels, cmap_old,
        "Vulnerable Versions  (old)", is_old=True,
    )
    _draw_panel(
        ax_new, new_matrix, new_counts, new_decisions, new_findings,
        new_ver_labels, cmap_new,
        "Patched Versions  (latest)", is_old=False,
    )

    # ── Legend ──────────────────────────────────────────────────────────────
    legend_handles = [
        mpatches.Patch(color="#C62828", label="Threat detected"),
        mpatches.Patch(color="#2E7D32", label="Clean / patched"),
        mpatches.Patch(color="#555577", label="Not detected"),
        mpatches.Patch(color=DECISION_COLOR["block"], label="Decision: BLOCK"),
        mpatches.Patch(color=DECISION_COLOR["warn"],  label="Decision: WARN"),
        mpatches.Patch(color=DECISION_COLOR["allow"], label="Decision: ALLOW"),
    ]
    leg = fig.legend(
        handles=legend_handles,
        loc="lower center", ncol=6,
        bbox_to_anchor=(0.5, -0.06),
        fontsize=9.5, frameon=True,
        facecolor="#FFFFFF", edgecolor="#CCCCCC",
        labelcolor="#333333",
        handlelength=1.4, handleheight=0.9,
        columnspacing=1.4,
    )

    # ── Main title ──────────────────────────────────────────────────────────
    fig.suptitle(
        "Security Effectiveness: Same Package — Vulnerable Version vs Patched Version",
        fontsize=14, fontweight="bold",
        color="#111111", y=1.03,
    )

    out = os.path.join(OUT_DIR, "poster_chart1_effectiveness.png")
    plt.savefig(out, dpi=180, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"Saved {out}")


# ---------------------------------------------------------------------------
# Chart 2 — Performance bar chart
# ---------------------------------------------------------------------------

def chart_performance(data: list) -> None:
    """
    Horizontal grouped bar chart.

    For each package: two bars
      - Cold scan  (first scan, no cache) — blue
      - Warm scan  (repeat scan, cached)  — green

    A vertical dashed line shows the average cold scan time.
    An annotation box shows avg cold / avg warm / speedup.
    """
    labels     = [r["display"] for r in data]
    cold_times = [r["cold_scan_sec"] for r in data]
    warm_times = [r["warm_scan_sec"] for r in data]

    n      = len(labels)
    y      = np.arange(n)
    height = 0.32

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#FAFAFA")
    ax.set_facecolor("#FAFAFA")

    bars_cold = ax.barh(
        y + height / 2, cold_times, height,
        label="First scan (no cache)",
        color="#1565C0", alpha=0.85, edgecolor="white", linewidth=0.8,
    )
    bars_warm = ax.barh(
        y - height / 2, warm_times, height,
        label="Cached scan",
        color="#2E7D32", alpha=0.85, edgecolor="white", linewidth=0.8,
    )

    # Value labels on bars
    max_cold = max(cold_times)
    for bar, val in zip(bars_cold, cold_times):
        ax.text(
            val + max_cold * 0.01,
            bar.get_y() + bar.get_height() / 2,
            f"{val:.2f}s",
            va="center", ha="left", fontsize=9, color="#1565C0", fontweight="bold",
        )
    for bar, val in zip(bars_warm, warm_times):
        label = f"{val:.3f}s" if val >= 0.001 else f"{val*1000:.1f}ms"
        ax.text(
            val + max_cold * 0.01,
            bar.get_y() + bar.get_height() / 2,
            label,
            va="center", ha="left", fontsize=9, color="#2E7D32", fontweight="bold",
        )

    # Average cold time line
    avg_cold = sum(cold_times) / n
    avg_warm = sum(warm_times) / n
    speedup  = avg_cold / avg_warm if avg_warm > 0 else 0

    ax.axvline(avg_cold, color="#1565C0", linestyle="--", linewidth=1.2, alpha=0.5)
    ax.text(
        avg_cold + max_cold * 0.01, n / 2,
        f"avg first scan\n{avg_cold:.2f}s",
        fontsize=8, color="#1565C0", alpha=0.8, va="center",
    )

    # Axes
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=11, fontweight="bold")
    ax.set_xlabel("Time (seconds)", fontsize=11)
    ax.set_xlim(0, max_cold * 1.25)
    ax.set_title(
        "Scan Overhead: First Scan vs Cached Scan",
        fontsize=13, fontweight="bold", pad=12,
    )

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="x", linestyle="--", alpha=0.35, color="#BDBDBD")

    # Stats box
    stats = (
        f"Avg first scan  : {avg_cold:.2f}s\n"
        f"Avg cached scan : {avg_warm:.3f}s\n"
        f"Cache speedup   : {speedup:.0f}×"
    )
    ax.text(
        0.98, 0.04, stats,
        transform=ax.transAxes, fontsize=10,
        va="bottom", ha="right",
        bbox=dict(boxstyle="round,pad=0.5", fc="white", ec="#BDBDBD", linewidth=1),
    )

    ax.legend(loc="upper right", fontsize=10, frameon=False)
    plt.tight_layout()

    out = os.path.join(OUT_DIR, "poster_chart2_performance.png")
    plt.savefig(out, dpi=180, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"Saved {out}")


# ---------------------------------------------------------------------------
# Chart 3 — Traditional vs Unified install time (stacked bar)
# ---------------------------------------------------------------------------

def chart_install_comparison(data: list[Any]) -> None:
    """
    Horizontal stacked bar chart.

    For each package one stacked bar:
      - Blue segment  : traditional install time (bare package manager)
      - Orange segment: security scan overhead added by unified

    A vertical dashed line marks the average traditional install time.
    """
    labels       = [r["display"] for r in data]
    trad_times   = [r["traditional_sec"] for r in data]
    overhead     = [r["scan_overhead_sec"] for r in data]
    unified      = [r["unified_sec"] for r in data]

    n = len(labels)
    y = np.arange(n)
    height = 0.45

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#FAFAFA")
    ax.set_facecolor("#FAFAFA")

    bars_trad = ax.barh(
        y, trad_times, height,
        label="Traditional install",
        color="#1565C0", alpha=0.85, edgecolor="white", linewidth=0.8,
    )
    bars_over = ax.barh(
        y, overhead, height, left=trad_times,
        label="Security scan overhead",
        color="#E65100", alpha=0.85, edgecolor="white", linewidth=0.8,
    )

    # Value labels: traditional on the blue segment, total at the end
    max_unified = max(unified)
    for i, (t, u) in enumerate(zip(trad_times, unified)):
        # Label inside the blue segment
        ax.text(
            t / 2, y[i],
            f"{t:.2f}s",
            va="center", ha="center", fontsize=8.5,
            color="white", fontweight="bold",
        )
        # Total label past the end of the bar
        ax.text(
            u + max_unified * 0.01, y[i],
            f"{u:.2f}s total",
            va="center", ha="left", fontsize=9,
            color="#E65100", fontweight="bold",
        )

    # Average traditional line
    avg_trad    = sum(trad_times) / n
    avg_unified = sum(unified) / n
    avg_overhead = sum(overhead) / n

    ax.axvline(avg_trad, color="#1565C0", linestyle="--", linewidth=1.2, alpha=0.5)
    ax.text(
        avg_trad + max_unified * 0.01, n / 2,
        f"avg traditional\n{avg_trad:.2f}s",
        fontsize=8, color="#1565C0", alpha=0.8, va="center",
    )

    # Axes
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=11, fontweight="bold")
    ax.set_xlabel("Time (seconds)", fontsize=11)
    ax.set_xlim(0, max_unified * 1.28)
    ax.set_title(
        "Install Time: Traditional vs Unified (with Security Scan)",
        fontsize=13, fontweight="bold", pad=12,
    )

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="x", linestyle="--", alpha=0.35, color="#BDBDBD")

    # Stats box
    stats = (
        f"Avg traditional : {avg_trad:.2f}s\n"
        f"Avg scan overhead: {avg_overhead:.2f}s\n"
        f"Avg unified total: {avg_unified:.2f}s"
    )
    ax.text(
        0.98, 0.04, stats,
        transform=ax.transAxes, fontsize=10,
        va="bottom", ha="right",
        bbox=dict(boxstyle="round,pad=0.5", fc="white", ec="#BDBDBD", linewidth=1),
    )

    ax.legend(loc="upper right", fontsize=10, frameon=False)
    plt.tight_layout()

    out = os.path.join(OUT_DIR, "poster_chart3_install_comparison.png")
    plt.savefig(out, dpi=180, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"Saved {out}")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(effectiveness: list, performance: list) -> None:
    print("\n--- Effectiveness Summary ---")
    for r in effectiveness:
        old_flag = r["old_decision"] in ("block", "warn")
        new_flag = r["new_decision"] in ("block", "warn")
        status = "CORRECT" if old_flag and not new_flag else ("PARTIAL" if old_flag else "MISSED")
        print(f"  {r['display']:12s}  old={r['old_decision']:5s}({r['old_findings']} findings)  "
              f"new={r['new_decision']:5s}({r['new_findings']} findings)  [{status}]")

    detected = sum(1 for r in effectiveness if r["old_decision"] in ("block", "warn"))
    false_pos = sum(1 for r in effectiveness if r["new_decision"] in ("block", "warn"))
    print(f"\n  Detection rate : {detected}/{len(effectiveness)} vulnerable versions flagged")
    print(f"  False positives: {false_pos}/{len(effectiveness)} patched versions flagged")

    avg_cold = sum(r["cold_scan_sec"] for r in performance) / len(performance)
    avg_warm = sum(r["warm_scan_sec"] for r in performance) / len(performance)
    print(f"\n--- Performance Summary ---")
    print(f"  Avg cold scan : {avg_cold:.2f}s")
    print(f"  Avg warm scan : {avg_warm:.3f}s")
    print(f"  Speedup       : {avg_cold / avg_warm:.0f}×")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if not os.path.isfile(DATA_FILE):
        print(f"ERROR: {DATA_FILE} not found. Run benchmark_results.py first.")
        sys.exit(1)

    with open(DATA_FILE, encoding="utf-8") as f:
        d = json.load(f)

    print("Generating Chart 1 — Effectiveness heatmap...")
    chart_effectiveness(d["effectiveness"])

    print("Generating Chart 2 — Performance bars...")
    chart_performance(d["performance"])

    print("Generating Chart 3 — Install comparison...")
    chart_install_comparison(d["install_comparison"])

    print_summary(d["effectiveness"], d["performance"])
    print("\nDone.")


if __name__ == "__main__":
    main()
