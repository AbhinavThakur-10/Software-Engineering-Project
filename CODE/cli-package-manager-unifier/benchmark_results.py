"""
Benchmark script for poster results.

Tests the SAME package at two versions:
  - old_version : a known-vulnerable release
  - new_version : the latest patched release

This directly shows the scanner catches old threats and clears patched ones.

Run from cli-package-manager-unifier/:
    python benchmark_results.py
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

from src.utils.security_aggregator import SecurityAggregator
from src.utils.virustotal import get_virustotal_api_key

# ---------------------------------------------------------------------------
# Test corpus — same package, old (vulnerable) vs new (patched/clean)
#
# Vulnerability sources:
#   lodash    : CVE-2019-10744  prototype pollution           OSV GHSA-jf85-cpcp-j695
#   minimist  : CVE-2021-44906  prototype pollution           OSV GHSA-xvch-5gv4-984h
#   axios     : CVE-2020-28168  SSRF                          GitHub Advisory
#   pyyaml    : CVE-2020-1747   RCE via unsafe load           OSV GHSA-6757-jp84-gxfx
#   pillow    : CVE-2021-25287  heap buffer overflow          OSV GHSA-8vj2-vxx3-667w
#   urllib3   : CVE-2019-11324  cert-verification bypass      OSV GHSA-mh33-7rrq-662w
# ---------------------------------------------------------------------------
TEST_PACKAGES = [
    # (package,    manager, old_version, new_version,  display_name)
    ("lodash",   "npm",   "4.17.4",   "4.17.21",  "lodash"),
    ("minimist", "npm",   "0.0.8",    "1.2.8",    "minimist"),
    ("axios",    "npm",   "0.19.0",   "1.6.8",    "axios"),
    ("pyyaml",   "pip3",  "5.1",      "6.0.1",    "PyYAML"),
    ("pillow",   "pip3",  "7.1.0",    "10.3.0",   "Pillow"),
    ("urllib3",  "pip3",  "1.24.1",   "2.2.1",    "urllib3"),
]

PROVIDERS = ["osv", "github_advisory", "oss_index", "virustotal"]
CACHE_FILE = os.path.join(os.path.dirname(__file__), ".benchmark_scan_cache.json")


def _fresh_aggregator() -> SecurityAggregator:
    agg = SecurityAggregator(api_key=get_virustotal_api_key(), cache_ttl_seconds=600)
    agg.cache.cache_file = CACHE_FILE
    return agg


def _clear_cache() -> None:
    if os.path.isfile(CACHE_FILE):
        os.remove(CACHE_FILE)


def _provider_detected(result: dict, provider: str) -> bool:
    providers = result.get("providers", {})
    pdata = providers.get(provider, {})
    findings = pdata.get("findings", [])
    return isinstance(findings, list) and len(findings) > 0


def _provider_finding_count(result: dict, provider: str) -> int:
    providers = result.get("providers", {})
    pdata = providers.get(provider, {})
    findings = pdata.get("findings", [])
    return len(findings) if isinstance(findings, list) else 0


def _scan(agg: SecurityAggregator, name: str, manager: str, version: str) -> dict:
    try:
        return agg.analyze(name, manager, version, file_hash=None)
    except Exception as ex:
        return {"decision": "error", "providers": {}, "findings": [], "error": str(ex)}


def run_effectiveness_benchmark(agg: SecurityAggregator) -> list:
    """Scan each package at old and new version, record provider detections."""
    _clear_cache()
    rows = []
    for pkg, manager, old_ver, new_ver, display in TEST_PACKAGES:
        print(f"  {display}:")

        print(f"    old ({old_ver})...")
        old_result = _scan(agg, pkg, manager, old_ver)

        print(f"    new ({new_ver})...")
        new_result = _scan(agg, pkg, manager, new_ver)

        row = {
            "display": display,
            "manager": manager,
            "old_version": old_ver,
            "new_version": new_ver,
            # old version scan
            "old_decision": old_result.get("decision", "unknown"),
            "old_findings": len(old_result.get("findings", [])),
            "old_osv":             _provider_detected(old_result, "osv"),
            "old_github_advisory": _provider_detected(old_result, "github_advisory"),
            "old_oss_index":       _provider_detected(old_result, "oss_index"),
            "old_virustotal":      _provider_detected(old_result, "virustotal"),
            # old version finding counts per provider
            "old_osv_count":             _provider_finding_count(old_result, "osv"),
            "old_github_advisory_count": _provider_finding_count(old_result, "github_advisory"),
            "old_oss_index_count":       _provider_finding_count(old_result, "oss_index"),
            "old_virustotal_count":      _provider_finding_count(old_result, "virustotal"),
            # new version scan
            "new_decision": new_result.get("decision", "unknown"),
            "new_findings": len(new_result.get("findings", [])),
            "new_osv":             _provider_detected(new_result, "osv"),
            "new_github_advisory": _provider_detected(new_result, "github_advisory"),
            "new_oss_index":       _provider_detected(new_result, "oss_index"),
            "new_virustotal":      _provider_detected(new_result, "virustotal"),
            # new version finding counts per provider
            "new_osv_count":             _provider_finding_count(new_result, "osv"),
            "new_github_advisory_count": _provider_finding_count(new_result, "github_advisory"),
            "new_oss_index_count":       _provider_finding_count(new_result, "oss_index"),
            "new_virustotal_count":      _provider_finding_count(new_result, "virustotal"),
        }
        rows.append(row)
        print(f"      old -> decision={row['old_decision']}  findings={row['old_findings']}")
        print(f"      new -> decision={row['new_decision']}  findings={row['new_findings']}")
    return rows


def run_performance_benchmark(agg: SecurityAggregator) -> list:
    """Time cold scan (no cache) and warm scan (cached) for each package's old version."""
    rows = []
    for pkg, manager, old_ver, new_ver, display in TEST_PACKAGES:
        print(f"  Timing {display}@{old_ver}...")

        # Cold scan
        _clear_cache()
        t0 = time.perf_counter()
        _scan(agg, pkg, manager, old_ver)
        cold_sec = time.perf_counter() - t0

        # Warm scan (cache from previous call)
        t0 = time.perf_counter()
        _scan(agg, pkg, manager, old_ver)
        warm_sec = time.perf_counter() - t0

        # Baseline: time without security scan (just a dict lookup — no network)
        t0 = time.perf_counter()
        _ = {"package": pkg, "version": old_ver}
        nosec_sec = time.perf_counter() - t0

        row = {
            "display": display,
            "manager": manager,
            "version": old_ver,
            "cold_scan_sec": round(cold_sec, 3),
            "warm_scan_sec": round(warm_sec, 4),
            "nosec_sec": round(nosec_sec, 6),
        }
        rows.append(row)
        print(f"    cold={cold_sec:.3f}s  warm={warm_sec:.4f}s")
    return rows


def run_install_comparison_benchmark(agg: SecurityAggregator) -> list:
    """
    Compare total wall-clock time for:
      - Traditional install: bare package manager (dry-run, no security scan)
      - Unified install:     traditional time + cold security scan overhead
    """
    import subprocess
    import shutil

    rows = []
    for pkg, manager, old_ver, new_ver, display in TEST_PACKAGES:
        print(f"  Timing install comparison for {display}@{old_ver}...")

        # ---- Traditional: bare package manager dry-run ----
        if manager == "npm":
            cmd = ["npm", "install", f"{pkg}@{old_ver}", "--dry-run", "--no-audit"]
        else:  # pip3
            cmd = ["pip", "install", f"{pkg}=={old_ver}", "--dry-run", "--quiet"]

        exe = shutil.which(cmd[0])
        if exe:
            cmd[0] = exe  # use the full resolved path so Windows can find it
            t0 = time.perf_counter()
            subprocess.run(cmd, capture_output=True, timeout=60)
            traditional_sec = time.perf_counter() - t0
        else:
            traditional_sec = 0.0

        # ---- Unified: traditional time + cold security scan overhead ----
        _clear_cache()
        t0 = time.perf_counter()
        _scan(agg, pkg, manager, old_ver)
        scan_overhead_sec = time.perf_counter() - t0

        unified_sec = traditional_sec + scan_overhead_sec

        row = {
            "display": display,
            "manager": manager,
            "version": old_ver,
            "traditional_sec": round(traditional_sec, 3),
            "scan_overhead_sec": round(scan_overhead_sec, 3),
            "unified_sec": round(unified_sec, 3),
        }
        rows.append(row)
        print(f"    traditional={traditional_sec:.3f}s  scan_overhead={scan_overhead_sec:.3f}s  unified={unified_sec:.3f}s")
    return rows


def main() -> None:
    print("=" * 60)
    print("Supply-Chain Security Scanner - Poster Benchmark")
    print("Same package: old (vulnerable) vs new (patched)")
    print("=" * 60)

    agg = _fresh_aggregator()

    print("\n[1/3] Security Effectiveness (old vs new version)")
    print("-" * 40)
    effectiveness = run_effectiveness_benchmark(agg)

    print("\n[2/3] Performance (cold vs warm scan)")
    print("-" * 40)
    performance = run_performance_benchmark(agg)

    print("\n[3/3] Install comparison (traditional vs unified)")
    print("-" * 40)
    install_comparison = run_install_comparison_benchmark(agg)

    output = {
        "effectiveness": effectiveness,
        "performance": performance,
        "install_comparison": install_comparison,
    }

    out_path = os.path.join(os.path.dirname(__file__), "benchmark_data.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"\nResults saved to {out_path}")
    print("Run plot_results.py to generate the charts.")
    _clear_cache()


if __name__ == "__main__":
    main()
