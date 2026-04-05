<#
.SYNOPSIS
    Track 1: Installation Overhead Timing Experiment

.DESCRIPTION
    Measures 4 conditions per package to quantify security-scan overhead:

        native          Raw package-manager install (npm / pip) — pure baseline
        unified_no_sec  Unified CLI install with --no-security flag (manager dispatch + DB, no scan)
        scan_cold       Security scan only via 'upgrade' (cache cleared each rep, press n to skip install)
        scan_warm       Security scan only via 'upgrade' (cache warm from prior run, press n to skip install)

    Native and unified_no_sec install into temp directories to avoid polluting the project.
    Scan conditions do NOT install anything — they decline the upgrade prompt.

    Outputs: experiments/timing_raw_<timestamp>.csv

.PARAMETER Reps
    Number of repetitions per condition (default: 5). Median is computed by analyze_timing.py.

.PARAMETER OutDir
    Directory for output CSV (default: experiments/).

.EXAMPLE
    # From cli-package-manager-unifier/
    pwsh -File experiments/run_timing.ps1
    pwsh -File experiments/run_timing.ps1 -Reps 3
#>

param(
    [int]$Reps    = 5,
    [string]$OutDir = "experiments/data/raw"
)

$ErrorActionPreference = "Stop"

# ── Resolve project root (grandparent of scripts/ → experiments/ → project) ──
$scriptDir      = Split-Path -Parent $MyInvocation.MyCommand.Path
$experimentsDir = Split-Path -Parent $scriptDir
$projectDir     = Split-Path -Parent $experimentsDir
Set-Location $projectDir

# ── Python interpreter ────────────────────────────────────────────────────────
$_pyCmd = Get-Command python -ErrorAction SilentlyContinue
$candidates = @(
    "e:\SE STUFF\Software-Engineering-Project\CODE\.venv\Scripts\python.exe",
    "e:\SE STUFF\Software-Engineering-Project\CODE\venv\Scripts\python.exe",
    $(if ($_pyCmd) { $_pyCmd.Source } else { $null })
) | Where-Object { $_ -and (Test-Path $_) }
if (-not $candidates) { throw "No Python interpreter found. Set \$python manually." }
$python = $candidates[0]
Write-Host "[setup] Using Python: $python"

# ── Packages under test ───────────────────────────────────────────────────────
# Lightweight packages — chosen to minimise download variance.
$targets = @(
    @{ package = "react";    manager = "npm"  },
    @{ package = "express";  manager = "npm"  },
    @{ package = "requests"; manager = "pip3" },
    @{ package = "click";    manager = "pip3" }
)

# ── Temp directories for install conditions ───────────────────────────────────
$npmTempDir = Join-Path $env:TEMP "unified_timing_npm"
$pipTempDir = Join-Path $env:TEMP "unified_timing_pip"

function Prepare-NpmTemp {
    New-Item -ItemType Directory -Force -Path $npmTempDir | Out-Null
    $pkgJson = Join-Path $npmTempDir "package.json"
    if (-not (Test-Path $pkgJson)) {
        '{"name":"timing-test","version":"1.0.0","private":true}' | Set-Content $pkgJson
    }
}

function Cleanup-NpmTemp {
    $nm = Join-Path $npmTempDir "node_modules"
    if (Test-Path $nm) { Remove-Item $nm -Recurse -Force -ErrorAction SilentlyContinue }
    $lock = Join-Path $npmTempDir "package-lock.json"
    if (Test-Path $lock) { Remove-Item $lock -Force -ErrorAction SilentlyContinue }
    # Reset package.json (remove installed deps)
    '{"name":"timing-test","version":"1.0.0","private":true}' | Set-Content (Join-Path $npmTempDir "package.json")
}

function Cleanup-PipTemp {
    if (Test-Path $pipTempDir) { Remove-Item $pipTempDir -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Force -Path $pipTempDir | Out-Null
}

# ── CSV output ────────────────────────────────────────────────────────────────
$timestamp = (Get-Date -Format "yyyyMMdd_HHmmss")
$csvPath   = Join-Path $OutDir "timing_raw_$timestamp.csv"

# Ensure output dir exists
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

"package,manager,condition,rep,time_s" | Set-Content $csvPath
Write-Host "[setup] Writing results to: $csvPath`n"

# ── Helper: append a row ──────────────────────────────────────────────────────
function Append-Row($pkg, $mgr, $condition, $rep, $timeSec) {
    $rounded = [math]::Round($timeSec, 4)
    "$pkg,$mgr,$condition,$rep,$rounded" | Add-Content $csvPath
    Write-Host ("  [{0}] rep {1}/{2}: {3:F3}s" -f $condition, $rep, $Reps, $timeSec)
}

# ── Pre-flight: verify Python module resolves ─────────────────────────────────
Write-Host "[setup] Verifying unified CLI..."
& $python -c "import src.cli" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Cannot import src.cli. Run from cli-package-manager-unifier/ and ensure the package is installed (pip install -e .)."
}
Write-Host "[setup] OK`n"

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────
foreach ($t in $targets) {
    $pkg = $t.package
    $mgr = $t.manager

    Write-Host ("=" * 60)
    Write-Host "Package: $pkg   Manager: $mgr"
    Write-Host ("=" * 60)

    # ── Condition 1: native ───────────────────────────────────────────────────
    Write-Host "`n[native] Raw $mgr install (no unified tool)"
    Prepare-NpmTemp

    for ($i = 1; $i -le $Reps; $i++) {
        if ($mgr -eq "npm") {
            Cleanup-NpmTemp
            $start = Get-Date
            npm install $pkg --prefix $npmTempDir --save 2>&1 | Out-Null
            $elapsed = ((Get-Date) - $start).TotalSeconds
        } else {
            Cleanup-PipTemp
            $start = Get-Date
            $ErrorActionPreference = "Continue"
            & $python -m pip install $pkg --target $pipTempDir --quiet 2>&1 | Out-Null
            $ErrorActionPreference = "Stop"
            $elapsed = ((Get-Date) - $start).TotalSeconds
        }
        Append-Row $pkg $mgr "native" $i $elapsed
    }

    # ── Condition 2: unified --no-security ────────────────────────────────────
    Write-Host "`n[unified_no_sec] Unified CLI install, security scan skipped"

    for ($i = 1; $i -le $Reps; $i++) {
        if ($mgr -eq "npm") {
            Cleanup-NpmTemp
            # Run unified from the npm temp dir so node_modules lands there,
            # but keep PYTHONPATH pointing at the project root so src.cli resolves.
            $env:PYTHONPATH = $projectDir
            Push-Location $npmTempDir
            $start = Get-Date
            @('n') | & $python -m src.cli install $pkg -m $mgr --no-security 2>&1 | Out-Null
            $elapsed = ((Get-Date) - $start).TotalSeconds
            Pop-Location
            Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
        } else {
            Cleanup-PipTemp
            $env:PIP_TARGET = $pipTempDir
            $start = Get-Date
            $ErrorActionPreference = "Continue"
            @('n') | & $python -m src.cli install $pkg -m $mgr --no-security 2>&1 | Out-Null
            $ErrorActionPreference = "Stop"
            $elapsed = ((Get-Date) - $start).TotalSeconds
            Remove-Item Env:PIP_TARGET -ErrorAction SilentlyContinue
        }
        Append-Row $pkg $mgr "unified_no_sec" $i $elapsed
    }

    # ── Condition 3: scan cold ────────────────────────────────────────────────
    # Uses 'upgrade --show-findings' which runs the full security pipeline.
    # Input 'n' declines the actual upgrade — nothing is installed.
    Write-Host "`n[scan_cold] Security scan, cold cache (cache cleared before each rep)"

    $ErrorActionPreference = "Continue"
    for ($i = 1; $i -le $Reps; $i++) {
        Remove-Item ".security_scan_cache.json" -ErrorAction SilentlyContinue
        $start = Get-Date
        @('n', 'n') | & $python -m src.cli upgrade $pkg -m $mgr --show-findings 1 2>&1 | Out-Null
        $elapsed = ((Get-Date) - $start).TotalSeconds
        Append-Row $pkg $mgr "scan_cold" $i $elapsed
    }
    $ErrorActionPreference = "Stop"

    # ── Condition 4: scan warm ────────────────────────────────────────────────
    # Prime the cache with one run, then measure 5 warm hits.
    Write-Host "`n[scan_warm] Security scan, warm cache (cache populated)"
    Remove-Item ".security_scan_cache.json" -ErrorAction SilentlyContinue
    Write-Host "  [priming cache...]"
    $ErrorActionPreference = "Continue"
    @('n', 'n') | & $python -m src.cli upgrade $pkg -m $mgr --show-findings 1 2>&1 | Out-Null

    for ($i = 1; $i -le $Reps; $i++) {
        $start = Get-Date
        @('n', 'n') | & $python -m src.cli upgrade $pkg -m $mgr --show-findings 1 2>&1 | Out-Null
        $elapsed = ((Get-Date) - $start).TotalSeconds
        Append-Row $pkg $mgr "scan_warm" $i $elapsed
    }
    $ErrorActionPreference = "Stop"

    Write-Host ""
}

# ── Cleanup temp dirs ─────────────────────────────────────────────────────────
Write-Host "[cleanup] Removing temp install directories..."
if (Test-Path $npmTempDir) { Remove-Item $npmTempDir -Recurse -Force -ErrorAction SilentlyContinue }
if (Test-Path $pipTempDir) { Remove-Item $pipTempDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "[done] Raw results saved to: $csvPath"
Write-Host "[next] Run:  python experiments/scripts/analyze_timing.py $csvPath"
