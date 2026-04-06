<#
.SYNOPSIS
    Track 2: Security Detection Experiment

.DESCRIPTION
    Scans every package in experiments/ground_truth.json through the full
    security pipeline (all 4 providers) WITHOUT actually installing anything.

    For each package the script:
      1. Clears the scan cache (fresh result per package)
      2. Runs:  python -m src.cli upgrade <pkg> -m <mgr> --show-findings 5
         and inputs 'n' twice to decline the upgrade prompt
      3. Reads the generated JSON security report from security_reports/
      4. Appends one row to experiments/security_raw_<timestamp>.csv

    Output columns:
        package, manager, version, test_type, ground_truth_vulnerable,
        decision, predicted_positive,
        coverage, from_cache,
        osv_status, github_status, oss_index_status, virustotal_status,
        critical, high, medium, low,
        runtime_s, report_file

.NOTES
    Run from cli-package-manager-unifier/.
    Requires: pip install -e . (or python -m src.cli importable)

.EXAMPLE
    pwsh -File experiments/run_security_detection.ps1
#>

$ErrorActionPreference = "Continue"

# ── Paths ─────────────────────────────────────────────────────────────────────
$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
Set-Location $projectDir

$groundTruthPath = Join-Path $scriptDir "ground_truth.json"
$outDir          = $scriptDir
$timestamp       = (Get-Date -Format "yyyyMMdd_HHmmss")
$csvPath         = Join-Path $outDir "security_raw_$timestamp.csv"

# ── Python interpreter ────────────────────────────────────────────────────────
$pyCmd = Get-Command python -ErrorAction SilentlyContinue
$candidates = @(
    "e:\SE STUFF\Software-Engineering-Project\CODE\.venv\Scripts\python.exe",
    "e:\SE STUFF\Software-Engineering-Project\CODE\venv\Scripts\python.exe",
    $(if ($pyCmd) { $pyCmd.Source } else { $null })
) | Where-Object { $_ -and (Test-Path $_) }
if (-not $candidates) { throw "No Python interpreter found." }
$python = $candidates[0]
Write-Host "[setup] Python  : $python"
Write-Host "[setup] Output  : $csvPath"
Write-Host "[setup] GT file : $groundTruthPath`n"

# ── Load ground truth ─────────────────────────────────────────────────────────
if (-not (Test-Path $groundTruthPath)) {
    throw "ground_truth.json not found at: $groundTruthPath"
}
$gt = Get-Content $groundTruthPath -Raw | ConvertFrom-Json

# ── CSV header ────────────────────────────────────────────────────────────────
$header = "package,manager,version,test_type,ground_truth_vulnerable," +
          "decision,predicted_positive," +
          "coverage,from_cache," +
          "osv_status,github_status,oss_index_status,virustotal_status," +
          "critical,high,medium,low," +
          "runtime_s,report_file"
$header | Set-Content $csvPath

# ── Verify CLI importable ─────────────────────────────────────────────────────
Write-Host "[setup] Verifying unified CLI..."
& $python -c "import src.cli" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Cannot import src.cli. Ensure you are in cli-package-manager-unifier/ and ran: pip install -e ."
}
Write-Host "[setup] OK`n"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Get-ProviderStatus($providers, $key) {
    $p = $providers.$key
    if ($null -eq $p) { return "missing" }
    return $p.status
}

function Get-Count($counts, $key) {
    $v = $counts.$key
    if ($null -eq $v) { return 0 }
    return [int]$v
}

# ── Main scan loop ────────────────────────────────────────────────────────────
$total   = $gt.packages.Count
$current = 0

foreach ($pkg in $gt.packages) {
    $current++
    $name    = $pkg.name
    $mgr     = $pkg.manager
    $ver     = if ($pkg.version) { $pkg.version } else { "latest" }
    $gtVuln  = [int]$pkg.ground_truth_vulnerable
    $testType = if ($pkg.test_type) { $pkg.test_type } else { "unknown" }

    Write-Host ("-" * 60)
    Write-Host ("[$current/$total] $name ($mgr, $testType, gt=$gtVuln)")
    Write-Host ("-" * 60)

    # Clear cache for a fresh scan
    Remove-Item ".security_scan_cache.json" -ErrorAction SilentlyContinue

    # Build versioned package specifier so the scanner checks the pinned vulnerable version
    if ($ver -ne "latest") {
        $pkgSpec = if ($mgr -eq "pip3") { "${name}==${ver}" } else { "${name}@${ver}" }
    } else {
        $pkgSpec = $name
    }

    # Timestamp before scan
    $scanStart = Get-Date

    # Run install with --no-security skipped (security ON), decline install prompt
    @('n') | & $python -m src.cli install $pkgSpec -m $mgr --show-findings 5 2>&1 | Tee-Object -Variable cliOutput | Out-Host

    $runtimeSec = [math]::Round(((Get-Date) - $scanStart).TotalSeconds, 3)

    # Find the newest install_<name>*.json report (name may include @version suffix in slug)
    $pattern = "install_{0}*.json" -f $name
    $report  = Get-ChildItem ".\security_reports\$pattern" -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending |
               Select-Object -First 1

    if ($null -eq $report) {
        Write-Warning "  No security report found for $name. Writing partial row."
        "$name,$mgr,$ver,$testType,$gtVuln,error,0,0,false,error,error,error,error,0,0,0,0,$runtimeSec,NOT_FOUND" |
            Add-Content $csvPath
        continue
    }

    $data = Get-Content $report.FullName -Raw | ConvertFrom-Json
    $sec  = $data.security

    $decision   = $sec.decision
    $predicted  = if ($decision -in @("warn","block")) { 1 } else { 0 }
    $coverage   = [int]$sec.coverage
    $fromCache  = if ($sec.from_cache) { "true" } else { "false" }
    $providers  = $sec.providers
    $counts     = $sec.counts

    $osvStatus  = Get-ProviderStatus $providers "osv"
    $ghStatus   = Get-ProviderStatus $providers "github_advisory"
    $ossStatus  = Get-ProviderStatus $providers "oss_index"
    $vtStatus   = Get-ProviderStatus $providers "virustotal"

    $critical = Get-Count $counts "critical"
    $high     = Get-Count $counts "high"
    $medium   = Get-Count $counts "medium"
    $low      = Get-Count $counts "low"

    $row = "$name,$mgr,$ver,$testType,$gtVuln," +
           "$decision,$predicted," +
           "$coverage,$fromCache," +
           "$osvStatus,$ghStatus,$ossStatus,$vtStatus," +
           "$critical,$high,$medium,$low," +
           "$runtimeSec,$($report.Name)"

    $row | Add-Content $csvPath
    Write-Host "  decision=$decision  coverage=$coverage  predicted=$predicted  runtime=${runtimeSec}s`n"
}

Write-Host ("=" * 60)
Write-Host "[done] Raw results saved to: $csvPath"
Write-Host "[next] Run:  python experiments/analyze_security.py $csvPath"
