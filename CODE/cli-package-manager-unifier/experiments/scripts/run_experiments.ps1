param(
    [string]$Mode = "baseline",   # baseline | ablation_no_oss | performance_cold | performance_warm
    [switch]$UseModuleEntrypoint = $true
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = "e:\SE STUFF\Software-Engineering-Project\CODE\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    throw "Python not found at $python"
}

$targets = @(
    @{ package = "react"; manager = "npm" },
    @{ package = "lodash"; manager = "npm" },
    @{ package = "express"; manager = "npm" },
    @{ package = "requests"; manager = "pip3" },
    @{ package = "flask"; manager = "pip3" },
    @{ package = "werkzeug"; manager = "pip3" }
)

if ($Mode -eq "ablation_no_oss") {
    Remove-Item Env:OSSINDEX_USERNAME -ErrorAction SilentlyContinue
    Remove-Item Env:OSSINDEX_TOKEN -ErrorAction SilentlyContinue
}

if ($Mode -eq "performance_cold") {
    Remove-Item ".security_scan_cache.json" -ErrorAction SilentlyContinue
}

foreach ($t in $targets) {
    $pkg = $t.package
    $mgr = $t.manager

    $start = Get-Date
    if ($UseModuleEntrypoint) {
        @('n','n') | & $python -m src.cli upgrade $pkg -m $mgr --show-findings 1 | Out-Host
    } else {
        @('n','n') | unified upgrade $pkg -m $mgr --show-findings 1 | Out-Host
    }
    $end = Get-Date
    $sec = [math]::Round(($end - $start).TotalSeconds, 2)

    $pattern = "upgrade_{0}_*.json" -f $pkg
    $report = Get-ChildItem ".\security_reports\$pattern" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($null -eq $report) {
        Write-Output "[$Mode] $pkg/$mgr => report not found, runtime=${sec}s"
        continue
    }

    $data = Get-Content $report.FullName -Raw | ConvertFrom-Json
    $decision = $data.security.decision
    $coverage = $data.security.coverage
    $oss = $data.security.providers.oss_index.status
    $cache = $data.security.from_cache

    Write-Output "[$Mode] $pkg/$mgr => decision=$decision coverage=$coverage oss_index=$oss from_cache=$cache runtime=${sec}s report=$($report.Name)"
}
