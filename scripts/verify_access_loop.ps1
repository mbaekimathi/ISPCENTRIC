# Run subscription-access correction loops on Windows (local).
# Usage:
#   .\scripts\verify_access_loop.ps1 7
#   .\scripts\verify_access_loop.ps1 7 -Loops 8 -Settle 3
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [int]$Customer,
    [int]$Loops = 5,
    [double]$Settle = 2.0,
    [switch]$SkipUnitTests
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

$Python = if (Test-Path "$Root\.venv\Scripts\python.exe") {
    "$Root\.venv\Scripts\python.exe"
} else {
    "python"
}

if (-not $SkipUnitTests) {
    Write-Host "==> Unit correction-loop tests"
    & $Python manage.py test `
        core.tests.AccessFlowCorrectionLoopTests `
        core.tests.ExpiredCaptivePayTests `
        core.tests.IspHotspotInstantPayTests `
        --keepdb -v 1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host ""
Write-Host "==> Live verify loop for customer $Customer"
& $Python manage.py verify_subscription_access `
    --customer $Customer `
    --loops $Loops `
    --settle $Settle
exit $LASTEXITCODE
