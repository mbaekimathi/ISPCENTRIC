# Partial recharge verification loop (Ctrl+C to stop)
$ErrorActionPreference = "Continue"
$IntervalSec = 120
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
Write-Host "Partial recharge loop every ${IntervalSec}s (customer 14)"
while ($true) {
    & ".\.venv\Scripts\python.exe" "tmp\verify_partial_recharge.py" 14
    $code = $LASTEXITCODE
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "AGENT_LOOP_TICK_partial_recharge exit=$code at=$ts"
    Start-Sleep -Seconds $IntervalSec
}
