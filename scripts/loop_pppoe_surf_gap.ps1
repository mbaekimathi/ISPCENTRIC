# Recurring PPPoE "billing OK but no internet" gap scanner (Windows).
# Usage:
#   .\scripts\loop_pppoe_surf_gap.ps1
#   .\scripts\loop_pppoe_surf_gap.ps1 -IntervalSec 300
param(
    [int]$IntervalSec = 300
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

$Python = if (Test-Path "$Root\.venv\Scripts\python.exe") {
    "$Root\.venv\Scripts\python.exe"
} else {
    "python"
}

$LogDir = Join-Path $Root "logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$Log = Join-Path $LogDir "pppoe_surf_gap_loop.log"

Write-Host "PPPoE surf-gap loop every ${IntervalSec}s -> $Log"
Write-Host "Stop with Ctrl+C or kill this process."

while ($true) {
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $header = "`n===== TICK $stamp =====`n"
    [System.IO.File]::AppendAllText($Log, $header, [System.Text.UTF8Encoding]::new($false))
    $out = & $Python "$Root\tmp\diagnose_pppoe_surf_gap.py" 2>&1 | Out-String
    $code = $LASTEXITCODE
    [System.IO.File]::AppendAllText($Log, $out, [System.Text.UTF8Encoding]::new($false))
    # Sentinel for Cursor agent wake (do not change format)
    Write-Output ("AGENT_LOOP_TICK_pppoe_surf_gap {""prompt"":""Read logs/pppoe_surf_gap_loop.log tail and summarize PPPoE billing-OK surf gaps; if gaps persist for customer with cpe_renew_pending or no_ppp_session, suggest next fix."",""exit"":" + $code + ",""at"":""" + $stamp + """}")
    Start-Sleep -Seconds $IntervalSec
}
