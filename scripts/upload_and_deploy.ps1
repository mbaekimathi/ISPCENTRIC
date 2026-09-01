# Upload production .env and trigger VPS first-boot deploy.
# Usage (from project root):
#   .\scripts\upload_and_deploy.ps1
#   .\scripts\upload_and_deploy.ps1 -Host isp.richcom.co.ke -User root
param(
    [string]$Host = "isp.richcom.co.ke",
    [string]$User = "root",
    [string]$EnvFile = "deploy\env.isp.richcom.co.ke",
    [string]$RemoteRoot = "/opt/ispcentric"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

if (-not (Test-Path $EnvFile)) {
    Write-Error "Missing $EnvFile — run deploy prep first or copy deploy/env.isp.richcom.co.ke.example"
}

Write-Host "==> Uploading $EnvFile to ${User}@${Host}:${RemoteRoot}/.env"
scp $EnvFile "${User}@${Host}:${RemoteRoot}/.env"

Write-Host "==> Running first-boot / deploy on VPS"
ssh "${User}@${Host}" @"
set -e
chmod 600 ${RemoteRoot}/.env
chown www-data:www-data ${RemoteRoot}/.env
cd ${RemoteRoot}
if [ -f scripts/vps_first_boot.sh ]; then
  bash scripts/vps_first_boot.sh
else
  sudo -u www-data bash scripts/vps_deploy.sh
  systemctl restart ispcentric
fi
"@

Write-Host "==> Done. Open http://${Host}/"
