#!/usr/bin/env bash
# Deploy/update ISPCENTRIC on an Ubuntu + nginx + gunicorn VPS.
# Run from the project root after `git pull`:
#   sudo -u www-data bash scripts/vps_deploy.sh
# then restart the service (needs root):
#   sudo systemctl restart ispcentric
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VENV="$ROOT/.venv"
if [[ ! -x "$VENV/bin/python" ]]; then
  echo "==> Creating virtualenv at $VENV"
  python3 -m venv "$VENV"
fi
PYTHON_BIN="$VENV/bin/python"

echo "==> Project: $ROOT"
echo "==> Python:  $PYTHON_BIN"

if [[ ! -f "$ROOT/.env" ]]; then
  echo "!! .env is missing. Copy .env.production.example to .env and fill it in."
  exit 1
fi

_env_val() {
  local key="$1"
  grep -E "^${key}=" "$ROOT/.env" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r' || true
}

HOSTED_VAL="$(_env_val DJANGO_HOSTED)"
if [[ ! "$HOSTED_VAL" =~ ^(1|true|yes|on|hosted|production|prod)$ ]]; then
  echo "!! DJANGO_HOSTED is not true in .env."
  echo "   Without it the app runs in local-dev mode: DEBUG on, LAN discovery, no tunnel dial."
  echo "   Add: DJANGO_HOSTED=true"
  exit 1
fi

PUBLIC_BASE="$(_env_val PUBLIC_BASE_URL)"
if [[ -z "$PUBLIC_BASE" || "$PUBLIC_BASE" =~ ^(auto|detect|lan|local)$ ]]; then
  echo "!! PUBLIC_BASE_URL must be set to your public site (e.g. http://isp.example.com)."
  exit 1
fi

WG_KEY="$(_env_val WIREGUARD_SERVER_PUBLIC_KEY)"
if [[ -z "$WG_KEY" ]]; then
  echo "!! WIREGUARD_SERVER_PUBLIC_KEY is empty."
  echo "   Run: $PYTHON_BIN manage.py wireguard_peer --server-keys"
  exit 1
fi

WG_SYNC="$(_env_val WIREGUARD_SYNC_COMMAND)"
if [[ -z "$WG_SYNC" ]]; then
  echo "!! WIREGUARD_SYNC_COMMAND is empty."
  echo "   Set: WIREGUARD_SYNC_COMMAND=sudo $ROOT/scripts/wireguard_apply_peer.sh"
  exit 1
fi

echo "==> Installing requirements"
"$PYTHON_BIN" -m pip install --upgrade pip
"$PYTHON_BIN" -m pip install -r requirements.txt

echo "==> Checking configuration"
"$PYTHON_BIN" manage.py check --deploy
"$PYTHON_BIN" manage.py check

echo "==> Migrating database"
"$PYTHON_BIN" manage.py migrate --noinput

echo "==> Collecting static files"
"$PYTHON_BIN" manage.py collectstatic --noinput

# gunicorn runs as www-data and needs to write these.
mkdir -p logs media .cache

echo "==> Ensuring deploy scripts are executable (Unix line endings)"
# Windows checkouts can leave CRLF shebangs; sudo then prints "command not found".
find "$ROOT/scripts" -maxdepth 1 -name '*.sh' -type f -print0 \
  | xargs -0 -r sed -i 's/\r$//'
chmod +x "$ROOT/scripts"/*.sh 2>/dev/null || true

echo "==> Syncing WireGuard peers to wg0"
set +e
"$PYTHON_BIN" manage.py wireguard_peer --sync-server 2>&1 | tee logs/wireguard_sync.log
WG_SYNC_RC=${PIPESTATUS[0]}
set -e
if [[ "$WG_SYNC_RC" -ne 0 ]]; then
  echo "!! WireGuard peer sync failed (see logs/wireguard_sync.log)."
  echo "   Ensure wg-quick@wg0 is enabled and sudoers allows wireguard_apply_peer.sh."
fi

echo "==> Pushing NAS config to active MikroTiks"
# Stamp so the app process also re-pushes after WireGuard comes up on restart.
mkdir -p logs
touch logs/.nas_config_sync_pending
# Routers keep old login.html / blocked profiles until this runs. Failures are
# logged but do not abort deploy — unreachable NAS boxes should not block a
# code release.
set +e
"$PYTHON_BIN" manage.py sync_nas_config 2>&1 | tee logs/nas_config_sync.log
NAS_SYNC_RC=${PIPESTATUS[0]}
set -e
if [[ "$NAS_SYNC_RC" -eq 0 ]]; then
  rm -f logs/.nas_config_sync_pending
else
  echo "!! NAS config sync reported errors (see logs/nas_config_sync.log)."
  echo "   App deploy continues; pending stamp kept for boot retry after restart."
  echo "   Or fix unreachable routers then re-run:"
  echo "     $PYTHON_BIN manage.py sync_nas_config"
fi

echo
echo "==> Done. Now restart the service:"
echo "     sudo systemctl restart ispcentric"
echo "     sudo systemctl status ispcentric --no-pager"
