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

echo "==> Installing requirements"
"$PYTHON_BIN" -m pip install --upgrade pip
"$PYTHON_BIN" -m pip install -r requirements.txt

echo "==> Checking configuration"
"$PYTHON_BIN" manage.py check --deploy || true

echo "==> Migrating database"
"$PYTHON_BIN" manage.py migrate --noinput

echo "==> Collecting static files"
"$PYTHON_BIN" manage.py collectstatic --noinput

# gunicorn runs as www-data and needs to write these.
mkdir -p logs media .cache

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
