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

echo
echo "==> Done. Now restart the service:"
echo "     sudo systemctl restart ispcentric"
echo "     sudo systemctl status ispcentric --no-pager"
