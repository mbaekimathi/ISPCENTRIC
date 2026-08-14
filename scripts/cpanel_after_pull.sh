#!/usr/bin/env bash
# Run on cPanel after: git pull
# Usage (from project root):
#   bash scripts/cpanel_after_pull.sh
# Or with explicit python:
#   bash scripts/cpanel_after_pull.sh /home/USER/virtualenv/ispcentric/3.11/bin/python

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${1:-}"

if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
    PYTHON_BIN="${VIRTUAL_ENV}/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  else
    PYTHON_BIN="$(command -v python)"
  fi
fi

echo "==> Project: $ROOT"
echo "==> Python:  $PYTHON_BIN"

echo "==> Installing requirements"
"$PYTHON_BIN" -m pip install -r requirements.txt

echo "==> Migrating database"
"$PYTHON_BIN" manage.py migrate --noinput

echo "==> Collecting static files"
"$PYTHON_BIN" manage.py collectstatic --noinput

echo "==> Ensuring deploy scripts are executable (Unix line endings)"
find "$ROOT/scripts" -maxdepth 1 -name '*.sh' -type f -print0 \
  | xargs -0 -r sed -i 's/\r$//'
chmod +x "$ROOT/scripts"/*.sh 2>/dev/null || true

echo "==> Pushing NAS config to active MikroTiks"
mkdir -p logs
touch logs/.nas_config_sync_pending
set +e
"$PYTHON_BIN" manage.py sync_nas_config 2>&1 | tee logs/nas_config_sync.log
NAS_SYNC_RC=${PIPESTATUS[0]}
set -e
if [[ "$NAS_SYNC_RC" -eq 0 ]]; then
  rm -f logs/.nas_config_sync_pending
else
  echo "!! NAS config sync reported errors (see logs/nas_config_sync.log)."
  echo "   Pending stamp kept — Passenger restart will retry after WireGuard."
  echo "   Or re-run: $PYTHON_BIN manage.py sync_nas_config"
fi

echo "==> Restarting Passenger"
mkdir -p tmp
touch tmp/restart.txt

echo "==> Done. Visit your domain to verify."
