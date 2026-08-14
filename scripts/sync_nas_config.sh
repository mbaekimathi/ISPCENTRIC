#!/usr/bin/env bash
# Re-push PPPoE / Hotspot / expired-redirect config to every active MikroTik.
# Called from vps_deploy.sh and cpanel_after_pull.sh after code updates.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$ROOT/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT/.venv/bin/python"
  else
    PYTHON_BIN="$(command -v python3 || command -v python)"
  fi
fi

mkdir -p logs
echo "==> Syncing NAS config on all active MikroTiks"
"$PYTHON_BIN" manage.py sync_nas_config 2>&1 | tee logs/nas_config_sync.log
