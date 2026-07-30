#!/usr/bin/env bash
# Expire lapsed packages on the NAS (Linux counterpart of
# scripts/sync_subscription_access.cmd). Hotspot packages are sold by the hour,
# so this must run on a short interval or a device stays online past the time
# it paid for. Driven by deploy/systemd/ispcentric-sweep.timer.
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
# Single > keeps only the last run so the log cannot grow without bound.
"$PYTHON_BIN" manage.py sync_subscription_access > logs/subscription_sweep.log 2>&1
