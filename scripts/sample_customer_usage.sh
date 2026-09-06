#!/usr/bin/env bash
# Persist PPPoE/Hotspot usage samples for General usage charts without anyone
# opening /app/clients/usage/ or per-client usage-analysis pages.
# Driven by deploy/systemd/ispcentric-usage-sample.timer (and the in-process
# boot loop as a second path).
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
"$PYTHON_BIN" manage.py sample_customer_usage > logs/usage_sample.log 2>&1
