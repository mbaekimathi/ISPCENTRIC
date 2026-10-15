#!/usr/bin/env bash
# Slow PPPoE/Hotspot usage snapshot so fair-usage caps still count when
# nobody has a usage page open. Live charts sample on those pages instead.
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
