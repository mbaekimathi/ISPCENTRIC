#!/usr/bin/env bash
# Run subscription-access correction loops on local or hosted.
# Usage:
#   ./scripts/verify_access_loop.sh 7
#   ./scripts/verify_access_loop.sh 7 --loops 8 --settle 3
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CUSTOMER="${1:?customer id required (e.g. 7)}"
shift || true

PYTHON="${PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
  if [[ -x "$ROOT/.venv/bin/python" ]]; then
    PYTHON="$ROOT/.venv/bin/python"
  else
    PYTHON="python"
  fi
fi

echo "==> Unit correction-loop tests"
"$PYTHON" manage.py test \
  core.tests.AccessFlowCorrectionLoopTests \
  core.tests.ExpiredCaptivePayTests \
  core.tests.IspHotspotInstantPayTests \
  --keepdb -v 1

echo
echo "==> Live verify loop for customer $CUSTOMER"
"$PYTHON" manage.py verify_subscription_access --customer "$CUSTOMER" "$@"
