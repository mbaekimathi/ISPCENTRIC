#!/usr/bin/env bash
# Soft-push PPPoE/Hotspot stack to selected MikroTiks WITHOUT rewriting
# /ppp/secret and WITHOUT reauthenticating paid sessions (clients stay dialed).
#
# Usage on VPS:
#   cd /opt/ispcentric
#   sudo -u www-data bash scripts/soft_sync_nas_routers.sh
#   sudo -u www-data bash scripts/soft_sync_nas_routers.sh 19 26 28
#   sudo -u www-data bash scripts/soft_sync_nas_routers.sh --dry-run 19 26 28
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$ROOT/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

DRY_RUN=0
ROUTER_IDS=()
for arg in "$@"; do
  case "$arg" in
    --dry-run|-n) DRY_RUN=1 ;;
    --help|-h)
      echo "Usage: $0 [--dry-run] [router_id ...]"
      echo "  No router ids → all active MikroTiks."
      echo "  Soft sync only (no --sync-secrets / no session kicks)."
      exit 0
      ;;
    *)
      if [[ "$arg" =~ ^[0-9]+$ ]]; then
        ROUTER_IDS+=("$arg")
      else
        echo "Unknown argument: $arg" >&2
        exit 2
      fi
      ;;
  esac
done

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-ispcentric.settings}"

IDS_CSV=""
if ((${#ROUTER_IDS[@]})); then
  IDS_CSV=$(IFS=,; echo "${ROUTER_IDS[*]}")
fi

"$PYTHON_BIN" - <<PY
import os
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ispcentric.settings")

import django
django.setup()

from core.mikrotik_connect import refresh_onboarded_router_config
from core.models import MikroTikRouter
from core.subscription_sync import (
    acquire_subscription_sweep_lock_with_retry,
    release_subscription_sweep_lock,
)

dry_run = ${DRY_RUN}
ids_csv = "${IDS_CSV}"
ids = [int(x) for x in ids_csv.split(",") if x.strip()]

qs = (
    MikroTikRouter.objects.filter(
        account_status=MikroTikRouter.AccountStatus.ACTIVE,
    )
    .exclude(host="")
    .select_related("organization")
    .order_by("id")
)
if ids:
    qs = qs.filter(pk__in=ids)

routers = list(qs)
if not routers:
    print("No matching active MikroTik routers.")
    sys.exit(1)

print(
    "Soft NAS sync (reauthenticate=False, sync_pppoe_secrets=False)"
    + (" [DRY-RUN]" if dry_run else "")
)
for r in routers:
    org = getattr(r.organization, "name", None)
    print(
        "  planned id=%s name=%r host=%s vpn=%s org=%s"
        % (r.pk, r.name, r.host, r.vpn_address or "-", org)
    )

if dry_run:
    print("Dry-run only — no MikroTik writes.")
    sys.exit(0)

if not acquire_subscription_sweep_lock_with_retry(
    ttl_sec=900, attempts=8, wait_sec=5.0
):
    print(
        "Skipped: subscription sweep / expiry watch holds the fleet lock. "
        "Retry in a minute.",
        file=sys.stderr,
    )
    sys.exit(2)

ok = errors = skipped = 0
try:
    for r in routers:
        label = "%s (%s)" % (r.name or r.host, r.host)
        print("--- %s ---" % label)
        try:
            result = refresh_onboarded_router_config(
                r,
                reauthenticate=False,
                sync_pppoe_secrets=False,
            )
        except Exception as exc:
            errors += 1
            print("ERROR %s: %s" % (label, exc), file=sys.stderr)
            continue
        if result.get("ok"):
            ok += 1
            print("OK: %s" % (result.get("message") or "synced"))
        elif result.get("skipped"):
            skipped += 1
            print("SKIP: %s" % (result.get("message") or "skipped"))
        else:
            errors += 1
            print(
                "FAIL: %s"
                % (result.get("error") or result.get("message") or "failed"),
                file=sys.stderr,
            )
finally:
    release_subscription_sweep_lock()

print(
    "Finished: %s ok, %s error(s), %s skipped [secrets not rewritten]"
    % (ok, errors, skipped)
)
sys.exit(1 if errors else 0)
PY
