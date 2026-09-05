#!/usr/bin/env bash
# Pull latest main on the production VPS and deploy.
#
# VPS: 178.162.241.99  (isp.richcom.co.ke)  app: /opt/ispcentric
#
# Recommended (as root — pull, migrate, collectstatic, restart):
#   cd /opt/ispcentric && sudo bash scripts/vps_pull.sh
#
# As www-data (code + migrate only; restart separately):
#   cd /opt/ispcentric && sudo -u www-data bash scripts/vps_pull.sh
#   sudo systemctl restart ispcentric
#
# Options:
#   --restart      restart ispcentric (default when run as root)
#   --no-restart   skip service restart
#   --skip-deploy  git only (no vps_deploy.sh)
#   --force        allow hard reset even if the tree is dirty
#   -h | --help
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REMOTE="${ISPCENTRIC_GIT_REMOTE:-origin}"
BRANCH="${ISPCENTRIC_GIT_BRANCH:-main}"
APP_USER="${ISPCENTRIC_APP_USER:-www-data}"
SERVICE="${ISPCENTRIC_SERVICE:-ispcentric}"

RESTART_AFTER=""
SKIP_DEPLOY=false
FORCE=false

for arg in "$@"; do
  case "$arg" in
    --restart) RESTART_AFTER=true ;;
    --no-restart) RESTART_AFTER=false ;;
    --skip-deploy) SKIP_DEPLOY=true ;;
    --force) FORCE=true ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "!! Unknown argument: $arg"
      echo "   Try: bash scripts/vps_pull.sh --help"
      exit 1
      ;;
  esac
done

# Root → restart by default. www-data → never restart (needs privileges).
if [[ -z "$RESTART_AFTER" ]]; then
  if [[ "$(id -un)" == "root" ]]; then
    RESTART_AFTER=true
  else
    RESTART_AFTER=false
  fi
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "!! Not a git repository: $ROOT"
  exit 1
fi

run_as_app() {
  if [[ "$(id -un)" == "root" ]]; then
    sudo -u "$APP_USER" "$@"
  elif [[ "$(id -un)" == "$APP_USER" ]]; then
    "$@"
  else
    echo "!! Run as root or $APP_USER (now: $(id -un))"
    exit 1
  fi
}

BEFORE="$(run_as_app git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BEFORE_SUBJ="$(run_as_app git show -s --format=%s HEAD 2>/dev/null || echo "")"

DIRTY="$(run_as_app git status --porcelain 2>/dev/null || true)"
if [[ -n "$DIRTY" && "$FORCE" != true ]]; then
  echo "!! Working tree has local changes. Re-run with --force to discard them, or stash first."
  run_as_app git status --short
  exit 1
fi

echo "==> Fetching ${REMOTE}/${BRANCH}"
run_as_app git fetch --prune "$REMOTE" "$BRANCH"

TARGET="$(run_as_app git rev-parse --verify "${REMOTE}/${BRANCH}^{commit}")"
TARGET_SHORT="$(run_as_app git rev-parse --short "$TARGET")"
TARGET_SUBJ="$(run_as_app git show -s --format=%s "$TARGET")"

if [[ "$BEFORE" == "$TARGET_SHORT" ]]; then
  echo "==> Already on ${TARGET_SHORT} — ${TARGET_SUBJ}"
else
  echo "==> Updating ${BEFORE} → ${TARGET_SHORT}"
  echo "     was: ${BEFORE_SUBJ}"
  echo "     now: ${TARGET_SUBJ}"
fi

# Stay on the branch (not detached) so future pulls stay simple.
run_as_app git checkout -B "$BRANCH" "$TARGET"
run_as_app git reset --hard "$TARGET"
run_as_app git clean -fd --exclude=.env --exclude=.venv --exclude=logs --exclude=media --exclude=.cache

AFTER="$(run_as_app git rev-parse --short HEAD)"
echo "==> Checked out ${AFTER} on ${BRANCH}"

if [[ "$SKIP_DEPLOY" == true ]]; then
  echo "==> Skipping deploy (--skip-deploy)"
else
  echo "==> Running vps_deploy.sh (migrate all apps, static, WireGuard, NAS sync)"
  run_as_app bash "$ROOT/scripts/vps_deploy.sh"
fi

if [[ "$RESTART_AFTER" == true ]]; then
  if [[ "$(id -un)" != "root" ]]; then
    echo "!! --restart needs root. Run:"
    echo "     sudo systemctl restart ${SERVICE}"
    exit 1
  fi
  echo "==> Restarting ${SERVICE}"
  systemctl restart "$SERVICE"
  systemctl --no-pager --full status "$SERVICE" || true
  echo
  echo "==> Live at commit ${AFTER}"
  echo "    Logs: journalctl -u ${SERVICE} -n 40 --no-pager"
else
  echo
  echo "==> Code is ready at ${AFTER}. Restart when ready:"
  echo "     sudo systemctl restart ${SERVICE}"
  echo "     sudo systemctl status ${SERVICE} --no-pager"
fi
