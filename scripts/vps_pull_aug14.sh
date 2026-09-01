#!/usr/bin/env bash
# Pull and deploy the last ISPCENTRIC release on 14 Aug 2026.
#
# That snapshot includes Hotspot/PPPoE pay pages, vouchers, faster captive
# pay/reconnect, Daraja STK field labels, and WireGuard script fixes through
# 14 Aug 2026.
#
# Run on the VPS from the project root:
#   cd /opt/ispcentric
#   sudo -u www-data bash scripts/vps_pull_aug14.sh
#   sudo systemctl restart ispcentric
#
# Optional: pass an explicit commit (short or full hash) instead of the date pin:
#   sudo -u www-data bash scripts/vps_pull_aug14.sh 31320f3
#
# Optional: restart the service when run as root:
#   sudo bash scripts/vps_pull_aug14.sh --restart
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REMOTE="${ISPCENTRIC_GIT_REMOTE:-origin}"
BRANCH="${ISPCENTRIC_GIT_BRANCH:-main}"
# Last commit strictly before this calendar date (UTC author date).
CUTOFF_DATE="${ISPCENTRIC_CUTOFF_DATE:-2026-08-15}"
# Known tip of 14 Aug 2026 (WireGuard apply script CRLF fix).
DEFAULT_AUG14_COMMIT="31320f31d0832b621493cf5db754ddfdb8ca601f"

RESTART_AFTER=false
EXPLICIT_COMMIT=""

for arg in "$@"; do
  case "$arg" in
    --restart) RESTART_AFTER=true ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      if [[ -z "$EXPLICIT_COMMIT" && "$arg" != --* ]]; then
        EXPLICIT_COMMIT="$arg"
      fi
      ;;
  esac
done

if [[ "$(id -un)" == "root" && "$RESTART_AFTER" == false ]]; then
  echo "!! Running as root. Git steps should normally run as www-data:"
  echo "     sudo -u www-data bash scripts/vps_pull_aug14.sh"
  echo "   Add --restart to restart ispcentric after deploy when using root."
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "!! Not a git repository: $ROOT"
  exit 1
fi

if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
  echo "!! Working tree has local changes. Commit, stash, or reset before pinning."
  git status --short
  exit 1
fi

echo "==> Fetching ${REMOTE}/${BRANCH}"
git fetch "$REMOTE" "$BRANCH"

if [[ -n "$EXPLICIT_COMMIT" ]]; then
  TARGET_COMMIT="$(git rev-parse --verify "${EXPLICIT_COMMIT}^{commit}")"
else
  TARGET_COMMIT="$(git rev-list -1 --before="$CUTOFF_DATE" "${REMOTE}/${BRANCH}" 2>/dev/null || true)"
  if [[ -z "$TARGET_COMMIT" ]]; then
    echo "!! Could not resolve a commit before $CUTOFF_DATE on ${REMOTE}/${BRANCH}."
    echo "   Using pinned Aug 14 commit instead."
    TARGET_COMMIT="$DEFAULT_AUG14_COMMIT"
  fi
fi

TARGET_SHORT="$(git rev-parse --short "$TARGET_COMMIT")"
TARGET_DATE="$(git show -s --format=%ad --date=short "$TARGET_COMMIT")"
TARGET_SUBJECT="$(git show -s --format=%s "$TARGET_COMMIT")"

echo "==> Checking out Aug 14 release snapshot"
echo "     $TARGET_SHORT  $TARGET_DATE  $TARGET_SUBJECT"

git checkout --detach "$TARGET_COMMIT"

echo "==> Deploying checked-out code"
bash "$ROOT/scripts/vps_deploy.sh"

echo
echo "==> Pinned to $TARGET_SHORT ($TARGET_DATE)."
echo "    To return to latest main later:"
echo "      cd $ROOT"
echo "      sudo -u www-data git fetch $REMOTE $BRANCH"
echo "      sudo -u www-data git checkout $BRANCH"
echo "      sudo -u www-data git pull $REMOTE $BRANCH"
echo "      sudo -u www-data bash scripts/vps_deploy.sh"
echo "      sudo systemctl restart ispcentric"

if [[ "$RESTART_AFTER" == true ]]; then
  if [[ "$(id -un)" != "root" ]]; then
    echo "!! --restart requires root. Run:"
    echo "     sudo systemctl restart ispcentric"
    exit 1
  fi
  echo "==> Restarting ispcentric"
  systemctl restart ispcentric
  systemctl status ispcentric --no-pager || true
else
  echo
  echo "==> Next step (needs root):"
  echo "     sudo systemctl restart ispcentric"
fi
