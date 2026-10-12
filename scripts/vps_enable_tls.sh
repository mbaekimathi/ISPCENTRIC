#!/usr/bin/env bash
# Enable HTTPS on isp.richcom.co.ke while keeping captive portal on HTTP :80.
#
# Safe path (webroot + our dual nginx config). Avoids `certbot --nginx`, which
# often adds a site-wide HTTP→HTTPS redirect and breaks Hotspot/PPPoE pay sheets.
#
# Usage (on the VPS as root):
#   cd /opt/ispcentric && sudo bash scripts/vps_enable_tls.sh
#   sudo bash scripts/vps_enable_tls.sh --email you@example.com
#   sudo bash scripts/vps_enable_tls.sh --skip-env   # nginx/certs only
#
# After this:
#   https://isp.richcom.co.ke  — admin / OAuth / M-Pesa callbacks
#   http://isp.richcom.co.ke   — captive probes + /hotspot/ + /pppoe/
set -euo pipefail

DOMAIN="${ISPCENTRIC_DOMAIN:-isp.richcom.co.ke}"
EMAIL="${ISPCENTRIC_TLS_EMAIL:-}"
WEBROOT="${ISPCENTRIC_CERTBOT_WEBROOT:-/var/www/certbot}"
SITE_AVAIL="${ISPCENTRIC_NGINX_AVAILABLE:-/etc/nginx/sites-available/ispcentric}"
SITE_ENABLED="${ISPCENTRIC_NGINX_ENABLED:-/etc/nginx/sites-enabled/ispcentric}"
ENV_FILE="${ISPCENTRIC_ENV_FILE:-/opt/ispcentric/.env}"
SERVICE="${ISPCENTRIC_SERVICE:-ispcentric}"
SKIP_ENV=false
DRY_RUN=false

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TLS_CONF="$ROOT/deploy/nginx/ispcentric.tls.conf"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --email)
      EMAIL="${2:-}"
      shift 2
      ;;
    --email=*)
      EMAIL="${1#*=}"
      shift
      ;;
    --domain)
      DOMAIN="${2:-}"
      shift 2
      ;;
    --skip-env) SKIP_ENV=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi

if [[ ! -f "$TLS_CONF" ]]; then
  echo "Missing TLS nginx template: $TLS_CONF" >&2
  exit 1
fi

run() {
  if $DRY_RUN; then
    echo "+ $*"
  else
    "$@"
  fi
}

echo "==> Packages (certbot + nginx plugin for ssl snippets only)"
export DEBIAN_FRONTEND=noninteractive
run apt-get update -qq
run apt-get install -y -qq certbot python3-certbot-nginx

echo "==> ACME webroot + firewall"
run mkdir -p "$WEBROOT"
if command -v ufw >/dev/null 2>&1; then
  run ufw allow 80/tcp || true
  run ufw allow 443/tcp || true
fi

# Ensure HTTP vhost is up so webroot challenges work (current site or HTTP-only template).
if [[ ! -e "$SITE_ENABLED" ]]; then
  echo "==> Installing HTTP nginx site first"
  run cp "$ROOT/deploy/nginx/ispcentric.conf" "$SITE_AVAIL"
  run ln -sf "$SITE_AVAIL" "$SITE_ENABLED"
  run rm -f /etc/nginx/sites-enabled/default
  run nginx -t
  run systemctl reload nginx
fi

CERT_LIVE="/etc/letsencrypt/live/$DOMAIN"
if [[ ! -f "$CERT_LIVE/fullchain.pem" ]]; then
  echo "==> Requesting Let's Encrypt certificate for $DOMAIN"
  CERTBOT_ARGS=(certonly --webroot -w "$WEBROOT" -d "$DOMAIN" --agree-tos --non-interactive --keep-until-expiring)
  if [[ -n "$EMAIL" ]]; then
    CERTBOT_ARGS+=(--email "$EMAIL")
  else
    CERTBOT_ARGS+=(--register-unsafely-without-email)
    echo "    (no --email; pass --email you@example.com for renewal notices)"
  fi
  run certbot "${CERTBOT_ARGS[@]}"
else
  echo "==> Certificate already present at $CERT_LIVE"
fi

# Certbot packages usually ship these; create dhparam if missing.
if [[ ! -f /etc/letsencrypt/options-ssl-nginx.conf ]]; then
  echo "Missing /etc/letsencrypt/options-ssl-nginx.conf (reinstall certbot?)" >&2
  exit 1
fi
if [[ ! -f /etc/letsencrypt/ssl-dhparams.pem ]]; then
  echo "==> Generating ssl-dhparams.pem (one-time)"
  run openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048
fi

echo "==> Installing dual HTTP+HTTPS nginx config (no site-wide redirect)"
run cp "$TLS_CONF" "$SITE_AVAIL"
run ln -sf "$SITE_AVAIL" "$SITE_ENABLED"
run nginx -t
run systemctl reload nginx

if ! $SKIP_ENV && [[ -f "$ENV_FILE" ]]; then
  echo "==> Updating Django CSRF origins for http + https (captive cookies stay non-Secure)"
  # Prefer both origins. Keep SESSION/CSRF cookie Secure=false so Hotspot/PPPoE
  # HTTP sessions still work; admin should use https://.
  if $DRY_RUN; then
    echo "+ update $ENV_FILE CSRF/TLS flags"
  else
    ISPCENTRIC_ENV_FILE="$ENV_FILE" ISPCENTRIC_DOMAIN="$DOMAIN" python3 - <<'PY'
import os
from pathlib import Path

path = Path(os.environ["ISPCENTRIC_ENV_FILE"])
domain = os.environ["ISPCENTRIC_DOMAIN"]
want = {
    "DJANGO_CSRF_TRUSTED_ORIGINS": f"https://{domain},http://{domain}",
    "DJANGO_SECURE_SSL_REDIRECT": "false",
    "DJANGO_SECURE_HSTS_SECONDS": "0",
    "DJANGO_SESSION_COOKIE_SECURE": "false",
    "DJANGO_CSRF_COOKIE_SECURE": "false",
}
lines = path.read_text(encoding="utf-8").splitlines()
out = []
seen = set()
for line in lines:
    if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
        out.append(line)
        continue
    key = line.partition("=")[0].strip()
    if key in want:
        out.append(f"{key}={want[key]}")
        seen.add(key)
    else:
        out.append(line)
for key, val in want.items():
    if key not in seen:
        out.append(f"{key}={val}")
path.write_text("\n".join(out) + "\n", encoding="utf-8")
print(f"Updated {path}")
PY
  fi
  if systemctl cat "$SERVICE" >/dev/null 2>&1; then
    echo "==> Restarting $SERVICE"
    run systemctl restart "$SERVICE"
  fi
elif ! $SKIP_ENV; then
  echo "NOTE: $ENV_FILE not found — set manually:"
  echo "  DJANGO_CSRF_TRUSTED_ORIGINS=https://$DOMAIN,http://$DOMAIN"
  echo "  DJANGO_SECURE_SSL_REDIRECT=false"
  echo "  DJANGO_SECURE_HSTS_SECONDS=0"
  echo "  DJANGO_SESSION_COOKIE_SECURE=false"
  echo "  DJANGO_CSRF_COOKIE_SECURE=false"
fi

echo
echo "Done."
echo "  Admin / OAuth / callbacks: https://$DOMAIN"
echo "  Captive Hotspot/PPPoE:     http:// or https://$DOMAIN/hotspot/… (both served)"
echo "  Keep PUBLIC_BASE_URL=http://$DOMAIN for MikroTik login.html / probes."
echo "  Renewals: certbot renew (deploy hook already reloads nginx if configured)."
