#!/usr/bin/env bash
# First-time ISPCENTRIC bootstrap on Ubuntu VPS (isp.richcom.co.ke).
#
# Run as root on a fresh Ubuntu 22.04/24.04 server:
#   curl -fsSL https://raw.githubusercontent.com/mbaekimathi/ISPCENTRIC/main/scripts/vps_first_boot.sh -o /tmp/vps_first_boot.sh
#   bash /tmp/vps_first_boot.sh
#
# Or after cloning locally:
#   sudo bash scripts/vps_first_boot.sh
#
# Prerequisites:
#   - DNS A record: isp.richcom.co.ke -> this server's public IP
#   - Copy deploy/env.isp.richcom.co.ke to /opt/ispcentric/.env BEFORE deploy,
#     or set ISPCENTRIC_ENV_FILE=/path/to/env
set -euo pipefail

APP_ROOT="${ISPCENTRIC_ROOT:-/opt/ispcentric}"
APP_USER="${ISPCENTRIC_USER:-www-data}"
REPO_URL="${ISPCENTRIC_REPO:-https://github.com/mbaekimathi/ISPCENTRIC.git}"
BRANCH="${ISPCENTRIC_BRANCH:-main}"
ENV_SOURCE="${ISPCENTRIC_ENV_FILE:-}"

if [[ "$(id -un)" != "root" ]]; then
  echo "!! Run as root: sudo bash scripts/vps_first_boot.sh"
  exit 1
fi

echo "==> Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  python3 python3-venv python3-pip python3-dev \
  nginx mysql-server \
  wireguard wireguard-tools \
  pkg-config default-libmysqlclient-dev build-essential \
  git curl ufw

echo "==> Preparing app directory: $APP_ROOT"
mkdir -p "$APP_ROOT"
if [[ ! -d "$APP_ROOT/.git" ]]; then
  sudo -u "$APP_USER" git clone --branch "$BRANCH" "$REPO_URL" "$APP_ROOT"
else
  echo "    Git repo already present — pulling latest $BRANCH"
  sudo -u "$APP_USER" git -C "$APP_ROOT" fetch origin "$BRANCH"
  sudo -u "$APP_USER" git -C "$APP_ROOT" checkout "$BRANCH"
  sudo -u "$APP_USER" git -C "$APP_ROOT" pull origin "$BRANCH"
fi
chown -R "$APP_USER:$APP_USER" "$APP_ROOT"

if [[ -n "$ENV_SOURCE" && -f "$ENV_SOURCE" ]]; then
  echo "==> Installing .env from $ENV_SOURCE"
  cp "$ENV_SOURCE" "$APP_ROOT/.env"
  chown "$APP_USER:$APP_USER" "$APP_ROOT/.env"
  chmod 600 "$APP_ROOT/.env"
elif [[ ! -f "$APP_ROOT/.env" ]]; then
  if [[ -f "$APP_ROOT/deploy/env.isp.richcom.co.ke" ]]; then
    echo "==> Installing .env from deploy/env.isp.richcom.co.ke"
    cp "$APP_ROOT/deploy/env.isp.richcom.co.ke" "$APP_ROOT/.env"
    chown "$APP_USER:$APP_USER" "$APP_ROOT/.env"
    chmod 600 "$APP_ROOT/.env"
  else
    echo "!! No .env found. Copy deploy/env.isp.richcom.co.ke to $APP_ROOT/.env and re-run."
    exit 1
  fi
fi

# Read DB password from .env for MySQL user setup.
DB_NAME="$(grep -E '^MYSQL_DATABASE=' "$APP_ROOT/.env" | tail -n1 | cut -d= -f2- | tr -d '\r' || true)"
DB_USER="$(grep -E '^MYSQL_USER=' "$APP_ROOT/.env" | tail -n1 | cut -d= -f2- | tr -d '\r' || true)"
DB_PASS="$(grep -E '^MYSQL_PASSWORD=' "$APP_ROOT/.env" | tail -n1 | cut -d= -f2- | tr -d '\r' || true)"
DB_NAME="${DB_NAME:-ispcentric}"
DB_USER="${DB_USER:-ispcentric}"

if [[ -z "$DB_PASS" || "$DB_PASS" == replace-* ]]; then
  echo "!! Set MYSQL_PASSWORD in $APP_ROOT/.env before running first boot."
  exit 1
fi

echo "==> Configuring MySQL database $DB_NAME / user $DB_USER"
mysql -e "CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';"
mysql -e "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'127.0.0.1'; FLUSH PRIVILEGES;"

echo "==> WireGuard sudoers for $APP_USER"
chmod +x "$APP_ROOT/scripts/wireguard_apply_peer.sh"
tee /etc/sudoers.d/ispcentric-wireguard >/dev/null <<EOF
${APP_USER} ALL=(root) NOPASSWD: ${APP_ROOT}/scripts/wireguard_apply_peer.sh
EOF
visudo -cf /etc/sudoers.d/ispcentric-wireguard

echo "==> Deploying application (venv, migrate, collectstatic, peer sync)"
sudo -u "$APP_USER" bash "$APP_ROOT/scripts/vps_deploy.sh"

echo "==> Installing systemd units"
cp "$APP_ROOT/deploy/systemd/ispcentric.service" /etc/systemd/system/
cp "$APP_ROOT/deploy/systemd/ispcentric-sweep.service" /etc/systemd/system/
cp "$APP_ROOT/deploy/systemd/ispcentric-sweep.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable ispcentric ispcentric-sweep.timer

echo "==> Installing nginx site"
cp "$APP_ROOT/deploy/nginx/ispcentric.conf" /etc/nginx/sites-available/ispcentric
ln -sf /etc/nginx/sites-available/ispcentric /etc/nginx/sites-enabled/ispcentric
rm -f /etc/nginx/sites-enabled/default
mkdir -p /var/www/certbot
nginx -t
systemctl reload nginx

echo "==> Configuring firewall"
ufw --force default deny incoming
ufw --force default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 51820/udp
ufw --force enable

WG_KEY="$(grep -E '^WIREGUARD_SERVER_PUBLIC_KEY=' "$APP_ROOT/.env" | tail -n1 | cut -d= -f2- | tr -d '\r' || true)"
if [[ -z "$WG_KEY" ]]; then
  echo "!! WIREGUARD_SERVER_PUBLIC_KEY is empty."
  echo "   Run on VPS:"
  echo "     cd $APP_ROOT"
  echo "     sudo -u $APP_USER .venv/bin/python manage.py wireguard_peer --server-keys"
  echo "   Then paste the public key into .env and re-run wg setup below."
else
  if [[ ! -f /etc/wireguard/wg0.conf ]]; then
    echo "==> WireGuard wg0.conf not found — generate with:"
    echo "     cd $APP_ROOT"
    echo "     sudo -u $APP_USER .venv/bin/python manage.py wireguard_peer --server-config '<private-key>' | tee /etc/wireguard/wg0.conf"
    echo "     chmod 600 /etc/wireguard/wg0.conf"
    echo "     systemctl enable --now wg-quick@wg0"
  else
    echo "==> Starting WireGuard"
    systemctl enable --now wg-quick@wg0 || true
    sudo -u "$APP_USER" "$APP_ROOT/.venv/bin/python" "$APP_ROOT/manage.py" wireguard_peer --sync-server || true
  fi
fi

echo "==> Starting ISPCENTRIC"
systemctl restart ispcentric
systemctl enable --now ispcentric-sweep.timer

echo
echo "============================================================"
echo " ISPCENTRIC first boot complete"
echo "============================================================"
echo " Site:    http://isp.richcom.co.ke"
echo " App:     $APP_ROOT"
echo " Logs:    journalctl -u ispcentric -f"
echo "          tail -f $APP_ROOT/logs/nas_config_sync.log"
echo
echo " Next steps:"
echo "  1. If wg0.conf is missing, run wireguard_peer --server-config (see above)"
echo "  2. Onboard MikroTik routers (tunnel script in the app)"
echo "  3. sudo -u $APP_USER $APP_ROOT/.venv/bin/python manage.py sync_nas_config"
echo "  4. Issue TLS: certbot --nginx -d isp.richcom.co.ke"
echo "  5. Encrypt legacy secrets: manage.py encrypt_sensitive_fields"
echo "============================================================"
systemctl status ispcentric --no-pager || true
