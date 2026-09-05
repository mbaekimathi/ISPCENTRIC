# Deploy ISPCENTRIC to isp.richcom.co.ke — do this now

**VPS IP:** `178.162.241.99` (DNS: `isp.richcom.co.ke`)

SSH from your machine was not reachable from the dev PC (port 22 timeout). Run these steps **on the VPS console** or from a machine that can SSH in.

---

## Daily update (pull latest main)

After code is pushed to GitHub, on the VPS:

```bash
cd /opt/ispcentric
sudo -u www-data git fetch origin
sudo -u www-data git reset --hard origin/main
sudo -u www-data bash scripts/vps_deploy.sh
sudo systemctl restart ispcentric
```

That fetches `origin/main`, hard-resets, runs migrate/static/WireGuard, then restarts the app.

**Deploy-safe:** NAS fleet push is **off by default** so live PPPoE/Hotspot clients are not disrupted. To push captive/firewall templates after a release:

```bash
sudo -u www-data bash scripts/vps_deploy.sh --sync-nas
# or later:
sudo -u www-data /opt/ispcentric/.venv/bin/python manage.py sync_nas_config
```

Do **not** run `migrate accounts` by itself — `vps_deploy.sh` already migrates every app.

Optional helper (same steps, plus restart when run as root): `sudo bash scripts/vps_pull.sh`

---

## Option A — One command (recommended)

Upload `deploy/env.isp.richcom.co.ke` to the server first (it has your production secrets — **do not commit it**).

On the VPS as **root**:

```bash
# 1. Clone (if fresh server)
mkdir -p /opt/ispcentric
chown -R www-data:www-data /opt/ispcentric
sudo -u www-data git clone https://github.com/mbaekimathi/ISPCENTRIC.git /opt/ispcentric

# 2. Copy your production .env (upload via SCP/SFTP from your PC)
#    Local file: deploy/env.isp.richcom.co.ke  ->  /opt/ispcentric/.env
chmod 600 /opt/ispcentric/.env
chown www-data:www-data /opt/ispcentric/.env

# 3. Bootstrap everything
cd /opt/ispcentric
bash scripts/vps_first_boot.sh
```

---

## Option B — From your Windows PC (when SSH works)

In PowerShell from the project folder:

```powershell
# Upload production env (secrets file — keep private)
scp deploy/env.isp.richcom.co.ke root@isp.richcom.co.ke:/opt/ispcentric/.env

# SSH in and bootstrap
ssh root@isp.richcom.co.ke "cd /opt/ispcentric && git pull && bash scripts/vps_first_boot.sh"
```

Or use the helper script:

```powershell
.\scripts\upload_and_deploy.ps1
```

---

## WireGuard server (one-time, on VPS)

If `/etc/wireguard/wg0.conf` does not exist yet:

```bash
cd /opt/ispcentric
sudo -u www-data .venv/bin/python manage.py wireguard_peer --server-keys
# Save the PRIVATE key securely — never put it in .env

sudo -u www-data .venv/bin/python manage.py wireguard_peer --server-config '<PRIVATE_KEY>' \
  | sudo tee /etc/wireguard/wg0.conf
sudo chmod 600 /etc/wireguard/wg0.conf
sudo systemctl enable --now wg-quick@wg0
sudo wg show
```

The **public** key is already in `.env`:
`UkOOxC6oM/Qyg53HUL/u3XKwK6ITa1VzBg9xlYqcyns=`

Sync all router peers:

```bash
sudo -u www-data .venv/bin/python manage.py wireguard_peer --sync-server
sudo -u www-data .venv/bin/python manage.py sync_nas_config
sudo systemctl restart ispcentric
```

---

## Migrate your local database to VPS (optional)

If you have routers/customers on your local MySQL:

```bash
# On Windows (local)
mysqldump -u root ISPCENTRIC > ispcentric_dump.sql

# Upload and import on VPS
scp ispcentric_dump.sql root@isp.richcom.co.ke:/tmp/
ssh root@isp.richcom.co.ke "mysql ispcentric < /tmp/ispcentric_dump.sql"
```

Then on VPS run `sync_nas_config` so Hotspot URLs point at `http://isp.richcom.co.ke`.

---

## Verify

```bash
curl -I http://isp.richcom.co.ke/
cd /opt/ispcentric && sudo -u www-data .venv/bin/python manage.py check
sudo wg show
sudo -u www-data .venv/bin/python manage.py verify_router_connectivity
```

Open `http://isp.richcom.co.ke` — log in, open MikroTik detail — status should show **Connected** via tunnel (`10.9.0.x`).

---

## Production secrets (generated for this deploy)

| Setting | Location |
|---------|----------|
| Django secret | `deploy/env.isp.richcom.co.ke` |
| Fernet encryption key | same file |
| MySQL password | same file (`ispcentric` user) |
| WireGuard public key | same file (matches your local .env) |

**Back up `deploy/env.isp.richcom.co.ke` offline.** If lost, generate new keys and re-encrypt fields.

---

## TLS (after HTTP works)

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d isp.richcom.co.ke
```

Then edit `/opt/ispcentric/.env`:

```
DJANGO_CSRF_TRUSTED_ORIGINS=https://isp.richcom.co.ke
DJANGO_SESSION_COOKIE_SECURE=true
DJANGO_CSRF_COOKIE_SECURE=true
```

Keep `PUBLIC_BASE_URL=http://isp.richcom.co.ke` for captive Hotspot interception.

```bash
sudo systemctl restart ispcentric
```
