# Deploying ISPCENTRIC to an Ubuntu + nginx VPS

**Quick start for isp.richcom.co.ke:** see [DEPLOY_NOW.md](DEPLOY_NOW.md) — production `.env` and one-shot bootstrap script are ready.

Target: `http://isp.richcom.co.ke`, app at `/opt/ispcentric`, served by gunicorn
behind nginx, expiry sweep driven by a systemd timer.

## Before you start

Two things must be true or the deployment will look healthy while doing nothing
useful:

1. **DNS.** `isp.richcom.co.ke` must have an A record pointing at the VPS
   (`178.162.241.99` as of Sep 2026).
2. **The VPS must be able to reach each MikroTik on TCP 8728.** Every
   provisioning action — Hotspot push, PPPoE secrets, authorising a paid MAC,
   the expiry sweep — connects *out* to `router.host`. Those are private
   addresses (`192.168.1.104`, `192.168.88.1`) and are unroutable from a public
   VPS. Payments will record correctly and never open anyone's access. See
   "Router reachability" below.

## 1. System packages

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip nginx mysql-server pkg-config \
    default-libmysqlclient-dev build-essential
```

## 2. Database

```bash
sudo mysql -e "CREATE DATABASE ispcentric CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
sudo mysql -e "CREATE USER 'ispcentric'@'127.0.0.1' IDENTIFIED BY 'STRONG_PASSWORD';"
sudo mysql -e "GRANT ALL PRIVILEGES ON ispcentric.* TO 'ispcentric'@'127.0.0.1'; FLUSH PRIVILEGES;"
```

## 3. Code and environment

```bash
sudo mkdir -p /opt/ispcentric
sudo chown -R www-data:www-data /opt/ispcentric
sudo -u www-data git clone https://github.com/mbaekimathi/ISPCENTRIC.git /opt/ispcentric
cd /opt/ispcentric
sudo -u www-data cp .env.production.example .env
sudo -u www-data nano .env          # fill in secret key + DB password
sudo chmod 600 .env
```

Generate the secret key with:

```bash
python3 -c "from django.core.management.utils import get_random_secret_key as k; print(k())"
```

## 4. Install and migrate

```bash
sudo -u www-data bash scripts/vps_deploy.sh
```

## 5. Services

```bash
sudo cp deploy/systemd/ispcentric.service /etc/systemd/system/
sudo cp deploy/systemd/ispcentric-sweep.service /etc/systemd/system/
sudo cp deploy/systemd/ispcentric-sweep.timer /etc/systemd/system/
sudo chmod +x scripts/*.sh
sudo systemctl daemon-reload
sudo systemctl enable --now ispcentric
sudo systemctl enable --now ispcentric-sweep.timer
```

Check them:

```bash
systemctl status ispcentric --no-pager
systemctl list-timers ispcentric-sweep --no-pager
tail -f /opt/ispcentric/logs/subscription_sweep.log
```

## 6. nginx

```bash
sudo cp deploy/nginx/ispcentric.conf /etc/nginx/sites-available/ispcentric
sudo ln -sf /etc/nginx/sites-available/ispcentric /etc/nginx/sites-enabled/ispcentric
sudo rm -f /etc/nginx/sites-enabled/default
sudo mkdir -p /var/www/certbot
sudo nginx -t && sudo systemctl reload nginx
```

The site is registered as `default_server` on purpose. Expired PPPoE clients are
dst-nat'd to this box with their original `Host` header (`www.msftconnecttest.com`
and similar), so nginx has to answer for names other than its own.

## 7. TLS (needed for M-Pesa callbacks)

Production Daraja rejects a plain-HTTP callback URL. Until TLS is in place,
payments still confirm through STK Query polling, but callbacks will not arrive.

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d isp.richcom.co.ke
```

After issuing, update `.env`:

```
DJANGO_CSRF_TRUSTED_ORIGINS=https://isp.richcom.co.ke
DJANGO_SESSION_COOKIE_SECURE=true
DJANGO_CSRF_COOKIE_SECURE=true
```

Leave `PUBLIC_BASE_URL` on `http://` if you want captive interception to keep
working, and keep port 80 answering — an HTTPS-only portal cannot be
transparently intercepted.

Then `sudo systemctl restart ispcentric`.

## Router reachability

The app is the *client* of the MikroTik API, so the routers do not need to reach
the VPS — the VPS needs to reach them. On a public VPS that means a tunnel: the
routers' `192.168.x.x` addresses are unroutable from the internet, so every push
times out and the app reports the router as offline.

`manage.py wireguard_peer` builds both sides of that tunnel. The VPS is the
WireGuard server and each MikroTik dials out to it, so no site needs a static
public IP or port forwarding.

Install WireGuard and open its port:

```bash
sudo apt install -y wireguard
sudo ufw allow 51820/udp
```

Generate the server keypair once:

```bash
cd /opt/ispcentric
sudo -u www-data .venv/bin/python manage.py wireguard_peer --server-keys
```

Put the **public** key and endpoint in `.env`, then restart the app:

```
WIREGUARD_ENDPOINT=isp.richcom.co.ke:51820
WIREGUARD_SERVER_PUBLIC_KEY=<public key from above>
WIREGUARD_SUBNET=10.9.0.0/24
```

### Routers already onboarded

If the database already holds your routers, give each one a peer:

```bash
sudo -u www-data .venv/bin/python manage.py wireguard_peer --all
```

Each router gets an address in the tunnel subnet and a script to paste into its
terminal (Winbox → New Terminal). RouterOS 7 is required.

The app dials the tunnel address in preference to the saved `host`, so leave each
router's host set to its real LAN address — it stays useful for on-site work.

### Routers not onboarded yet

Onboarding verifies the API login, which the VPS cannot do until it can reach the
router — and it can only reach the router once the tunnel is up. Reserve the peer
first to break that circle:

```bash
sudo -u www-data .venv/bin/python manage.py wireguard_peer --new "Kariobangi"
```

Paste the script into that router, finish the server steps below, confirm the
handshake, then onboard the router in the app using the **reserved tunnel
address** as its host. The next `wireguard_peer` run for that router adopts the
reserved peer rather than issuing a second one.

### Server side

Write the server config using the **private** key you kept, and start it:

```bash
sudo -u www-data .venv/bin/python manage.py wireguard_peer --server-config '<private key>' \
    | sudo tee /etc/wireguard/wg0.conf > /dev/null
sudo chmod 600 /etc/wireguard/wg0.conf
sudo systemctl enable --now wg-quick@wg0
```

Re-run that whenever you add a router or reserve a peer. Confirm a site is up
with `sudo wg show` (a recent handshake) and `ping 10.9.0.2`, then push
Hotspot/PPPoE settings from the app.

### Automatic peer registration (hosted onboarding)

When a client generates a Winbox script in the app, ISPCENTRIC saves the peer in
the database. The VPS must also accept that peer on `wg0` or the tunnel never
comes up (empty WireGuard handshake, ping to `10.9.0.1` fails, Verify shows
**VPS peer missing**).

**Required on every hosted deploy:** set `WIREGUARD_SYNC_COMMAND` and sudoers
below. Without them, Generate looks successful but Connect never completes.

Allow the app user to run the helper as root:

```bash
sudo chmod +x /opt/ispcentric/scripts/wireguard_apply_peer.sh
sudo tee /etc/sudoers.d/ispcentric-wireguard >/dev/null <<'EOF'
www-data ALL=(root) NOPASSWD: /opt/ispcentric/scripts/wireguard_apply_peer.sh
EOF
sudo visudo -cf /etc/sudoers.d/ispcentric-wireguard
```

Set in `.env` (see `.env.production.example`):

```
WIREGUARD_SYNC_COMMAND="sudo /opt/ispcentric/scripts/wireguard_apply_peer.sh"
```

Then `sudo systemctl restart ispcentric`. New script generations register the
peer immediately. To backfill every reservation and onboarded router:

```bash
sudo -u www-data .venv/bin/python manage.py wireguard_peer --sync-server
```

The app stops scanning the local network for routers when `DJANGO_HOSTED=true`,
since on a VPS that would only probe unrelated datacentre hosts. Add routers by
hand instead.

One consequence worth planning for: the PPPoE renew page identifies a subscriber
from the session address in `/ppp/active`. That only works while the client's
PPP address survives to the billing server. If the MikroTik masquerades PPPoE
traffic on the way to the VPS, every request arrives from the router's public
address and identification fails with "Could not match this connection to a
PPPoE account." Route the PPPoE pool over the tunnel without NAT so
`10.20.0.x` reaches the app intact.

## Updating later

```bash
cd /opt/ispcentric
sudo -u www-data git fetch origin
sudo -u www-data git reset --hard origin/main
sudo -u www-data bash scripts/vps_deploy.sh
sudo systemctl restart ispcentric
```

Prefer this over a separate `migrate accounts` step — full migrate is already
inside `vps_deploy.sh`. Optional shorthand: `sudo bash scripts/vps_pull.sh`.

**Deploy-safe default:** `vps_deploy.sh` does **not** push MikroTik fleets on
every release (avoids brief LAN blips and accidental CPE redials). To refresh
captive/firewall templates after a code change that needs it:

```bash
sudo -u www-data bash scripts/vps_deploy.sh --sync-nas
# or later:
sudo -u www-data /opt/ispcentric/.venv/bin/python manage.py sync_nas_config
```

`sync_nas_config` (when opted in) re-pushes to every **active** MikroTik:

- PPPoE pool / blocked profile / firewall stack (secrets only with `--sync-secrets`)
- Expired-client pay redirect rules
- Hotspot `login.html` / captive portal (when Hotspot is enabled)

Check the result:

```bash
sudo -u www-data tail -n 50 /opt/ispcentric/logs/nas_config_sync.log
```

If a router was offline during an **opt-in** NAS sync, the pending stamp is kept
and the app retries once after WireGuard comes up on restart (after a settle
delay). Set `NAS_CONFIG_SYNC_ON_BOOT=true` in `.env` only if you want **every**
app restart to re-push all routers (slower; usually unnecessary).

## Security hardening (production checklist)

### VPS firewall and SSH

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 51820/udp
sudo ufw enable
```

Prefer SSH keys only (`PasswordAuthentication no`), disable root login, and
install fail2ban. Restrict SSH to your office/admin IP when practical.

### Secrets and field encryption

1. Set `FIELD_ENCRYPTION_KEY` in `.env` (Fernet key — see `.env.production.example`).
2. Keep a secure offline backup of that key.
3. After deploy/migrate, encrypt any legacy plaintext credential rows:

```bash
sudo -u www-data /opt/ispcentric/.venv/bin/python manage.py encrypt_sensitive_fields
```

Router API passwords, Daraja secrets, CPE/PPPoE passwords, WireGuard peer
private keys, and SMS/SMTP/WhatsApp tokens are stored encrypted at rest.

### M-Pesa callback allowlist

Set `MPESA_CALLBACK_ALLOWED_IPS` to Safaricom’s published callback source IPs
once you have them from Daraja. Keep `STK_CALLBACK_REQUIRE_DARAJA_QUERY=true`.

### MikroTik API lockdown (each router)

After the WireGuard tunnel is up, restrict RouterOS API to the tunnel subnet
only (example for `10.9.0.0/24`):

```
/ip service set api address=10.9.0.0/24
/ip service set winbox address=10.9.0.0/24,192.168.88.0/24
/ip service disable www,ftp,telnet
```

Never expose API (8728) or Winbox on the public WAN.

### Audit log

Privileged IT Support role/client switches and WireGuard `.rsc` downloads are
recorded in Django admin under **Security audit logs**.
