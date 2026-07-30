# Deploying ISPCENTRIC to an Ubuntu + nginx VPS

Target: `http://isp.richcom.co.ke`, app at `/opt/ispcentric`, served by gunicorn
behind nginx, expiry sweep driven by a systemd timer.

## Before you start

Two things must be true or the deployment will look healthy while doing nothing
useful:

1. **DNS.** `isp.richcom.co.ke` must have an A record pointing at the VPS. At the
   time of writing it does not exist (`NXDOMAIN`); only the apex `richcom.co.ke`
   resolves.
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
the VPS — the VPS needs to reach them. On a public VPS that means a tunnel.

Recommended: WireGuard with the VPS as the server and each MikroTik as a peer
that dials out. No static public IP or port forwarding is needed at the sites.
Once the tunnel is up, edit each router in the app and set its host to the
tunnel address (for example `10.9.0.2`), then push Hotspot/PPPoE settings again.

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
sudo -u www-data git pull
sudo -u www-data bash scripts/vps_deploy.sh
sudo systemctl restart ispcentric
```
