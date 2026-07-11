# ISPCENTRIC

ISP operations platform for internet service providers — Django + PyMySQL + cPanel-ready.

**GitHub:** https://github.com/mbaekimathi/ISPCENTRIC

## Stack

- **Backend:** Django 4.2 LTS
- **Database:** MySQL / MariaDB via PyMySQL
- **Static files:** WhiteNoise (works on cPanel Passenger)
- **Hosting:** local XAMPP or cPanel Python App (Passenger)

## Local setup (Windows / XAMPP)

1. Copy env and edit MySQL credentials:

```bash
copy .env.example .env
```

2. Install and run:

```bash
pip install -r requirements.txt
python manage.py runserver
```

Open http://127.0.0.1:8000/

## Push updates from your PC

```bash
git add -A
git commit -m "Describe your change"
git push origin main
```

Remote: `https://github.com/mbaekimathi/ISPCENTRIC.git`

## cPanel: first-time deploy

1. **Create MySQL database + user** in cPanel → MySQL Databases. Note the full names (`user_dbname`, `user_dbuser`).

2. **Setup Python App** (cPanel → Setup Python App):
   - Python version **3.10+**
   - Application root = folder you will clone into (e.g. `ispcentric`)
   - Startup file = `passenger_wsgi.py`
   - Entry point = `application`
   - Create the app (this creates a virtualenv)

3. **Clone the repo** into the application root (Terminal):

```bash
cd ~/ispcentric   # use your application root
git clone https://github.com/mbaekimathi/ISPCENTRIC.git .
```

If the folder is not empty, clone into a temp dir and move files, or init and pull:

```bash
git init
git remote add origin https://github.com/mbaekimathi/ISPCENTRIC.git
git fetch origin
git checkout -b main origin/main
```

4. **Create `.env`** on the server (never commit this file):

```bash
cp .env.example .env
nano .env
```

Use production values:

```env
DJANGO_SECRET_KEY=long-random-secret
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
DJANGO_CSRF_TRUSTED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
DJANGO_SERVE_MEDIA=true
DJANGO_AUTO_MIGRATE=true
MYSQL_AUTO_CREATE_DB=false

MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=cpaneluser_dbuser
MYSQL_PASSWORD=your-db-password
MYSQL_DATABASE=cpaneluser_ispcentric
```

5. **Enter the virtualenv** (cPanel shows the `source .../bin/activate` command), then:

```bash
bash scripts/cpanel_after_pull.sh
# or:
# bash scripts/cpanel_after_pull.sh /home/USER/virtualenv/ispcentric/3.11/bin/python
```

6. Optional: create a superuser:

```bash
python manage.py createsuperuser
```

## cPanel: update after every push

In Terminal (application root + virtualenv activated):

```bash
git pull origin main
bash scripts/cpanel_after_pull.sh
```

That installs new packages, runs migrations, rebuilds static files, and restarts Passenger (`tmp/restart.txt`).

## Important

| Item | Notes |
|------|--------|
| `.env` | Stays on the server only (gitignored) |
| `media/` | Uploads; gitignored — back up separately |
| `staticfiles/` | Built by `collectstatic`; gitignored |
| Auto DB create | Off on cPanel (`MYSQL_AUTO_CREATE_DB=false`) |
| Auto migrate | On by default; still run `scripts/cpanel_after_pull.sh` after each pull |
| Error log | `logs/django.log` on the server when a page 500s |

## Modules

- Workspace, billing, staff roles, client + HR management
- Network / hotspot modules planned
