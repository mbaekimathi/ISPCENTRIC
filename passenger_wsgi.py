"""
Passenger WSGI entrypoint for cPanel Python apps.

In cPanel → Setup Python App:
  Application root  = folder where this file lives (git clone)
  Application URL   = your domain or subdomain
  Application startup file = passenger_wsgi.py
  Application Entry point  = application
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Ensure project root is importable
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Prefer the virtualenv that cPanel creates (passenger often injects this already)
VENV_DIR = os.environ.get("VIRTUAL_ENV") or os.environ.get("PASSENGER_VIRTUALENV")
if VENV_DIR:
    venv_site = Path(VENV_DIR) / "lib"
    # Find pythonX.Y/site-packages under the venv
    if venv_site.exists():
        for site in venv_site.glob("python*/site-packages"):
            site_str = str(site)
            if site_str not in sys.path:
                sys.path.insert(0, site_str)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ispcentric.settings")

from django.core.wsgi import get_wsgi_application  # noqa: E402

application = get_wsgi_application()

from ispcentric.db_bootstrap import ensure_tables  # noqa: E402

ensure_tables()
