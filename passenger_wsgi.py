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
import traceback
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

# Passenger often hides stderr — tee startup + runtime errors into logs/.
_LOG_DIR = BASE_DIR / "logs"
try:
    _LOG_DIR.mkdir(exist_ok=True)
    _passenger_log = open(_LOG_DIR / "passenger.log", "a", encoding="utf-8", buffering=1)

    class _Tee:
        def __init__(self, *streams):
            self._streams = streams

        def write(self, data):
            for stream in self._streams:
                try:
                    stream.write(data)
                    stream.flush()
                except Exception:
                    pass
            return len(data) if isinstance(data, str) else 0

        def flush(self):
            for stream in self._streams:
                try:
                    stream.flush()
                except Exception:
                    pass

        def isatty(self):
            return False

    sys.stdout = _Tee(sys.__stdout__, _passenger_log)
    sys.stderr = _Tee(sys.__stderr__, _passenger_log)
    print(f"[passenger_wsgi] starting in {BASE_DIR}", flush=True)
except OSError:
    pass

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ispcentric.settings")

try:
    from django.core.wsgi import get_wsgi_application  # noqa: E402

    application = get_wsgi_application()

    from ispcentric.db_bootstrap import ensure_tables  # noqa: E402

    ensure_tables()
except Exception:
    traceback.print_exc()
    raise
