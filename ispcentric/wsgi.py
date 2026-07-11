"""
WSGI config for ISPCENTRIC.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ispcentric.settings")

application = get_wsgi_application()

from ispcentric.db_bootstrap import ensure_tables  # noqa: E402

ensure_tables()
