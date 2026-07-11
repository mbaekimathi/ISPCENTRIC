"""
ASGI config for ISPCENTRIC.
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ispcentric.settings")

application = get_asgi_application()

from ispcentric.db_bootstrap import ensure_tables  # noqa: E402

ensure_tables()
