"""
Allow CSRF from the current request host when hosted on cPanel.

Domains often change (addon domains / subdomains); this avoids hardcoding
DJANGO_CSRF_TRUSTED_ORIGINS for every hostname.
"""

from __future__ import annotations

import logging
import re

from django.http import HttpResponseServerError

logger = logging.getLogger(__name__)

_SCHEMA_HINT_RE = re.compile(
    r"unknown column|doesn't exist|does not exist|no such table|table .* not found",
    re.IGNORECASE,
)


class AutoCsrfOriginMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.conf import settings

        if getattr(settings, "AUTO_CSRF_ORIGINS", False):
            host = request.get_host()
            if host:
                scheme = "https" if request.is_secure() else request.scheme
                # Behind cPanel SSL terminators, prefer https when forwarded
                forwarded = request.META.get("HTTP_X_FORWARDED_PROTO", "")
                if "https" in forwarded.lower():
                    scheme = "https"
                origin = f"{scheme}://{host}"
                trusted = settings.CSRF_TRUSTED_ORIGINS
                if origin not in trusted:
                    trusted.append(origin)
        return self.get_response(request)


class PrefetchEmployeeMiddleware:
    """Load employee + organization once per request to avoid repeated FK hits."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and getattr(user, "is_authenticated", False):
            from accounts.models import Employee

            try:
                employee = (
                    Employee.objects.select_related("organization")
                    .filter(user_id=user.id)
                    .first()
                )
                # Cache on the reverse OneToOne (including None) so later getattr
                # does not issue another query.
                Employee._meta.get_field("user").remote_field.set_cached_value(
                    user, employee
                )
            except Exception:
                pass
        return self.get_response(request)


class SchemaErrorMiddleware:
    """Turn missing-table / missing-column DB errors into an actionable page."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        from django.db.utils import DatabaseError, OperationalError, ProgrammingError

        if not isinstance(exception, (OperationalError, ProgrammingError, DatabaseError)):
            return None

        message = str(exception)
        if not _SCHEMA_HINT_RE.search(message):
            return None

        logger.exception("Database schema is behind the application code")
        body = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Database update needed</title>
<style>
body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5}
code{background:#f3f4f6;padding:.15rem .35rem;border-radius:.25rem}
pre{background:#111827;color:#f9fafb;padding:1rem;border-radius:.5rem;overflow:auto}
</style></head><body>
<h1>Database update needed</h1>
<p>This page failed because the hosted MySQL schema is behind the latest code
(missing tables or columns). That usually happens after a <code>git pull</code>
without running migrations.</p>
<p>In cPanel Terminal, from the app root with the virtualenv active:</p>
<pre>git pull origin main
bash scripts/cpanel_after_pull.sh</pre>
<p>Or only migrate + restart:</p>
<pre>python manage.py migrate --noinput
mkdir -p tmp &amp;&amp; touch tmp/restart.txt</pre>
<p>Then reload this page. Error detail is also written to <code>logs/django.log</code>.</p>
</body></html>"""
        return HttpResponseServerError(body)
