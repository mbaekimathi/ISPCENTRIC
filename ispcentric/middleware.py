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
    """On missing-table / missing-column errors, auto-migrate then ask for a reload."""

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

        repaired = False
        try:
            from ispcentric.db_bootstrap import repair_schema_if_needed

            repaired = bool(repair_schema_if_needed())
        except Exception:
            logger.exception("Automatic schema repair failed")

        if repaired:
            body = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Database updated</title>
<style>
body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5}
a.button{display:inline-block;margin-top:1rem;padding:.65rem 1rem;background:#0e7490;color:#fff;text-decoration:none;border-radius:.4rem;font-weight:700}
</style></head><body>
<h1>Database updated</h1>
<p>Missing tables or columns were detected and migrations were applied automatically.</p>
<p><a class="button" href="">Reload this page</a></p>
</body></html>"""
            return HttpResponseServerError(body)

        body = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Database update needed</title>
<style>
body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5}
code{background:#f3f4f6;padding:.15rem .35rem;border-radius:.25rem}
pre{background:#111827;color:#f9fafb;padding:1rem;border-radius:.5rem;overflow:auto}
</style></head><body>
<h1>Database update needed</h1>
<p>Automatic migration could not finish. Check MySQL credentials in <code>.env</code>
and <code>logs/django.log</code> / <code>logs/passenger.log</code>.</p>
<p>In cPanel Terminal (app root + virtualenv):</p>
<pre>python manage.py migrate --noinput
mkdir -p tmp &amp;&amp; touch tmp/restart.txt</pre>
<p>Then reload this page.</p>
</body></html>"""
        return HttpResponseServerError(body)
