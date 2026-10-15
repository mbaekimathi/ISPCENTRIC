"""
Allow CSRF from the current request host when hosted on cPanel.

Domains often change (addon domains / subdomains); this avoids hardcoding
DJANGO_CSRF_TRUSTED_ORIGINS for every hostname.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from django.http import HttpResponseServerError, JsonResponse

logger = logging.getLogger(__name__)

_SCHEMA_HINT_RE = re.compile(
    r"unknown column|doesn't exist|does not exist|no such table|table .* not found",
    re.IGNORECASE,
)

# OS / OEM captive probes. Keep in sync with core.mikrotik_connect.CAPTIVE_PROBE_HOSTS
# and ALLOWED_HOSTS — phones only pop the sign-in page when these resolve to us.
CAPTIVE_PROBE_HOSTS = {
    "www.msftconnecttest.com",
    "msftconnecttest.com",
    "dns.msftncsi.com",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "captive.apple.com",
    "www.apple.com",
    "www.appleiphonecell.com",
    "www.itools.info",
    "www.ibook.info",
    "www.airport.us",
    "www.thinkdifferent.us",
    "detectportal.firefox.com",
    "network-test.debian.org",
    "neverssl.com",
    "example.com",
    "connectivitycheck.platform.hicloud.com",
    "connectivitycheck.platform.hihonorcloud.com",
    "www.msftncsi.com",
    "ipv6.msftconnecttest.com",
}


def _is_unlisted_private_host(host: str) -> bool:
    """True for a private IPv4 Host header that ALLOWED_HOSTS would reject."""
    import ipaddress

    from django.conf import settings

    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if not address.is_private or address.is_loopback:
        return False
    allowed = {str(item).strip() for item in (settings.ALLOWED_HOSTS or ())}
    if "*" in allowed:
        return False
    return host not in allowed


class RealClientIpMiddleware:
    """
    Restore the client address when running behind nginx.

    Captive identification reads REMOTE_ADDR — the PPPoE session lookup matches
    it against /ppp/active — and a reverse proxy would otherwise make every
    request look like it came from the proxy itself. Only headers from a
    trusted proxy address are honoured, since X-Forwarded-For is spoofable.

    gunicorn bound to a unix socket often reports REMOTE_ADDR as empty; treat
    that as a local trusted hop so X-Real-IP / X-Forwarded-For still apply.
    Without this, multi-tenant captive probes 404 (org cannot be resolved).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.conf import settings

        trusted = set(getattr(settings, "TRUSTED_PROXY_IPS", ()) or ())
        remote = (request.META.get("REMOTE_ADDR") or "").strip()
        # Empty / unix: nginx → gunicorn.sock (common VPS layout).
        from_trusted_hop = remote in trusted or remote in {"", "unix"}
        if from_trusted_hop:
            client = (request.META.get("HTTP_X_REAL_IP") or "").strip()
            if not client:
                forwarded = (request.META.get("HTTP_X_FORWARDED_FOR") or "").split(",")
                client = forwarded[0].strip() if forwarded else ""
            if client:
                request.META["REMOTE_ADDR"] = client
        return self.get_response(request)


class CaptiveHostRewriteMiddleware:
    """
    Rewrite foreign Host headers from captive probes / transparent NAT.

    Expired PPPoE clients are dst-nat'd to Django with Host: www.msftconnect…
    which would otherwise 400 DisallowedHost before any view runs. Replace the
    Host with PUBLIC_BASE_URL so CommonMiddleware accepts the request.

    The original Host is kept on the request so HotspotCaptiveProbeMiddleware
    can still recognize the probe after rewrite (otherwise Android/iOS probes
    look like normal billing traffic and never 302 to /pay).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        raw_host = (request.META.get("HTTP_HOST") or "").strip()
        host = raw_host.split(":")[0].strip().lower()
        remote = (request.META.get("REMOTE_ADDR") or "").strip()
        rewrite = host in CAPTIVE_PROBE_HOSTS
        if not rewrite:
            try:
                from core.mikrotik_connect import (
                    is_cpe_renew_pool_ip,
                    is_hotspot_pool_ip,
                    is_pppoe_pool_ip,
                )

                rewrite = (
                    is_pppoe_pool_ip(remote)
                    or is_hotspot_pool_ip(remote)
                    or is_cpe_renew_pool_ip(remote)
                )
            except Exception:
                rewrite = False
        if not rewrite:
            # A captive client that opens the gateway IP directly arrives with the
            # router's address as Host. Without this it is a 400 DisallowedHost
            # error page instead of the payment page.
            rewrite = _is_unlisted_private_host(host)
        if rewrite:
            # Preserve before mutating — probe middleware runs after this.
            request.captive_original_host = host
            request.META["HTTP_X_CAPTIVE_ORIGINAL_HOST"] = host
            from django.conf import settings

            try:
                from core.hotspot_portal import (
                    prefer_http_captive_url,
                    preferred_lan_ipv4,
                    public_base_url,
                )

                base = prefer_http_captive_url(
                    public_base_url(request)
                    or (getattr(settings, "PUBLIC_BASE_URL", "") or "").strip()
                )
            except Exception:
                base = (getattr(settings, "PUBLIC_BASE_URL", "") or "").strip()
                preferred_lan_ipv4 = None  # type: ignore[assignment]
            parsed = urlparse(base)
            if parsed.hostname:
                port = f":{parsed.port}" if parsed.port else ""
                request.META["HTTP_HOST"] = f"{parsed.hostname}{port}"
            else:
                # Never leave a probe/private Host in place — CommonMiddleware
                # would 400 DisallowedHost before HotspotCaptiveProbeMiddleware.
                # Hosted: prefer a public ALLOWED_HOSTS entry (phones cannot
                # reach the VPS LAN IP). Local DEBUG: prefer this machine's LAN.
                fallback = ""
                hosted = bool(getattr(settings, "HOSTED", False))
                if not hosted:
                    try:
                        fallback = (
                            (preferred_lan_ipv4() or "").strip()
                            if preferred_lan_ipv4
                            else ""
                        )
                    except Exception:
                        fallback = ""
                if not fallback:
                    for candidate in getattr(settings, "ALLOWED_HOSTS", []) or []:
                        candidate = (candidate or "").strip()
                        if (
                            candidate
                            and candidate != "*"
                            and not candidate.startswith(".")
                            and candidate.lower() not in CAPTIVE_PROBE_HOSTS
                        ):
                            # Skip private IPs on hosted — same dead-end as above.
                            if hosted:
                                try:
                                    import ipaddress

                                    addr = ipaddress.ip_address(candidate)
                                    if addr.is_private:
                                        continue
                                except ValueError:
                                    pass
                            fallback = candidate
                            break
                if fallback:
                    if (
                        not hosted
                        and getattr(settings, "DEBUG", False)
                        and ":" not in fallback
                    ):
                        # Local runserver listens on :8000; keep Host consistent.
                        fallback = f"{fallback}:8000"
                    request.META["HTTP_HOST"] = fallback
        return self.get_response(request)


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


_CAPTIVE_PORTAL_PATH_RE = re.compile(
    r"^/(hotspot|pppoe)/[^/]+/"
    r"(pay|reconnect|pause|voucher|welcome|status)(/|$)",
    re.IGNORECASE,
)


def is_captive_portal_path(path: str) -> bool:
    """True for Hotspot/PPPoE captive sheets that must stay on plain HTTP."""
    return bool(_CAPTIVE_PORTAL_PATH_RE.search((path or "").split("?", 1)[0]))


class CaptivePortalHttpMiddleware:
    """
    Captive Hotspot/PPPoE pay pages on HTTP and HTTPS.

    MikroTik walled-garden/ip allows the billing host on both :80 and :443.
    After public TLS is enabled, Chrome/Edge HTTPS-First often upgrades pay
    URLs to https://. Redirecting those back to http:// fights the browser
    (upgrade ↔ redirect) or times out when :443 never completes. Serve the
    page on whichever scheme arrived, and strip HSTS so phones are not
    permanently pinned to HTTPS after an admin visit.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path or ""
        response = self.get_response(request)
        if is_captive_portal_path(path):
            # Undo any HSTS from an earlier https admin visit / misconfig.
            if "Strict-Transport-Security" in response:
                del response["Strict-Transport-Security"]
            # Phone sign-in sheets often show the pay page inside a frame.
            # DENY leaves the user on the router "Opening payment page" bounce.
            if "X-Frame-Options" in response:
                del response["X-Frame-Options"]
            csp = response.get("Content-Security-Policy") or ""
            if "frame-ancestors 'none'" in csp:
                response["Content-Security-Policy"] = csp.replace(
                    "frame-ancestors 'none'",
                    "frame-ancestors *",
                )
            response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response["Pragma"] = "no-cache"
        return response


class HotspotCaptiveProbeMiddleware:
    """
    Turn OS captive-portal probes into the Hotspot or PPPoE payment / pause page.

    MikroTik DNS points probe hostnames at the gateway; a dst-nat rule forwards
    gateway:80 to Django. Windows opens ``/redirect`` on msftconnecttest.com —
    without this handler that request 404s instead of showing the captive page.

    Expired PPPoE sessions are dst-nat'd the same way; their REMOTE_ADDR sits in
    the PPPoE pool, so they land on ``/pppoe/…/pay/``.

    CaptiveHostRewriteMiddleware may have already replaced the Host header —
    always also check ``request.captive_original_host``.
    """

    CAPTIVE_HOSTS = CAPTIVE_PROBE_HOSTS
    CAPTIVE_PATHS = {
        "/redirect",
        "/connecttest.txt",
        "/ncsi.txt",
        "/generate_204",
        "/gen_204",
        "/hotspot-detect.html",
        "/library/test/success.html",
        "/success.txt",
        "/kindle-wifi/wifistub.html",
        "/success.html",
        # Some Android builds probe the site root after DNS hijack.
        "/",
    }

    def __init__(self, get_response):
        self.get_response = get_response

    @staticmethod
    def _original_probe_host(request) -> str:
        original = getattr(request, "captive_original_host", None) or (
            request.META.get("HTTP_X_CAPTIVE_ORIGINAL_HOST") or ""
        )
        if original:
            return str(original).split(":")[0].strip().lower()
        return (request.get_host() or "").split(":")[0].strip().lower()

    def __call__(self, request):
        path = request.path or "/"
        # Never intercept the real payment/welcome app routes.
        if (
            path.startswith("/hotspot/")
            or path.startswith("/pppoe/")
            or path.startswith("/billing/")
            or path.startswith("/static/")
            or path.startswith("/api/")
            or path.startswith("/accounts/")
            or path.startswith("/admin/")
        ):
            return self.get_response(request)

        host = self._original_probe_host(request)
        current_host = (
            (request.META.get("HTTP_HOST") or "").split(":")[0].strip().lower()
        )
        remote = (request.META.get("REMOTE_ADDR") or "").strip()
        from core.mikrotik_connect import (
            captive_redirect_cache_key,
            find_pppoe_customer_for_ip,
            is_cpe_renew_pool_ip,
            is_hotspot_pool_ip,
            is_pppoe_pool_ip,
            resolve_captive_organization,
        )

        # CPE renew Wi‑Fi (192.168.189.x) is for expired PPPoE homes — never treat
        # those phones as ISP Hotspot clients or they land on /hotspot/…/pay/.
        renew_or_pppoe_pool = is_pppoe_pool_ip(remote) or is_cpe_renew_pool_ip(remote)
        hotspot_client = is_hotspot_pool_ip(remote)
        probe_host = host in self.CAPTIVE_HOSTS or current_host in self.CAPTIVE_HOSTS
        # Root "/" alone is too broad for normal browsing — only treat it as a
        # probe when the Host (original or current) is a known captive hostname
        # or the client is already in a captive pool.
        path_is_probe = path in self.CAPTIVE_PATHS and (
            path != "/" or probe_host or renew_or_pppoe_pool or hotspot_client
        )
        if not (renew_or_pppoe_pool or hotspot_client or probe_host or path_is_probe):
            return self.get_response(request)

        from django.conf import settings
        from django.core.cache import cache
        from django.shortcuts import redirect
        from django.urls import reverse

        query = request.META.get("QUERY_STRING") or ""

        # Probe bursts hit this path many times per second. Cache the final URL by
        # client IP (generation-bumped on pause/resume/renew) so we do not re-walk
        # NAS identity on every generate_204. Pool/pay/pause are encoded in the
        # cached Location itself.
        cache_key = captive_redirect_cache_key(remote, query)
        cached_target = cache.get(cache_key)
        if cached_target:
            return redirect(cached_target)

        # Prefer the NAS/org that currently owns this client IP so multi-tenant
        # deployments do not send users to the wrong payment join_code.
        org = resolve_captive_organization(remote)
        if org is None and (renew_or_pppoe_pool or hotspot_client or probe_host):
            # Pool / probe clients must never fall through to a normal 200/404 —
            # that is the "other phones redirect, this one does not" report.
            # resolve_captive_organization already handles single-tenant and
            # service-scoped pool fallbacks; last resort is a global fallback
            # only when exactly one captive org exists in the fleet.
            try:
                from core.mikrotik_connect import _captive_org_candidates

                candidates = _captive_org_candidates()
                if len(candidates) == 1:
                    org = candidates[0]
            except Exception:
                org = None
        if org is None:
            return self.get_response(request)

        pppoe_customer = None
        try:
            pppoe_customer = find_pppoe_customer_for_ip(org, remote)
        except Exception:
            pppoe_customer = None
        # Expired PPPoE always opens /pppoe/…/pay/. The pay page itself sends a
        # frozen package on to the pause notice.
        prefer_pppoe = bool(renew_or_pppoe_pool or pppoe_customer is not None)

        # Every Hotspot sign-in opens the pay page. That page reconnects a
        # paid device and shows the pause notice when the package is frozen.
        hotspot_mac = ""
        if not prefer_pppoe:
            try:
                from core.mikrotik_connect import find_hotspot_mac_for_ip

                hotspot_mac = find_hotspot_mac_for_ip(org, remote) or ""
            except Exception:
                hotspot_mac = ""

        if prefer_pppoe:
            pay_path = reverse(
                "core:pppoe_pay",
                kwargs={"join_code": org.join_code},
            )
        else:
            pay_path = reverse(
                "core:hotspot_pay",
                kwargs={"join_code": org.join_code},
            )
        from core.hotspot_portal import (
            prefer_hotspot_open_url,
            prefer_http_captive_url,
            public_base_url,
        )

        try:
            base = prefer_http_captive_url(public_base_url(request) or "").rstrip("/")
        except Exception:
            base = prefer_http_captive_url(
                (getattr(settings, "PUBLIC_BASE_URL", "") or "").rstrip("/")
            )
        if not base:
            base = prefer_http_captive_url(
                request.build_absolute_uri("/")
            ).rstrip("/")
        # One http pay URL for both Hotspot and expired PPPoE. A bare billing
        # IPv4 is what left the sign-in sheet on the redirect page.
        target = prefer_hotspot_open_url(f"{base}{pay_path}")
        if query:
            target = f"{target}?{query}"
        if prefer_pppoe:
            # Attach a signed account token when we can resolve this PPP IP so the
            # renew page auto-fills even if a later /ppp/active lookup misses.
            try:
                from urllib.parse import urlencode

                from django.core import signing

                customer = pppoe_customer
                if customer is not None:
                    token = signing.dumps(
                        {
                            "cid": customer.pk,
                            "org": org.pk,
                            "mode": "pppoe",
                        },
                        salt="pppoe-payment",
                        compress=True,
                    )
                    params = {"t": token}
                    account = (getattr(customer, "account_number", None) or "").strip()
                    if account:
                        params["account"] = account
                    sep = "&" if "?" in target else "?"
                    target = f"{target}{sep}{urlencode(params)}"
            except Exception:
                pass
        else:
            # Captive probes often skip RouterOS login.html, so attach MAC from
            # the earlier host-table lookup (do not walk NAS a second time).
            try:
                from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

                from core.mikrotik_connect import remember_hotspot_mac_for_ip

                if hotspot_mac:
                    remember_hotspot_mac_for_ip(org, remote, hotspot_mac)
                    parts = urlsplit(target)
                    q = parse_qs(parts.query, keep_blank_values=True)
                    if not q.get("mac"):
                        q["mac"] = [hotspot_mac]
                        target = urlunsplit(
                            (
                                parts.scheme,
                                parts.netloc,
                                parts.path,
                                urlencode(q, doseq=True),
                                parts.fragment,
                            )
                        )
            except Exception:
                pass
        try:
            # Short TTL: OS probe bursts stay instant. Only cache when the
            # client IP is already in a known pool (or a PPP session matched)
            # so multi-tenant fallback guesses never stick a wrong join_code.
            if renew_or_pppoe_pool or hotspot_client or pppoe_customer is not None:
                cache.set(cache_key, target, 5)
        except Exception:
            pass
        return redirect(target)


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

        wants_json = "application/json" in (request.headers.get("Accept") or "")
        if not wants_json:
            path = request.path or ""
            if "/pay/" in path or "/voucher/" in path:
                wants_json = True

        if wants_json:
            if repaired:
                return JsonResponse(
                    {
                        "ok": False,
                        "error": "Database was updated. Refresh the page and try again.",
                        "schema_repaired": True,
                    },
                    status=500,
                )
            return JsonResponse(
                {
                    "ok": False,
                    "error": (
                        "Database update needed. Ask the ISP admin to run "
                        "migrations on the server, then retry."
                    ),
                    "schema_repaired": False,
                },
                status=500,
            )

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
