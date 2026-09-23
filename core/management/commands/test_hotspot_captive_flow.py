"""
Verify Hotspot captive portal HTTP endpoints (run on VPS after deploy).

Usage:
    python manage.py test_hotspot_captive_flow --join-code 534970
    python manage.py test_hotspot_captive_flow --join-code 534970 --base http://127.0.0.1:8000
"""

from __future__ import annotations

import urllib.error
import urllib.request
from urllib.parse import urlparse

from django.core.management.base import BaseCommand, CommandError
from django.test import Client


def _http_host_from_base(base: str) -> str:
    """Host header Django expects (PUBLIC_BASE_URL domain, not testserver)."""
    candidate = (base or "").strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    parsed = urlparse(candidate)
    return (parsed.netloc or parsed.path.split("/")[0] or "").strip()


class Command(BaseCommand):
    help = "Loop-check Hotspot captive URLs until pay page and login HTML endpoints respond."

    def add_arguments(self, parser):
        parser.add_argument(
            "--join-code",
            required=True,
            help="Organization join code (e.g. 534970).",
        )
        parser.add_argument(
            "--base",
            default="",
            help="Optional origin override (default: PUBLIC_BASE_URL / request host).",
        )
        parser.add_argument(
            "--loops",
            type=int,
            default=3,
            help="How many times to run the full check sequence.",
        )

    def handle(self, *args, **options):
        from accounts.models import Organization
        from core.hotspot_portal import hotspot_portal_urls
        from core.mikrotik_connect import (
            _captive_pay_redirect_html,
            _hotspot_captive_login_fetch_url,
            _MIN_HOTSPOT_LOGIN_BYTES,
        )

        join_code = (options.get("join_code") or "").strip()
        loops = max(1, int(options.get("loops") or 1))
        org = Organization.objects.filter(join_code=join_code).first()
        if org is None:
            raise CommandError(f"No organization with join_code={join_code!r}")

        urls = hotspot_portal_urls(join_code)
        base = (options.get("base") or urls.get("base_url") or "").strip().rstrip("/")
        if not base:
            raise CommandError("No base URL — set PUBLIC_BASE_URL or pass --base")

        http_host = _http_host_from_base(base)
        if not http_host:
            raise CommandError(f"Could not parse HTTP host from base URL {base!r}")

        pay_url = urls.get("pay_url") or ""
        captive_fetch = _hotspot_captive_login_fetch_url(pay_url)
        paths = {
            "captive-login": f"/hotspot/{join_code}/captive-login/",
            "reconnect": f"/hotspot/{join_code}/reconnect/?mac=AA:BB:CC:DD:EE:FF",
            "pay": f"/hotspot/{join_code}/pay/?mac=AA:BB:CC:DD:EE:FF",
        }

        client = Client()
        failures = 0

        for loop in range(1, loops + 1):
            self.stdout.write(f"\n=== Loop {loop}/{loops} ===")
            for label, path in paths.items():
                response = client.get(path, follow=False, HTTP_HOST=http_host)
                status = response.status_code
                body_len = len(response.content or b"")
                ok = status in {200, 302}
                if label == "captive-login":
                    ok = ok and body_len >= _MIN_HOTSPOT_LOGIN_BYTES
                    ok = ok and b"mac=$(mac)" in response.content
                if label == "reconnect":
                    ok = status == 302 and "pay" in (response.get("Location") or "")
                if label == "pay":
                    ok = status == 200 and body_len > 5000
                style = self.style.SUCCESS if ok else self.style.ERROR
                self.stdout.write(
                    style(f"{label}: HTTP {status} len={body_len} {'OK' if ok else 'FAIL'}")
                )
                if not ok:
                    failures += 1

            if captive_fetch:
                try:
                    with urllib.request.urlopen(captive_fetch, timeout=15) as resp:
                        remote_len = len(resp.read() or b"")
                    ok = remote_len >= _MIN_HOTSPOT_LOGIN_BYTES
                    style = self.style.SUCCESS if ok else self.style.ERROR
                    self.stdout.write(
                        style(
                            f"fetch-src {captive_fetch}: len={remote_len} "
                            f"{'OK' if ok else 'FAIL'}"
                        )
                    )
                    if not ok:
                        failures += 1
                except urllib.error.URLError as exc:
                    failures += 1
                    self.stdout.write(self.style.ERROR(f"fetch-src unreachable: {exc}"))

            sample_html = _captive_pay_redirect_html(pay_url)
            ok = len(sample_html) >= _MIN_HOTSPOT_LOGIN_BYTES and "mac=$(mac)" in sample_html
            self.stdout.write(
                (self.style.SUCCESS if ok else self.style.ERROR)(
                    f"login.html template len={len(sample_html)} {'OK' if ok else 'FAIL'}"
                )
            )
            if not ok:
                failures += 1

        if failures:
            raise CommandError(
                f"Hotspot captive flow check failed ({failures} issue(s)). "
                "Fix billing URLs, deploy, then sync_nas_config --force."
            )
        self.stdout.write(
            self.style.SUCCESS(
                f"Hotspot captive flow OK for join_code={join_code} ({loops} loop(s))."
            )
        )
