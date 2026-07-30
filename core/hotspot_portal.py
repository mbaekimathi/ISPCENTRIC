"""Helpers for public Hotspot / captive-portal URLs reachable from routers and phones."""

from __future__ import annotations

from urllib.parse import urlparse

from django.conf import settings
from django.urls import reverse


def is_loopback_url(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").strip().lower()
    except Exception:
        return False
    return host in {"localhost", "127.0.0.1", "::1"}


def public_base_url(request=None) -> str:
    """
    Prefer PUBLIC_BASE_URL when it is reachable from LAN/WAN devices.

    Falls back to the current request host. Loopback bases work for local
    browser previews but not for phones on Hotspot Wi‑Fi.
    """
    configured = (getattr(settings, "PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
    if configured and not is_loopback_url(configured):
        return configured
    if request is not None:
        try:
            return request.build_absolute_uri("/").rstrip("/")
        except Exception:
            pass
    return configured


def public_absolute_url(path: str, request=None) -> str:
    path = path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    base = public_base_url(request)
    if base:
        return f"{base}{path}"
    if request is not None:
        return request.build_absolute_uri(path)
    return path


def hotspot_portal_urls(join_code: str, request=None) -> dict[str, str]:
    """Absolute URLs for Hotspot portal pages pushed to MikroTik."""
    login_path = reverse("core:hotspot_portal_login_page", kwargs={"join_code": join_code})
    alogin_path = reverse("core:hotspot_alogin_page", kwargs={"join_code": join_code})
    welcome_path = reverse("core:hotspot_welcome", kwargs={"join_code": join_code})
    pay_path = reverse("core:hotspot_pay", kwargs={"join_code": join_code})
    return {
        "login_path": login_path,
        "alogin_path": alogin_path,
        "welcome_path": welcome_path,
        "pay_path": pay_path,
        "login_url": public_absolute_url(login_path, request),
        "alogin_url": public_absolute_url(alogin_path, request),
        "welcome_url": public_absolute_url(welcome_path, request),
        "pay_url": public_absolute_url(pay_path, request),
        "base_url": public_base_url(request),
        "base_is_loopback": is_loopback_url(public_base_url(request) or ""),
    }
