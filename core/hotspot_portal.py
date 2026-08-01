"""Helpers for public Hotspot / captive-portal URLs reachable from routers and phones."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from django.conf import settings
from django.urls import reverse


def is_loopback_url(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").strip().lower()
    except Exception:
        return False
    return host in {"localhost", "127.0.0.1", "::1"}


def local_ipv4_addresses() -> set[str]:
    """Every IPv4 address this machine currently answers on."""
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except OSError:
        pass
    # getaddrinfo misses interfaces on some Windows setups; ask the routing table
    # which source address would be used for an off-link destination.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 53))
        found.add(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()
    return {ip for ip in found if ip}


def unreachable_base_url_reason(url: str) -> str:
    """
    Explain why captive clients cannot load this base URL, or "" when it is fine.

    A private IPv4 that this machine does not own is the failure worth catching:
    the portal URL is pushed to the router and handed to phones, so a stale
    address from an earlier network silently breaks every payment redirect while
    the app itself keeps working on localhost.
    """
    host = ""
    try:
        host = (urlparse(url or "").hostname or "").strip()
    except Exception:
        return ""
    if not host:
        return ""

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # Hostnames resolve through DNS wherever the client sits; not our call.
        return ""
    if address.is_loopback or address.version != 4:
        return ""
    # A public address usually reaches the server through NAT or a proxy.
    if not address.is_private:
        return ""
    if host in local_ipv4_addresses():
        return ""
    return (
        f"PUBLIC_BASE_URL points at {host}, but this server has no such address. "
        "Hotspot clients are redirected there and get a dead page. Set "
        "PUBLIC_BASE_URL to this machine's LAN IP, add it to DJANGO_ALLOWED_HOSTS, "
        "restart with `python manage.py runserver 0.0.0.0:8000`, then push Hotspot again."
    )


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
        "base_unreachable_reason": unreachable_base_url_reason(
            public_base_url(request) or ""
        ),
    }
