"""Helpers for public Hotspot / captive-portal URLs reachable from routers and phones."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from django.conf import settings
from django.urls import reverse

_AUTO_SENTINELS = frozenset({"", "auto", "detect", "lan", "local"})


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


def _wireguard_network() -> ipaddress.IPv4Network | None:
    raw = (getattr(settings, "WIREGUARD_SUBNET", "") or "10.9.0.0/24").strip()
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None
    if isinstance(net, ipaddress.IPv4Network):
        return net
    return None


def _default_route_ipv4() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 53))
        return (probe.getsockname()[0] or "").strip()
    except OSError:
        return ""
    finally:
        probe.close()


def preferred_lan_ipv4() -> str:
    """
    Best private IPv4 for Hotspot clients on the same LAN as this server.

    Skips loopback, link-local, and the WireGuard tunnel subnet (phones on Wi‑Fi
    cannot reach 10.9.0.x). Prefers the default-route source address.
    """
    wg = _wireguard_network()
    usable: list[str] = []
    for ip in local_ipv4_addresses():
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_link_local:
            continue
        if not addr.is_private:
            continue
        if wg is not None and addr in wg:
            continue
        usable.append(str(addr))
    if not usable:
        return ""

    route_ip = _default_route_ipv4()
    if route_ip in usable:
        return route_ip

    def sort_key(ip: str) -> tuple[int, str]:
        addr = ipaddress.IPv4Address(ip)
        if addr in ipaddress.ip_network("192.168.0.0/16"):
            return (0, ip)
        if addr in ipaddress.ip_network("10.0.0.0/8"):
            return (1, ip)
        return (2, ip)

    return sorted(usable, key=sort_key)[0]


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
        "PUBLIC_BASE_URL to this machine's LAN IP (or auto), add it to "
        "DJANGO_ALLOWED_HOSTS, restart with `python manage.py runserver 0.0.0.0:8000`, "
        "then push Hotspot again."
    )


def _is_hosted() -> bool:
    return bool(getattr(settings, "HOSTED", False))


def _normalize_configured_base(raw: str) -> str:
    value = (raw or "").strip().rstrip("/")
    if value.lower() in _AUTO_SENTINELS:
        return ""
    return value


def _host_is_private_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address((host or "").strip())
    except ValueError:
        return False
    return bool(addr.version == 4 and addr.is_private)


def _configured_base_is_usable(url: str) -> bool:
    """True when this URL is safe to push to Hotspot clients as-is."""
    if not url or is_loopback_url(url):
        return False
    if unreachable_base_url_reason(url):
        return False
    host = ""
    try:
        host = (urlparse(url).hostname or "").strip()
    except Exception:
        return False
    if not host:
        return False
    # Hosted leftovers often keep a local LAN IP from a copied .env. Phones at
    # remote sites cannot reach that address — ignore it and use the public host.
    if _is_hosted() and _host_is_private_ip(host):
        return False
    return True


def _port_from_url(url: str) -> int | None:
    try:
        port = urlparse(url or "").port
    except Exception:
        return None
    return int(port) if port else None


def _local_http_port(configured: str = "", request=None) -> int:
    """Port Hotspot clients should use for the local Django server."""
    for candidate in (configured,):
        port = _port_from_url(candidate)
        if port:
            return port
    if request is not None:
        try:
            port = request.get_port()
            if port:
                return int(port)
        except Exception:
            pass
    if getattr(settings, "DEBUG", False):
        return 8000
    return 80


def _format_base(scheme: str, host: str, port: int | None = None) -> str:
    scheme = (scheme or "http").strip().lower() or "http"
    host = (host or "").strip().rstrip("/")
    if not host:
        return ""
    if port and port not in (80, 443):
        return f"{scheme}://{host}:{port}"
    if port == 443:
        return f"https://{host}"
    if port == 80:
        return f"http://{host}"
    return f"{scheme}://{host}"


def auto_local_base_url(configured: str = "", request=None) -> str:
    """Build http://<lan-ip>:<port> from interfaces this machine owns."""
    ip = preferred_lan_ipv4()
    if not ip:
        return ""
    port = _local_http_port(configured, request)
    return _format_base("http", ip, port)


def hosted_fallback_base_url(request=None) -> str:
    """
    Public host for a hosted deploy when PUBLIC_BASE_URL is missing/stale.

    Prefer the current request host, then the first concrete ALLOWED_HOSTS entry.
    Always http:// for captive Hotspot interception.
    """
    if request is not None:
        try:
            host = (request.get_host() or "").split(":")[0].strip()
        except Exception:
            host = ""
        if host and host != "*" and not is_loopback_url(f"http://{host}"):
            if not _host_is_private_ip(host):
                return _format_base("http", host)
    for host in getattr(settings, "ALLOWED_HOSTS", []) or []:
        host = (host or "").strip()
        if not host or host == "*":
            continue
        if host.startswith("."):
            continue
        if is_loopback_url(f"http://{host}"):
            continue
        if host in {
            "www.msftconnecttest.com",
            "msftconnecttest.com",
            "dns.msftncsi.com",
            "connectivitycheck.gstatic.com",
            "clients3.google.com",
            "captive.apple.com",
            "www.apple.com",
            "detectportal.firefox.com",
            "neverssl.com",
            "example.com",
            "10.10.0.1",
        }:
            continue
        if _host_is_private_ip(host):
            continue
        return _format_base("http", host)
    return ""


def public_base_url(request=None) -> str:
    """
    Absolute origin Hotspot clients (and STK callbacks) should use.

    Local: use a reachable PUBLIC_BASE_URL, otherwise auto-pick this machine's
    LAN IPv4 (never a stale .env address from another network).

    Hosted: use PUBLIC_BASE_URL when it is a public host/IP; ignore leftover
    private LAN URLs from local .env copies; fall back to the request host or
    ALLOWED_HOSTS.
    """
    configured = _normalize_configured_base(
        getattr(settings, "PUBLIC_BASE_URL", "") or ""
    )

    if configured and _configured_base_is_usable(configured):
        return configured

    if request is not None:
        try:
            req_base = request.build_absolute_uri("/").rstrip("/")
        except Exception:
            req_base = ""
        if req_base and _configured_base_is_usable(req_base):
            return req_base
        # Local request on the LAN IP we own (even if PUBLIC_BASE_URL was stale).
        if (
            req_base
            and not is_loopback_url(req_base)
            and not unreachable_base_url_reason(req_base)
            and not (_is_hosted() and _host_is_private_ip(urlparse(req_base).hostname or ""))
        ):
            return req_base

    if _is_hosted():
        return hosted_fallback_base_url(request) or ""

    auto = auto_local_base_url(configured, request)
    if auto:
        return auto

    # Last resort: keep configured (may be loopback for browser previews).
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
    base = public_base_url(request)
    configured = _normalize_configured_base(
        getattr(settings, "PUBLIC_BASE_URL", "") or ""
    )
    # Surface stale configured values even when we auto-healed the effective base.
    configured_reason = (
        unreachable_base_url_reason(configured)
        if configured and configured.rstrip("/") != (base or "").rstrip("/")
        else ""
    )
    effective_reason = unreachable_base_url_reason(base or "")
    return {
        "login_path": login_path,
        "alogin_path": alogin_path,
        "welcome_path": welcome_path,
        "pay_path": pay_path,
        "login_url": public_absolute_url(login_path, request),
        "alogin_url": public_absolute_url(alogin_path, request),
        "welcome_url": public_absolute_url(welcome_path, request),
        "pay_url": public_absolute_url(pay_path, request),
        "base_url": base,
        "base_is_loopback": is_loopback_url(base or ""),
        "base_unreachable_reason": effective_reason or configured_reason,
        "base_auto_selected": bool(
            base
            and configured
            and base.rstrip("/") != configured.rstrip("/")
        )
        or bool(base and not configured),
    }
