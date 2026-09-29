"""
WireGuard peering between the billing server and each MikroTik.

A hosted billing server cannot reach a MikroTik that sits behind NAT on a
customer site, and every provisioning call in mikrotik_connect dials *out* to
the router's API. The router therefore establishes a tunnel to the VPS and the
app talks to it on a stable tunnel address instead of its LAN address.

Keys are X25519, the same primitive WireGuard uses, so `cryptography` (already
a dependency) can generate them without shelling out to `wg`.
"""

from __future__ import annotations

import base64
import ipaddress
import logging
import os
import shlex
import shutil
import socket
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from django.conf import settings

logger = logging.getLogger(__name__)


def router_keepalive_interval() -> str:
    """RouterOS persistent-keepalive toward the VPS (NAT traversal)."""
    try:
        sec = int(os.getenv("WIREGUARD_KEEPALIVE_SEC", "15"))
    except (TypeError, ValueError):
        sec = 15
    sec = max(5, min(sec, 120))
    return f"{sec}s"


def handshake_max_age_sec() -> int:
    """Treat WireGuard as stale when last handshake is older than this."""
    try:
        return max(60, int(os.getenv("WIREGUARD_HANDSHAKE_MAX_AGE_SEC", "180")))
    except (TypeError, ValueError):
        return 180


def _handshake_fresh(handshake_age_sec) -> bool:
    if handshake_age_sec is None:
        return False
    try:
        return int(handshake_age_sec) <= handshake_max_age_sec()
    except (TypeError, ValueError):
        return False


def generate_keypair() -> tuple[str, str]:
    """Return (private_key, public_key) base64-encoded as WireGuard expects."""
    private = X25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(private_bytes).decode(),
        base64.b64encode(public_bytes).decode(),
    )


def public_key_for(private_key: str) -> str:
    """Derive the public key from a stored private key."""
    raw = base64.b64decode((private_key or "").strip())
    public = X25519PrivateKey.from_private_bytes(raw).public_key()
    return base64.b64encode(
        public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode()


def tunnel_network() -> ipaddress.IPv4Network:
    return ipaddress.ip_network(
        getattr(settings, "WIREGUARD_SUBNET", "") or "10.9.0.0/24"
    )


def server_address() -> ipaddress.IPv4Address:
    """First usable address in the tunnel subnet belongs to the VPS."""
    return next(tunnel_network().hosts())


def allocate_address(exclude: set[str] | None = None) -> str:
    """
    Pick the lowest free tunnel address.

    The server holds the first host address, so peers start one above it.
    """
    from core.models import MikroTikRouter, WireGuardReservation

    taken = {
        (value or "").strip()
        for value in MikroTikRouter.objects.exclude(vpn_address__isnull=True)
        .values_list("vpn_address", flat=True)
    }
    taken |= {
        (value or "").strip()
        for value in WireGuardReservation.objects.values_list("address", flat=True)
    }
    taken |= {str(server_address())}
    taken |= set(exclude or set())

    for candidate in tunnel_network().hosts():
        text = str(candidate)
        if text not in taken:
            return text
    raise ValueError(
        f"No free address left in the WireGuard subnet {tunnel_network()}. "
        "Widen WIREGUARD_SUBNET."
    )


def allocate_lan_address(exclude: set[str] | None = None) -> str:
    """Return the stock MikroTik LAN gateway for the Winbox script."""
    return "192.168.88.1"


def server_on_tunnel() -> bool:
    """
    True when this machine holds the tunnel's server address.

    A router dials the VPS, so only the VPS can reach peer addresses like
    10.9.0.4. A laptop running the app on localhost has no wg interface and
    every probe to the tunnel subnet times out — worth saying plainly instead
    of polling forever. Binding to the address succeeds only when it is
    configured locally, which needs no extra dependency or shelling out to wg.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind((str(server_address()), 0))
        return True
    except OSError:
        return False


def looks_like_wg_key(value: str) -> bool:
    """True for a base64-encoded 32-byte WireGuard key (not a placeholder)."""
    value = (value or "").strip()
    if len(value) != 44 or "<" in value or " " in value:
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except Exception:
        return False


def configured() -> bool:
    """True when the VPS endpoint and a real public key are set."""
    endpoint = (getattr(settings, "WIREGUARD_ENDPOINT", "") or "").strip()
    key = (getattr(settings, "WIREGUARD_SERVER_PUBLIC_KEY", "") or "").strip()
    return bool(endpoint and ":" in endpoint and looks_like_wg_key(key))


def tunnel_endpoint() -> str:
    """Configured VPS endpoint, or a placeholder when it is not set yet."""
    return (getattr(settings, "WIREGUARD_ENDPOINT", "") or "").strip() or "the billing VPS"


def _endpoint() -> str:
    endpoint = (getattr(settings, "WIREGUARD_ENDPOINT", "") or "").strip()
    if not endpoint:
        raise ValueError(
            "WIREGUARD_ENDPOINT is not set. Add it to .env as host:port, "
            "for example isp.richcom.co.ke:51820."
        )
    return endpoint


def _resolved_endpoint_host(host: str) -> str:
    """
    Prefer a literal IPv4 in generated scripts so MikroTiks without DNS still
    dial the billing VPS (common on fresh routers with empty /ip dns servers).
    """
    host = (host or "").strip()
    if not host:
        return host
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
        if infos:
            return str(infos[0][4][0])
    except OSError as exc:
        logger.warning("Could not resolve WireGuard endpoint host %s: %s", host, exc)
    return host


def _router_listen_port(address: str) -> int:
    """Unique UDP port per tunnel IP so several MikroTiks behind one NAT can coexist."""
    try:
        last = int(str(address).rsplit(".", 1)[-1])
    except (TypeError, ValueError):
        last = 31
    return 13200 + max(1, min(last, 254))


def probe_router_wg_listen(
    host: str,
    address: str,
    *,
    timeout: float = 0.55,
) -> bool | None:
    """
    Credential-free guess for the ISPCENTRIC WireGuard listen-port.

    Returns:
      False — port clearly closed (ICMP unreachable / connection reset)
      None  — inconclusive (timeouts are common for both open and filtered-closed)
      True  — only if the peer sends any UDP reply (rare for WireGuard junk)

    Never treat a bare timeout as installed — factory-reset routers often time out
    the same way and would false-pass the Winbox-script check.
    """
    host = (host or "").strip()
    address = (address or "").strip()
    if not host or not address:
        return None
    port = _router_listen_port(address)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"\x01" + b"\x00" * 15, (host, port))
        try:
            sock.recvfrom(64)
            return True
        except TimeoutError:
            return None
        except ConnectionRefusedError:
            return False
        except OSError as exc:
            # Windows: WSAECONNRESET (10054) when ICMP port unreachable.
            if getattr(exc, "winerror", None) == 10054 or getattr(exc, "errno", None) in {
                10054,
                111,
                61,
            }:
                return False
            return None
    except OSError:
        return None
    finally:
        sock.close()


def script_ready_identity(address: str) -> str:
    """RouterOS identity set by the Winbox paste so LAN Check can see it via MNDP (no login)."""
    address = (address or "").strip()
    return f"ispcentric.{address}" if address else "ispcentric"


def identity_marks_script_ready(identity: str, address: str = "") -> bool:
    """True when a discovered MikroTik identity proves the ISPCENTRIC paste ran."""
    text = (identity or "").strip().lower()
    if not text.startswith("ispcentric."):
        return False
    address = (address or "").strip().lower()
    if not address:
        return True
    return address in text


def lan_tunnel_script_installed(
    host: str,
    address: str,
    *,
    username: str = "",
    password: str = "",
    identity: str = "",
    devices: list | None = None,
    timeout: float = 1.2,
) -> dict[str, object]:
    """
    Detect whether the Connect paste ran on a LAN router — without requiring login.

    Primary proof: MNDP / discovery identity ``ispcentric.<tunnel-ip>`` (set by the script).
    Optional: RouterOS API when credentials are already known.
    """
    host = (host or "").strip()
    address = (address or "").strip()
    username = (username or "").strip()
    marker = script_ready_identity(address)
    result: dict[str, object] = {
        "installed": False,
        "via": "",
        "listen_port": _router_listen_port(address) if address else 0,
        "marker": marker,
        "error": "",
        "needs_login": False,
    }
    if not address:
        result["error"] = "missing tunnel address"
        return result

    # 1) Identity from the candidate host / discovery list (no credentials).
    identities: list[str] = []
    if identity:
        identities.append(identity)
    for device in devices or []:
        if host and (device.get("host") or "").strip() != host:
            continue
        for key in ("identity", "name"):
            value = (device.get(key) or "").strip()
            if value:
                identities.append(value)
    for value in identities:
        if identity_marks_script_ready(value, address):
            result["installed"] = True
            result["via"] = "mndp"
            return result

    # Any discovered router advertising this paste marker (host may still be resolving).
    if not host:
        for device in devices or []:
            for key in ("identity", "name"):
                if identity_marks_script_ready(device.get(key) or "", address):
                    result["installed"] = True
                    result["via"] = "mndp"
                    return result

    # 2) Optional API confirmation when the user already typed a login (not required).
    if username and host:
        try:
            from core.mikrotik_connect import _api_session, _print

            with _api_session(
                host, username, password or "", timeout=timeout
            ) as sock:
                rows = [
                    row
                    for row in _print(sock, "/interface/wireguard", props=".id,name")
                    if (row.get("name") or "").strip() == "ispcentric-vpn"
                ]
                if rows:
                    result["installed"] = True
                    result["via"] = "api"
                    return result
                result["via"] = "api"
                result["error"] = (
                    "Logged in, but ispcentric-vpn is missing — paste the Winbox script"
                )
                return result
        except Exception as exc:
            result["error"] = str(exc)[:180]
            result["via"] = "api"

    result["error"] = (
        f"Paste the Winbox script and wait until identity becomes {marker} "
        "(then Check now). Login is only needed after all checks pass."
    )
    return result


def _server_public_key() -> str:
    key = (getattr(settings, "WIREGUARD_SERVER_PUBLIC_KEY", "") or "").strip()
    if not looks_like_wg_key(key):
        raise ValueError(
            "WIREGUARD_SERVER_PUBLIC_KEY is missing or invalid. Run "
            "`python manage.py wireguard_peer --server-keys` and put the "
            "public key in .env (not the placeholder text)."
        )
    return key


def _read_live_wg_interface_public_key() -> str:
    """Best-effort ``wg show <iface> public-key`` on the billing host."""
    iface = _wireguard_interface()
    wg_bin = shutil.which("wg") or "/usr/bin/wg"
    try:
        proc = subprocess.run(
            [wg_bin, "show", iface, "public-key"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if proc.returncode == 0:
            key = (proc.stdout or "").strip()
            if looks_like_wg_key(key):
                return key
    except Exception as exc:
        logger.debug("Could not read %s public-key: %s", iface, exc)
    return ""


def resolve_server_public_key(*, prefer_live: bool = True) -> str:
    """
    Public key embedded in MikroTik onboarding scripts.

    On a hosted VPS, prefer the live ``wg0`` key so Copy script matches ``wg show``
    even when ``.env`` drifted (common after manual wg0 rebuilds). Settings must
    still define a valid key — see ``_server_public_key()``.
    """
    configured = _server_public_key()
    if not prefer_live:
        return configured
    live = _read_live_wg_interface_public_key()
    if not live:
        return configured
    if live != configured:
        logger.warning(
            "WIREGUARD_SERVER_PUBLIC_KEY differs from live %s; "
            "onboarding scripts will embed the live interface public-key.",
            _wireguard_interface(),
        )
    return live


def _ros_quote_key(key: str) -> str:
    return (key or "").strip().replace("\\", "\\\\").replace('"', '\\"')


def _reservation_purge_enabled() -> bool:
    raw = (os.getenv("WIREGUARD_RESERVATION_PURGE_ENABLED") or "").strip().lower()
    if raw in {"0", "false", "no"}:
        return False
    if raw in {"1", "true", "yes"}:
        return True
    return bool(getattr(settings, "HOSTED", False))


def _reservation_never_handshake_grace_sec() -> float:
    """Drop pending onboardings that never handshook after this long."""
    try:
        hours = float(os.getenv("WIREGUARD_RESERVATION_NEVER_HANDSHAKE_HOURS", "6"))
    except (TypeError, ValueError):
        hours = 6.0
    return max(1.0, hours) * 3600.0


def _reservation_stale_handshake_sec() -> int:
    """Abandoned tunnel — router stopped dialing or keys were replaced."""
    try:
        days = float(os.getenv("WIREGUARD_RESERVATION_STALE_DAYS", "3"))
    except (TypeError, ValueError):
        days = 3.0
    return max(int(handshake_max_age_sec()), int(days * 86400))


def _clear_runtime_peers_for_address(
    address: str, *, except_public_key: str = ""
) -> int:
    """Remove every wg0 peer bound to ``address/32``, optionally keeping one key."""
    address = (address or "").strip()
    except_public_key = (except_public_key or "").strip()
    needle = f"{address}/32"
    if not address or not can_apply_server_peers():
        return 0

    rows, err = _run_wg_interface_dump()
    if err:
        return 0

    removed = 0
    for row in rows:
        public_key = (row.get("public_key") or "").strip()
        if not public_key or public_key == except_public_key:
            continue
        allowed = (row.get("allowed_ips") or "").replace(" ", ",")
        if needle not in allowed.split(","):
            continue
        if remove_server_peer(public_key).get("ok"):
            removed += 1
    return removed


def _remove_runtime_peers_for_address(address: str, keep_public_key: str) -> int:
    """
    Drop wg0 peers bound to ``address/32`` except ``keep_public_key``.

    Prevents stale onboarding keys from blocking handshakes for the same tunnel IP.
    """
    keep_public_key = (keep_public_key or "").strip()
    if not keep_public_key:
        return 0
    return _clear_runtime_peers_for_address(
        address, except_public_key=keep_public_key
    )


def live_tunnel_key_conflicts_with_reservation(reservation) -> bool:
    """
    True when the router is actively handshaking on wg0 with a different public key
    than the pending WireGuardReservation (stale Winbox paste / manual key edit).
    """
    public_key = (getattr(reservation, "public_key", None) or "").strip()
    address = (getattr(reservation, "address", None) or "").strip()
    if not public_key or not address:
        return False
    live = find_handshake_peer_for_address(address)
    live_key = (live.get("public_key") or "").strip()
    return bool(
        live.get("checked")
        and live_key
        and live_key != public_key
        and _handshake_fresh(live.get("handshake_age_sec"))
    )


def rotate_reservation_keys(reservation):
    """
    Issue a fresh keypair for a pending reservation, drop stale wg0 peers, re-sync.

    Returns ``(reservation, peer_sync)``. The MikroTik must receive a new full paste
    (Generate / Check now refreshes the script automatically).
    """
    old_public = (getattr(reservation, "public_key", None) or "").strip()
    address = (getattr(reservation, "address", None) or "").strip()
    if old_public:
        remove_server_peer(old_public)
    if address:
        _clear_runtime_peers_for_address(address)

    private_key, public_key = generate_keypair()
    reservation.private_key = private_key
    reservation.public_key = public_key
    reservation.save(update_fields=["private_key", "public_key"])

    label = (getattr(reservation, "label", None) or "").strip() or "MikroTik"
    peer_sync = apply_server_peer(label, address, public_key)
    logger.info(
        "Rotated WireGuard onboarding keys for %s (%s)",
        label,
        address or "?",
    )
    return reservation, peer_sync


def remove_server_peer(public_key: str) -> dict:
    """Remove one peer from runtime wg0 (best-effort; conf file may retain a stub)."""
    public_key = (public_key or "").strip()
    if not public_key or not configured():
        return {"ok": False, "skipped": True, "reason": "missing_key"}
    if not can_apply_server_peers():
        return {"ok": False, "skipped": True, "reason": "not_on_tunnel"}
    iface = _wireguard_interface()
    wg_bin = shutil.which("wg") or "/usr/bin/wg"
    try:
        proc = subprocess.run(
            [wg_bin, "set", iface, "peer", public_key, "remove"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0:
            return {"ok": True}
        err = (proc.stderr or proc.stdout or "wg peer remove failed").strip()
        return {"ok": False, "error": err}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _active_router_public_keys() -> set[str]:
    from core.models import MikroTikRouter

    keys: set[str] = set()
    for row in MikroTikRouter.objects.exclude(vpn_public_key="").values_list(
        "vpn_public_key", flat=True
    ):
        value = (row or "").strip()
        if value:
            keys.add(value)
    return keys


def _orphan_peer_prune_enabled() -> bool:
    raw = (os.getenv("WIREGUARD_PRUNE_ORPHAN_PEERS", "true") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _tunnel_peer_directory() -> tuple[dict[str, str], dict[str, str]]:
    """Return (tunnel_address -> public_key, public_key -> tunnel_address) from the DB."""
    from core.models import MikroTikRouter, WireGuardReservation

    by_addr: dict[str, str] = {}
    by_key: dict[str, str] = {}
    for row in MikroTikRouter.objects.exclude(vpn_address="").exclude(vpn_public_key=""):
        addr = (row.vpn_address or "").strip()
        pk = (row.vpn_public_key or "").strip()
        if addr and pk:
            by_addr[addr] = pk
            by_key[pk] = addr
    for res in WireGuardReservation.objects.all():
        addr = (res.address or "").strip()
        pk = (res.public_key or "").strip()
        if addr and pk:
            by_addr[addr] = pk
            by_key[pk] = addr
    return by_addr, by_key


def reconcile_runtime_allowed_ips() -> dict:
    """
    Fix wg0 peers that hold another site's ``/32`` or the wrong AllowedIPs list.

    Overlapping AllowedIPs send tunnel traffic to the wrong peer (handshake/API
    checks fail even when sync-server reports success).
    """
    if not can_apply_server_peers():
        return {"ok": False, "skipped": True, "reason": "not_on_tunnel", "fixed": 0}

    by_addr, by_key = _tunnel_peer_directory()
    rows, err = _run_wg_interface_dump()
    if err:
        return {"ok": False, "error": err, "fixed": 0}

    iface = _wireguard_interface()
    wg_bin = shutil.which("wg") or "/usr/bin/wg"
    fixed = 0
    errors: list[str] = []

    for addr, owner_pk in by_addr.items():
        removed = _remove_runtime_peers_for_address(addr, owner_pk)
        if removed:
            fixed += removed

    for row in rows:
        public_key = (row.get("public_key") or "").strip()
        canonical = by_key.get(public_key)
        if not public_key or not canonical:
            continue
        allowed_raw = (row.get("allowed_ips") or "").replace(" ", ",")
        allowed = [part for part in allowed_raw.split(",") if part]
        want = f"{canonical}/32"
        holds_foreign = False
        for cidr in allowed:
            if not cidr.endswith("/32"):
                continue
            addr = cidr[: -len("/32")]
            owner = by_addr.get(addr)
            if owner and owner != public_key:
                holds_foreign = True
                break
        if not holds_foreign and allowed == [want]:
            continue
        try:
            proc = subprocess.run(
                [wg_bin, "set", iface, "peer", public_key, "allowed-ips", want],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode == 0:
                fixed += 1
            else:
                errors.append(
                    (proc.stderr or proc.stdout or "wg set failed").strip()
                )
        except Exception as exc:
            errors.append(str(exc))

    if fixed:
        logger.info("Reconciled %s WireGuard runtime peer route(s) on wg0", fixed)
    return {"ok": not errors, "skipped": False, "fixed": fixed, "errors": errors}


def desired_server_peer_public_keys() -> set[str]:
    """Public keys that should exist on wg0 (onboarded routers + pending reservations)."""
    from core.models import WireGuardReservation

    keys = _active_router_public_keys()
    for row in WireGuardReservation.objects.exclude(public_key="").values_list(
        "public_key", flat=True
    ):
        value = (row or "").strip()
        if value:
            keys.add(value)
    return keys


def prune_orphan_runtime_peers() -> dict:
    """
    Drop wg0 peers that are not in the database (stale onboarding keys, manual adds).

    Runtime only — wg0.conf may still list removed peers until the next rebuild.
    """
    if not _orphan_peer_prune_enabled():
        return {"ok": True, "skipped": True, "pruned": 0, "public_keys": []}
    if not can_apply_server_peers():
        return {"ok": False, "skipped": True, "reason": "not_on_tunnel", "pruned": 0}

    desired = desired_server_peer_public_keys()
    rows, err = _run_wg_interface_dump()
    if err:
        return {"ok": False, "error": err, "pruned": 0, "public_keys": []}

    removed: list[str] = []
    errors: list[str] = []
    for row in rows:
        public_key = (row.get("public_key") or "").strip()
        if not public_key or public_key in desired:
            continue
        outcome = remove_server_peer(public_key)
        if outcome.get("ok"):
            removed.append(public_key)
        elif outcome.get("error"):
            errors.append(f"{public_key[:10]}…: {outcome['error']}")

    if removed:
        logger.info(
            "Pruned %s orphan WireGuard peer(s) from runtime wg0",
            len(removed),
        )
    return {
        "ok": not errors,
        "skipped": False,
        "pruned": len(removed),
        "public_keys": removed,
        "errors": errors,
    }


def reservation_connect_is_stale(reservation, *, keep: bool = False) -> bool:
    """
    True when a pending onboarding reservation will not pass Connect checks.

    ``keep`` skips purge for the site the operator is actively connecting.
    """
    if keep:
        return False
    from django.utils import timezone

    created_age = (
        timezone.now() - reservation.created_at
    ).total_seconds()
    grace = _reservation_never_handshake_grace_sec()
    stale_limit = _reservation_stale_handshake_sec()
    peer = inspect_server_peer((reservation.public_key or "").strip())
    age = peer.get("handshake_age_sec")
    if age is not None:
        try:
            return int(age) > stale_limit
        except (TypeError, ValueError):
            return created_age > grace
    if not peer.get("present"):
        return created_age > grace
    return created_age > grace


def reservation_for_address(address: str, *, organization=None):
    """Return a pending reservation when it belongs to the given ISP workspace."""
    address = (address or "").strip()
    if not address:
        return None
    from core.models import WireGuardReservation

    reservation = WireGuardReservation.objects.filter(address=address).first()
    if reservation is None:
        return None
    org_id = getattr(organization, "pk", organization)
    if org_id and reservation.organization_id not in (None, org_id):
        return None
    return reservation


def purge_stale_wireguard_reservations(
    *,
    keep_labels: set[str] | None = None,
    organization=None,
    remove_runtime_peers: bool = True,
) -> dict:
    """
    Delete abandoned WireGuardReservation rows and drop their wg0 peers.

    Called when generating a Connect script and during ``--sync-server`` so old
    onboarding attempts do not block the UI with ``handshake missing``.
    """
    from core.models import WireGuardReservation

    if not _reservation_purge_enabled():
        return {"ok": True, "skipped": True, "purged": 0, "labels": []}

    keep_norm = {
        (label or "").strip().lower()
        for label in (keep_labels or set())
        if (label or "").strip()
    }
    router_keys = _active_router_public_keys()
    purged_labels: list[str] = []
    errors: list[str] = []

    org_id = getattr(organization, "pk", organization)

    for reservation in list(WireGuardReservation.objects.order_by("id")):
        label = (reservation.label or "").strip()
        keep = label.lower() in keep_norm if label else False
        if keep and org_id and reservation.organization_id not in (None, org_id):
            keep = False
        if not reservation_connect_is_stale(reservation, keep=keep):
            continue
        public_key = (reservation.public_key or "").strip()
        address = (reservation.address or "").strip()
        if public_key in router_keys:
            continue
        if remove_runtime_peers and public_key:
            outcome = remove_server_peer(public_key)
            if not outcome.get("ok") and not outcome.get("skipped"):
                errors.append(
                    f"{address or label}: {outcome.get('error') or 'peer remove failed'}"
                )
        reservation.delete()
        purged_labels.append(label or address or public_key[:8])

    if purged_labels:
        logger.info(
            "Purged %s stale WireGuard reservation(s): %s",
            len(purged_labels),
            ", ".join(purged_labels[:8])
            + ("…" if len(purged_labels) > 8 else ""),
        )
    return {
        "ok": not errors,
        "skipped": False,
        "purged": len(purged_labels),
        "labels": purged_labels,
        "errors": errors,
    }


def reserve_peer(label: str, *, organization=None, rotate_keys: bool = False):
    """
    Create or reuse a WireGuardReservation for a router that is not onboarded yet.

    Returns (reservation, peer_sync). Same label (case-insensitive) within one ISP
    workspace keeps one peer so the Connect modal can regenerate the paste script
    without burning addresses. Each organization gets its own keys and tunnel IP.

    When ``rotate_keys`` is true, or the VPS sees a live handshake under another
    public key for this tunnel IP, keys are rotated automatically so operators
    never edit keys manually in the database or wg0.
    """
    from core.models import WireGuardReservation

    if organization is None:
        raise ValueError(
            "An organization is required to reserve a WireGuard onboarding peer."
        )

    label = (label or "").strip() or "New MikroTik"
    purge_stale_wireguard_reservations(keep_labels={label}, organization=organization)
    reservation = (
        WireGuardReservation.objects.filter(
            organization=organization,
            label__iexact=label,
        ).first()
    )
    if reservation is None:
        private_key, public_key = generate_keypair()
        reservation = WireGuardReservation.objects.create(
            organization=organization,
            label=label,
            address=allocate_address(),
            lan_address=allocate_lan_address(),
            private_key=private_key,
            public_key=public_key,
        )
    elif not (reservation.lan_address or "").strip():
        reservation.lan_address = allocate_lan_address()
        reservation.save(update_fields=["lan_address"])

    if rotate_keys or live_tunnel_key_conflicts_with_reservation(reservation):
        reservation, peer_sync = rotate_reservation_keys(reservation)
    else:
        peer_sync = apply_server_peer(
            reservation.label,
            reservation.address,
            reservation.public_key,
        )
    # Generate must not block on a false "sync skipped" when the peer is already
    # on wg0 (e.g. after wireguard_peer --sync-server, or a prior successful apply).
    if not peer_sync.get("ok"):
        peer = inspect_server_peer(reservation.public_key)
        if peer.get("checked") and peer.get("present"):
            peer_sync = {
                "ok": True,
                "runtime": True,
                "persisted": True,
                "skipped": False,
                "error": "",
                "already_present": True,
            }
        elif peer_sync.get("skipped"):
            logger.warning(
                "WireGuard peer apply skipped for %s (%s): %s",
                reservation.address,
                peer_sync.get("reason") or "",
                peer_sync.get("error") or "",
            )
    return reservation, peer_sync


def adopt_reservation_for_router(router) -> bool:
    """
    If the router was onboarded on a reserved tunnel address, attach that peer.

    Returns True when keys were adopted (or already match the reservation).
    """
    from core.models import WireGuardReservation

    vpn = (getattr(router, "vpn_address", None) or "").strip()
    host = (getattr(router, "host", None) or "").strip()
    reservation = None
    if vpn:
        reservation = WireGuardReservation.objects.filter(address=vpn).first()
    if reservation is None and host:
        reservation = WireGuardReservation.objects.filter(address=host).first()
    if reservation is None:
        return False

    router_org_id = getattr(router, "organization_id", None)
    if (
        router_org_id
        and reservation.organization_id
        and reservation.organization_id != router_org_id
    ):
        return False

    changed: list[str] = []
    tunnel = (reservation.address or "").strip()
    planned_lan = (getattr(reservation, "lan_address", None) or "192.168.88.1").strip()
    if planned_lan and (router.host or "").strip() != planned_lan:
        router.host = planned_lan
        changed.append("host")
    if tunnel and router.vpn_address != tunnel:
        router.vpn_address = tunnel
        changed.append("vpn_address")
    if not router.vpn_private_key:
        router.vpn_private_key = reservation.private_key
        router.vpn_public_key = reservation.public_key
        changed += ["vpn_private_key", "vpn_public_key"]
    elif not router.vpn_public_key:
        router.vpn_public_key = reservation.public_key or public_key_for(
            router.vpn_private_key
        )
        changed.append("vpn_public_key")

    if changed:
        router.save(update_fields=[*dict.fromkeys(changed), "updated_at"])
    reservation.delete()
    return True


def _ros_ok(message: str) -> str:
    return f':put "[ISPCENTRIC OK] {message}"'


def _ros_fail(message: str) -> str:
    return f':put "[ISPCENTRIC FAIL] {message}"'


def _ros_warn(message: str) -> str:
    return f':put "[ISPCENTRIC WARN] {message}"'


def _ros_info(message: str) -> str:
    return f':put "[ISPCENTRIC] {message}"'


def _ros_check(condition: str, ok_message: str, fail_message: str) -> str:
    """Single-line pass/fail check for Winbox terminal paste."""
    return (
        f":if ({condition}) do={{{_ros_ok(ok_message)}}} "
        f"else={{{_ros_fail(fail_message)}}}"
    )


def _ros_api_enabled_condition() -> str:
    return "[:len [/ip service find where name=api and disabled=no and port=8728]] > 0"


def _ros_api_enable_lines(*, verify: bool = True) -> list[str]:
    """
    RouterOS lines that force API :8728 on (create service if missing).

    Used in the onboarding tunnel script (step 2 + final verify) and recovery
    paste snippets. Multiple set/enable paths cover RouterOS builds where a
    single ``on-error={}`` line would silently skip activation.
    """
    lines = [
        "# Compulsory: RouterOS API on 8728 — Connect/Reconnect cannot work without it.",
        ':do { /ip service add name=api port=8728 disabled=no address="" } on-error={}',
        ':do { /ip service enable [find where name=api] } on-error={}',
        ':do { /ip service set [find where name=api] disabled=no port=8728 address="" } on-error={}',
        ":do { /ip service set [find where name=api] disabled=no port=8728 address=0.0.0.0/0 } on-error={}",
        ":do { /ip service set api disabled=no port=8728 address=0.0.0.0/0 } on-error={}",
        (
            ":do { :foreach i in=[/ip service find where name=api] do={ "
            '/ip service set $i disabled=no port=8728 address="" '
            "} } on-error={}"
        ),
    ]
    if verify:
        lines += [
            _ros_check(
                _ros_api_enabled_condition(),
                "RouterOS API enabled on port 8728",
                "RouterOS API still disabled - open IP > Services > api, port 8728, Allowed From empty",
            ),
            (
                ':do { :put ("[ISPCENTRIC] API allowed-from: " . '
                '[/ip service get [find where name=api] address]) } on-error={'
                f'{_ros_warn("Could not read API allowed-from list")}'
                "}"
            ),
        ]
    return lines


def routeros_standalone_api_enable_script() -> str:
    """
    Winbox terminal paste when billing cannot reach RouterOS API :8728.

    Opens API for LAN *and* the ISPCENTRIC WireGuard tunnel (required for
    hosted Connect/Reconnect). The previous LAN-only paste left tunnel
    management blocked after uplink/bond flaps.
    """
    network = tunnel_network()
    server = str(server_address())
    mgmt_ports = "8728,8291,22"
    lines = [
        "# Winbox -> New Terminal -> paste ALL lines once, press Enter",
        "# Then in ISPCENTRIC click Reconnect on this MikroTik.",
        "# Opens RouterOS API :8728 for LAN + WireGuard tunnel management.",
        "",
        *_ros_api_enable_lines(verify=True),
        "",
        "# Keep the billing WireGuard interface up (Combine links can flap WAN).",
        ':do { /interface enable [find where name=ispcentric-vpn] } on-error={}',
        ':do { /interface wireguard enable [find where name=ispcentric-vpn] } on-error={}',
        "",
        "/ip firewall filter",
        # Prefer tunnel + RFC1918 accepts near the top of input.
        _ros_filter_add(
            "action=accept protocol=tcp dst-port=8728 in-interface=ispcentric-vpn",
            "ispcentric-vpn-api",
        ),
        _ros_filter_add(
            f"action=accept protocol=tcp dst-port=8728 src-address={network}",
            "ispcentric-vpn-api-net",
        ),
        _ros_filter_add(
            "action=accept protocol=icmp in-interface=ispcentric-vpn",
            "ispcentric-vpn-icmp",
        ),
        _ros_filter_add(
            f"action=accept protocol=icmp src-address={network}",
            "ispcentric-vpn-icmp-net",
        ),
        _ros_filter_add(
            "action=accept protocol=tcp dst-port=8728 src-address=10.0.0.0/8",
            "ispcentric-vpn-api-lan-10",
        ),
        _ros_filter_add(
            "action=accept protocol=tcp dst-port=8728 src-address=172.16.0.0/12",
            "ispcentric-vpn-api-lan-172",
        ),
        _ros_filter_add(
            "action=accept protocol=tcp dst-port=8728 src-address=192.168.0.0/16",
            "ispcentric-vpn-api-lan-192",
        ),
        (
            ':do { /ip firewall filter add chain=input action=accept protocol=tcp '
            f'dst-port={mgmt_ports} comment="ispcentric-vpn-api-mgmt-input" '
            "place-before=([find where chain=input and jump-target=hs-input]->0) } "
            "on-error={ :do { /ip firewall filter add chain=input action=accept "
            f'protocol=tcp dst-port={mgmt_ports} comment="ispcentric-vpn-api-mgmt-input" '
            "} on-error={} }"
        ),
        _ros_filter_add(
            f"action=accept protocol=tcp dst-port={mgmt_ports}",
            "ispcentric-vpn-hs-input",
            chain="hs-input",
        ),
        _ros_filter_add(
            f"action=accept protocol=tcp dst-port={mgmt_ports}",
            "ispcentric-vpn-hs-unauth",
            chain="hs-unauth",
        ),
        "",
        "# Do not NAT traffic toward the billing tunnel.",
        "/ip firewall nat",
        _ros_nat_add(
            f"action=accept dst-address={network}",
            "ispcentric-vpn-no-nat",
        ),
        "",
        "# Hotspot must not captive the tunnel subnet.",
        (
            f':do {{ /ip hotspot ip-binding add type=bypassed address={network} '
            f'comment="ispcentric-vpn-hotspot-bypass" }} on-error={{}}'
        ),
        "",
        _ros_check(
            '[:len [/ip firewall filter find where comment="ispcentric-vpn-api"]] > 0 '
            'or [:len [/ip firewall filter find where comment="ispcentric-vpn-api-net"]] > 0 '
            'or [:len [/interface wireguard find where name=ispcentric-vpn]] = 0',
            "Tunnel API firewall ready (or WireGuard not installed yet)",
            "Tunnel API firewall missing - re-paste this script",
        ),
        (
            f':do {{ :if ([/ping {server} count=2] > 0) do={{ '
            f'{_ros_ok(f"Tunnel reaches billing {server} — click Reconnect in ISPCENTRIC")} '
            f'}} else={{ {_ros_warn(f"No ping to {server} yet — wait 10s then Reconnect")} }} }} '
            f"on-error={{{_ros_warn('Ping check skipped')}}}"
        ),
        _ros_ok("Management recovery done — click Reconnect in ISPCENTRIC now"),
    ]
    return "\n".join(lines)


def _ros_filter_add(rule: str, comment: str, *, chain: str = "input") -> str:
    """
    Insert a filter rule near the top of ``chain`` when that chain has rules.

    ``place-before=0`` fails with "no such item" when the filter list is empty
    (common on cleaned or CHR configs). Fall back to append in that case.

    Relative ``add``/``find`` — caller must be under ``/ip firewall filter``.
    """
    chain = (chain or "input").strip() or "input"
    body = f'add chain={chain} {rule} comment="{comment}"'
    return (
        f":do {{ {body} place-before=([find where chain={chain} and dynamic=no]->0) }} "
        f"on-error={{ :do {{ {body} place-before=([find where chain={chain}]->0) }} "
        f"on-error={{ {body} }} }}"
    )


def _ros_nat_add(rule: str, comment: str) -> str:
    """Same safe placement for srcnat rules inside /ip firewall nat."""
    body = f'add chain=srcnat {rule} comment="{comment}"'
    return (
        f":do {{ {body} place-before=([find where chain=srcnat and dynamic=no]->0) }} "
        f"on-error={{ :do {{ {body} place-before=([find where chain=srcnat]->0) }} "
        f"on-error={{ {body} }} }}"
    )


def _wan_wait_lines(
    probe_host: str = "8.8.8.8",
    *,
    attempts: int = 6,
    delay: str = "4s",
) -> list[str]:
    """
    WAN wait for imported .rsc / post-reset (not the short Connect paste).

    Prefer bound DHCP; else unbridge ether1 and DHCP. Require a real ping.
    """
    probe_host = (probe_host or "8.8.8.8").strip() or "8.8.8.8"
    attempts = max(1, int(attempts))
    ping_ok = f"([/ping {probe_host} count=1] > 0)"
    lines = [
        _ros_info(f"WAN: bound DHCP or unbridge ether1 - ping {probe_host}..."),
        ':do { /ip address disable [find where comment~"ispcentric-hotspot"] } on-error={}',
        (
            ":do { /ip dhcp-client set [find] disabled=no add-default-route=yes "
            "use-peer-dns=yes } on-error={}"
        ),
        (
            ":if ([:len [/ip dhcp-client find where status=bound]] = 0) do={"
            ':do { /interface bridge port remove [find where interface=ether1] } on-error={}; '
            ":do { /ip dhcp-client remove [find where interface=ether1] } on-error={}; "
            ":do { /ip dhcp-client add interface=ether1 disabled=no "
            "add-default-route=yes use-peer-dns=yes comment=\"ispcentric-wan\" } "
            "on-error={}}"
        ),
        ":do { /ip dns set servers=8.8.8.8,1.1.1.1 allow-remote-requests=no } on-error={}",
        ":global IspWanOk",
        ":set IspWanOk 0",
    ]
    for try_n in range(1, attempts + 1):
        lines.append(
            f":if ($IspWanOk = 0) do={{:if ({ping_ok}) do={{:set IspWanOk 1; "
            f'{_ros_ok(f"WAN ready (ping {probe_host})")}}} else={{'
            f':put "[ISPCENTRIC] WAN {try_n}/{attempts}..."; :delay {delay}}}}}'
        )
    lines.append(
        f":if ($IspWanOk = 0) do={{{_ros_fail(f'No ping to {probe_host} - fix WAN, re-run')}}}"
    )
    return lines


def _wan_quick_probe_lines(probe_host: str = "8.8.8.8") -> list[str]:
    """One-shot WAN ping before tunnel tests (no :global — safe for Connect paste)."""
    probe_host = (probe_host or "8.8.8.8").strip() or "8.8.8.8"
    ping = f"[/ping {probe_host} count=2]"
    return [
        _ros_info(f"WAN check — ping {probe_host} before tunnel test"),
        _ros_check(
            f"{ping} > 0",
            f"WAN reachable ({probe_host})",
            f"No ping to {probe_host} — fix internet/DHCP first, then Check now",
        ),
    ]


def _ros_wg_udp_output_lines(endpoint_host: str, port: str) -> list[str]:
    """Allow WireGuard UDP toward the billing VPS (strict output chains)."""
    endpoint_host = (endpoint_host or "").strip()
    port = (port or "51820").strip() or "51820"
    if not endpoint_host:
        return []
    comment = "ispcentric-vpn-wg-udp-out"
    rule = f"action=accept protocol=udp dst-address={endpoint_host} dst-port={port}"
    return [
        _ros_info(f"WireGuard egress — allow UDP to {endpoint_host}:{port}"),
        "/ip firewall filter",
        _ros_filter_add(rule, comment, chain="output"),
        _ros_check(
            f'[:len [/ip firewall filter find where comment="{comment}"]] > 0',
            "Output firewall allows WireGuard UDP to billing VPS",
            "Output UDP rule missing — run: /ip firewall filter print where chain=output",
        ),
    ]


def _ros_tunnel_watchdog_lines(server: str) -> list[str]:
    """
    RouterOS scheduler that re-enables WireGuard and pings the billing server.

    Keeps the tunnel warm after WAN/uplink flaps without waiting for the next
    billing poll. One-line script source — safe for Winbox paste.
    """
    server = (server or "").strip()
    if not server:
        return []
    ping = f"/ping {server} count=1"
    source = (
        ':do { /interface enable [find where name=ispcentric-vpn] } on-error={} ; '
        ':do { /interface wireguard enable [find where name=ispcentric-vpn] } on-error={} ; '
        f"{ping}"
    )
    return [
        _ros_info("Tunnel watchdog — ping billing server every 3 minutes"),
        ':do { /system script remove [find where name="ispcentric-tunnel-watch"] } on-error={}',
        ':do { /system scheduler remove [find where name="ispcentric-tunnel-watch"] } on-error={}',
        (
            f':do {{ /system script add name=ispcentric-tunnel-watch comment=ispcentric '
            f'policy=read,write,test source="{source}" ; '
            f'{_ros_ok("Tunnel watchdog script installed")} }} on-error='
            f'{{{_ros_warn("Tunnel watchdog script skipped")}}}'
        ),
        (
            ':do { /system scheduler add name=ispcentric-tunnel-watch interval=3m '
            'on-event=ispcentric-tunnel-watch comment=ispcentric ; '
            f'{_ros_ok("Tunnel watchdog scheduler every 3m")} }} on-error='
            f'{{{_ros_warn("Tunnel watchdog scheduler skipped")}}}'
        ),
    ]


def _handshake_wait_lines(server: str, address: str, *, attempts: int = 8) -> list[str]:
    """Retry ping/handshake so Connect Verify can catch up after dial."""
    ok = (
        f'Tunnel {address} reaches billing server {server} - click Connect in ISPCENTRIC'
    )
    fail = (
        f"No ping from {server}. On VPS: manage.py wireguard_peer --sync-server, "
        f"wait 30s, then Check now (handshake may finish after this script)"
    )
    ping = f"[/ping {server} count=2]"
    attempts = max(2, int(attempts))
    lines: list[str] = [
        *_wan_quick_probe_lines(),
        _ros_info("Probing tunnel to billing server (retries ~55s)..."),
        ":delay 5s",
    ]
    for _ in range(attempts - 1):
        lines.append(f':if ({ping} > 0) do={{{_ros_ok(ok)}}}')
        lines.append(":delay 5s")
    lines += [
        _ros_check(f"{ping} > 0", ok, fail),
        (
            ':do { :put ("[ISPCENTRIC] WireGuard last-handshake: " . '
            '[/interface wireguard peers get [find where interface=ispcentric-vpn] '
            'last-handshake]) } on-error={'
            f'{_ros_warn("No handshake yet - need internet + VPS peer")}'
            "}"
        ),
        _ros_info(
            "If ping FAIL: run wireguard_peer --sync-server on VPS, wait 30s, "
            "then Check now in ISPCENTRIC"
        ),
    ]
    return lines


def _wireguard_interface() -> str:
    return (getattr(settings, "WIREGUARD_INTERFACE", None) or "wg0").strip() or "wg0"


def _wireguard_conf_path() -> str:
    return (
        getattr(settings, "WIREGUARD_CONF_PATH", None) or "/etc/wireguard/wg0.conf"
    ).strip()


def _append_peer_to_conf(conf_path: str, public_key: str, block: str) -> bool:
    """Append a [Peer] block when the public key is not already in wg0.conf."""
    path = Path(conf_path)
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    if public_key in text:
        return True
    with path.open("a", encoding="utf-8") as handle:
        if text and not text.endswith("\n"):
            handle.write("\n")
        handle.write("\n")
        handle.write(block.rstrip())
        handle.write("\n")
    return True


def can_apply_server_peers() -> bool:
    """True when this process can update wg0 (local address or sudo sync helper)."""
    if not configured():
        return False
    if server_on_tunnel():
        return True
    return bool((getattr(settings, "WIREGUARD_SYNC_COMMAND", None) or "").strip())


def peer_sync_report(peer_sync: dict | None) -> dict:
    """
    Normalize apply_server_peer() outcome for the Connect UI / tunnel-script API.

    peer_sync_required: operator must fix VPS wg0 before Connect can succeed over
    the tunnel (always true on failed apply; true on skip only when HOSTED).
    """
    peer_sync = peer_sync or {}
    ok = bool(peer_sync.get("ok"))
    skipped = bool(peer_sync.get("skipped"))
    hosted = bool(getattr(settings, "HOSTED", False))
    reason = (peer_sync.get("reason") or "").strip()
    error = (peer_sync.get("error") or "").strip()

    if ok:
        return {
            "peer_synced": True,
            "peer_sync_skipped": False,
            "peer_sync_required": False,
            "peer_sync_error": "",
            "peer_sync_reason": "",
            "peer_sync_hint": (
                "Script ready. Copy it and paste into Winbox → New Terminal. "
                "ISPCENTRIC will verify the tunnel and API automatically."
            ),
        }

    if skipped and not hosted:
        return {
            "peer_synced": False,
            "peer_sync_skipped": True,
            "peer_sync_required": False,
            "peer_sync_error": error,
            "peer_sync_reason": reason or "sync_unavailable",
            "peer_sync_hint": (
                "Local mode: paste the script, then Connect with the router LAN IP. "
                "On the hosted VPS, set WIREGUARD_SYNC_COMMAND so peers register on wg0."
            ),
        }

    if skipped:
        sync_set = bool(
            (getattr(settings, "WIREGUARD_SYNC_COMMAND", None) or "").strip()
        )
        hint = (
            "This VPS could not register the router on WireGuard. "
            'Set WIREGUARD_SYNC_COMMAND="sudo /opt/ispcentric/scripts/wireguard_apply_peer.sh" '
            "(quoted for systemd), install sudoers for that script, restart ispcentric, "
            "then Generate again (or run: manage.py wireguard_peer --sync-server)."
        )
        if reason == "sync_command_unset":
            hint = (
                "WIREGUARD_SYNC_COMMAND is missing on this VPS — peers never reach wg0. "
                "Add the quoted value to .env with sudoers for wireguard_apply_peer.sh, "
                "restart the app, then Generate again."
            )
        elif reason == "peer_missing":
            hint = (
                "This peer is not on VPS wg0 yet. Run: "
                "manage.py wireguard_peer --sync-server — then Generate / Check now."
            )
        elif sync_set and error:
            hint = error
        return {
            "peer_synced": False,
            "peer_sync_skipped": True,
            "peer_sync_required": True,
            "peer_sync_error": error or hint,
            "peer_sync_reason": reason or "sync_unavailable",
            "peer_sync_hint": hint,
        }

    return {
        "peer_synced": False,
        "peer_sync_skipped": False,
        "peer_sync_required": True,
        "peer_sync_error": error or "WireGuard peer sync failed on the VPS.",
        "peer_sync_reason": reason or "sync_failed",
        "peer_sync_hint": (
            "Script is ready, but the billing server did not accept this peer yet. "
            "Fix: "
            + (error + " — " if error else "")
            + "run manage.py wireguard_peer --sync-server on the VPS "
            "(or paste the [Peer] block into /etc/wireguard/wg0.conf and restart wg-quick), "
            "then paste the script in Winbox."
        ),
    }


def onboard_tunnel_peer_ready(tunnel_address: str, *, organization=None) -> dict:
    """
    Return whether the VPS wg0 peer for a pending onboarding reservation exists.

    Used to block Connect on hosted servers until the tunnel peer is registered.
    Prefer apply-success / live reachability over `wg show` (www-data often cannot
    read WireGuard state without sudo).
    """
    address = (tunnel_address or "").strip()
    if not address or not bool(getattr(settings, "HOSTED", False)):
        return {"ok": True, "required": False}

    try:
        reservation = reservation_for_address(address, organization=organization)
    except Exception:
        reservation = None

    public_key = (getattr(reservation, "public_key", None) or "").strip()
    if not reservation or not public_key:
        org_id = getattr(organization, "pk", organization)
        if org_id:
            from core.models import WireGuardReservation

            foreign = WireGuardReservation.objects.filter(address=address).first()
            if foreign and foreign.organization_id not in (None, org_id):
                return {
                    "ok": False,
                    "required": True,
                    "error": (
                        "This tunnel address belongs to another ISP account. "
                        "Generate a new script from your Connect router wizard."
                    ),
                }
        return {"ok": True, "required": False}

    live = find_handshake_peer_for_address(address)
    live_key = (live.get("public_key") or "").strip()
    live_age = live.get("handshake_age_sec")
    if (
        live.get("checked")
        and live_key
        and live_key != public_key
        and _handshake_fresh(live_age)
    ):
        reservation, rot_sync = rotate_reservation_keys(reservation)
        public_key = (reservation.public_key or "").strip()
        sync = apply_server_peer(
            getattr(reservation, "label", None) or "MikroTik",
            address,
            public_key,
        )
        if not sync.get("ok"):
            sync = rot_sync
        peer = inspect_server_peer(public_key)
        return {
            "ok": False,
            "required": True,
            "peer_synced": bool(sync.get("ok") or peer.get("present")),
            "keys_rotated": True,
            "error": (
                f"Tunnel {address} was using an old WireGuard key — ISPCENTRIC issued "
                "new keys and registered them on the VPS. Copy script again, paste the "
                "full script in Winbox → New Terminal, then Check now."
            ),
            "peer_sync": sync,
            "key_mismatch": False,
        }

    sync = apply_server_peer(
        getattr(reservation, "label", None) or "MikroTik",
        address,
        public_key,
    )

    peer = inspect_server_peer(public_key)
    if peer.get("checked") and peer.get("present") and _handshake_fresh(
        peer.get("handshake_age_sec")
    ):
        return {
            "ok": True,
            "required": True,
            "peer_synced": True,
            "peer": peer,
            "peer_sync": sync,
        }

    if live_key == public_key and _handshake_fresh(live_age):
        return {
            "ok": True,
            "required": True,
            "peer_synced": True,
            "peer": peer,
            "peer_sync": sync,
            "handshake_via": "address",
        }

    if _tunnel_host_reachable(address):
        return {
            "ok": True,
            "required": True,
            "peer_synced": bool(sync.get("ok") or peer.get("present")),
            "reachable": True,
            "peer_sync": sync,
            "peer": peer,
        }

    report = peer_sync_report(
        sync
        or {
            "ok": False,
            "skipped": not bool(peer.get("checked")),
            "error": (peer.get("error") or sync.get("error") or "").strip(),
            "reason": (sync.get("reason") if sync else "") or "peer_missing",
        }
    )
    return {
        "ok": False,
        "required": True,
        "peer_synced": False,
        "error": report.get("peer_sync_hint") or report.get("peer_sync_error") or "",
        "peer": peer,
        **report,
    }


def _tunnel_host_reachable(address: str, timeout: float = 1.5) -> bool:
    """True when the tunnel IP answers ICMP or TCP/8728 (peer is live on wg0)."""
    address = (address or "").strip()
    if not address:
        return False
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "1", address],
            capture_output=True,
            text=True,
            timeout=timeout + 1,
            check=False,
        )
        if proc.returncode == 0:
            return True
    except Exception:
        pass
    try:
        with socket.create_connection((address, 8728), timeout=timeout):
            return True
    except OSError:
        return False


def _wg_interface_dump_command() -> list[str] | None:
    """Command argv for ``wg show <iface> dump`` (may use WIREGUARD_SYNC_COMMAND --dump)."""
    iface = _wireguard_interface()
    wg_bin = shutil.which("wg") or "/usr/bin/wg"
    sync_cmd = (getattr(settings, "WIREGUARD_SYNC_COMMAND", None) or "").strip()
    sync_cmd = sync_cmd.strip('"').strip("'")
    if sync_cmd:
        try:
            parts = shlex.split(sync_cmd)
        except ValueError:
            parts = []
        if parts:
            return [*parts, "--dump"]
    if not Path(wg_bin).is_file() and not shutil.which("wg"):
        return None
    return [wg_bin, "show", iface, "dump"]


def _run_wg_interface_dump() -> tuple[list[dict], str]:
    """
    Parse ``wg show <iface> dump`` into peer rows.

    Each row: public_key, allowed_ips, handshake_age_sec (None if never).
    """
    dump_cmd = _wg_interface_dump_command()
    if dump_cmd is None:
        return [], "wg_not_found"
    try:
        proc = subprocess.run(
            dump_cmd,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
            env={
                **os.environ,
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            },
        )
    except Exception as exc:
        return [], str(exc)
    if proc.returncode != 0:
        return [], (proc.stderr or proc.stdout or "wg show failed").strip()

    now = int(time.time())
    rows: list[dict] = []
    for line in (proc.stdout or "").splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        try:
            latest = int(parts[4] or "0")
        except ValueError:
            latest = 0
        age = max(0, now - latest) if latest > 0 else None
        rows.append(
            {
                "public_key": parts[0],
                "allowed_ips": parts[3] if len(parts) > 3 else "",
                "handshake_age_sec": age,
            }
        )
    return rows, ""


def inspect_server_peer(public_key: str) -> dict:
    """
    Read live WireGuard state for one peer on this host.

    latest_handshake 0 means the peer exists but never completed a handshake.
    """
    public_key = (public_key or "").strip()
    out: dict = {
        "checked": False,
        "present": False,
        "handshake_age_sec": None,
        "allowed_ips": "",
        "error": "",
    }
    if not public_key:
        out["error"] = "missing_public_key"
        return out

    rows, err = _run_wg_interface_dump()
    if err:
        out["error"] = err
        return out

    out["checked"] = True
    for row in rows:
        if row.get("public_key") != public_key:
            continue
        out["present"] = True
        out["allowed_ips"] = row.get("allowed_ips") or ""
        out["handshake_age_sec"] = row.get("handshake_age_sec")
        return out
    return out


def find_handshake_peer_for_address(address: str) -> dict:
    """
    Among wg0 peers, return the row for ``address/32`` with the freshest handshake.
    """
    address = (address or "").strip()
    needle = f"{address}/32"
    out: dict = {
        "checked": False,
        "public_key": "",
        "handshake_age_sec": None,
        "error": "",
    }
    if not address:
        out["error"] = "missing_address"
        return out

    rows, err = _run_wg_interface_dump()
    if err:
        out["error"] = err
        return out
    out["checked"] = True

    best_age: int | None = None
    best_key = ""
    for row in rows:
        allowed = (row.get("allowed_ips") or "").replace(" ", ",")
        if needle not in allowed.split(","):
            continue
        age = row.get("handshake_age_sec")
        if age is None:
            continue
        if best_age is None or age < best_age:
            best_age = age
            best_key = row.get("public_key") or ""
    if best_key:
        out["public_key"] = best_key
        out["handshake_age_sec"] = best_age
    return out


def fresh_tunnel_reservations_for_org(
    organization,
    *,
    exclude_address: str = "",
) -> list[dict]:
    """
    Reservations for this ISP that currently have a fresh WireGuard handshake on wg0.

    Used when Verify is polling one tunnel IP but the router is online under another.
    """
    org_id = getattr(organization, "pk", organization)
    if not org_id:
        return []

    from core.models import WireGuardReservation

    by_key: dict[str, WireGuardReservation] = {}
    for res in WireGuardReservation.objects.filter(organization_id=org_id):
        pk = (res.public_key or "").strip()
        if pk:
            by_key[pk] = res

    rows, err = _run_wg_interface_dump()
    if err:
        return []

    exclude = (exclude_address or "").strip()
    out: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        pk = (row.get("public_key") or "").strip()
        if not pk or pk in seen:
            continue
        age = row.get("handshake_age_sec")
        if not _handshake_fresh(age):
            continue
        res = by_key.get(pk)
        if not res:
            continue
        addr = (res.address or "").strip()
        if not addr or (exclude and addr == exclude):
            continue
        seen.add(pk)
        out.append(
            {
                "address": addr,
                "label": (res.label or "").strip() or "MikroTik",
                "handshake_age_sec": age,
            }
        )
    out.sort(key=lambda row: row.get("address") or "")
    return out


def alternate_live_tunnel_message(
    organization,
    checked_address: str,
    *,
    sessions: list[dict] | None = None,
) -> str:
    """Human hint when Verify targets ``checked_address`` but another site is already up."""
    checked = (checked_address or "").strip()
    live = sessions if sessions is not None else fresh_tunnel_reservations_for_org(
        organization, exclude_address=checked
    )
    if not live:
        return ""
    parts = [
        f"{row.get('label') or 'Site'} ({row.get('address')})"
        for row in live[:3]
    ]
    summary = ", ".join(parts)
    return (
        f"WireGuard is already live for {summary}, but this check is for {checked or 'this site'}. "
        "Open that site name in Step 1, click Generate script (or resume its draft), then Check now — "
        "or finish Connect using that tunnel IP in Step 4."
    )


def ensure_reservation_peer(reservation) -> dict:
    """
    Re-apply a pending reservation to wg0 and classify why the tunnel may be down.

    Codes: ok | peer_missing | no_handshake | keys_rotated | waiting_router | unknown
    """
    label = getattr(reservation, "label", None) or "MikroTik"
    address = (getattr(reservation, "address", None) or "").strip()
    public_key = (getattr(reservation, "public_key", None) or "").strip()

    reconcile_runtime_allowed_ips()
    sync = apply_server_peer(label, address, public_key)
    peer = inspect_server_peer(public_key)

    live = find_handshake_peer_for_address(address)
    live_key = (live.get("public_key") or "").strip()
    live_age = live.get("handshake_age_sec")
    if (
        live.get("checked")
        and live_key
        and live_key != public_key
        and _handshake_fresh(live_age)
    ):
        reservation, rot_sync = rotate_reservation_keys(reservation)
        public_key = (reservation.public_key or "").strip()
        sync = apply_server_peer(label, address, public_key)
        if not sync.get("ok"):
            sync = rot_sync
        peer = inspect_server_peer(public_key)
        return {
            "code": "keys_rotated",
            "keys_rotated": True,
            "message": (
                f"VPS saw an old WireGuard key on {address}. New keys are registered "
                "on the billing server — copy the refreshed script, paste it once in "
                "Winbox → New Terminal, then Check now."
            ),
            "peer_sync": sync,
            "peer": peer,
            "reservation": reservation,
            "live_peer_public_key": live_key,
        }

    if peer.get("checked") and not peer.get("present") and not sync.get("ok"):
        return {
            "code": "peer_missing",
            "message": (
                f"VPS wg0 does not have peer {address} yet. "
                "Run manage.py wireguard_peer --sync-server "
                "(or set WIREGUARD_SYNC_COMMAND), then Check now."
            ),
            "peer_sync": sync,
            "peer": peer,
        }

    if peer.get("checked") and peer.get("present"):
        age = peer.get("handshake_age_sec")
        if age is None:
            return {
                "code": "no_handshake",
                "message": (
                    f"VPS has peer {address}, but WireGuard has no handshake yet. "
                    "Paste the script in Winbox if you have not, and open UDP "
                    f"{(_endpoint().partition(':')[2] or '51820')} toward this server."
                ),
                "peer_sync": sync,
                "peer": peer,
            }
        if not _handshake_fresh(age):
            return {
                "code": "no_handshake",
                "message": (
                    f"Last WireGuard handshake for {address} was {age}s ago. "
                    "Re-paste the script on the MikroTik or check the router’s internet path."
                ),
                "peer_sync": sync,
                "peer": peer,
            }
        return {
            "code": "waiting_router",
            "message": (
                f"Handshake ok for {address}, but API is not open yet. "
                "Wait for the Winbox script to finish, then Check now."
            ),
            "peer_sync": sync,
            "peer": peer,
        }

    if not peer.get("checked"):
        if live_key == public_key and _handshake_fresh(live_age):
            return {
                "code": "waiting_router",
                "message": (
                    f"Handshake ok for {address}, but API is not open yet. "
                    "Wait for the Winbox script to finish, then Check now."
                ),
                "peer_sync": sync,
                "peer": peer,
            }
        if _tunnel_host_reachable(address):
            return {
                "code": "waiting_router",
                "message": (
                    f"Tunnel IP {address} is reachable from the VPS, but RouterOS API "
                    "is not open yet. Wait for the Winbox script to finish, then Check now."
                ),
                "peer_sync": sync,
                "peer": peer,
            }
        if sync.get("ok"):
            return {
                "code": "waiting_router",
                "message": (
                    f"Peer {address} is registered on the VPS. "
                    "Paste the script in Winbox → New Terminal and wait for [ISPCENTRIC OK]."
                ),
                "peer_sync": sync,
                "peer": peer,
            }
        hint = (peer.get("error") or "").strip()
        return {
            "code": "unknown",
            "message": (
                "Waiting for MikroTik… paste the script in Winbox → New Terminal. "
                + (
                    f"({hint}) "
                    if hint
                    else "If Check now stays red, run wireguard_peer --sync-server on the VPS. "
                )
                + "Ensure WIREGUARD_SYNC_COMMAND supports --dump for Verify."
            ),
            "peer_sync": sync,
            "peer": peer,
        }

    if sync.get("ok"):
        return {
            "code": "waiting_router",
            "message": (
                f"Peer {address} is registered on the VPS. "
                "Paste the script in Winbox → New Terminal and wait for [ISPCENTRIC OK]."
            ),
            "peer_sync": sync,
            "peer": peer,
        }

    return {
        "code": "unknown",
        "message": (
            "Waiting for MikroTik… paste the script in Winbox → New Terminal. "
            "If Winbox shows ping FAIL with an empty handshake, register this peer on VPS wg0."
        ),
        "peer_sync": sync,
        "peer": peer,
    }


def _try_bring_up_interface() -> dict:
    """Best-effort `wg-quick up` when a conf exists (hosted Linux)."""
    iface = _wireguard_interface()
    conf = Path(_wireguard_conf_path())
    wg_bin = shutil.which("wg")
    if wg_bin:
        try:
            probe = subprocess.run(
                [wg_bin, "show", iface],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if probe.returncode == 0:
                return {"ok": True, "already_up": True}
        except Exception:
            pass

    if not conf.is_file():
        return {"ok": False, "reason": "no_conf"}

    wg_quick = shutil.which("wg-quick")
    if not wg_quick:
        return {"ok": False, "reason": "no_wg_quick"}

    try:
        proc = subprocess.run(
            [wg_quick, "up", iface],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        err = (proc.stderr or proc.stdout or "").strip()
        if proc.returncode == 0 or "already" in err.lower():
            logger.info("WireGuard interface %s is up.", iface)
            return {"ok": True, "brought_up": proc.returncode == 0, "already_up": proc.returncode != 0}
        logger.warning("wg-quick up %s failed: %s", iface, err)
        return {"ok": False, "error": err}
    except Exception as exc:
        logger.warning("wg-quick up %s raised: %s", iface, exc)
        return {"ok": False, "error": str(exc)}


def ensure_tunnel_runtime() -> dict:
    """
    Refresh WireGuard whenever the app starts (local runserver or hosted WSGI).

    Hosted: bring wg0 up if needed, then sync every DB peer.
    Local: sync via WIREGUARD_SYNC_COMMAND when set; otherwise skip (LAN NAS
    still works). Never blocks startup — caller should run this off-thread.
    """
    if not configured():
        logger.info("WireGuard is not configured — skipping peer sync.")
        return {"ok": False, "skipped": True, "reason": "not_configured", "synced": 0}

    brought_up = False
    if not server_on_tunnel():
        brought_up = bool(_try_bring_up_interface().get("ok"))

    if not can_apply_server_peers():
        logger.info(
            "WireGuard endpoint is set, but this process cannot update wg0 "
            "(not bound to %s and WIREGUARD_SYNC_COMMAND is empty). "
            "LAN MikroTiks still work. On the VPS set WIREGUARD_SYNC_COMMAND "
            "or enable wg-quick@wg0.",
            server_address(),
        )
        return {
            "ok": False,
            "skipped": True,
            "reason": "not_on_tunnel",
            "synced": 0,
            "brought_up": brought_up,
        }

    result = sync_all_server_peers()
    result["brought_up"] = brought_up
    logger.info(
        "WireGuard peer sync on startup: synced=%s errors=%s brought_up=%s",
        result.get("synced", 0),
        len(result.get("errors") or []),
        brought_up,
    )
    for err in result.get("errors") or []:
        logger.warning("WireGuard peer sync: %s", err)
    return result


def apply_server_peer(label: str, address: str, public_key: str) -> dict:
    """
    Register a MikroTik peer on the billing VPS WireGuard interface.

    Without this step the router can dial the VPS but the server never accepts
    the tunnel, so ping/API checks stay on Waiting forever.
    """
    if not configured():
        return {"ok": False, "skipped": True, "reason": "wireguard_not_configured"}
    if not can_apply_server_peers():
        sync_cmd = (getattr(settings, "WIREGUARD_SYNC_COMMAND", None) or "").strip()
        if not sync_cmd and not server_on_tunnel():
            return {
                "ok": False,
                "skipped": True,
                "reason": "sync_command_unset",
                "error": (
                    "WIREGUARD_SYNC_COMMAND is empty — the app cannot update wg0. "
                    "Set WIREGUARD_SYNC_COMMAND=sudo /opt/ispcentric/scripts/wireguard_apply_peer.sh "
                    "and install sudoers for that script."
                ),
            }
        return {
            "ok": False,
            "skipped": True,
            "reason": "not_on_tunnel",
            "error": (
                f"This process is not bound to {server_address()} and has no sync helper."
            ),
        }

    public_key = (public_key or "").strip()
    address = (address or "").strip()
    if not public_key or not address:
        return {"ok": False, "skipped": True, "reason": "missing_peer_fields"}

    stale = _remove_runtime_peers_for_address(address, public_key)
    if stale:
        logger.info(
            "Removed %s stale runtime peer(s) for tunnel IP %s before apply",
            stale,
            address,
        )

    iface = _wireguard_interface()
    conf_path = _wireguard_conf_path()
    sync_cmd = (getattr(settings, "WIREGUARD_SYNC_COMMAND", None) or "").strip()
    sync_cmd = sync_cmd.strip('"').strip("'")
    # systemd may leave PATH thin; keep sudo/wg absolute when possible.
    if sync_cmd == "sudo" or sync_cmd.startswith("sudo "):
        sync_cmd = "/usr/bin/sudo " + sync_cmd[len("sudo") :].lstrip()
    block = server_peer_block(label or "MikroTik", address, public_key)
    result: dict = {
        "ok": False,
        "runtime": False,
        "persisted": False,
        "skipped": False,
        "error": "",
    }

    if sync_cmd:
        try:
            proc = subprocess.run(
                [*shlex.split(sync_cmd), public_key, address, label or ""],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                env={**os.environ, "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
            )
            if proc.returncode == 0:
                result.update(ok=True, runtime=True, persisted=True)
                return result
            result["error"] = (proc.stderr or proc.stdout or "sync command failed").strip()
            logger.warning(
                "WIREGUARD_SYNC_COMMAND failed for %s: %s",
                address,
                result["error"],
            )
        except Exception as exc:
            result["error"] = str(exc)
            logger.warning("WIREGUARD_SYNC_COMMAND raised for %s: %s", address, exc)

    wg_bin = shutil.which("wg") or "/usr/bin/wg"
    try:
        proc = subprocess.run(
            [wg_bin, "set", iface, "peer", public_key, "allowed-ips", f"{address}/32"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0:
            result["runtime"] = True
            result["ok"] = True
        elif not result["error"]:
            result["error"] = (proc.stderr or "wg set failed").strip()
    except Exception as exc:
        if not result["error"]:
            result["error"] = str(exc)

    try:
        if _append_peer_to_conf(conf_path, public_key, block):
            result["persisted"] = True
            result["ok"] = True
    except OSError as exc:
        if not result["error"]:
            result["error"] = str(exc)

    if not result["ok"]:
        logger.warning(
            "WireGuard peer sync failed for %s (%s): %s",
            address,
            label,
            result.get("error") or "unknown",
        )
    return result


def _wireguard_sync_script_problem() -> str:
    """
    Return a single actionable hint when WIREGUARD_SYNC_COMMAND points at a
    missing or broken helper script (common after deploy without vps_deploy.sh).
    """
    sync_cmd = (
        (getattr(settings, "WIREGUARD_SYNC_COMMAND", None) or "")
        .strip()
        .strip('"')
        .strip("'")
    )
    if not sync_cmd:
        return ""
    for token in shlex.split(sync_cmd):
        if not (token.endswith(".sh") and os.path.isabs(token)):
            continue
        path = Path(token)
        if not path.is_file():
            app_root = Path(getattr(settings, "BASE_DIR", "/opt/ispcentric"))
            return (
                f"helper missing at {token}. On the VPS run: "
                f"cd {app_root} && git pull && sed -i 's/\\r$//' scripts/*.sh "
                f"&& chmod +x scripts/*.sh "
                f"&& .venv/bin/python manage.py wireguard_peer --sync-server"
            )
        try:
            if b"\r" in path.read_bytes()[:256]:
                return (
                    f"helper has Windows CRLF line endings: {token}. "
                    f"Run: sed -i 's/\\r$//' {token} && chmod +x {token}"
                )
        except OSError:
            pass
        if not os.access(token, os.X_OK):
            return f"helper not executable: chmod +x {token}"
    return ""


def sync_all_server_peers() -> dict:
    """Apply every onboarded router and pending reservation to the local wg0."""
    from core.models import MikroTikRouter, WireGuardReservation

    purge_meta = purge_stale_wireguard_reservations(
        remove_runtime_peers=can_apply_server_peers(),
    )

    if not can_apply_server_peers():
        out = {"ok": False, "skipped": True, "reason": "not_on_tunnel", "synced": 0}
        if purge_meta.get("purged"):
            out["reservations_purged"] = int(purge_meta["purged"])
        return out

    script_problem = _wireguard_sync_script_problem()
    if script_problem:
        logger.warning("WireGuard peer sync: %s", script_problem)
        return {
            "ok": False,
            "skipped": True,
            "reason": "sync_script_missing",
            "synced": 0,
            "errors": [script_problem],
        }

    route_meta = reconcile_runtime_allowed_ips()
    synced = 0
    errors: list[str] = []
    if route_meta.get("errors"):
        errors.extend(route_meta["errors"])
    for router in MikroTikRouter.objects.exclude(vpn_address__isnull=True).exclude(
        vpn_public_key=""
    ):
        outcome = apply_server_peer(
            f"{router.name} (router id {router.pk})",
            router.vpn_address,
            router.vpn_public_key,
        )
        if outcome.get("ok"):
            synced += 1
        elif not outcome.get("skipped") and outcome.get("error"):
            errors.append(f"{router.vpn_address}: {outcome['error']}")
    for reservation in WireGuardReservation.objects.all():
        outcome = apply_server_peer(
            reservation.label,
            reservation.address,
            reservation.public_key,
        )
        if outcome.get("ok"):
            synced += 1
        elif not outcome.get("skipped") and outcome.get("error"):
            errors.append(f"{reservation.address}: {outcome['error']}")
    prune_meta = prune_orphan_runtime_peers()
    result = {"ok": not errors, "synced": synced, "errors": errors}
    if route_meta.get("fixed"):
        result["routes_reconciled"] = int(route_meta["fixed"])
    if purge_meta.get("purged"):
        result["reservations_purged"] = int(purge_meta["purged"])
        result["purged_labels"] = list(purge_meta.get("labels") or [])
    if prune_meta.get("pruned"):
        result["orphans_pruned"] = int(prune_meta["pruned"])
    if prune_meta.get("errors"):
        result.setdefault("errors", []).extend(prune_meta["errors"])
        result["ok"] = False
    return result


def tunnel_verification_checks(
    *,
    local_mode: bool,
    address: str,
    tunnel_reachable: bool,
    api_enabled: bool,
    lan_address: str = "",
    subnet_mismatch: bool = False,
    multiple_devices: bool = False,
    peer_state: str = "",
    script_installed: bool = False,
    peer_present: bool = False,
    peer_synced: bool = False,
) -> list[dict[str, str]]:
    """
    Structured pass/fail rows for the Connect modal (mirrors Winbox script summary).

    Each item: key, status (ok|fail|warn|waiting), label, message.
    peer_state (hosted only): ok | missing | no_handshake | waiting_router | unknown
    script_installed (local only): True when ispcentric-vpn / WG listen-port is present.
    """
    server = str(server_address())
    checks: list[dict[str, str]] = []

    if local_mode:
        if multiple_devices and not lan_address:
            checks.append(
                {
                    "key": "lan",
                    "status": "warn",
                    "label": "MikroTik on LAN",
                    "message": "Several routers found — pick the LAN IP above, then Check now",
                }
            )
        elif lan_address:
            checks.append(
                {
                    "key": "lan",
                    "status": "ok",
                    "label": "MikroTik on LAN",
                    "message": f"Found at {lan_address}",
                }
            )
        else:
            checks.append(
                {
                    "key": "lan",
                    "status": "waiting",
                    "label": "MikroTik on LAN",
                    "message": "Connect this PC to the router network, then Check now",
                }
            )

        if lan_address:
            checks.append(
                {
                    "key": "subnet",
                    "status": "ok" if not subnet_mismatch else "fail",
                    "label": "Same subnet as MikroTik",
                    "message": (
                        "This PC can reach the router LAN"
                        if not subnet_mismatch
                        else "PC and MikroTik are on different subnets — fix IP, then Check now"
                    ),
                }
            )

        checks.append(
            {
                "key": "api",
                "status": (
                    "ok"
                    if api_enabled
                    else ("fail" if lan_address and not subnet_mismatch else "waiting")
                ),
                "label": "API port 8728",
                "message": (
                    f"RouterOS API open at {lan_address}:8728"
                    if api_enabled
                    else (
                        "API closed - paste script and wait for API listening on 8728"
                        if lan_address and not subnet_mismatch
                        else "Waiting for LAN discovery and script"
                    )
                ),
            }
        )

        # TCP success ≠ confirmed ispcentric filter rows — label honestly.
        if lan_address and not subnet_mismatch:
            checks.append(
                {
                    "key": "firewall",
                    "status": "ok" if api_enabled else "waiting",
                    "label": "API reachable",
                    "message": (
                        f"TCP 8728 accepts connections from this PC at {lan_address}"
                        if api_enabled
                        else "Waiting for API — finish Winbox paste (opens LAN management)"
                    ),
                }
            )

        # Script paste is required — API alone (common on stock routers) is not enough.
        if script_installed:
            wg_status, wg_msg = (
                "ok",
                f"ISPCENTRIC script applied — ispcentric-vpn ready for tunnel IP {address}",
            )
        elif lan_address and not subnet_mismatch:
            wg_status, wg_msg = (
                "waiting",
                (
                    f"Paste the Winbox script — identity should become "
                    f"{script_ready_identity(address)}, then Check now "
                    "(login is only after all checks pass)"
                    if api_enabled
                    else f"Paste the script for tunnel IP {address}, then Check now"
                ),
            )
        else:
            wg_status, wg_msg = (
                "waiting",
                f"Tunnel IP {address} — paste script after the router is on LAN",
            )
        checks.append(
            {
                "key": "wireguard",
                "status": wg_status,
                "label": "Winbox script / WireGuard",
                "message": wg_msg,
            }
        )
        return checks

    state = (peer_state or "").strip() or (
        "ok" if tunnel_reachable else "unknown"
    )
    if tunnel_reachable:
        state = "ok"

    if state == "missing":
        tunnel_status, tunnel_msg = (
            "fail",
            f"Tunnel IP {address} unreachable — VPS has not accepted this peer",
        )
        peer_status, peer_msg = (
            "fail",
            f"Missing on VPS wg0 — run wireguard_peer --sync-server (AllowedIPs={address}/32)",
        )
        ping_status, ping_msg = (
            "fail",
            f"No route to {server} until the VPS peer exists",
        )
    elif state == "no_handshake":
        if peer_present or peer_synced:
            tunnel_status, tunnel_msg = (
                "waiting",
                f"Paste the Winbox script — tunnel {address} comes up after the router dials in",
            )
            peer_status, peer_msg = (
                "ok",
                f"VPS peer {address}/32 is registered — waiting for MikroTik handshake",
            )
            ping_status, ping_msg = (
                "waiting",
                f"Router will reach {server} after the script finishes in Winbox",
            )
        else:
            tunnel_status, tunnel_msg = (
                "waiting",
                f"Tunnel IP {address} not up yet — paste the script in Winbox",
            )
            peer_status, peer_msg = (
                "waiting",
                "Waiting for VPS peer registration and MikroTik handshake",
            )
            ping_status, ping_msg = (
                "waiting",
                f"No ping to {server} until the router connects WireGuard",
            )
    elif state == "key_mismatch":
        tunnel_status, tunnel_msg = (
            "fail",
            f"Tunnel IP {address} — router keys do not match this Connect reservation",
        )
        peer_status, peer_msg = (
            "fail",
            "Stale wg0 peer or old Winbox paste — regenerate script, full paste, sync-server",
        )
        ping_status, ping_msg = (
            "fail",
            f"Billing checks use reservation keys — fix keys, then Check now",
        )
    elif state == "keys_rotated":
        tunnel_status, tunnel_msg = (
            "waiting",
            f"New keys for {address} — paste the refreshed script in Winbox",
        )
        peer_status, peer_msg = (
            "ok",
            "VPS wg0 updated — waiting for MikroTik to use the new private key",
        )
        ping_status, ping_msg = (
            "waiting",
            f"Ping to {server} after the router pastes the new script",
        )
    elif state == "waiting_router":
        tunnel_status, tunnel_msg = (
            "waiting",
            f"VPS peer ready — waiting for MikroTik {address} to come online",
        )
        peer_status, peer_msg = (
            "ok",
            f"Billing server accepts traffic to {address}",
        )
        ping_status, ping_msg = (
            "waiting",
            f"Waiting for router path to {server}",
        )
    elif state == "unknown":
        tunnel_status, tunnel_msg = (
            "waiting",
            "Paste the full script in Winbox → New Terminal, then Check now",
        )
        if peer_present or peer_synced:
            peer_status, peer_msg = (
                "ok",
                f"VPS peer {address}/32 registered — waiting for MikroTik",
            )
        else:
            peer_status, peer_msg = (
                "waiting",
                f"Register peer {address}/32 on VPS wg0 if Generate did not sync",
            )
        ping_status, ping_msg = (
            "waiting",
            f"Billing ping runs after the router brings up the tunnel",
        )
    elif tunnel_reachable:
        tunnel_status, tunnel_msg = (
            "ok",
            f"Tunnel IP {address} reachable from billing server",
        )
        peer_status, peer_msg = (
            "ok",
            f"Billing server accepts traffic to {address}",
        )
        ping_status = "ok" if api_enabled else "warn"
        ping_msg = (
            f"Router can reach {server} and API is open — ready to Connect"
            if api_enabled
            else f"Tunnel up — confirm [ISPCENTRIC OK] ping line in Winbox"
        )
    else:
        tunnel_status, tunnel_msg = (
            "waiting",
            "Waiting — paste script in Winbox New Terminal",
        )
        if peer_present or peer_synced:
            peer_status, peer_msg = (
                "ok",
                f"VPS peer {address}/32 ready — waiting for Winbox paste on the router",
            )
        else:
            peer_status, peer_msg = (
                "waiting",
                f"VPS should register {address}/32 when you Generate — paste script next",
            )
        ping_status, ping_msg = (
            "waiting",
            f"Router will ping {server} after WireGuard connects",
        )

    checks.append(
        {
            "key": "tunnel",
            "status": tunnel_status,
            "label": "WireGuard interface",
            "message": tunnel_msg,
        }
    )
    checks.append(
        {
            "key": "vps_peer",
            "status": peer_status,
            "label": "VPS peer",
            "message": peer_msg,
        }
    )
    checks.append(
        {
            "key": "billing_ping",
            "status": ping_status,
            "label": f"Ping billing server {server}",
            "message": ping_msg,
        }
    )
    checks.append(
        {
            "key": "api",
            "status": (
                "ok"
                if api_enabled
                else ("fail" if tunnel_reachable else "waiting")
            ),
            "label": "API port 8728",
            "message": (
                "RouterOS API enabled on port 8728"
                if api_enabled
                else (
                    "Tunnel up but API closed — re-paste script or enable IP > Services > api"
                    if tunnel_reachable
                    else "Waiting for tunnel and script"
                )
            ),
        }
    )
    checks.append(
        {
            "key": "firewall",
            "status": "ok" if api_enabled else "waiting",
            "label": "Firewall API rule",
            "message": (
                "ispcentric-vpn-api rules active"
                if api_enabled
                else "Script installs API allow rules — finish Winbox paste"
            ),
        }
    )
    return checks


def peer_payload(
    label: str,
    address: str,
    private_key: str,
    public_key: str,
    lan_address: str = "",
) -> dict:
    """JSON-friendly tunnel details for the Connect modal."""
    lan_address = (lan_address or "").strip()
    return {
        "label": label,
        "address": address,
        "lan_address": lan_address,
        "script": routeros_script(address, private_key, lan_address=lan_address),
        "server_peer": server_peer_block(label, address, public_key),
        "endpoint": _endpoint(),
    }


# Ordered markers for Connect paste / unit step-matrix. Keep in install order.
INLINE_INSTALL_STEPS: tuple[str, ...] = (
    "1/8 cleanup",
    "2/8 management",
    "3/8 wireguard",
    "4/8 tunnel-firewall",
    "5/8 hotspot-tunnel",
    "6/8 nat",
    "7/8 handshake",
    "8/8 backup",
)


def validate_inline_install_steps(script: str) -> list[str]:
    """
    Return missing/out-of-order step problems for the Connect paste script.

    Used by tests to lock first→last install order (management before WireGuard).
    """
    text = script or ""
    problems: list[str] = []
    positions: list[tuple[str, int]] = []
    for step in INLINE_INSTALL_STEPS:
        needle = f"Step {step}"
        idx = text.find(needle)
        if idx < 0:
            problems.append(f"missing {needle}")
        else:
            positions.append((step, idx))
    for earlier, later in zip(positions, positions[1:]):
        if earlier[1] >= later[1]:
            problems.append(f"order: Step {earlier[0]} must precede Step {later[0]}")
    # Management must open API before WireGuard so LAN Reconnect works mid-paste.
    mgmt = text.find("Step 2/8 management")
    wg = text.find("Step 3/8 wireguard")
    if mgmt >= 0 and wg >= 0 and mgmt > wg:
        problems.append("management must run before wireguard")
    if "chain=hs-input" not in text and 'comment="ispcentric-vpn-hs-input"' not in text:
        problems.append("missing Hotspot hs-input management allow")
    if 'identity set name="ispcentric.' not in text:
        problems.append("missing ispcentric identity marker for LAN Check")
    if "Key verify — WireGuard public keys" not in text:
        problems.append("missing WireGuard key self-verify after peer add")
    if "Assign unique LAN IP" in text and 'comment="ispcentric-lan"' not in text:
        problems.append("missing ispcentric-lan LAN assignment in script")
    return problems


def _ros_lan_assign_lines(lan_ip: str) -> list[str]:
    """
    RouterOS lines that assign a LAN gateway on the bridge interface.

    Skipped when ``lan_ip`` is the factory default — the router already has it.
    """
    from core.mikrotik_connect import _dhcp_pool_ranges_for_gateway, is_factory_default_mikrotik_ip

    lan_ip = (lan_ip or "").strip()
    if not lan_ip or is_factory_default_mikrotik_ip(lan_ip):
        return []
    try:
        prefix = 24
        net = ipaddress.ip_network(f"{lan_ip}/{prefix}", strict=False)
    except ValueError:
        return []

    cidr = f"{lan_ip}/{prefix}"
    net_str = str(net)
    pool_ranges = _dhcp_pool_ranges_for_gateway(lan_ip, prefix)
    if not pool_ranges:
        pool_ranges = f"{net.network_address + 10}-{net.network_address + 200}"

    ok_lan = _ros_ok(f"LAN IP {cidr} assigned on bridge")
    fail_lan = _ros_fail("Could not add LAN IP on bridge")
    ok_dhcp = _ros_ok(f"DHCP network {net_str} configured")
    ok_remove = _ros_ok("Removed factory LAN 192.168.88.x")
    warn_remove = _ros_warn(
        "Factory LAN 192.168.88.x not found (may already be changed)"
    )

    lines = [
        _ros_info(f"Assign unique LAN IP {lan_ip} (script-set — avoids factory collisions)"),
        ":global IspLanBridge",
        ':set IspLanBridge "bridgeLocal"',
        (
            ":if ([:len [/interface find where name=bridgeLocal]] = 0) do="
            "{:if ([:len [/interface find where name=bridge]] > 0) do="
            '{:set IspLanBridge "bridge"}}}'
        ),
        (
            f":if ([:len [/ip address find where address~\"^{lan_ip}/\"]] = 0) do="
            f'{{:do {{ /ip address add address={cidr} interface=$IspLanBridge '
            f'comment="ispcentric-lan" ; {ok_lan} }} '
            f"on-error={{{fail_lan}}}}}"
        ),
        (
            f':do {{ /ip dhcp-server network set [find where gateway=192.168.88.1] '
            f'address={net_str} gateway={lan_ip} dns-server={lan_ip} }} on-error={{}}'
        ),
        (
            f':if ([:len [/ip dhcp-server network find where address={net_str}]] = 0) do='
            f'{{:do {{ /ip dhcp-server network add address={net_str} gateway={lan_ip} '
            f'dns-server={lan_ip} comment="ispcentric-lan" ; {ok_dhcp} }} on-error={{}}}}'
        ),
        (
            f':do {{ /ip pool set [find where name="ispcentric-lan"] ranges={pool_ranges} }} '
            "on-error={}"
        ),
        (
            ':do { /ip address remove [find where interface=$IspLanBridge and '
            'address~"^192.168.88."] ; '
            f"{ok_remove} }} on-error={{{warn_remove}}}"
        ),
        _ros_check(
            f'[:len [/ip address find where address~\"^{lan_ip}/\"]] > 0',
            f"Verify: LAN gateway {lan_ip} is on the bridge",
            f"Verify: LAN gateway {lan_ip} missing — check bridge interface",
        ),
    ]
    return lines


def _ros_vps_billing_peer_ensure_lines(
    *,
    endpoint_host: str,
    port: str,
    allowed_network: str,
    endpoint_label: str,
    server_public_key: str,
) -> list[str]:
    """
    Add the billing-server peer or repair a wrong public-key / endpoint in place.

    Fixes handshakes when Winbox paste corrupted 0/O in the VPS public-key, or when
    an old manual ``peers set`` left a stale key on the router.
    """
    server_key = _ros_quote_key(server_public_key)
    ka = router_keepalive_interval()
    add_fail = _ros_fail("VPS peer sync failed - check WireGuard interface ispcentric-vpn")
    sync_ok = _ros_ok(f"VPS billing peer synced toward {endpoint_label}")
    return [
        _ros_info("Sync VPS WireGuard peer — add or repair public-key / endpoint"),
        (
            f':do {{ :local expS "{server_key}" ; :local ep "{endpoint_host}" ; '
            f':local pt {port} ; :local net "{allowed_network}" ; :local ka "{ka}" ; '
            f':if ([:len [/interface wireguard peers find where interface=ispcentric-vpn]] = 0) do={{ '
            f'/interface wireguard peers add interface=ispcentric-vpn public-key=$expS '
            f"endpoint-address=$ep endpoint-port=$pt allowed-address=$net "
            f'persistent-keepalive=$ka comment="ispcentric billing server" }} else={{ '
            f":local gotS [/interface wireguard peers get [find where interface=ispcentric-vpn] public-key] ; "
            f':if ($gotS != $expS) do={{ :put "[ISPCENTRIC] Repairing VPS peer public-key from script" ; '
            f"/interface wireguard peers set [find where interface=ispcentric-vpn] public-key=$expS }} ; "
            f"/interface wireguard peers set [find where interface=ispcentric-vpn] endpoint-address=$ep "
            f"endpoint-port=$pt allowed-address=$net persistent-keepalive=$ka "
            f'comment="ispcentric billing server" }} ; '
            f"{sync_ok} }} on-error={{{add_fail}}}"
        ),
    ]


def _ros_wireguard_key_verify_lines(router_public_key: str, server_public_key: str) -> list[str]:
    """
    Compare live WG keys to the reservation; auto-correct VPS peer key once, then verify.
    """
    router_public_key = _ros_quote_key(router_public_key)
    server_public_key = _ros_quote_key(server_public_key)
    if not router_public_key or not server_public_key:
        return []
    fail_router = _ros_fail(
        "Router WG public-key mismatch — paste the full Copy script; never type keys in Winbox"
    )
    fail_server = _ros_fail(
        "VPS peer public-key still wrong after auto-repair — Generate script again and full paste"
    )
    ok_keys = _ros_ok("WireGuard keys match ISPCENTRIC reservation")
    fix_server = _ros_ok("VPS peer public-key corrected automatically")
    return [
        _ros_info("Key verify — WireGuard public keys (must match Copy script)"),
        (
            f':do {{ :local expR "{router_public_key}" ; :local expS "{server_public_key}" ; '
            f':if ([:len [/interface wireguard peers find where interface=ispcentric-vpn]] > 0) do={{ '
            f":local gotS [/interface wireguard peers get [find where interface=ispcentric-vpn] public-key] ; "
            f':if ($gotS != $expS) do={{ /interface wireguard peers set [find where interface=ispcentric-vpn] public-key=$expS ; '
            f"{fix_server} }} }} ; "
            f':local gotR [/interface wireguard get [find name=ispcentric-vpn] public-key] ; '
            f":local gotS2 [/interface wireguard peers get [find interface=ispcentric-vpn] public-key] ; "
            f':if ($gotR != $expR) do={{{fail_router}}} ; '
            f':if ($gotS2 != $expS) do={{{fail_server}}} ; '
            f':if (($gotR = $expR) && ($gotS2 = $expS)) do={{{ok_keys}}} }} '
            f"on-error={{{_ros_warn('Key verify skipped — WireGuard not ready yet')}}}"
        ),
    ]


def _routeros_install_lines(
    address: str,
    private_key: str,
    *,
    include_cleanup: bool,
    lan_address: str = "",
) -> list[str]:
    """
    RouterOS commands that install the billing tunnel (paste-safe, one line each).

    Order (first → last):
      1 cleanup → 2 open management (API + LAN + Hotspot hs-input) →
      3 WireGuard → 4 tunnel firewall → 5 Hotspot bypass (tunnel subnet only) →
      6 NAT → 7 handshake → 8 backup/summary
    """
    host, _, port = _endpoint().partition(":")
    port = port or "51820"
    network = tunnel_network()
    server = str(server_address())
    address = (address or "").strip()
    private_key = (private_key or "").strip()
    if not address or not private_key:
        raise ValueError("This peer has no tunnel address or key yet.")
    endpoint_host = _resolved_endpoint_host(host)
    listen_port = _router_listen_port(address)
    endpoint_label = (
        f"{endpoint_host}:{port}"
        if endpoint_host != host
        else f"{host}:{port}"
    )
    # API / Winbox / SSH — allow through Hotspot without full LAN bypass.
    mgmt_ports = "8728,8291,22"
    server_public_key = resolve_server_public_key()

    lines: list[str] = [
        _ros_info("ISPCENTRIC tunnel install running (8 steps)..."),
    ]

    # --- Step 1: cleanup -------------------------------------------------
    if include_cleanup:
        lines += [
            _ros_info("Step 1/8 cleanup — remove previous ISPCENTRIC tunnel"),
            "# Remove any previous ISPCENTRIC tunnel before replacing it.",
            ':do { /system script remove [find where name~"ispcentric"] ; '
            f'/system script remove [find where comment~"ispcentric"] ; '
            f'/system scheduler remove [find where name~"ispcentric"] ; '
            f'/system scheduler remove [find where comment~"ispcentric"] ; '
            f'{_ros_ok("Old ISPCENTRIC scripts/schedulers removed")} }} on-error='
            f'{{{_ros_warn("Script/scheduler cleanup skipped (none found)")}}}',
            '/ip firewall filter remove [find where comment~"ispcentric-vpn-"]',
            '/ip firewall nat remove [find where comment="ispcentric-vpn-no-nat"]',
            ':do { /ip hotspot ip-binding remove [find where comment~"ispcentric-hotspot-bypass"] } '
            "on-error={}",
            ':do { /ip hotspot ip-binding remove [find where comment~"ispcentric-vpn-hotspot-bypass"] } '
            "on-error={}",
            "/interface wireguard peers remove [find where interface=ispcentric-vpn]",
            "/ip address remove [find where interface=ispcentric-vpn]",
            "/interface wireguard remove [find where name=ispcentric-vpn]",
            _ros_ok("Previous ISPCENTRIC tunnel and rules removed"),
        ]
    else:
        lines.append(_ros_info("Step 1/8 cleanup — skipped (fresh install body)"))

    # --- Step 2: management BEFORE WireGuard (LAN Reconnect / Hotspot) ----
    lines += [
        _ros_info(
            "Step 2/8 management — enable API 8728 + LAN/Hotspot management ports"
        ),
        *_ros_api_enable_lines(verify=True),
    ]
    lan_ip = (lan_address or "").strip()
    if lan_ip:
        lines += _ros_lan_assign_lines(lan_ip)
    lines += [
        "/ip firewall filter",
        # LAN RFC1918 → API (firewall only; never whole-LAN Hotspot bypass).
        # Must sit above the dynamic Hotspot jump on input, or captive PCs never
        # reach these accepts.
        _ros_filter_add(
            "action=accept protocol=tcp dst-port=8728 src-address=10.0.0.0/8",
            "ispcentric-vpn-api-lan-10",
        ),
        _ros_filter_add(
            "action=accept protocol=tcp dst-port=8728 src-address=172.16.0.0/12",
            "ispcentric-vpn-api-lan-172",
        ),
        _ros_filter_add(
            "action=accept protocol=tcp dst-port=8728 src-address=192.168.0.0/16",
            "ispcentric-vpn-api-lan-192",
        ),
        # Before Hotspot jump: management ports for any client (no free internet).
        (
            ':do { /ip firewall filter add chain=input action=accept protocol=tcp '
            f'dst-port={mgmt_ports} comment="ispcentric-vpn-api-mgmt-input" '
            "place-before=([find where chain=input and jump-target=hs-input]->0) } "
            "on-error={ :do { /ip firewall filter add chain=input action=accept "
            f'protocol=tcp dst-port={mgmt_ports} comment="ispcentric-vpn-api-mgmt-input" '
            "} on-error={} }"
        ),
        # Hotspot captive portal: allow mgmt to the router without free internet.
        _ros_filter_add(
            f"action=accept protocol=tcp dst-port={mgmt_ports}",
            "ispcentric-vpn-hs-input",
            chain="hs-input",
        ),
        _ros_filter_add(
            f"action=accept protocol=tcp dst-port={mgmt_ports}",
            "ispcentric-vpn-hs-unauth",
            chain="hs-unauth",
        ),
        (
            ':do { /ip firewall filter add chain=hs-unauth action=accept protocol=tcp '
            f'dst-port={mgmt_ports} comment="ispcentric-vpn-hs-unauth" '
            "place-before=([find where chain=hs-unauth and action=reject]->0) } "
            "on-error={}"
        ),
        _ros_check(
            '[:len [find where comment="ispcentric-vpn-api-lan-192"]] > 0',
            "LAN API firewall rules installed",
            "LAN API firewall rule missing - run: /ip firewall filter print",
        ),
        _ros_ok("Management path open (API + Hotspot-safe ports) — Reconnect can use LAN"),
    ]

    # --- Step 3: WireGuard ------------------------------------------------
    lines += [
        _ros_info("Step 3/8 wireguard — create ispcentric-vpn + peer"),
        "# >>> Required: creates ispcentric-vpn (do not skip) <<<",
        (
            f':do {{ /interface wireguard add name=ispcentric-vpn listen-port={listen_port} '
            f'private-key="{private_key}" comment="ispcentric billing tunnel" ; '
            f'{_ros_ok("WireGuard interface ispcentric-vpn created")} }} '
            f'on-error={{{_ros_fail("WireGuard add failed - copy the add line from Connect and run it alone")}}}'
        ),
        (
            f':do {{ /ip address add address={address}/{network.prefixlen} '
            f'interface=ispcentric-vpn comment="ispcentric billing tunnel" ; '
            f'{_ros_ok(f"Tunnel IP {address}/{network.prefixlen} assigned")} }} '
            f'on-error={{{_ros_fail("Could not assign tunnel IP - WireGuard interface missing")}}}'
        ),
        *_ros_vps_billing_peer_ensure_lines(
            endpoint_host=endpoint_host,
            port=port,
            allowed_network=str(network),
            endpoint_label=endpoint_label,
            server_public_key=server_public_key,
        ),
        _ros_check(
            "[:len [/interface wireguard find where name=ispcentric-vpn]] > 0",
            "Verify: WireGuard interface exists",
            "Verify: WireGuard interface missing - re-paste full script",
        ),
        _ros_check(
            "[:len [/interface wireguard peers find where interface=ispcentric-vpn]] > 0",
            "Verify: VPS peer row exists",
            "Verify: VPS peer row missing",
        ),
        # MNDP-visible marker so LAN Check can confirm paste without login.
        (
            f':do {{ /system identity set name="{script_ready_identity(address)}" ; '
            f'{_ros_ok(f"Identity set to {script_ready_identity(address)} (for Check now)")} }} '
            f"on-error={{{_ros_warn('Could not set identity marker')}}}"
        ),
        *_ros_wireguard_key_verify_lines(
            public_key_for(private_key),
            server_public_key,
        ),
    ]

    # --- Step 4: tunnel firewall (needs WG interface) ---------------------
    lines += [
        _ros_info("Step 4/8 tunnel-firewall — accept API/ICMP from billing tunnel"),
        "/ip firewall filter",
        _ros_filter_add(
            "action=accept protocol=tcp dst-port=8728 in-interface=ispcentric-vpn",
            "ispcentric-vpn-api",
        ),
        _ros_filter_add(
            f"action=accept protocol=tcp dst-port=8728 src-address={network}",
            "ispcentric-vpn-api-net",
        ),
        _ros_filter_add(
            "action=accept protocol=icmp in-interface=ispcentric-vpn",
            "ispcentric-vpn-icmp",
        ),
        _ros_filter_add(
            f"action=accept protocol=icmp src-address={network}",
            "ispcentric-vpn-icmp-net",
        ),
        _ros_check(
            '[:len [find where comment="ispcentric-vpn-api"]] > 0',
            "Input firewall rules for API and ICMP installed",
            "API firewall rule missing - run: /ip firewall filter print",
        ),
        *_ros_wg_udp_output_lines(endpoint_host, port),
    ]

    # --- Step 5: Hotspot bypass for tunnel subnet only --------------------
    lines += [
        _ros_info(
            f"Step 5/8 hotspot-tunnel — bypass Hotspot for billing subnet {network} only"
        ),
        (
            f":do {{ /ip hotspot ip-binding add type=bypassed address={network} "
            f'comment="ispcentric-vpn-hotspot-bypass" ; '
            f'{_ros_ok(f"Hotspot bypass for billing subnet {network}")} }} '
            f"on-error={{{_ros_warn('Hotspot bypass skipped (Hotspot may not be running)')}}}"
        ),
    ]

    # --- Step 6: NAT ------------------------------------------------------
    lines += [
        _ros_info("Step 6/8 nat — do not masquerade traffic to billing tunnel"),
        "/ip firewall nat",
        _ros_nat_add(f"action=accept dst-address={network}", "ispcentric-vpn-no-nat"),
        _ros_check(
            '[:len [find where comment="ispcentric-vpn-no-nat"]] > 0',
            "Srcnat bypass for billing tunnel installed",
            "No-nat rule missing - run: /ip firewall nat print",
        ),
    ]

    # --- Step 7: handshake ------------------------------------------------
    lines += [
        _ros_info("Step 7/8 handshake — ping billing server over WireGuard"),
        *_handshake_wait_lines(server, address),
    ]

    # --- Step 8: backup + summary -----------------------------------------
    lines += [
        _ros_info("Step 8/8 backup — save config and print summary"),
        *_ros_tunnel_watchdog_lines(server),
        _ros_info("Final verify — RouterOS API must stay enabled on 8728"),
        *_ros_api_enable_lines(verify=True),
        ':do { /file remove [find where name="ispcentric-tunnel.backup"] } on-error={}',
        "/system backup",
        "save name=ispcentric-tunnel dont-encrypt=yes",
        _ros_ok("Backup saved as ispcentric-tunnel.backup"),
        _ros_info("---------- ISPCENTRIC summary ----------"),
        _ros_check(
            "[:len [/interface wireguard find where name=ispcentric-vpn]] > 0",
            "Summary: WireGuard interface",
            "Summary: WireGuard interface",
        ),
        _ros_check(
            "[:len [/interface wireguard peers find where interface=ispcentric-vpn]] > 0",
            "Summary: VPS peer",
            "Summary: VPS peer",
        ),
        _ros_check(
            _ros_api_enabled_condition(),
            "Summary: API port 8728",
            "Summary: API port 8728",
        ),
        _ros_check(
            '[:len [/ip firewall filter find where comment="ispcentric-vpn-api"]] > 0',
            "Summary: Firewall API rule",
            "Summary: Firewall API rule",
        ),
        _ros_check(
            '[:len [/ip firewall filter find where comment="ispcentric-vpn-hs-input"]] > 0',
            "Summary: Hotspot management allow (hs-input)",
            "Summary: Hotspot hs-input rule missing (ok if no Hotspot package)",
        ),
        _ros_check(
            f'[/ping {server} count=1] > 0',
            f"Summary: Ping to billing server {server}",
            f"Summary: Ping to billing server {server} (VPS peer / handshake missing)",
        ),
        _ros_info(
            "If ping FAIL: sync-server on VPS, wait 30s (keepalive), then Check now"
        ),
        _ros_info("---------- end ISPCENTRIC install ----------"),
    ]
    return lines


def _escape_ros_file_contents(text: str) -> str:
    """Escape text for RouterOS /file add contents=\"...\"."""
    return (
        (text or "")
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\n", "\\n")
    )


def _routeros_customized_flag_lines() -> list[str]:
    """
    Short one-line checks that set :global IspCentricCustom.

    Kept as separate lines so Winbox paste never wraps mid-command (e.g. /queue -> ueue).
    Used inside downloaded .rsc files only — not in the bootstrap paste.
    """
    return [
        ":global IspCentricCustom 0",
        ":if ([:len [/ip hotspot find]] > 0) do={:set IspCentricCustom 1}",
        ":if ([:len [/ip hotspot user find]] > 0) do={:set IspCentricCustom 1}",
        ":if ([:len [/ppp secret find]] > 0) do={:set IspCentricCustom 1}",
        (
            ":if ([:len [/interface pppoe-server server find]] > 0) do="
            "{:set IspCentricCustom 1}"
        ),
        ":if ([:len [/interface wireguard find]] > 1) do={:set IspCentricCustom 1}",
        (
            ":if ([:len [/interface wireguard find]] > 0) do={"
            ":if ([:len [/interface wireguard find where name=ispcentric-vpn]] = 0) do="
            "{:set IspCentricCustom 1}}"
        ),
    ]


def _routeros_maybe_reset_lines() -> list[str]:
    """If IspCentricCustom=1, factory-reset using downloaded .rsc; else continue."""
    return [
        (
            ":if ($IspCentricCustom = 1) do={"
            ':put "[ISPCENTRIC WARN] Custom config - factory reset in 5s (passwords kept)"; '
            ":delay 5s; "
            ':if ([:len [/file find where name="flash/ispcentric-post-reset.rsc"]] > 0) do={'
            "/system reset-configuration keep-users=yes skip-backup=yes "
            "run-after-reset=flash/ispcentric-post-reset.rsc}; "
            ':if ([:len [/file find where name="ispcentric-post-reset.rsc"]] > 0) do={'
            "/system reset-configuration keep-users=yes skip-backup=yes "
            "run-after-reset=ispcentric-post-reset.rsc}; "
            ':error "ISPCENTRIC: reset scheduled or post-reset.rsc missing"}'
        ),
        _ros_ok("Clean router - continuing tunnel install (no reset)"),
    ]


def rsc_download_mac(address: str) -> str:
    """Short HMAC so MikroTik can fetch .rsc without a long signed query string."""
    import hashlib
    import hmac

    address = (address or "").strip()
    key = (getattr(settings, "SECRET_KEY", "") or "ispcentric").encode("utf-8")
    digest = hmac.new(
        key,
        f"mikrotik-rsc:{address}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:12]


def verify_rsc_download_mac(address: str, mac: str) -> bool:
    import hmac

    expected = rsc_download_mac(address)
    return hmac.compare_digest(expected, (mac or "").strip().lower())


def rsc_download_allowed(address: str) -> bool:
    """
    Rate-limit public .rsc downloads per tunnel address.

    MikroTik may retry /tool fetch a few times during paste, so this is not a
    single-use token — it caps abuse while keeping install scripts reliable.
    """
    from django.core.cache import cache

    address = (address or "").strip()
    if not address:
        return False
    limit = int(getattr(settings, "WIREGUARD_RSC_DOWNLOAD_LIMIT", 20) or 20)
    window = int(getattr(settings, "WIREGUARD_RSC_DOWNLOAD_WINDOW", 3600) or 3600)
    key = f"wg_rsc_dl:{address}"
    data = cache.get(key) or {"count": 0}
    count = int(data.get("count") or 0)
    if count >= limit:
        return False
    cache.set(key, {"count": count + 1}, window)
    return True


def short_rsc_url(address: str, kind: str) -> tuple[str, str]:
    """
    Return (url, http_host) for /app/m/<addr>/<mac>/<i|p>/.

    Trailing slash is required — without it Django returns 301 and MikroTik
    /tool fetch fails. Keep the path short; paste builds it in pieces.
    """
    fetch_base, http_host = _script_fetch_target()
    if not fetch_base:
        return "", ""
    address = (address or "").strip()
    kind = "p" if (kind or "").strip().lower() in {"p", "post-reset", "reset", "post_reset"} else "i"
    mac = rsc_download_mac(address)
    return f"{fetch_base}/app/m/{address}/{mac}/{kind}/", http_host


def _fetch_rsc_parts(url: str) -> tuple[str, str, str]:
    """Split http://host/path into (origin, path_prefix, path_tail) for short paste lines."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    # Keep each RouterOS string literal well under typical Winbox wrap width.
    if len(path) <= 40:
        return origin, path, ""
    cut = path.rfind("/", 0, max(len(path) // 2, 1))
    if cut <= 0:
        cut = len(path) // 2
    return origin, path[:cut], path[cut:]


def _fetch_rsc_retry_lines(
    url: str,
    host_header: str,
    dst: str,
    ok_msg: str,
    fail_msg: str,
    *,
    attempts: int = 5,
    require_wan: bool = False,
) -> list[str]:
    """
    Build URL from short pieces, then retry /tool fetch (one short line per try).

    Winbox paste cannot run multi-line :for { } blocks — each line is its own
    prompt. :global keeps the URL across lines (:local does not). When
    require_wan=True, skips fetch unless IspWanOk=1 (bootstrap paste).
    """
    origin, mid, tail = _fetch_rsc_parts(url)
    header = ""
    host_lines: list[str] = []
    if host_header and host_header not in url:
        host_lines = [
            ":global IspFetchHost",
            f':set IspFetchHost "Host:{host_header}"',
        ]
        header = " http-header-field=$IspFetchHost"
    tag = "Flash" if "flash/" in dst else ("Inst" if "install" in dst else "Root")
    url_var = f"IspUrl{tag}"
    attempts = max(1, int(attempts))
    missing = f'([:len [/file find where name="{dst}"]] = 0)'
    gate = f"($IspWanOk = 1) && {missing}" if require_wan else missing
    lines = [
        f":global {url_var}",
        f':set {url_var} "{origin}"',
        f':set {url_var} (${url_var} . "{mid}")',
    ]
    if tail:
        lines.append(f':set {url_var} (${url_var} . "{tail}")')
    lines.extend(host_lines)
    if require_wan:
        lines.append(
            f':if ($IspWanOk = 0) do={{{_ros_fail("Skip download - WAN ping failed")}}} '
            f"else={{{_ros_info(f'Downloading {dst}...')}}}"
        )
    for try_n in range(1, attempts + 1):
        lines.append(
            f":if ({gate}) do={{:do {{ /tool fetch url=${url_var}{header} "
            f"dst-path={dst} mode=http ; {_ros_ok(ok_msg)} }} on-error={{"
            f':put "[ISPCENTRIC] Download {try_n}/{attempts} failed"; :delay 3s}}}}'
        )
    lines.append(f":if ({missing}) do={{{_ros_fail(fail_msg)}}}")
    return lines


def install_rsc_body(address: str, private_key: str, lan_address: str = "") -> str:
    """Full install .rsc: fetch post-reset if needed, decide reset vs install, configure."""
    address = (address or "").strip()
    private_key = (private_key or "").strip()
    lan_address = (lan_address or "").strip()
    lines = ["# ISPCENTRIC install.rsc"]
    reset_url, http_host = short_rsc_url(address, "p")
    if reset_url:
        lines += [
            "# Download post-reset .rsc before any factory reset (inside /import — no Winbox wrap).",
            ':do { /file remove [find where name="ispcentric-post-reset.rsc"] } on-error={}',
            ':do { /file remove [find where name="flash/ispcentric-post-reset.rsc"] } on-error={}',
            *_fetch_rsc_retry_lines(
                reset_url,
                http_host,
                "flash/ispcentric-post-reset.rsc",
                "Downloaded flash/ispcentric-post-reset.rsc",
                "Fetch post-reset.rsc to flash failed after retries",
                attempts=5,
            ),
            *_fetch_rsc_retry_lines(
                reset_url,
                http_host,
                "ispcentric-post-reset.rsc",
                "Downloaded ispcentric-post-reset.rsc (root fallback)",
                "Fetch post-reset.rsc to root failed after retries",
                attempts=5,
            ),
        ]
    lines += [
        *_routeros_customized_flag_lines(),
        *_routeros_maybe_reset_lines(),
        *_routeros_install_lines(
            address, private_key, include_cleanup=True, lan_address=lan_address
        ),
    ]
    return "\n".join(lines)


def post_reset_rsc_body(address: str, private_key: str, lan_address: str = "") -> str:
    """Compact post-reset .rsc body."""
    return _routeros_post_reset_rsc_body(address, private_key, lan_address=lan_address)


def _fetch_rsc_line(url: str, host_header: str, dst: str, ok_msg: str, fail_msg: str) -> str:
    """One /tool fetch line (prefer _fetch_rsc_retry_lines for paste)."""
    header = ""
    if host_header and host_header not in url:
        header = f' http-header-field="Host:{host_header}"'
    return (
        f':do {{ /tool fetch url="{url}"{header} dst-path={dst} mode=http ; '
        f'{_ros_ok(ok_msg)} }} on-error={{{_ros_fail(fail_msg)}}}'
    )


def _routeros_post_reset_rsc_body(
    address: str, private_key: str, lan_address: str = ""
) -> str:
    """
    Compact .rsc run after factory reset (must stay small for /file contents=).

    run-after-reset has a ~2 minute runtime cap and needs a boot delay so
    interfaces exist before WireGuard/API rules are applied.
    """
    host, _, port = _endpoint().partition(":")
    port = port or "51820"
    network = tunnel_network()
    server = str(server_address())
    address = (address or "").strip()
    private_key = (private_key or "").strip()
    lan_address = (lan_address or "").strip()
    endpoint_host = _resolved_endpoint_host(host)
    listen_port = _router_listen_port(address)
    server_public_key = resolve_server_public_key()
    endpoint_label = (
        f"{endpoint_host}:{port}"
        if endpoint_host != host
        else f"{host}:{port}"
    )
    body = [
        "# ISPCENTRIC post-reset tunnel install",
        ":delay 20s",
        *_wan_wait_lines(endpoint_host),
        (
            f'/interface wireguard add name=ispcentric-vpn listen-port={listen_port} '
            f'private-key="{private_key}" comment="ispcentric billing tunnel"'
        ),
        (
            f'/ip address add address={address}/{network.prefixlen} '
            f'interface=ispcentric-vpn comment="ispcentric billing tunnel"'
        ),
        *_ros_vps_billing_peer_ensure_lines(
            endpoint_host=endpoint_host,
            port=port,
            allowed_network=str(network),
            endpoint_label=endpoint_label,
            server_public_key=server_public_key,
        ),
        *_ros_api_enable_lines(verify=False),
        (
            '/ip firewall filter add chain=input action=accept protocol=tcp '
            'dst-port=8728 in-interface=ispcentric-vpn comment="ispcentric-vpn-api"'
        ),
        (
            f'/ip firewall filter add chain=input action=accept protocol=tcp '
            f'dst-port=8728 src-address={network} comment="ispcentric-vpn-api-net"'
        ),
        (
            '/ip firewall filter add chain=input action=accept protocol=icmp '
            'in-interface=ispcentric-vpn comment="ispcentric-vpn-icmp"'
        ),
        (
            '/ip firewall filter add chain=input action=accept protocol=tcp '
            'dst-port=8728 src-address=10.0.0.0/8 comment="ispcentric-vpn-api-lan-10"'
        ),
        (
            '/ip firewall filter add chain=input action=accept protocol=tcp '
            'dst-port=8728 src-address=172.16.0.0/12 comment="ispcentric-vpn-api-lan-172"'
        ),
        (
            '/ip firewall filter add chain=input action=accept protocol=tcp '
            'dst-port=8728 src-address=192.168.0.0/16 comment="ispcentric-vpn-api-lan-192"'
        ),
        (
            f'/ip firewall nat add chain=srcnat action=accept dst-address={network} '
            f'comment="ispcentric-vpn-no-nat"'
        ),
        (
            f':do {{ /ip hotspot ip-binding add type=bypassed address={network} '
            f'comment="ispcentric-vpn-hotspot-bypass" }} on-error={{}}'
        ),
        (
            f'/ip firewall filter add chain=output action=accept protocol=udp '
            f'dst-address={endpoint_host} dst-port={port} '
            f'comment="ispcentric-vpn-wg-udp-out"'
        ),
        *_handshake_wait_lines(server, address),
        ':put "[ISPCENTRIC OK] Post-reset tunnel install finished - Check now in ISPCENTRIC"',
    ]
    if lan_address:
        body = body[:4] + _ros_lan_assign_lines(lan_address) + body[4:]
    return "\n".join(body)


def _script_fetch_target() -> tuple[str, str]:
    """
    Return (fetch_base_url, http_host_header_value).

    Prefer a literal IPv4 base so MikroTik /tool fetch works when DNS is broken.
    nginx still needs Host: when the site is name-based — pass that separately.
    """
    base = _script_public_base_url()
    if not base:
        return "", ""
    from urllib.parse import urlparse

    parsed = urlparse(base if "://" in base else f"http://{base}")
    host = (parsed.hostname or "").strip()
    port = parsed.port
    scheme = parsed.scheme or "http"
    if not host:
        return base, ""
    resolved = _resolved_endpoint_host(host)
    netloc = resolved
    if port and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        netloc = f"{resolved}:{port}"
    return f"{scheme}://{netloc}", host


def _script_public_base_url() -> str:
    """Absolute HTTP base from PUBLIC_BASE_URL / portal helper."""
    try:
        from core.mikrotik_connect import _billing_portal_base_url

        base = (_billing_portal_base_url() or "").strip().rstrip("/")
    except Exception:
        base = ""
    if not base:
        base = (getattr(settings, "PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
    if base.lower() in {"", "auto"}:
        return ""
    if base.startswith("https://"):
        base = "http://" + base[len("https://") :]
    return base


def rsc_access_token(address: str) -> str:
    """Signed token so MikroTik can download .rsc without a browser session."""
    from django.core import signing

    return signing.dumps(
        {"address": (address or "").strip()},
        salt="mikrotik-tunnel-rsc",
        compress=True,
    )


def routeros_script(
    address: str,
    private_key: str,
    *,
    factory_reset: bool = True,
    lan_address: str = "",
) -> str:
    """
    Full inline Winbox paste to join the billing WireGuard tunnel.

    Install order (see ``INLINE_INSTALL_STEPS``): cleanup → management (API +
    Hotspot-safe ports) → WireGuard → tunnel firewall → Hotspot tunnel bypass →
    NAT → handshake → backup. ``factory_reset`` is accepted for call-site
    compatibility but ignored — Connect always pastes this full inline script.
    """
    _endpoint()
    _server_public_key()
    resolve_server_public_key()
    install = _routeros_install_lines(
        address,
        private_key,
        include_cleanup=True,
        lan_address=lan_address,
    )
    return "\n".join(
        [
            "# ISPCENTRIC billing tunnel - paste into the MikroTik terminal.",
            "# Requires RouterOS 7. Safe to re-run: replaces previous ISPCENTRIC config only.",
            _ros_info("Starting ISPCENTRIC tunnel install..."),
            _ros_info("Look for [ISPCENTRIC OK] or [ISPCENTRIC FAIL] on each line below"),
            *install,
        ]
    )


def server_peer_block(label: str, address: str, public_key: str) -> str:
    """The [Peer] stanza to add to the VPS wg0.conf for one router."""
    public_key = (public_key or "").strip()
    address = (address or "").strip()
    if not public_key or not address:
        raise ValueError("This peer has no tunnel address or key yet.")
    return "\n".join(
        [
            f"# {label}",
            "[Peer]",
            f"PublicKey = {public_key}",
            f"AllowedIPs = {address}/32",
        ]
    )


def server_config(private_key: str) -> str:
    """A complete wg0.conf for the VPS, with every peer known so far."""
    from core.models import MikroTikRouter, WireGuardReservation

    _, _, port = _endpoint().partition(":")
    network = tunnel_network()
    lines = [
        "# /etc/wireguard/wg0.conf on the billing VPS",
        "[Interface]",
        f"Address = {server_address()}/{network.prefixlen}",
        f"ListenPort = {port or '51820'}",
        f"PrivateKey = {private_key}",
        "",
    ]

    blocks: list[str] = []
    for router in (
        MikroTikRouter.objects.exclude(vpn_address__isnull=True)
        .exclude(vpn_public_key="")
        .order_by("id")
    ):
        blocks.append(
            server_peer_block(
                f"{router.name} (router id {router.pk})",
                router.vpn_address,
                router.vpn_public_key,
            )
        )
    for reservation in WireGuardReservation.objects.all():
        blocks.append(
            server_peer_block(
                f"{reservation.label} (not onboarded yet)",
                reservation.address,
                reservation.public_key,
            )
        )

    if not blocks:
        lines.append("# No peers provisioned yet.")
    for block in blocks:
        lines.append(block)
        lines.append("")
    return "\n".join(lines)
