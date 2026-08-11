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
import shlex
import shutil
import socket
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from django.conf import settings

logger = logging.getLogger(__name__)


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


def _server_public_key() -> str:
    key = (getattr(settings, "WIREGUARD_SERVER_PUBLIC_KEY", "") or "").strip()
    if not looks_like_wg_key(key):
        raise ValueError(
            "WIREGUARD_SERVER_PUBLIC_KEY is missing or invalid. Run "
            "`python manage.py wireguard_peer --server-keys` and put the "
            "public key in .env (not the placeholder text)."
        )
    return key


def reserve_peer(label: str):
    """
    Create or reuse a WireGuardReservation for a router that is not onboarded yet.

    Returns (reservation, peer_sync). Same label (case-insensitive) keeps one peer
    so the Connect modal can regenerate the paste script without burning addresses.
    """
    from core.models import WireGuardReservation

    label = (label or "").strip() or "New MikroTik"
    reservation = WireGuardReservation.objects.filter(label__iexact=label).first()
    if reservation is None:
        private_key, public_key = generate_keypair()
        reservation = WireGuardReservation.objects.create(
            label=label,
            address=allocate_address(),
            private_key=private_key,
            public_key=public_key,
        )

    peer_sync = apply_server_peer(
        reservation.label,
        reservation.address,
        reservation.public_key,
    )
    return reservation, peer_sync


def adopt_reservation_for_router(router) -> bool:
    """
    If the router was onboarded on a reserved tunnel address, attach that peer.

    Returns True when keys were adopted (or already match the reservation).
    """
    from core.models import WireGuardReservation

    host = (getattr(router, "host", None) or "").strip()
    if not host:
        return False

    reservation = WireGuardReservation.objects.filter(address=host).first()
    if reservation is None:
        return False

    changed: list[str] = []
    if router.vpn_address != reservation.address:
        router.vpn_address = reservation.address
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


def _ros_filter_add(rule: str, comment: str) -> str:
    """
    Insert an input-chain filter rule near the top when the chain has rules.

    ``place-before=0`` fails with "no such item" when the filter list is empty
    (common on cleaned or CHR configs). Fall back to append in that case.
    """
    body = f'add chain=input {rule} comment="{comment}"'
    return (
        f":do {{ {body} place-before=([find where chain=input and dynamic=no]->0) }} "
        f"on-error={{ :do {{ {body} place-before=([find where chain=input]->0) }} "
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


def _ros_ping_probe(server: str, address: str) -> str:
    """
    Ping the billing server several times without :local or multi-line blocks.

    RouterOS New Terminal executes pasted lines one-by-one. Chaining multiple
    :delay commands on one line fails with "expected end of command", so each
    wait and check is its own line.
    """
    ok_message = (
        f"Tunnel {address} reaches billing server {server} - click Connect in ISPCENTRIC"
    )
    fail_message = (
        f"No ping from {server}. Add this router [Peer] on VPS wg0, "
        f"run: wg-quick down wg0; wg-quick up wg0, then re-paste or Connect"
    )
    ping = f"[/ping {server} count=2]"
    lines = [
        ":delay 3s",
        f':if ({ping} > 0) do={{{_ros_ok(ok_message)}}}',
        ":delay 5s",
        f':if ({ping} > 0) do={{{_ros_ok(ok_message)}}}',
        ":delay 5s",
        f':if ({ping} > 0) do={{{_ros_ok(ok_message)}}}',
        ":delay 5s",
        _ros_check(f"{ping} > 0", ok_message, fail_message),
    ]
    return "\n".join(lines)


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


def apply_server_peer(label: str, address: str, public_key: str) -> dict:
    """
    Register a MikroTik peer on the billing VPS WireGuard interface.

    Without this step the router can dial the VPS but the server never accepts
    the tunnel, so ping/API checks stay on Waiting forever.
    """
    if not configured():
        return {"ok": False, "skipped": True, "reason": "wireguard_not_configured"}
    if not server_on_tunnel():
        return {"ok": False, "skipped": True, "reason": "not_on_tunnel"}

    public_key = (public_key or "").strip()
    address = (address or "").strip()
    if not public_key or not address:
        return {"ok": False, "skipped": True, "reason": "missing_peer_fields"}

    iface = _wireguard_interface()
    conf_path = _wireguard_conf_path()
    sync_cmd = (getattr(settings, "WIREGUARD_SYNC_COMMAND", None) or "").strip()
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
            )
            if proc.returncode == 0:
                result.update(ok=True, runtime=True, persisted=True)
                return result
            result["error"] = (proc.stderr or proc.stdout or "sync command failed").strip()
        except Exception as exc:
            result["error"] = str(exc)

    wg_bin = shutil.which("wg") or "wg"
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


def sync_all_server_peers() -> dict:
    """Apply every onboarded router and pending reservation to the local wg0."""
    from core.models import MikroTikRouter, WireGuardReservation

    if not server_on_tunnel():
        return {"ok": False, "skipped": True, "reason": "not_on_tunnel", "synced": 0}

    synced = 0
    errors: list[str] = []
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
    return {"ok": not errors, "synced": synced, "errors": errors}


def tunnel_verification_checks(
    *,
    local_mode: bool,
    address: str,
    tunnel_reachable: bool,
    api_enabled: bool,
    lan_address: str = "",
    subnet_mismatch: bool = False,
    multiple_devices: bool = False,
) -> list[dict[str, str]]:
    """
    Structured pass/fail rows for the Connect modal (mirrors Winbox script summary).

    Each item: key, status (ok|fail|warn|waiting), label, message.
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
                        "Paste the script in Winbox and wait for [ISPCENTRIC OK] lines"
                        if lan_address and not subnet_mismatch
                        else "Waiting for LAN discovery and script"
                    )
                ),
            }
        )

        if lan_address and not subnet_mismatch:
            checks.append(
                {
                    "key": "firewall",
                    "status": "ok" if api_enabled else "waiting",
                    "label": "Firewall API rule",
                    "message": (
                        "Input filter accepts API from this LAN"
                        if api_enabled
                        else "Script adds ispcentric-vpn-api rules — finish paste in Winbox"
                    ),
                }
            )
        return checks

    checks.append(
        {
            "key": "tunnel",
            "status": "ok" if tunnel_reachable else "waiting",
            "label": "WireGuard interface",
            "message": (
                f"Tunnel IP {address} reachable from billing server"
                if tunnel_reachable
                else "Waiting — paste script in Winbox New Terminal"
            ),
        }
    )
    checks.append(
        {
            "key": "vps_peer",
            "status": "ok" if tunnel_reachable else "fail",
            "label": "VPS peer",
            "message": (
                f"Billing server accepts traffic to {address}"
                if tunnel_reachable
                else f"Add [Peer] AllowedIPs={address}/32 on VPS wg0, restart WireGuard"
            ),
        }
    )
    checks.append(
        {
            "key": "billing_ping",
            "status": (
                "ok"
                if tunnel_reachable and api_enabled
                else ("waiting" if not tunnel_reachable else "warn")
            ),
            "label": f"Ping billing server {server}",
            "message": (
                f"Router can reach {server} and API is open — ready to Connect"
                if tunnel_reachable and api_enabled
                else (
                    f"Tunnel up — confirm [ISPCENTRIC OK] ping line in Winbox"
                    if tunnel_reachable
                    else f"No route to {server} yet — register peer on VPS"
                )
            ),
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
            "status": "ok" if api_enabled else ("waiting" if tunnel_reachable else "waiting"),
            "label": "Firewall API rule",
            "message": (
                "ispcentric-vpn-api rules active"
                if api_enabled
                else "Script installs API allow rules — finish Winbox paste"
            ),
        }
    )
    return checks


def peer_payload(label: str, address: str, private_key: str, public_key: str) -> dict:
    """JSON-friendly tunnel details for the Connect modal."""
    return {
        "label": label,
        "address": address,
        "script": routeros_script(address, private_key),
        "server_peer": server_peer_block(label, address, public_key),
        "endpoint": _endpoint(),
    }


def routeros_script(address: str, private_key: str) -> str:
    """
    Commands to paste into the MikroTik terminal to join the tunnel.

    The interface name is fixed rather than per-site: a router has one tunnel to
    the billing server. Every run removes all earlier ISPCENTRIC components
    before installing the latest address, private key, server peer, and rules.

    Besides bringing WireGuard up, the script always:
    - deletes any previous ISPCENTRIC /system script and scheduler entries first
    - force-enables the RouterOS API on port 8728 (compulsory for Connect)
    - clears any /ip service address= restriction that silently blocks API
    - accepts API + ICMP from the tunnel and private LANs in the input filter
    - removes any old LAN-wide Hotspot bypasses (those opened free internet for everyone)
    - bypasses Hotspot only for the billing WireGuard subnet (not customer LAN)
    - prints [ISPCENTRIC OK/FAIL/WARN] after every step for Winbox visibility
    - skips srcnat/masquerade for traffic to the tunnel so PPP client IPs survive
    - retries ping for ~30s while WireGuard negotiates, then prints pass/fail

    API access is locked down by firewall (tunnel + private LAN only), not by the
    /ip service address= list — that property has broken silently on some
    RouterOS builds and left API disabled, which blocks Connect entirely.

    Do not Hotspot-bypass whole RFC1918 ranges. That made every unpaid Wi‑Fi
    client look authorized. Customer internet stays per-MAC Hotspot users; the
    billing server LAN IP is bypassed separately when Hotspot is applied.
    """
    host, _, port = _endpoint().partition(":")
    port = port or "51820"
    network = tunnel_network()
    server = str(server_address())
    address = (address or "").strip()
    private_key = (private_key or "").strip()
    if not address or not private_key:
        raise ValueError("This peer has no tunnel address or key yet.")

    return "\n".join(
        [
            "# ISPCENTRIC billing tunnel - paste into the MikroTik terminal.",
            "# Requires RouterOS 7. Safe to re-run: the newest script replaces the old one.",
            _ros_info("Starting ISPCENTRIC tunnel install..."),
            _ros_info("Look for [ISPCENTRIC OK] or [ISPCENTRIC FAIL] on each line below"),
            "# 1) Delete any previous ISPCENTRIC scripts/schedulers saved on the router.",
            ':do { /system script remove [find where name~"ispcentric"] ; '
            f'/system script remove [find where comment~"ispcentric"] ; '
            f'/system scheduler remove [find where name~"ispcentric"] ; '
            f'/system scheduler remove [find where comment~"ispcentric"] ; '
            f'{_ros_ok("Old ISPCENTRIC scripts/schedulers removed")} }} on-error='
            f'{{{_ros_warn("Script/scheduler cleanup skipped (none found)")}}}',
            "# 2) Remove the complete previous ISPCENTRIC tunnel, then install this version.",
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
            "# Install the latest tunnel interface, key, address, and VPS peer.",
            "# >>> Required: the next line creates ispcentric-vpn (do not skip) <<<",
            (
                f':do {{ /interface wireguard add name=ispcentric-vpn listen-port=13231 '
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
            (
                f':do {{ /interface wireguard peers add interface=ispcentric-vpn '
                f'public-key="{_server_public_key()}" endpoint-address={host} endpoint-port={port} '
                f"allowed-address={network} persistent-keepalive=25s "
                f'comment="ispcentric billing server" ; '
                f'{_ros_ok(f"VPS peer configured toward {host}:{port}")} }} '
                f'on-error={{{_ros_fail("VPS peer add failed - check WireGuard interface")}}}'
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
            "# Compulsory: RouterOS API on 8728 - Connect cannot work without it.",
            "# Clear address= restrictions (empty + 0.0.0.0/0) - a LAN-only list looks",
            "# like 'connection refused' from the billing PC / tunnel.",
            ":do { /ip service set [find where name=api] disabled=no port=8728 address=\"\" } on-error={}",
            ":do { /ip service set [find where name=api] disabled=no port=8728 address=0.0.0.0/0 } on-error={}",
            ":do { /ip service set api disabled=no port=8728 address=0.0.0.0/0 } on-error={}",
            ":do { /ip service enable [find where name=api] } on-error={}",
            _ros_check(
                "[:len [/ip service find where name=api and disabled=no and port=8728]] > 0",
                "RouterOS API enabled on port 8728",
                "RouterOS API still disabled - open IP > Services > api, port 8728, Allowed From empty",
            ),
            (
                ':do { :put ("[ISPCENTRIC] API allowed-from: " . '
                '[/ip service get [find where name=api] address]) } on-error={'
                f'{_ros_warn("Could not read API allowed-from list")}'
                "}"
            ),
            "# Hotspot may still sit on the LAN; only the billing tunnel subnet may bypass.",
            "# Never bypass 10/8, 172.16/12, or 192.168/16 - that opens free internet for all clients.",
            (
                f":do {{ /ip hotspot ip-binding add type=bypassed address={network} "
                f'comment="ispcentric-vpn-hotspot-bypass" ; '
                f'{_ros_ok(f"Hotspot bypass for billing subnet {network}")} }} '
                f"on-error={{{_ros_warn('Hotspot bypass skipped (Hotspot may not be running)')}}}"
            ),
            "# Allow API + ICMP from the billing tunnel (not the public WAN).",
            "# place-before=0 fails on empty chains - each add falls back to append.",
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
            _ros_check(
                '[:len [find where comment="ispcentric-vpn-api"]] > 0',
                "Input firewall rules for API and ICMP installed",
                "API firewall rule missing - run: /ip firewall filter print",
            ),
            "# Keep client/PPP source IPs intact when talking to the billing tunnel.",
            "/ip firewall nat",
            _ros_nat_add(f"action=accept dst-address={network}", "ispcentric-vpn-no-nat"),
            _ros_check(
                '[:len [find where comment="ispcentric-vpn-no-nat"]] > 0',
                "Srcnat bypass for billing tunnel installed",
                "No-nat rule missing - run: /ip firewall nat print",
            ),
            _ros_info("Probing tunnel to billing server (retries ~20s)..."),
            *_ros_ping_probe(server, address).splitlines(),
            (
                ':do { :put ("[ISPCENTRIC] WireGuard last-handshake: " . '
                '[/interface wireguard peers get [find where interface=ispcentric-vpn] '
                'last-handshake]) } on-error={'
                f'{_ros_warn("No handshake yet - add [Peer] on VPS wg0 and restart WireGuard")}'
                "}"
            ),
            "# Replace the old backup so it always contains the latest tunnel.",
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
                "[:len [/ip service find where name=api and disabled=no and port=8728]] > 0",
                "Summary: API port 8728",
                "Summary: API port 8728",
            ),
            _ros_check(
                '[:len [/ip firewall filter find where comment="ispcentric-vpn-api"]] > 0',
                "Summary: Firewall API rule",
                "Summary: Firewall API rule",
            ),
            _ros_check(
                f'[/ping {server} count=1] > 0',
                f"Summary: Ping to billing server {server}",
                f"Summary: Ping to billing server {server} (add VPS [Peer] if FAIL)",
            ),
            _ros_info("If all lines above show OK and ping FAIL, add [Peer] on VPS wg0"),
            _ros_info("Then click Connect in ISPCENTRIC when ping shows OK"),
            _ros_info("---------- end ISPCENTRIC install ----------"),
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
