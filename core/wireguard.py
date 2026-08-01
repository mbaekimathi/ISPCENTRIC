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
import socket

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from django.conf import settings


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

    Returns the reservation. Same label (case-insensitive) keeps one peer so the
    Connect modal can regenerate the paste script without burning addresses.
    """
    from core.models import WireGuardReservation

    label = (label or "").strip() or "New MikroTik"
    reservation = WireGuardReservation.objects.filter(label__iexact=label).first()
    if reservation is not None:
        return reservation

    private_key, public_key = generate_keypair()
    return WireGuardReservation.objects.create(
        label=label,
        address=allocate_address(),
        private_key=private_key,
        public_key=public_key,
    )


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
    - force-enables the RouterOS API on port 8728 (compulsory for Connect)
    - accepts API + ICMP from the tunnel in the input filter
    - skips srcnat/masquerade for traffic to the tunnel so PPP client IPs survive
    - pings the billing server and prints a clear pass/fail line

    API access is locked down by firewall (tunnel subnet only), not by the
    /ip service address= list — that property has broken silently on some
    RouterOS builds and left API disabled, which blocks Connect entirely.
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
            "# Remove the complete previous ISPCENTRIC tunnel before applying this version.",
            '/ip firewall filter remove [find where comment~"ispcentric-vpn-"]',
            '/ip firewall nat remove [find where comment="ispcentric-vpn-no-nat"]',
            "/interface wireguard peers remove [find where interface=ispcentric-vpn]",
            "/ip address remove [find where interface=ispcentric-vpn]",
            "/interface wireguard remove [find where name=ispcentric-vpn]",
            "# Install the latest tunnel interface, key, address, and VPS peer.",
            f'/interface wireguard add name=ispcentric-vpn listen-port=13231 private-key="{private_key}" '
            'comment="ispcentric billing tunnel"',
            f"/ip address add address={address}/{network.prefixlen} interface=ispcentric-vpn "
            'comment="ispcentric billing tunnel"',
            f'/interface wireguard peers add interface=ispcentric-vpn public-key="{_server_public_key()}" '
            f"endpoint-address={host} endpoint-port={port} "
            f"allowed-address={network} persistent-keepalive=25s "
            'comment="ispcentric billing server"',
            "# Compulsory: RouterOS API on 8728 — Connect cannot work without it.",
            "/ip service",
            "set [find where name=api] disabled=no port=8728 address=0.0.0.0/0",
            ":do { /ip service set api disabled=no port=8728 } on-error={}",
            (
                ":if ([:len [/ip service find where name=api and disabled=no]] = 0) do={"
                ':put "ispcentric ERROR: RouterOS API is still disabled — enable IP > Services > api"} '
                'else={:put "ispcentric API: enabled on port 8728"}'
            ),
            "# Allow API + ICMP only from the billing tunnel (not the public WAN).",
            "/ip firewall filter",
            "add chain=input action=accept protocol=tcp dst-port=8728 "
            f'in-interface=ispcentric-vpn place-before=0 comment="ispcentric-vpn-api"',
            "add chain=input action=accept protocol=tcp dst-port=8728 "
            f'src-address={network} place-before=0 comment="ispcentric-vpn-api-net"',
            "add chain=input action=accept protocol=icmp "
            f'in-interface=ispcentric-vpn place-before=0 comment="ispcentric-vpn-icmp"',
            "add chain=input action=accept protocol=icmp "
            f'src-address={network} place-before=0 comment="ispcentric-vpn-icmp-net"',
            "# Local development: permit API from RFC1918 LANs before Hotspot/drop rules.",
            "add chain=input action=accept protocol=tcp dst-port=8728 "
            'src-address=10.0.0.0/8 place-before=0 comment="ispcentric-vpn-api-lan-10"',
            "add chain=input action=accept protocol=tcp dst-port=8728 "
            'src-address=172.16.0.0/12 place-before=0 comment="ispcentric-vpn-api-lan-172"',
            "add chain=input action=accept protocol=tcp dst-port=8728 "
            'src-address=192.168.0.0/16 place-before=0 comment="ispcentric-vpn-api-lan-192"',
            "# Keep client/PPP source IPs intact when talking to the billing tunnel.",
            "/ip firewall nat",
            "add chain=srcnat action=accept "
            f'dst-address={network} place-before=0 comment="ispcentric-vpn-no-nat"',
            "# Wait for the handshake, then prove the billing server answers.",
            ":delay 3s",
            (
                f":if ([/ping {server} count=4 interval=500ms] > 0) do={{:put "
                f'"ispcentric OK: tunnel {address} reaches {server} - Connect in ISPCENTRIC"'
                f"}} else={{:put "
                f'"ispcentric: tunnel set on {address} but no ping from {server}. '
                f'Add this peer on the VPS wg0, restart WireGuard, then retry Connect."}}'
            ),
            "# Replace the old backup so it always contains the latest tunnel.",
            ':do { /file remove [find where name="ispcentric-tunnel.backup"] } on-error={}',
            "/system backup",
            "save name=ispcentric-tunnel dont-encrypt=yes",
            ':put "Backup saved as ispcentric-tunnel.backup - Winbox Save is also fine."',
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
