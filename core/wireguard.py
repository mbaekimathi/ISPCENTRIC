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
    from core.models import MikroTikRouter

    taken = {
        (value or "").strip()
        for value in MikroTikRouter.objects.exclude(vpn_address__isnull=True)
        .values_list("vpn_address", flat=True)
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
    if not key:
        raise ValueError(
            "WIREGUARD_SERVER_PUBLIC_KEY is not set. Run "
            "`python manage.py wireguard_peer --server` on the VPS first."
        )
    return key


def routeros_script(router) -> str:
    """
    Commands to paste into the MikroTik terminal to join the tunnel.

    Interface names are suffixed with nothing special on purpose: a site has one
    tunnel to the billing server, and reusing a fixed name makes re-running the
    script idempotent.
    """
    host, _, port = _endpoint().partition(":")
    port = port or "51820"
    network = tunnel_network()
    address = (router.vpn_address or "").strip()
    private_key = (router.vpn_private_key or "").strip()
    if not address or not private_key:
        raise ValueError(
            f"Router {router.pk} has no tunnel keys yet. Run "
            f"`python manage.py wireguard_peer {router.pk}` first."
        )

    return "\n".join(
        [
            "# ISPCENTRIC billing tunnel - paste into the MikroTik terminal.",
            "# Requires RouterOS 7. Safe to re-run.",
            "/interface/wireguard",
            "remove [find name=ispcentric-vpn]",
            f'add name=ispcentric-vpn listen-port=13231 private-key="{private_key}" '
            'comment="ispcentric billing tunnel"',
            "/ip/address",
            "remove [find interface=ispcentric-vpn]",
            f"add address={address}/{network.prefixlen} interface=ispcentric-vpn",
            "/interface/wireguard/peers",
            "remove [find interface=ispcentric-vpn]",
            f'add interface=ispcentric-vpn public-key="{_server_public_key()}" '
            f"endpoint-address={host} endpoint-port={port} "
            f"allowed-address={network} persistent-keepalive=25s "
            'comment="ispcentric billing server"',
            "# Let the billing server reach the API over the tunnel only.",
            "/ip/service",
            "set [find name=api] disabled=no port=8728",
            "/ip/firewall/filter",
            'remove [find comment="ispcentric-vpn-api"]',
            "add chain=input action=accept protocol=tcp dst-port=8728 "
            f'src-address={network} place-before=0 comment="ispcentric-vpn-api"',
            f':put "ispcentric tunnel up on {address} - retry Connect in ISPCENTRIC"',
        ]
    )


def server_peer_block(router) -> str:
    """The [Peer] stanza to add to the VPS wg0.conf for this router."""
    public_key = (router.vpn_public_key or "").strip()
    address = (router.vpn_address or "").strip()
    if not public_key or not address:
        raise ValueError(f"Router {router.pk} has no tunnel keys yet.")
    return "\n".join(
        [
            f"# {router.name} (router id {router.pk})",
            "[Peer]",
            f"PublicKey = {public_key}",
            f"AllowedIPs = {address}/32",
        ]
    )


def server_config(private_key: str) -> str:
    """A complete wg0.conf for the VPS, with every provisioned peer."""
    from core.models import MikroTikRouter

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
    peers = (
        MikroTikRouter.objects.exclude(vpn_address__isnull=True)
        .exclude(vpn_public_key="")
        .order_by("id")
    )
    for router in peers:
        lines.append(server_peer_block(router))
        lines.append("")
    if not peers:
        lines.append("# No router peers provisioned yet.")
    return "\n".join(lines)
