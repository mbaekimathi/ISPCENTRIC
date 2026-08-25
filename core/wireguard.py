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
import time
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


def _ros_filter_add_abs(rule: str, comment: str) -> str:
    """
    Paste-safe input filter add (absolute path, short line).

    ``place-before=0`` puts the rule first when the chain has items; on empty
    chains it errors and we fall back to a plain add.
    """
    body = f'/ip firewall filter add chain=input {rule} comment="{comment}"'
    return f":do {{ {body} place-before=0 }} on-error={{ {body} }}"


def _api_lan_ready_lines() -> list[str]:
    """
    Enable RouterOS API on 8728 and accept it on the input chain (top).

    Runs first so Connect LAN checks can pass before WAN download finishes.
    One short firewall rule (not three RFC1918 lines) — Winbox wraps long lines.
    """
    return [
        _ros_info("Enabling RouterOS API on 8728 (needed for Check now)..."),
        ":do { /ip service set [find where name=api] disabled=no port=8728 address=0.0.0.0/0 } on-error={}",
        ":do { /ip service set api disabled=no port=8728 address=0.0.0.0/0 } on-error={}",
        ":do { /ip service enable [find where name=api] } on-error={}",
        ':do { /ip firewall filter remove [find where comment="ispcentric-api-boot"] } on-error={}',
        ':do { /ip firewall filter remove [find where comment~"ispcentric-vpn-api-lan-"] } on-error={}',
        _ros_filter_add_abs(
            "action=accept protocol=tcp dst-port=8728",
            "ispcentric-api-boot",
        ),
        _ros_check(
            "[:len [/ip service find where name=api and disabled=no and port=8728]] > 0",
            "API listening on 8728 - Check now can use LAN",
            "API still closed - IP > Services > api, port 8728, Allowed From empty",
        ),
    ]


def _wan_wait_lines(
    probe_host: str = "8.8.8.8",
    *,
    attempts: int = 8,
    delay: str = "4s",
) -> list[str]:
    """
    Ensure WAN works, then require a real ping to probe_host.

    Prefer an already-bound DHCP client (often bridgeLocal on defconf). If none
    is bound, take ether1 out of any bridge (DHCP on a bridge-port fails with
    \"no route to host\"), then add DHCP on ether1.
    """
    probe_host = (probe_host or "8.8.8.8").strip() or "8.8.8.8"
    attempts = max(1, int(attempts))
    ping_ok = f"([/ping {probe_host} count=1] > 0)"
    lines = [
        _ros_info(f"WAN: use bound DHCP, else unbridge ether1 + DHCP — ping {probe_host}..."),
        ':do { /ip address disable [find where comment~"ispcentric-hotspot"] } on-error={}',
        # Keep any existing clients enabled (bridgeLocal defconf, etc.).
        (
            ":do { /ip dhcp-client set [find] disabled=no add-default-route=yes "
            "use-peer-dns=yes } on-error={}"
        ),
        # No lease yet → ether1 must not be a bridge port or DHCP never binds.
        (
            ":if ([:len [/ip dhcp-client find where status=bound]] = 0) do={"
            ':do { /interface bridge port remove [find where interface=ether1] } on-error={}; '
            ":do { /ip dhcp-client remove [find where interface=ether1] } on-error={}; "
            ":do { /ip dhcp-client add interface=ether1 disabled=no "
            "add-default-route=yes use-peer-dns=yes comment=\"ispcentric-wan\" } "
            "on-error={}; "
            ":do { /ip dhcp-client set [find where interface=ether1] disabled=no "
            "add-default-route=yes use-peer-dns=yes } on-error={}}"
        ),
        ":do { /ip dns set servers=8.8.8.8,1.1.1.1 allow-remote-requests=no } on-error={}",
        ":global IspWanOk",
        ":set IspWanOk 0",
    ]
    for try_n in range(1, attempts + 1):
        lines.append(
            f":if ($IspWanOk = 0) do={{:if ({ping_ok}) do={{:set IspWanOk 1; "
            f'{_ros_ok(f"WAN ready (ping {probe_host})")}}} else={{'
            f':put "[ISPCENTRIC] WAN {try_n}/{attempts} - no ping to {probe_host} '
            f'(ISP on ether1, wait DHCP bound)"; :delay {delay}}}}}'
        )
    lines.append(
        f":if ($IspWanOk = 0) do={{{_ros_fail(f'No ping to {probe_host} - unbridge ether1, DHCP bound, re-paste')}}}"
    )
    return lines


def _handshake_wait_lines(server: str, address: str) -> list[str]:
    """Retry ping/handshake so Connect Verify can catch up after dial."""
    ok = (
        f'Tunnel {address} reaches billing server {server} - click Connect in ISPCENTRIC'
    )
    fail = (
        f"No ping from {server}. Confirm WAN works (/ping 8.8.8.8), then on VPS: "
        f"manage.py wireguard_peer --sync-server, then Check now"
    )
    ping = f"[/ping {server} count=2]"
    return [
        _ros_info("Probing tunnel to billing server (retries ~40s)..."),
        ":delay 5s",
        f':if ({ping} > 0) do={{{_ros_ok(ok)}}}',
        ":delay 5s",
        f':if ({ping} > 0) do={{{_ros_ok(ok)}}}',
        ":delay 5s",
        f':if ({ping} > 0) do={{{_ros_ok(ok)}}}',
        ":delay 5s",
        f':if ({ping} > 0) do={{{_ros_ok(ok)}}}',
        ":delay 5s",
        f':if ({ping} > 0) do={{{_ros_ok(ok)}}}',
        ":delay 5s",
        _ros_check(f"{ping} > 0", ok, fail),
        (
            ':do { :put ("[ISPCENTRIC] WireGuard last-handshake: " . '
            '[/interface wireguard peers get [find where interface=ispcentric-vpn] '
            'last-handshake]) } on-error={'
            f'{_ros_warn("No handshake yet - need internet + VPS peer")}'
            "}"
        ),
    ]


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
        hint = (
            "This VPS could not register the router on WireGuard. "
            "Set WIREGUARD_SYNC_COMMAND=sudo /opt/ispcentric/scripts/wireguard_apply_peer.sh, "
            "install sudoers for that script, then Generate again "
            "(or run: manage.py wireguard_peer --sync-server)."
        )
        if reason == "sync_command_unset":
            hint = (
                "WIREGUARD_SYNC_COMMAND is missing on this VPS — peers never reach wg0. "
                "Add it to .env with sudoers for wireguard_apply_peer.sh, restart the app, "
                "then Generate again."
            )
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

    iface = _wireguard_interface()
    wg_bin = shutil.which("wg")
    if not wg_bin:
        out["error"] = "wg_not_found"
        return out

    try:
        proc = subprocess.run(
            [wg_bin, "show", iface, "dump"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except Exception as exc:
        out["error"] = str(exc)
        return out

    if proc.returncode != 0:
        out["error"] = (proc.stderr or proc.stdout or "wg show failed").strip()
        return out

    out["checked"] = True
    now = int(time.time())
    for line in (proc.stdout or "").splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 5 or parts[0] != public_key:
            continue
        out["present"] = True
        out["allowed_ips"] = parts[3] if len(parts) > 3 else ""
        try:
            latest = int(parts[4] or "0")
        except ValueError:
            latest = 0
        if latest > 0:
            out["handshake_age_sec"] = max(0, now - latest)
        else:
            out["handshake_age_sec"] = None
        return out
    return out


def ensure_reservation_peer(reservation) -> dict:
    """
    Re-apply a pending reservation to wg0 and classify why the tunnel may be down.

    Codes: ok | peer_missing | no_handshake | waiting_router | unknown
    """
    label = getattr(reservation, "label", None) or "MikroTik"
    address = (getattr(reservation, "address", None) or "").strip()
    public_key = (getattr(reservation, "public_key", None) or "").strip()

    sync = apply_server_peer(label, address, public_key)
    peer = inspect_server_peer(public_key)

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
        if age > 180:
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

    if not can_apply_server_peers():
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
    peer_state: str = "",
) -> list[dict[str, str]]:
    """
    Structured pass/fail rows for the Connect modal (mirrors Winbox script summary).

    Each item: key, status (ok|fail|warn|waiting), label, message.
    peer_state (hosted only): ok | missing | no_handshake | waiting_router | unknown
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
                        "API closed — paste script and wait for “API listening on 8728”"
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
        tunnel_status, tunnel_msg = (
            "fail",
            f"Tunnel IP {address} unreachable — WireGuard handshake missing",
        )
        peer_status, peer_msg = (
            "fail",
            "Peer is on VPS wg0 but handshake is empty — paste script / open UDP to endpoint",
        )
        ping_status, ping_msg = (
            "fail",
            f"No ping to {server} until handshake succeeds",
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
        peer_status, peer_msg = (
            "fail",
            f"Add [Peer] AllowedIPs={address}/32 on VPS wg0, then wireguard_peer --sync-server",
        )
        ping_status, ping_msg = (
            "waiting",
            f"No route to {server} yet — register peer on VPS if Winbox handshake is empty",
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


def peer_payload(label: str, address: str, private_key: str, public_key: str) -> dict:
    """JSON-friendly tunnel details for the Connect modal."""
    return {
        "label": label,
        "address": address,
        "script": routeros_script(address, private_key),
        "server_peer": server_peer_block(label, address, public_key),
        "endpoint": _endpoint(),
    }


def _routeros_install_lines(
    address: str,
    private_key: str,
    *,
    include_cleanup: bool,
) -> list[str]:
    """RouterOS commands that install the billing tunnel (paste-safe, one line each)."""
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

    lines: list[str] = [
        _ros_info("ISPCENTRIC tunnel install running..."),
        *_wan_wait_lines(endpoint_host),
    ]

    if include_cleanup:
        lines += [
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

    lines += [
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
        (
            f':do {{ /interface wireguard peers add interface=ispcentric-vpn '
            f'public-key="{_server_public_key()}" endpoint-address={endpoint_host} endpoint-port={port} '
            f"allowed-address={network} persistent-keepalive=25s "
            f'comment="ispcentric billing server" ; '
            f'{_ros_ok(f"VPS peer configured toward {endpoint_label}")} }} '
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
        (
            f":do {{ /ip hotspot ip-binding add type=bypassed address={network} "
            f'comment="ispcentric-vpn-hotspot-bypass" ; '
            f'{_ros_ok(f"Hotspot bypass for billing subnet {network}")} }} '
            f"on-error={{{_ros_warn('Hotspot bypass skipped (Hotspot may not be running)')}}}"
        ),
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
        "/ip firewall nat",
        _ros_nat_add(f"action=accept dst-address={network}", "ispcentric-vpn-no-nat"),
        _ros_check(
            '[:len [find where comment="ispcentric-vpn-no-nat"]] > 0',
            "Srcnat bypass for billing tunnel installed",
            "No-nat rule missing - run: /ip firewall nat print",
        ),
        *_handshake_wait_lines(server, address),
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
            f"Summary: Ping to billing server {server} (VPS peer / handshake missing)",
        ),
        _ros_info(
            "If ping FAIL: run wireguard_peer --sync-server on VPS, then Check now in ISPCENTRIC"
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


def install_rsc_body(address: str, private_key: str) -> str:
    """Full install .rsc: fetch post-reset if needed, decide reset vs install, configure."""
    address = (address or "").strip()
    private_key = (private_key or "").strip()
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
        *_routeros_install_lines(address, private_key, include_cleanup=True),
    ]
    return "\n".join(lines)


def post_reset_rsc_body(address: str, private_key: str) -> str:
    """Compact post-reset .rsc body."""
    return _routeros_post_reset_rsc_body(address, private_key)


def _fetch_rsc_line(url: str, host_header: str, dst: str, ok_msg: str, fail_msg: str) -> str:
    """One /tool fetch line (prefer _fetch_rsc_retry_lines for paste)."""
    header = ""
    if host_header and host_header not in url:
        header = f' http-header-field="Host:{host_header}"'
    return (
        f':do {{ /tool fetch url="{url}"{header} dst-path={dst} mode=http ; '
        f'{_ros_ok(ok_msg)} }} on-error={{{_ros_fail(fail_msg)}}}'
    )


def _routeros_smart_install_script(address: str, private_key: str) -> str:
    """
    Short Winbox paste: wait for WAN → download install.rsc → import.

    URL is built from short pieces (Winbox wrap-safe). Path ends with / so
    Django does not 301 (MikroTik /tool fetch fails on redirect).
    """
    address = (address or "").strip()
    private_key = (private_key or "").strip()
    endpoint_host = _resolved_endpoint_host(_endpoint().partition(":")[0])
    install_url, http_host = short_rsc_url(address, "i")

    if not install_url:
        return "\n".join(
            [
                "# ISPCENTRIC billing tunnel - paste into Winbox -> New Terminal.",
                "# PUBLIC_BASE_URL unset - using inline install (no remote .rsc fetch).",
                _ros_info("Starting inline ISPCENTRIC tunnel install..."),
                *_routeros_customized_flag_lines(),
                *_routeros_maybe_reset_lines(),
                *_routeros_install_lines(address, private_key, include_cleanup=True),
            ]
        )

    return "\n".join(
        [
            "# ISPCENTRIC - Winbox -> New Terminal. Paste once (ISP already online OK).",
            "# 1) open API  2) wait WAN ping  3) download install.rsc  4) import",
            *_api_lan_ready_lines(),
            _ros_info("Waiting for internet, then downloading install..."),
            *_wan_wait_lines(endpoint_host),
            ':do { /file remove [find where name="ispcentric-install.rsc"] } on-error={}',
            *_fetch_rsc_retry_lines(
                install_url,
                http_host,
                "ispcentric-install.rsc",
                "Downloaded install.rsc",
                "Download failed - check ether1 WAN and billing server HTTP",
                attempts=5,
                require_wan=True,
            ),
            (
                ':if ([:len [/file find where name="ispcentric-install.rsc"]] > 0) do={'
                ':put "[ISPCENTRIC OK] Importing install.rsc..."; '
                "/import file-name=ispcentric-install.rsc} else={"
                ':put "[ISPCENTRIC FAIL] install.rsc missing - fix WAN and re-paste"}'
            ),
        ]
    )


def _routeros_post_reset_rsc_body(address: str, private_key: str) -> str:
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
    endpoint_host = _resolved_endpoint_host(host)
    listen_port = _router_listen_port(address)
    return "\n".join(
        [
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
            (
                f'/interface wireguard peers add interface=ispcentric-vpn '
                f'public-key="{_server_public_key()}" '
                f'endpoint-address={endpoint_host} endpoint-port={port} '
                f'allowed-address={network} persistent-keepalive=25s '
                f'comment="ispcentric billing server"'
            ),
            '/ip service set [find where name=api] disabled=no port=8728 address=0.0.0.0/0',
            ':do { /ip service set api disabled=no port=8728 address=0.0.0.0/0 } on-error={}',
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
            *_handshake_wait_lines(server, address),
            ':put "[ISPCENTRIC OK] Post-reset tunnel install finished - Check now in ISPCENTRIC"',
        ]
    )


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


def routeros_script(address: str, private_key: str, *, factory_reset: bool = True) -> str:
    """
    Commands to paste into the MikroTik terminal to join the tunnel.

    When factory_reset is True (default for Connect onboarding), the paste
    checks the router first:
    - Clean / ISPCENTRIC-only → install in place (no reboot)
    - Hotspot, PPPoE, or other custom config → factory reset (keep-users), then
      auto-install from ispcentric-post-reset.rsc after reboot

    When factory_reset is False, always replaces previous ISPCENTRIC components
    in-place without any reset check.
    """
    # Validate server settings up front (also used by downloaded .rsc bodies).
    _endpoint()
    _server_public_key()
    if factory_reset:
        return _routeros_smart_install_script(address, private_key)

    install = _routeros_install_lines(
        address,
        private_key,
        include_cleanup=True,
    )
    return "\n".join(
        [
            "# ISPCENTRIC billing tunnel - paste into the MikroTik terminal.",
            "# Requires RouterOS 7. Safe to re-run: replaces previous ISPCENTRIC config only.",
            _ros_info("Starting ISPCENTRIC tunnel install (no factory reset)..."),
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
