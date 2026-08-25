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
        f"No ping from {server}. On the VPS run: "
        f"manage.py wireguard_peer --sync-server "
        f"(or add [Peer] AllowedIPs={address}/32 on wg0 and restart), "
        f"then re-paste or click Check now in ISPCENTRIC"
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
        "# DNS for routers that reach the internet; endpoint uses VPS IP when possible.",
        ':do { /ip dns set servers=8.8.8.8,1.1.1.1 allow-remote-requests=no ; '
        f'{_ros_ok("DNS servers configured")} }} on-error='
        f'{{{_ros_warn("DNS setup skipped - endpoint uses VPS IP")}}}',
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
        _ros_info("Probing tunnel to billing server (retries ~20s)..."),
        *_ros_ping_probe(server, address).splitlines(),
        (
            ':do { :put ("[ISPCENTRIC] WireGuard last-handshake: " . '
            '[/interface wireguard peers get [find where interface=ispcentric-vpn] '
            'last-handshake]) } on-error={'
            f'{_ros_warn("No handshake yet - VPS must have this [Peer] on wg0 (wireguard_peer --sync-server), then wait or re-paste")}'
            "}"
        ),
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
            "/ip dns set servers=8.8.8.8,1.1.1.1 allow-remote-requests=no",
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
            ":delay 10s",
            f":do {{ /ping {server} count=5 }} on-error={{}}",
            ':put "[ISPCENTRIC OK] Post-reset tunnel install finished - Check now in ISPCENTRIC"',
        ]
    )


def _routeros_factory_reset_wrapper(address: str, private_key: str) -> str:
    """
    Write a .rsc installer to flash (survives reboot), factory-reset (keep passwords),
    then run that file via run-after-reset.

    RouterOS rejects /system script names for run-after-reset — only .rsc files work.
    Devices with a flash/ folder must store the file there (RAM files are wiped).
    """
    rsc_body = _routeros_post_reset_rsc_body(address, private_key)
    escaped = _escape_ros_file_contents(rsc_body)
    flash_name = "flash/ispcentric-post-reset.rsc"
    root_name = "ispcentric-post-reset.rsc"
    return "\n".join(
        [
            "# ISPCENTRIC billing tunnel - paste once into Winbox -> New Terminal.",
            "# FACTORY RESET: removes ALL MikroTik config except admin passwords.",
            "# Winbox disconnects in ~5s; reconnect by MAC/IP after reboot (~2 min).",
            "# Tunnel + API install runs automatically from ispcentric-post-reset.rsc.",
            _ros_warn(
                "Factory reset scheduled - every setting except admin passwords will be cleared"
            ),
            ':do { /file remove [find where name="flash/ispcentric-post-reset.rsc"] } on-error={}',
            ':do { /file remove [find where name="ispcentric-post-reset.rsc"] } on-error={}',
            ':do { /file remove [find where name="ispcentric-post-reset.txt"] } on-error={}',
            '/system script remove [find where name="ispcentric-post-reset"]',
            '/system scheduler remove [find where name="ispcentric-post-reset"]',
            (
                f':do {{ /file add name="{flash_name}" contents="{escaped}" ; '
                f'{_ros_ok(f"Saved post-reset installer {flash_name}")} }} on-error={{ '
                f'/file add name="{root_name}" contents="{escaped}" ; '
                f'{_ros_ok(f"Saved post-reset installer {root_name}")} }}'
            ),
            _ros_info("Factory reset in 5 seconds - Winbox will disconnect"),
            ":delay 5s",
            (
                f':if ([:len [/file find where name="{flash_name}"]] > 0) do={{ '
                f"/system reset-configuration keep-users=yes skip-backup=yes "
                f"run-after-reset={flash_name} }} else={{ "
                f"/system reset-configuration keep-users=yes skip-backup=yes "
                f"run-after-reset={root_name} }}"
            ),
        ]
    )


def routeros_script(address: str, private_key: str, *, factory_reset: bool = True) -> str:
    """
    Commands to paste into the MikroTik terminal to join the tunnel.

    When factory_reset is True (default for Connect onboarding), the paste:
    1. Writes ispcentric-post-reset.rsc (on flash/ when available)
    2. Factory-resets to RouterOS defaults (admin passwords kept via keep-users)
    3. Runs that .rsc automatically after reboot (run-after-reset)

    When factory_reset is False, only replaces previous ISPCENTRIC components
    in-place (no factory reset) — useful for re-runs on live routers.
    """
    if factory_reset:
        return _routeros_factory_reset_wrapper(address, private_key)

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
