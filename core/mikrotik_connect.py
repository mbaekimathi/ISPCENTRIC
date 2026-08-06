"""MikroTik RouterOS API: login, identity, and Wi‑Fi configuration."""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from http.cookies import SimpleCookie
from typing import Any, Iterator
from urllib.parse import urlencode, urlparse, urlunparse

from django.conf import settings


WIFI_PACKAGES = (
    {
        "mode": "wireless",
        "iface_path": "/interface/wireless",
        "sec_path": "/interface/wireless/security-profiles",
        "profile_key": "security-profile",
        "classic": True,
        "iface_props": ".id,name,ssid,mode,security-profile",
    },
    {
        "mode": "wifi",
        "iface_path": "/interface/wifi",
        "sec_path": "/interface/wifi/security",
        "profile_key": "security",
        "classic": False,
        "iface_props": ".id,name,ssid,mode,security",
    },
    {
        "mode": "wifiwave2",
        "iface_path": "/interface/wifiwave2",
        "sec_path": "/interface/wifiwave2/security",
        "profile_key": "security",
        "classic": False,
        "iface_props": ".id,name,ssid,mode,security",
    },
)


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length < 0x4000:
        length |= 0x8000
        return bytes([(length >> 8) & 0xFF, length & 0xFF])
    if length < 0x200000:
        length |= 0xC00000
        return bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    if length < 0x10000000:
        length |= 0xE0000000
        return bytes(
            [
                (length >> 24) & 0xFF,
                (length >> 16) & 0xFF,
                (length >> 8) & 0xFF,
                length & 0xFF,
            ]
        )
    return bytes(
        [
            0xF0,
            (length >> 24) & 0xFF,
            (length >> 16) & 0xFF,
            (length >> 8) & 0xFF,
            length & 0xFF,
        ]
    )


def _read_length(sock: socket.socket) -> int:
    first = sock.recv(1)
    if not first:
        raise ConnectionError("Connection closed while reading length.")
    b = first[0]
    if (b & 0x80) == 0x00:
        return b
    if (b & 0xC0) == 0x80:
        second = sock.recv(1)
        if not second:
            raise ConnectionError("Connection closed while reading length.")
        return ((b & ~0xC0) << 8) + second[0]
    if (b & 0xE0) == 0xC0:
        more = sock.recv(2)
        if len(more) < 2:
            raise ConnectionError("Connection closed while reading length.")
        return ((b & ~0xE0) << 16) + (more[0] << 8) + more[1]
    if (b & 0xF0) == 0xE0:
        more = sock.recv(3)
        if len(more) < 3:
            raise ConnectionError("Connection closed while reading length.")
        return ((b & ~0xF0) << 24) + (more[0] << 16) + (more[1] << 8) + more[2]
    if (b & 0xF8) == 0xF0:
        more = sock.recv(4)
        if len(more) < 4:
            raise ConnectionError("Connection closed while reading length.")
        return (more[0] << 24) + (more[1] << 16) + (more[2] << 8) + more[3]
    raise ConnectionError("Unsupported RouterOS API length encoding.")


def _read_word(sock: socket.socket) -> str:
    length = _read_length(sock)
    if length == 0:
        return ""
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while reading word.")
        data += chunk
    return data.decode("utf-8", errors="replace")


def _write_word(sock: socket.socket, word: str) -> None:
    raw = word.encode("utf-8")
    sock.sendall(_encode_length(len(raw)) + raw)


def _write_sentence(sock: socket.socket, words: list[str]) -> None:
    for word in words:
        _write_word(sock, word)
    _write_word(sock, "")


def _read_sentence(sock: socket.socket) -> list[str]:
    words: list[str] = []
    while True:
        word = _read_word(sock)
        if word == "":
            break
        words.append(word)
    return words


def _attrs(sentence: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for word in sentence:
        if word.startswith("=") and "=" in word[1:]:
            key, value = word[1:].split("=", 1)
            out[key] = value
        elif word.startswith("!"):
            out["_reply"] = word
    return out


def _login_failed(attrs: dict[str, str]) -> dict[str, Any]:
    return {
        "ok": False,
        "error": attrs.get("message") or "Login failed. Check username and password.",
    }


def _api_login(sock: socket.socket, username: str, password: str) -> dict[str, Any] | None:
    """Authenticate on an open socket. Returns None on success, or an error dict."""
    _write_sentence(sock, ["/login", f"=name={username}", f"=password={password}"])
    attrs = _attrs(_read_sentence(sock))
    reply = attrs.get("_reply") or ""

    if reply == "!done" and "ret" not in attrs:
        return None
    if reply == "!trap":
        return _login_failed(attrs)

    challenge = attrs.get("ret") or ""
    if not challenge:
        _write_sentence(sock, ["/login"])
        challenge_attrs = _attrs(_read_sentence(sock))
        if challenge_attrs.get("_reply") == "!trap":
            return _login_failed(challenge_attrs)
        challenge = challenge_attrs.get("ret") or ""

    if not challenge:
        return {"ok": False, "error": "Unexpected reply from RouterOS API."}

    digest = hashlib.md5()
    digest.update(b"\x00")
    digest.update(password.encode("utf-8"))
    digest.update(bytes.fromhex(challenge))
    response = "00" + digest.hexdigest()
    _write_sentence(sock, ["/login", f"=name={username}", f"=response={response}"])
    legacy = _attrs(_read_sentence(sock))
    if legacy.get("_reply") == "!done":
        return None
    return _login_failed(legacy)


def _command(sock: socket.socket, words: list[str]) -> tuple[list[dict[str, str]], dict[str, str]]:
    """Run a RouterOS API command. Returns (replies, done/trap attrs).

    RouterOS may send one or more !trap sentences before a final !done.
    We must consume through !done/!fatal or the next command reads a stale !done
    and looks like an empty successful reply (e.g. secret print returns no rows).
    """
    _write_sentence(sock, words)
    replies: list[dict[str, str]] = []
    terminal: dict[str, str] = {}
    trapped: dict[str, str] | None = None
    while True:
        sentence = _read_sentence(sock)
        if not sentence:
            break
        attrs = _attrs(sentence)
        reply = attrs.get("_reply") or (sentence[0] if sentence else "")
        if reply == "!re":
            replies.append(attrs)
        elif reply == "!trap":
            trapped = attrs
            trapped["_reply"] = "!trap"
        elif reply in {"!done", "!fatal"}:
            terminal = attrs
            terminal["_reply"] = reply
            break
    if trapped is not None:
        # Prefer trap details for callers; keep done attrs under _done if present.
        if terminal:
            trapped["_done"] = terminal.get("_reply", "!done")
        return replies, trapped
    return replies, terminal


def _print(
    sock: socket.socket,
    path: str,
    *,
    props: str = "",
    query: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    words = [f"{path}/print"]
    if props:
        words.append(f"=.proplist={props}")
    if query:
        for key, value in query.items():
            if value is None:
                continue
            words.append(f"?{key}={value}")
    replies, terminal = _command(sock, words)
    if terminal.get("_reply") in {"!trap", "!fatal"}:
        return []
    return replies


def _set(sock: socket.socket, path: str, item_id: str, **props: str) -> dict[str, str]:
    words = [f"{path}/set", f"=.id={item_id}"]
    for key, value in props.items():
        words.append(f"={key}={value}")
    _, terminal = _command(sock, words)
    return terminal


def _add(sock: socket.socket, path: str, **props: str) -> dict[str, str]:
    words = [f"{path}/add"]
    for key, value in props.items():
        if value is None:
            continue
        words.append(f"={key}={value}")
    _, terminal = _command(sock, words)
    return terminal


def _remove(sock: socket.socket, path: str, item_id: str) -> dict[str, str]:
    _, terminal = _command(sock, [f"{path}/remove", f"=.id={item_id}"])
    return terminal


CLEAN_UPLINK_TAG = "ispcentric-clean-uplink"
UPLINK_TAG = "ispcentric-uplink"
CPE_PROXY_TAG = "ispcentric-cpe-proxy"
CPE_API_AUTO_TAG = "ispcentric-cpe-api"
# ISP PPPoE pool used when opening CPE management from the NAS side.
PPPOE_LOCAL_ADDRESS = "10.20.0.1"
PPPOE_POOL_NAME = "ispcentric-pppoe"
PPPOE_POOL_RANGES = "10.20.0.10-10.20.0.250"
PPPOE_POOL_NETWORK = "10.20.0.0/24"
_PPPOE_POOL_NET = ipaddress.ip_network(PPPOE_POOL_NETWORK)
CPE_PROXY_PORT_BASE = 38728
CPE_PROXY_PORT_SPAN = 900
DEFAULT_BOND_NAME = "bond-wan"
BOND_MODES = (
    "balance-xor",
    "802.3ad",
    "active-backup",
    "balance-rr",
    "balance-tlb",
    "balance-alb",
)


def _trap_message(terminal: dict[str, str], fallback: str) -> str:
    return (terminal.get("message") or "").strip() or fallback


def _unknown_parameter_name(message: str) -> str:
    """Extract RouterOS 'unknown parameter X' name, if present."""
    import re

    match = re.search(r"unknown parameter[, ]+['\"]?([^\s'\"]+)", message or "", re.I)
    return (match.group(1) if match else "").strip()


def _add_or_set_attempts(
    sock: socket.socket,
    path: str,
    item_id: str,
    attempts: list[dict[str, str]],
    *,
    required: tuple[str, ...] = (),
) -> tuple[dict[str, str], str]:
    """
    Try add/set prop sets in order. If RouterOS rejects an unknown parameter,
    automatically retry the same props without that field.

    Keys listed in ``required`` are never trimmed. Use it for match conditions:
    dropping one turns a scoped rule into a match-everything rule, which in a
    walled garden would allow every unauthenticated client straight through.
    """
    terminal: dict[str, str] = {"_reply": "!trap"}
    resolved_id = (item_id or "").strip()
    seen: set[tuple[tuple[str, str], ...]] = set()
    queue: list[dict[str, str]] = [dict(props) for props in attempts if props]

    while queue:
        props = queue.pop(0)
        key = tuple(sorted((k, str(v)) for k, v in props.items()))
        if key in seen:
            continue
        seen.add(key)

        if resolved_id:
            terminal = _set(sock, path, resolved_id, **props)
        else:
            terminal = _add(sock, path, **props)
            if terminal.get("_reply") != "!trap":
                resolved_id = (terminal.get("ret") or "").strip() or resolved_id

        if terminal.get("_reply") != "!trap":
            return terminal, resolved_id

        bad = _unknown_parameter_name(_trap_message(terminal, ""))
        if bad and bad in props and bad not in required:
            trimmed = {k: v for k, v in props.items() if k != bad}
            if trimmed:
                queue.insert(0, trimmed)

    return terminal, resolved_id


def _rows_with_tag(sock: socket.socket, path: str, *, props: str = ".id,comment") -> list[dict[str, str]]:
    tag = CLEAN_UPLINK_TAG
    matched: list[dict[str, str]] = []
    for row in _print(sock, path, props=props):
        comment = row.get("comment") or ""
        if tag in comment:
            matched.append(row)
    return matched


def _remove_tagged(sock: socket.socket, path: str) -> int:
    removed = 0
    for row in _rows_with_tag(sock, path):
        item_id = (row.get(".id") or "").strip()
        if not item_id:
            continue
        terminal = _remove(sock, path, item_id)
        if terminal.get("_reply") != "!trap":
            removed += 1
    return removed


def _rows_with_comment_tag(
    sock: socket.socket,
    path: str,
    tag: str,
    *,
    props: str = ".id,comment",
) -> list[dict[str, str]]:
    matched: list[dict[str, str]] = []
    for row in _print(sock, path, props=props):
        comment = row.get("comment") or ""
        if tag in comment:
            matched.append(row)
    return matched


def _remove_comment_tagged(sock: socket.socket, path: str, tag: str) -> int:
    removed = 0
    for row in _rows_with_comment_tag(sock, path, tag):
        item_id = (row.get(".id") or "").strip()
        if not item_id:
            continue
        terminal = _remove(sock, path, item_id)
        if terminal.get("_reply") not in {"!trap", "!fatal"}:
            removed += 1
    return removed


def _ensure_interface_list(sock: socket.socket, name: str) -> None:
    for row in _print(sock, "/interface/list", props=".id,name"):
        if (row.get("name") or "").strip() == name:
            return
    _add(sock, "/interface/list", name=name, comment=CLEAN_UPLINK_TAG)


def _ensure_list_member(sock: socket.socket, list_name: str, interface: str) -> None:
    for row in _print(sock, "/interface/list/member", props=".id,list,interface,comment"):
        if (row.get("list") or "").strip() == list_name and (row.get("interface") or "").strip() == interface:
            return
    _add(
        sock,
        "/interface/list/member",
        list=list_name,
        interface=interface,
        comment=CLEAN_UPLINK_TAG,
    )


def _bridge_port_id(sock: socket.socket, interface: str) -> str:
    for row in _print(sock, "/interface/bridge/port", props=".id,interface,bridge"):
        if (row.get("interface") or "").strip() == interface:
            return (row.get(".id") or "").strip()
    return ""


def _ensure_dhcp_client(sock: socket.socket, interface: str) -> None:
    for row in _print(sock, "/ip/dhcp-client", props=".id,interface,disabled,comment"):
        if (row.get("interface") or "").strip() != interface:
            continue
        item_id = (row.get(".id") or "").strip()
        if not item_id:
            return
        # Reuse the existing client — do not tag it so disable won't delete it.
        _set(
            sock,
            "/ip/dhcp-client",
            item_id,
            disabled="no",
            **{"add-default-route": "yes", "use-peer-dns": "no"},
        )
        return
    _add(
        sock,
        "/ip/dhcp-client",
        interface=interface,
        disabled="no",
        **{"add-default-route": "yes", "use-peer-dns": "no", "comment": CLEAN_UPLINK_TAG},
    )


# Candidate LAN plans when the current LAN overlaps the ISP/WAN side.
# Avoid 10.20.0.0/24 (PPPoE CPE management pool) and 10.9.0.0/24 (WireGuard).
CLEAN_UPLINK_LAN_CANDIDATES: tuple[tuple[str, str, str], ...] = (
    ("10.10.0.0/24", "10.10.0.1", "10.10.0.10-10.10.0.200"),
    ("10.11.0.0/24", "10.11.0.1", "10.11.0.10-10.11.0.200"),
    ("172.21.0.0/24", "172.21.0.1", "172.21.0.10-172.21.0.200"),
    ("192.168.88.0/24", "192.168.88.1", "192.168.88.10-192.168.88.200"),
)


def parse_provider_gateways(raw: str) -> list[str]:
    """Split and validate one or more IPv4 provider admin / gateway addresses."""
    found: list[str] = []
    seen: set[str] = set()
    for part in (raw or "").replace(";", ",").split(","):
        token = part.strip()
        if not token:
            continue
        try:
            ip = str(ipaddress.IPv4Address(token))
        except ValueError as exc:
            raise ValueError(f"Invalid provider gateway IP: {token}") from exc
        if ip not in seen:
            seen.add(ip)
            found.append(ip)
    return found


def _ip_network_from_cidr(value: str) -> ipaddress.IPv4Network | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return ipaddress.ip_interface(text).network
    except ValueError:
        try:
            return ipaddress.ip_network(text, strict=False)
        except ValueError:
            return None


def _find_pppoe_client_for_wan(sock: socket.socket, wan_interface: str) -> str:
    """Return PPPoE client interface name bound to wan_interface, if any."""
    wan_interface = (wan_interface or "").strip()
    if not wan_interface:
        return ""
    for path in ("/interface/pppoe-client", "/interface/pppoe-server"):
        try:
            rows = _print(sock, path, props=".id,name,interface,disabled")
        except Exception:
            continue
        for row in rows:
            if (row.get("interface") or "").strip() != wan_interface:
                continue
            if (row.get("disabled") or "").lower() in {"true", "yes"}:
                continue
            name = (row.get("name") or "").strip()
            if name:
                return name
    # Also accept an already-named pppoe-out used as the WAN itself.
    if wan_interface.lower().startswith("pppoe"):
        return wan_interface
    return ""


def _collect_interface_networks(sock: socket.socket, *interfaces: str) -> list[ipaddress.IPv4Network]:
    wanted = {name.strip() for name in interfaces if (name or "").strip()}
    if not wanted:
        return []
    nets: list[ipaddress.IPv4Network] = []
    for row in _print(sock, "/ip/address", props="address,interface"):
        if (row.get("interface") or "").strip() not in wanted:
            continue
        net = _ip_network_from_cidr(row.get("address") or "")
        if net is not None:
            nets.append(net)
    return nets


def _detect_dhcp_gateways(sock: socket.socket, wan_interface: str) -> list[str]:
    """Best-effort ISP gateway from DHCP client status / gateway fields."""
    gateways: list[str] = []
    for row in _print(
        sock,
        "/ip/dhcp-client",
        props="interface,gateway,status,disabled",
    ):
        if (row.get("interface") or "").strip() != wan_interface:
            continue
        if (row.get("disabled") or "").lower() in {"true", "yes"}:
            continue
        raw = (row.get("gateway") or "").strip()
        if not raw:
            continue
        # RouterOS may show "192.168.1.1%ether1"
        token = raw.split("%", 1)[0].strip()
        try:
            gateways.append(str(ipaddress.IPv4Address(token)))
        except ValueError:
            continue
    return gateways


def _networks_overlap(a: ipaddress.IPv4Network, b: ipaddress.IPv4Network) -> bool:
    return a.overlaps(b)


def pick_clean_uplink_lan_plan(
    wan_networks: list[ipaddress.IPv4Network],
    existing_lan: ipaddress.IPv4Network | None = None,
) -> tuple[str, str, str]:
    """
    Choose a LAN network that does not overlap ISP/WAN addressing.

    Prefer keeping the existing LAN when it is already safe.
    """
    if existing_lan is not None and not any(
        _networks_overlap(existing_lan, wan) for wan in wan_networks
    ):
        gateway = str(existing_lan.network_address + 1)
        # Usable hosts excluding network, gateway, broadcast.
        start = existing_lan.network_address + 10
        end = existing_lan.broadcast_address - 1
        if int(end) <= int(start):
            start = existing_lan.network_address + 2
            end = existing_lan.broadcast_address - 1
        ranges = f"{start}-{end}"
        return str(existing_lan), gateway, ranges

    for network, gateway, ranges in CLEAN_UPLINK_LAN_CANDIDATES:
        candidate = ipaddress.ip_network(network, strict=False)
        if any(_networks_overlap(candidate, wan) for wan in wan_networks):
            continue
        return network, gateway, ranges
    # Last resort — still return default even if overlapping (caller notes it).
    return CLEAN_UPLINK_LAN_CANDIDATES[0]


def _ensure_masquerade(sock: socket.socket) -> None:
    for row in _rows_with_tag(
        sock,
        "/ip/firewall/nat",
        props=".id,chain,action,out-interface-list,comment",
    ):
        if (row.get("chain") or "") == "srcnat" and (row.get("action") or "") == "masquerade":
            return
    _add(
        sock,
        "/ip/firewall/nat",
        chain="srcnat",
        action="masquerade",
        **{"out-interface-list": "WAN", "comment": f"{CLEAN_UPLINK_TAG} NAT"},
    )


def _ensure_dns_redirect(sock: socket.socket) -> None:
    existing = {
        ((row.get("protocol") or ""), (row.get("dst-port") or ""))
        for row in _rows_with_tag(
            sock,
            "/ip/firewall/nat",
            props=".id,chain,protocol,dst-port,action,comment",
        )
        if (row.get("chain") or "") == "dstnat" and (row.get("action") or "") == "redirect"
    }
    for protocol in ("udp", "tcp"):
        if (protocol, "53") in existing:
            continue
        _add(
            sock,
            "/ip/firewall/nat",
            chain="dstnat",
            protocol=protocol,
            **{
                "in-interface-list": "LAN",
                "dst-port": "53",
                "action": "redirect",
                "to-ports": "53",
                "comment": f"{CLEAN_UPLINK_TAG} force DNS",
            },
        )


def _ensure_filter_rules(
    sock: socket.socket,
    *,
    mode: str,
    provider_gateways: list[str] | None = None,
    provider_networks: list[str] | None = None,
) -> None:
    """Install tagged filter rules. Existing non-tagged rules are left alone.

    Intentionally does NOT drop all WAN→router traffic. That locked operators
    out when they managed the MikroTik from the ISP/modem side of the WAN port.
    Clean uplink focuses on DNS/NAT and blocking provider admin pages instead.
    """
    _remove_tagged(sock, "/ip/firewall/filter")

    rules: list[dict[str, str]] = [
        {
            "chain": "forward",
            "action": "accept",
            "connection-state": "established,related,untracked",
            "comment": f"{CLEAN_UPLINK_TAG} forward OK",
        },
        {
            "chain": "forward",
            "action": "accept",
            "in-interface-list": "LAN",
            "out-interface-list": "WAN",
            "comment": f"{CLEAN_UPLINK_TAG} LAN to internet",
        },
    ]

    if mode == "behind":
        insert_at = 1
        for gateway in provider_gateways or []:
            rules.insert(
                insert_at,
                {
                    "chain": "forward",
                    "action": "drop",
                    "dst-address": gateway,
                    "comment": f"{CLEAN_UPLINK_TAG} block provider admin",
                },
            )
            insert_at += 1
        for network in provider_networks or []:
            # Block the ISP modem LAN (private only) so customers cannot open
            # other admin hosts on that side (ONTs, fibre CPE, etc.).
            net = _ip_network_from_cidr(network)
            if net is None or not net.is_private:
                continue
            rules.insert(
                insert_at,
                {
                    "chain": "forward",
                    "action": "drop",
                    "dst-address": str(net),
                    "comment": f"{CLEAN_UPLINK_TAG} block provider lan",
                },
            )
            insert_at += 1

    for rule in rules:
        _add(sock, "/ip/firewall/filter", **rule)


def _wait_for_api(
    host: str,
    *,
    port: int = 8728,
    attempts: int = 8,
    delay: float = 1.25,
    connect_timeout: float = 4.0,
) -> None:
    """Wait until RouterOS API accepts TCP again after a topology change."""
    last_error: OSError | None = None
    for _ in range(max(1, attempts)):
        try:
            with socket.create_connection((dial_host(host), port), timeout=connect_timeout):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(delay)
    if last_error:
        raise ConnectionError(
            f"Router API at {host}:{port} did not come back after changing the WAN bridge. "
            f"Wait a few seconds and try Enable again. ({last_error})"
        )


def ensure_mikrotik_lan_passthrough(
    sock: socket.socket,
    *,
    wan_interface: str = "ether1",
    lan_bridge: str = "bridgeLocal",
    lan_network: str = "",
    lan_gateway: str = "",
    lan_pool_ranges: str = "",
) -> list[str]:
    """
    Make MikroTik route internet cleanly for any ISP uplink:

    - WAN via existing PPPoE client when present, otherwise DHCP on wan_interface
    - LAN on a subnet that does not overlap the ISP/WAN side
    - NAT masquerade out WAN
    """
    wan_interface = (wan_interface or "ether1").strip()
    lan_bridge = (lan_bridge or "bridgeLocal").strip()
    notes: list[str] = []

    pppoe_iface = _find_pppoe_client_for_wan(sock, wan_interface)
    wan_members = [wan_interface]
    if pppoe_iface and pppoe_iface != wan_interface:
        wan_members.append(pppoe_iface)
        notes.append(f"using PPPoE uplink {pppoe_iface} on {wan_interface}")

    # DHCP client belongs on WAN only — never on the LAN bridge.
    # Skip adding DHCP when PPPoE already owns the uplink.
    for row in _print(sock, "/ip/dhcp-client", props=".id,interface"):
        iface = (row.get("interface") or "").strip()
        item_id = (row.get(".id") or "").strip()
        if iface == lan_bridge and item_id:
            _remove(sock, "/ip/dhcp-client", item_id)
            notes.append(f"removed DHCP client from {lan_bridge}")
        elif iface == wan_interface and item_id and not pppoe_iface:
            _set(
                sock,
                "/ip/dhcp-client",
                item_id,
                disabled="no",
                **{"add-default-route": "yes", "use-peer-dns": "no"},
            )

    if not pppoe_iface:
        wan_dhcp = any(
            (row.get("interface") or "").strip() == wan_interface
            for row in _print(sock, "/ip/dhcp-client", props="interface")
        )
        if not wan_dhcp:
            _add(
                sock,
                "/ip/dhcp-client",
                interface=wan_interface,
                disabled="no",
                **{
                    "add-default-route": "yes",
                    "use-peer-dns": "no",
                    "comment": CLEAN_UPLINK_TAG,
                },
            )
            notes.append(f"added DHCP client on {wan_interface}")
    else:
        notes.append("skipped WAN DHCP client (PPPoE present)")

    wan_networks = _collect_interface_networks(sock, *wan_members)
    existing_lan_net: ipaddress.IPv4Network | None = None
    for row in _print(sock, "/ip/address", props="address,interface"):
        if (row.get("interface") or "").strip() != lan_bridge:
            continue
        net = _ip_network_from_cidr(row.get("address") or "")
        if net is not None:
            existing_lan_net = net
            break

    if lan_network and lan_gateway and lan_pool_ranges:
        plan_network, plan_gateway, plan_ranges = lan_network, lan_gateway, lan_pool_ranges
    else:
        plan_network, plan_gateway, plan_ranges = pick_clean_uplink_lan_plan(
            wan_networks, existing_lan_net
        )
    plan_net = ipaddress.ip_network(plan_network, strict=False)

    # Drop LAN addresses that collide with WAN or sit outside the chosen plan.
    for row in _print(sock, "/ip/address", props=".id,address,interface"):
        if (row.get("interface") or "").strip() != lan_bridge:
            continue
        item_id = (row.get(".id") or "").strip()
        address = (row.get("address") or "").strip()
        row_net = _ip_network_from_cidr(address)
        if not item_id or row_net is None:
            continue
        overlaps_wan = any(_networks_overlap(row_net, wan) for wan in wan_networks)
        if row_net == plan_net and not overlaps_wan:
            continue
        _remove(sock, "/ip/address", item_id)
        notes.append(f"removed conflicting LAN address {address}")

    has_lan_ip = any(
        (row.get("interface") or "").strip() == lan_bridge
        and _ip_network_from_cidr(row.get("address") or "") == plan_net
        for row in _print(sock, "/ip/address", props="address,interface")
    )
    if not has_lan_ip:
        _add(
            sock,
            "/ip/address",
            address=f"{plan_gateway}/{plan_net.prefixlen}",
            interface=lan_bridge,
            comment=CLEAN_UPLINK_TAG,
        )
        notes.append(f"set LAN {plan_gateway}/{plan_net.prefixlen} on {lan_bridge}")

    pool_names = {
        (row.get("name") or "").strip()
        for row in _print(sock, "/ip/pool", props="name")
    }
    if "ispcentric-lan" not in pool_names:
        _add(
            sock,
            "/ip/pool",
            name="ispcentric-lan",
            ranges=plan_ranges,
            comment=CLEAN_UPLINK_TAG,
        )
        notes.append("added LAN DHCP pool")
    else:
        for row in _print(sock, "/ip/pool", props=".id,name"):
            if (row.get("name") or "").strip() != "ispcentric-lan":
                continue
            item_id = (row.get(".id") or "").strip()
            if item_id:
                _set(sock, "/ip/pool", item_id, ranges=plan_ranges)
            break

    lan_server_id = ""
    for row in _print(sock, "/ip/dhcp-server", props=".id,interface,name"):
        if (row.get("interface") or "").strip() == lan_bridge:
            lan_server_id = (row.get(".id") or "").strip()
            break
    if lan_server_id:
        _set(
            sock,
            "/ip/dhcp-server",
            lan_server_id,
            disabled="no",
            **{"address-pool": "ispcentric-lan"},
        )
    else:
        _add(
            sock,
            "/ip/dhcp-server",
            name="ispcentric-lan",
            interface=lan_bridge,
            **{"address-pool": "ispcentric-lan", "comment": CLEAN_UPLINK_TAG},
        )
        notes.append("added LAN DHCP server")

    has_net = any(
        _ip_network_from_cidr(row.get("address") or "") == plan_net
        for row in _print(sock, "/ip/dhcp-server/network", props="address")
    )
    if not has_net:
        _add(
            sock,
            "/ip/dhcp-server/network",
            address=str(plan_net),
            gateway=plan_gateway,
            **{"dns-server": plan_gateway, "comment": CLEAN_UPLINK_TAG},
        )
        notes.append(f"added LAN DHCP network {plan_net}")

    _ensure_interface_list(sock, "WAN")
    _ensure_interface_list(sock, "LAN")
    for member in wan_members:
        _ensure_list_member(sock, "WAN", member)
    _ensure_list_member(sock, "LAN", lan_bridge)
    _ensure_masquerade(sock)
    _command(
        sock,
        [
            "/ip/dns/set",
            "=allow-remote-requests=yes",
            "=servers=1.1.1.1,8.8.8.8",
        ],
    )

    notes.append(f"wan_mode={'pppoe' if pppoe_iface else 'dhcp'}")
    notes.append(f"lan_plan={plan_net}")
    return notes


def read_mikrotik_clean_uplink(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Detect whether ISPCENTRIC clean-uplink rules are present on the router."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not host or not username:
        return {"ok": False, "enabled": False, "error": "Router credentials are required."}

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            filter_hits = _rows_with_tag(sock, "/ip/firewall/filter")
            nat_hits = _rows_with_tag(sock, "/ip/firewall/nat")
            enabled = bool(filter_hits or nat_hits)
            mode = "behind" if any(
                "block provider" in (row.get("comment") or "") for row in filter_hits
            ) else "bypass"
            return {
                "ok": True,
                "enabled": enabled,
                "mode": mode if enabled else "",
                "filter_rules": len(filter_hits),
                "nat_rules": len(nat_hits),
            }
    except TimeoutError:
        return {"ok": False, "enabled": False, "error": "Timed out reading clean uplink status.", "timeout": True}
    except ConnectionError as exc:
        return {"ok": False, "enabled": False, "error": str(exc)}
    except OSError as exc:
        return {
            "ok": False,
            "enabled": False,
            "error": f"Could not reach {host}:8728.",
            "detail": str(exc),
        }
    except Exception as exc:
        return {"ok": False, "enabled": False, "error": f"Clean uplink status failed: {exc}"}


def set_mikrotik_clean_uplink(
    host: str,
    username: str,
    password: str,
    *,
    enabled: bool,
    mode: str = "bypass",
    wan_interface: str = "ether1",
    lan_bridge: str = "bridgeLocal",
    provider_gateway: str = "",
    separate_wan: bool = True,
    restore_wan_to_bridge: bool = False,
    port: int = 8728,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """
    Apply or remove clean-uplink rules on RouterOS for any ISP uplink.

    Supports DHCP and PPPoE WAN, picks a LAN subnet that does not collide with
    the provider side, and (in behind mode) blocks one or more provider admin
    IPs plus the private ISP modem LAN when detected.

    Runs in phases and reconnects after unbridging WAN, because that change
    often drops the active API TCP session.
    """
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    mode = (mode or "bypass").strip().lower()
    if mode not in {"bypass", "behind"}:
        mode = "bypass"
    wan_interface = (wan_interface or "ether1").strip()
    lan_bridge = (lan_bridge or "bridgeLocal").strip()
    provider_gateway_raw = (provider_gateway or "").strip()

    if not host or not username:
        return {"ok": False, "error": "Router credentials are required."}
    if not wan_interface:
        return {"ok": False, "error": "WAN interface is required."}
    if not lan_bridge:
        return {"ok": False, "error": "LAN bridge is required."}

    provider_gateways: list[str] = []
    if provider_gateway_raw:
        try:
            provider_gateways = parse_provider_gateways(provider_gateway_raw)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}

    try:
        if not enabled:
            with _api_session(host, username, password, port=port, timeout=timeout) as sock:
                _remove_tagged(sock, "/ip/firewall/filter")
                _remove_tagged(sock, "/ip/firewall/nat")
                _remove_tagged(sock, "/ip/dhcp-client")
                _remove_tagged(sock, "/interface/list/member")
                if restore_wan_to_bridge and wan_interface and lan_bridge:
                    if not _bridge_port_id(sock, wan_interface):
                        terminal = _add(
                            sock,
                            "/interface/bridge/port",
                            interface=wan_interface,
                            bridge=lan_bridge,
                            comment=CLEAN_UPLINK_TAG,
                        )
                        if terminal.get("_reply") == "!trap":
                            return {
                                "ok": False,
                                "enabled": False,
                                "wan_was_bridged": False,
                                "error": _trap_message(
                                    terminal,
                                    "Removed clean uplink rules, but could not restore WAN to the bridge.",
                                ),
                            }
            return {
                "ok": True,
                "enabled": False,
                "mode": mode,
                "wan_was_bridged": False,
                "message": "Clean uplink disabled. Provider-block rules were removed from the MikroTik.",
            }

        wan_was_bridged = False
        detected_gateways: list[str] = []
        provider_networks: list[str] = []
        wan_mode = "dhcp"

        # Phase 1: validate interfaces and optionally unbridge WAN.
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            iface_names = {
                (row.get("name") or "").strip()
                for row in _print(sock, "/interface", props="name")
            }
            if wan_interface not in iface_names:
                return {
                    "ok": False,
                    "error": f"WAN interface “{wan_interface}” was not found on this MikroTik.",
                }
            if lan_bridge not in iface_names:
                return {
                    "ok": False,
                    "error": f"LAN bridge “{lan_bridge}” was not found on this MikroTik.",
                }

            pppoe_iface = _find_pppoe_client_for_wan(sock, wan_interface)
            if pppoe_iface:
                wan_mode = "pppoe"
            detected_gateways = _detect_dhcp_gateways(sock, wan_interface)
            wan_nets = _collect_interface_networks(
                sock, wan_interface, *( [pppoe_iface] if pppoe_iface else [])
            )
            provider_networks = [
                str(net) for net in wan_nets if net.is_private
            ]

            if separate_wan:
                port_id = _bridge_port_id(sock, wan_interface)
                if port_id:
                    terminal = _remove(sock, "/interface/bridge/port", port_id)
                    if terminal.get("_reply") == "!trap":
                        return {
                            "ok": False,
                            "error": _trap_message(
                                terminal,
                                f"Could not remove {wan_interface} from the bridge.",
                            ),
                        }
                    wan_was_bridged = True

        if mode == "behind":
            if not provider_gateways and detected_gateways:
                provider_gateways = detected_gateways
            if not provider_gateways:
                return {
                    "ok": False,
                    "error": (
                        "Provider gateway IP is required for behind-provider mode. "
                        "Enter the modem/ONT admin IP (e.g. 192.168.1.1 or 192.168.100.1)."
                    ),
                }

        # Unbridging often kills the current API TCP session — wait, then continue.
        if wan_was_bridged:
            time.sleep(1.5)
            _wait_for_api(host, port=port)

        # Phase 2: lists, DHCP/PPPoE, DNS, NAT, firewall (fresh session).
        last_error = ""
        passthrough_notes: list[str] = []
        for attempt in range(1, 4):
            try:
                with _api_session(
                    host, username, password, port=port, timeout=timeout
                ) as sock:
                    _ensure_interface_list(sock, "WAN")
                    _ensure_interface_list(sock, "LAN")
                    passthrough_notes = ensure_mikrotik_lan_passthrough(
                        sock,
                        wan_interface=wan_interface,
                        lan_bridge=lan_bridge,
                    )
                    # Refresh private WAN nets after DHCP/PPPoE may have addressed them.
                    pppoe_iface = _find_pppoe_client_for_wan(sock, wan_interface)
                    wan_nets = _collect_interface_networks(
                        sock,
                        wan_interface,
                        *([pppoe_iface] if pppoe_iface else []),
                    )
                    provider_networks = [
                        str(net) for net in wan_nets if net.is_private
                    ]
                    if mode == "behind" and not provider_gateways:
                        provider_gateways = _detect_dhcp_gateways(sock, wan_interface)

                    _command(
                        sock,
                        [
                            "/ip/dns/set",
                            "=allow-remote-requests=yes",
                            "=servers=1.1.1.1,8.8.8.8",
                        ],
                    )
                    _remove_tagged(sock, "/ip/firewall/nat")
                    _ensure_masquerade(sock)
                    _ensure_dns_redirect(sock)
                    _ensure_filter_rules(
                        sock,
                        mode=mode,
                        provider_gateways=provider_gateways if mode == "behind" else None,
                        provider_networks=provider_networks if mode == "behind" else None,
                    )
                break
            except (TimeoutError, ConnectionError, OSError) as exc:
                last_error = str(exc)
                if attempt >= 3:
                    return {
                        "ok": False,
                        "error": (
                            last_error
                            or "Could not finish clean uplink after reconnecting to the router."
                        ),
                    }
                time.sleep(1.5 * attempt)
                _wait_for_api(host, port=port)

        mode_label = (
            "Modem bypass" if mode == "bypass" else "Behind provider router"
        )
        detail = ""
        if passthrough_notes:
            detail = " " + "; ".join(
                n for n in passthrough_notes if n.startswith(("wan_mode=", "lan_plan=", "using "))
            )
        return {
            "ok": True,
            "enabled": True,
            "mode": mode,
            "wan_mode": wan_mode,
            "provider_gateways": provider_gateways,
            "wan_was_bridged": wan_was_bridged,
            "notes": passthrough_notes,
            "message": (
                f"Clean uplink enabled ({mode_label}). "
                "MikroTik will pass internet and block provider settings pages."
                f"{detail}"
            ),
        }
    except TimeoutError:
        return {
            "ok": False,
            "error": (
                "Timed out while updating clean uplink. "
                "If WAN was just taken out of the bridge, wait 5 seconds and click Enable again."
            ),
            "timeout": True,
        }
    except ConnectionError as exc:
        return {"ok": False, "error": str(exc)}
    except OSError as exc:
        return {
            "ok": False,
            "error": f"Could not reach {host}:8728 to update clean uplink.",
            "detail": str(exc),
        }
    except Exception as exc:
        return {"ok": False, "error": f"Clean uplink update failed: {exc}"}


def recover_mikrotik_connection(
    host: str,
    username: str,
    password: str,
    *,
    wan_interface: str = "ether1",
    lan_bridge: str = "bridgeLocal",
    candidate_hosts: list[str] | None = None,
    restore_bridge: bool = True,
    remove_clean_rules: bool = True,
    port: int = 8728,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """
    Bring a MikroTik back under management after clean-uplink / network lockout.

    Tries the saved host first, then any discovered candidate IPs with the same
    credentials. When API works, optionally restores WAN into the LAN bridge and
    removes ISPCENTRIC clean-uplink firewall/NAT rules that can block access.
    """
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    wan_interface = (wan_interface or "ether1").strip()
    lan_bridge = (lan_bridge or "bridgeLocal").strip()

    if not username:
        return {"ok": False, "error": "Router username is required."}
    if not password:
        return {"ok": False, "error": "Router password is required."}

    hosts: list[str] = []
    for candidate in [
        host,
        *(["192.168.88.1"] if on_router_lan() else []),
        *(candidate_hosts or []),
    ]:
        value = (candidate or "").strip()
        if value and value not in hosts:
            hosts.append(value)
    if not hosts:
        return {
            "ok": False,
            "error": "No router IP to try. Plug your PC into a LAN port and scan again.",
        }

    last_error = "Could not reach the MikroTik API on any candidate IP."
    working_host = ""
    pingable_hosts: list[str] = []
    manageable_hosts: list[str] = []
    api_refused_hosts: list[str] = []
    _auth_tokens = (
        "invalid user",
        "password",
        "cannot log in",
        "login failed",
        "authentication",
        "bad name",
    )
    _network_tokens = (
        "refused",
        "10061",
        "10060",
        "unreachable",
        "no route",
        "network is unreachable",
        "timed out",
        "forcibly closed",
        "reset by peer",
    )

    for candidate in hosts:
        probe = check_mikrotik_reachable(candidate, timeout=min(2.0, timeout))
        via = (probe.get("via") or "").strip()
        if probe.get("online") and via == "ping":
            pingable_hosts.append(candidate)
        if probe.get("online") and via in {"api", "winbox", "http"}:
            manageable_hosts.append(candidate)

        # Don't burn long timeouts on ping-only hosts — API is almost certainly firewalled.
        attempt_timeout = 2.5 if via == "ping" else timeout

        try:
            with _api_session(
                candidate, username, password, port=port, timeout=attempt_timeout
            ) as sock:
                # Prove the session is usable.
                _print(sock, "/system/identity", props="name")
                working_host = candidate

                repaired: list[str] = []
                if remove_clean_rules:
                    removed_filter = _remove_tagged(sock, "/ip/firewall/filter")
                    removed_nat = _remove_tagged(sock, "/ip/firewall/nat")
                    removed_dhcp = _remove_tagged(sock, "/ip/dhcp-client")
                    removed_members = _remove_tagged(sock, "/interface/list/member")
                    if removed_filter or removed_nat or removed_dhcp or removed_members:
                        repaired.append("removed clean-uplink rules")

                if restore_bridge and wan_interface and lan_bridge:
                    iface_names = {
                        (row.get("name") or "").strip()
                        for row in _print(sock, "/interface", props="name")
                    }
                    if wan_interface in iface_names and lan_bridge in iface_names:
                        if not _bridge_port_id(sock, wan_interface):
                            # Do NOT put WAN back in the bridge — that breaks routing.
                            # Instead ensure proper LAN/WAN passthrough.
                            pass

                try:
                    repaired.extend(
                        ensure_mikrotik_lan_passthrough(
                            sock,
                            wan_interface=wan_interface,
                            lan_bridge=lan_bridge,
                        )
                    )
                except Exception as exc:
                    repaired.append(f"passthrough warning: {exc}")

                identity = ""
                for row in _print(sock, "/system/identity", props="name"):
                    identity = (row.get("name") or "").strip() or identity

            note = "; ".join(repaired) if repaired else "API login verified"
            host_note = (
                f" (updated IP to {working_host})"
                if working_host != host and host
                else ""
            )
            return {
                "ok": True,
                "host": working_host,
                "host_changed": bool(host and working_host != host),
                "identity": identity,
                "repaired": repaired,
                "message": (
                    f"MikroTik is back online{host_note}. {note}. "
                    "Clients must use ether2–ether5 and get a 10.10.0.x address."
                ),
            }
        except ConnectionRefusedError:
            api_refused_hosts.append(candidate)
            last_error = (
                f"{candidate}: API port {port} refused "
                "(RouterOS API service may be disabled)"
            )
            continue
        except ConnectionError as exc:
            message = str(exc) or "Login failed."
            low = message.lower()
            # socket.create_connection failures are ConnectionError subclasses on
            # some platforms; never treat those as wrong-password auth errors.
            if any(token in low for token in _network_tokens):
                if "refused" in low or "10061" in low:
                    api_refused_hosts.append(candidate)
                last_error = f"{candidate}: {message}"
                continue
            # Wrong password after TCP connected — stop trying other IPs.
            if any(token in low for token in _auth_tokens):
                return {
                    "ok": False,
                    "error": (
                        f"{message} Update Login credentials on this router "
                        "(sidebar) with the same username/password used in Winbox, "
                        "then click Reconnect again."
                    ),
                    "auth_error": True,
                    "host": candidate,
                }
            last_error = f"{candidate}: {message}"
            continue
        except TimeoutError:
            last_error = f"{candidate}: API timed out"
            continue
        except OSError as exc:
            message = str(exc) or "OS error"
            low = message.lower()
            if "refused" in low or "10061" in low:
                api_refused_hosts.append(candidate)
            last_error = f"{candidate}: {exc}"
            continue
        except Exception as exc:
            last_error = f"{candidate}: {exc}"
            continue

    # Hotspot rejects every service port for a client that has not logged in,
    # so "refused" here means this PC is captive — not that API is disabled.
    hotspot_hosts = [
        candidate
        for candidate in sorted(set(api_refused_hosts))
        if _serves_hotspot_portal(dial_host(candidate))
    ]
    if hotspot_hosts:
        shown = ", ".join(hotspot_hosts[:3])
        return {
            "ok": False,
            "error": (
                f"Router {shown} is running Hotspot and this PC is not logged in, "
                f"so RouterOS rejects API {port}, Winbox 8291 and SSH 22. "
                "Open Winbox → Neighbors and connect by MAC address (that works "
                "without an IP), then run: /ip hotspot ip-binding add "
                "address=<this PC's IP> type=bypassed comment=\"ispcentric\" — "
                "or paste the ISPCENTRIC tunnel script, which allows API from the "
                "LAN. Then click Reconnect again."
            ),
            "hotspot_lockout": True,
            "host": hotspot_hosts[0],
            "pingable_hosts": sorted(set(pingable_hosts)),
        }

    # Device answers WebFig/Winbox but API TCP is refused → enable api service.
    if api_refused_hosts and manageable_hosts:
        shown = ", ".join(sorted(set(api_refused_hosts))[:3])
        return {
            "ok": False,
            "error": (
                f"Router {shown} is online (WebFig/Winbox), but RouterOS API "
                f"port {port} is closed. In Winbox: IP → Services → enable api "
                f"(port {port}), allow this PC in the service address list if set, "
                "then click Reconnect again."
            ),
            "api_disabled": True,
            "host": api_refused_hosts[0],
            "pingable_hosts": sorted(set(pingable_hosts)),
        }

    # Ping works but every management TCP port is dead → IP firewall lockout.
    if pingable_hosts and not manageable_hosts:
        shown = ", ".join(sorted(set(pingable_hosts))[:3])
        return {
            "ok": False,
            "error": (
                f"Router {shown} answers ping, but API/Winbox ports are blocked "
                "(likely leftover clean-uplink firewall). ISPCENTRIC cannot repair "
                "this over the network. Open Winbox → Neighbors → connect by MAC, then: "
                "1) IP → Firewall → Filter/NAT — remove rows with comment "
                "ispcentric-clean-uplink; "
                "2) Bridge → Ports — add ether1 to bridgeLocal if missing; "
                "3) IP → Services — ensure api is enabled. "
                "Plug PC into ether2–ether5, then click Reconnect again."
            ),
            "firewall_lockout": True,
            "pingable_hosts": sorted(set(pingable_hosts)),
        }

    return {
        "ok": False,
        "error": (
            f"{last_error}. Plug this PC into MikroTik ether2–ether5 (LAN), "
            "wait a few seconds, then click Reconnect again."
        ),
    }


@contextmanager
def _api_session(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 5.0,
) -> Iterator[socket.socket]:
    with socket.create_connection((dial_host(host), port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        login_error = _api_login(sock, username, password)
        if login_error:
            raise ConnectionError(login_error.get("error") or "Login failed.")
        yield sock


def _cpe_proxy_port(cpe_host: str, scope: str = "") -> int:
    digest = hashlib.sha256(f"{cpe_host}|{scope}".encode()).hexdigest()
    offset = int(digest[:8], 16) % CPE_PROXY_PORT_SPAN
    return CPE_PROXY_PORT_BASE + offset


def _cpe_proxy_comment(proxy_port: int) -> str:
    return f"{CPE_PROXY_TAG}:{proxy_port}"


CPE_HOTSPOT_BYPASS_TAG = f"{CPE_PROXY_TAG}-hsbypass"


def _ensure_hotspot_bypass(sock: socket.socket, address: str) -> None:
    """
    Let a management source reach the NAS through Hotspot.

    Hotspot intercepts every unauthenticated LAN client, so the billing server
    (or office PC) cannot open the temporary CPE proxy port until its own
    address is bypassed. The binding is stable and idempotent — repeated proxy
    installs reuse it instead of thrashing per request. No-ops when the Hotspot
    package is absent.
    """
    address = (address or "").strip()
    if not address:
        return
    try:
        for row in _print(
            sock, "/ip/hotspot/ip-binding", props=".id,address,type,comment"
        ):
            if (row.get("address") or "").strip() != address:
                continue
            if (row.get("type") or "").strip() == "bypassed":
                return  # already bypassed
            item_id = (row.get(".id") or "").strip()
            if item_id:
                _remove(sock, "/ip/hotspot/ip-binding", item_id)
            break
    except Exception:
        # /ip/hotspot absent (no Hotspot on this router) — nothing to bypass.
        return
    try:
        _add(
            sock,
            "/ip/hotspot/ip-binding",
            address=address,
            type="bypassed",
            comment=CPE_HOTSPOT_BYPASS_TAG,
        )
    except Exception:
        pass


def _install_cpe_proxy(
    sock: socket.socket,
    proxy_port: int,
    cpe_host: str,
    cpe_port: int = 8728,
    allowed_source: str = "",
) -> str | None:
    """Forward a NAS TCP port to a CPE management port."""
    comment = _cpe_proxy_comment(proxy_port)
    _remove_comment_tagged(sock, "/ip/firewall/nat", comment)
    _remove_comment_tagged(sock, "/ip/firewall/filter", comment)
    # A captive Hotspot client (this billing server / office PC) is dropped
    # before it can reach the proxy port. Bypass its source first.
    _ensure_hotspot_bypass(sock, allowed_source)
    source_match = (
        {"src-address": allowed_source.strip()} if allowed_source.strip() else {}
    )
    nat = _add(
        sock,
        "/ip/firewall/nat",
        chain="dstnat",
        protocol="tcp",
        **{"dst-port": str(proxy_port)},
        **source_match,
        action="dst-nat",
        **{"to-addresses": cpe_host},
        **{"to-ports": str(cpe_port)},
        comment=comment,
    )
    if nat.get("_reply") in {"!trap", "!fatal"}:
        return _trap_message(nat, "Could not create CPE proxy on the ISP MikroTik.")

    # Make the CPE see the ISP gateway (10.20.0.1), not the office PC IP.
    # Many CPEs drop WAN management from foreign source addresses.
    src = _add(
        sock,
        "/ip/firewall/nat",
        chain="srcnat",
        protocol="tcp",
        **source_match,
        **{"dst-address": cpe_host},
        **{"dst-port": str(cpe_port)},
        action="src-nat",
        **{"to-addresses": PPPOE_LOCAL_ADDRESS},
        comment=comment,
    )
    if src.get("_reply") in {"!trap", "!fatal"}:
        src = _add(
            sock,
            "/ip/firewall/nat",
            chain="srcnat",
            protocol="tcp",
            **{"dst-address": cpe_host},
            **{"dst-port": str(cpe_port)},
            action="masquerade",
            comment=comment,
        )
        if src.get("_reply") in {"!trap", "!fatal"}:
            return _trap_message(src, "Could not NAT CPE proxy traffic on the ISP MikroTik.")

    # dst-nat sends traffic to the CPE, so it uses the forward chain (not input).
    forward = _add(
        sock,
        "/ip/firewall/filter",
        chain="forward",
        protocol="tcp",
        **{"dst-address": cpe_host},
        **{"dst-port": str(cpe_port)},
        action="accept",
        comment=comment,
        **{"place-before": "0"},
    )
    if forward.get("_reply") in {"!trap", "!fatal"}:
        forward = _add(
            sock,
            "/ip/firewall/filter",
            chain="forward",
            protocol="tcp",
            **{"dst-address": cpe_host},
            **{"dst-port": str(cpe_port)},
            action="accept",
            comment=comment,
        )
    if forward.get("_reply") in {"!trap", "!fatal"}:
        # Still try a broader dstnat-related allow.
        forward = _add(
            sock,
            "/ip/firewall/filter",
            chain="forward",
            **{"connection-nat-state": "dstnat"},
            action="accept",
            comment=comment,
        )
    if forward.get("_reply") in {"!trap", "!fatal"}:
        _remove_comment_tagged(sock, "/ip/firewall/nat", comment)
        _remove_comment_tagged(sock, "/ip/firewall/filter", comment)
        return _trap_message(forward, "Could not allow CPE proxy traffic on the ISP MikroTik.")

    # Also accept the pre-NAT hit on the NAS listening port (some ROS builds need this).
    _add(
        sock,
        "/ip/firewall/filter",
        chain="input",
        protocol="tcp",
        **{"dst-port": str(proxy_port)},
        **source_match,
        action="accept",
        comment=comment,
        **{"place-before": "0"},
    )
    return None


def _uninstall_cpe_proxy(sock: socket.socket, proxy_port: int) -> None:
    comment = _cpe_proxy_comment(proxy_port)
    _remove_comment_tagged(sock, "/ip/firewall/nat", comment)
    _remove_comment_tagged(sock, "/ip/firewall/filter", comment)


# A browser session against one CPE web UI fires dozens of asset requests plus
# steady AJAX polling. Installing/removing NAS NAT per request melts the router
# API and produces intermittent 502s, so a single proxy per (NAS, client) is
# installed once and reused for a short TTL. Idempotent installs refresh it.
_CPE_WEB_PROXY_TTL = 90.0
_CPE_WEB_PROXY_CACHE: dict[tuple[str, str], dict[str, Any]] = {}
_CPE_WEB_PROXY_LOCKS: dict[tuple[str, str], threading.Lock] = {}
_CPE_WEB_PROXY_REGISTRY_LOCK = threading.Lock()


def _cpe_web_proxy_lock(key: tuple[str, str]) -> threading.Lock:
    with _CPE_WEB_PROXY_REGISTRY_LOCK:
        lock = _CPE_WEB_PROXY_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _CPE_WEB_PROXY_LOCKS[key] = lock
        return lock


@contextmanager
def customer_cpe_web_proxy(
    nas_host: str,
    nas_username: str,
    nas_password: str,
    *,
    pppoe_username: str,
    cpe_port: int = 80,
    nas_port: int = 8728,
    timeout: float = 8.0,
) -> Iterator[dict[str, Any]]:
    """
    Expose one active PPPoE CPE web port to this app, reusing a cached tunnel.

    A stable proxy port per (NAS, client, cpe_port) is installed once and kept
    for `_CPE_WEB_PROXY_TTL`. Concurrent requests for the same client reuse it
    behind a per-key lock instead of reinstalling NAT, which is what caused
    intermittent 502s under the router UI's rapid polling. The dst-nat rule is
    source-restricted to the app's address as seen by the NAS.
    """
    key = (dial_host(nas_host), f"{pppoe_username}|{cpe_port}")
    now = time.monotonic()

    cached = _CPE_WEB_PROXY_CACHE.get(key)
    if cached and cached.get("expires_at", 0) > now:
        yield {
            "host": cached["host"],
            "port": cached["port"],
            "cpe_host": cached["cpe_host"],
            "source_address": cached.get("source_address", ""),
        }
        return

    lock = _cpe_web_proxy_lock(key)
    with lock:
        # Another thread may have installed it while we waited on the lock.
        cached = _CPE_WEB_PROXY_CACHE.get(key)
        now = time.monotonic()
        if cached and cached.get("expires_at", 0) > now:
            yield {
                "host": cached["host"],
                "port": cached["port"],
                "cpe_host": cached["cpe_host"],
                "source_address": cached.get("source_address", ""),
            }
            return

        session = resolve_customer_cpe_session(
            nas_host,
            nas_username,
            nas_password,
            pppoe_username=pppoe_username,
            port=nas_port,
            timeout=min(timeout, 5.0),
        )
        if not session.get("ok"):
            raise ConnectionError(
                session.get("error") or "Could not read the client's PPPoE session."
            )
        if not session.get("session_active") or not session.get("address"):
            raise ConnectionError(
                session.get("hint") or "The client router is offline."
            )

        cpe_host = str(session["address"]).strip()
        # Stable scope → same proxy port on every refresh, so repeated installs
        # replace their own rule (idempotent) rather than piling up NAT entries.
        proxy_port = _cpe_proxy_port(cpe_host, f"web|{pppoe_username}|{cpe_port}")
        source_address = ""

        with _api_session(
            nas_host,
            nas_username,
            nas_password,
            port=nas_port,
            timeout=timeout,
        ) as nas_sock:
            try:
                source_address = str(nas_sock.getsockname()[0]).strip()
            except (AttributeError, OSError, IndexError):
                source_address = ""
            error = _install_cpe_proxy(
                nas_sock,
                proxy_port,
                cpe_host,
                cpe_port,
                allowed_source=source_address,
            )
            if error:
                raise ConnectionError(error)

        entry = {
            "host": dial_host(nas_host),
            "port": proxy_port,
            "cpe_host": cpe_host,
            "source_address": source_address,
            "expires_at": time.monotonic() + _CPE_WEB_PROXY_TTL,
        }
        _CPE_WEB_PROXY_CACHE[key] = entry

    yield {
        "host": entry["host"],
        "port": entry["port"],
        "cpe_host": entry["cpe_host"],
        "source_address": entry["source_address"],
    }


def release_customer_cpe_web_proxy(
    nas_host: str,
    nas_username: str,
    nas_password: str,
    *,
    pppoe_username: str,
    cpe_port: int = 80,
    nas_port: int = 8728,
    timeout: float = 5.0,
) -> None:
    """Tear down a cached CPE web proxy and forget it (best-effort)."""
    key = (dial_host(nas_host), f"{pppoe_username}|{cpe_port}")
    with _cpe_web_proxy_lock(key):
        entry = _CPE_WEB_PROXY_CACHE.pop(key, None)
    if not entry:
        return
    try:
        with _api_session(
            nas_host,
            nas_username,
            nas_password,
            port=nas_port,
            timeout=timeout,
        ) as nas_sock:
            _uninstall_cpe_proxy(nas_sock, entry["port"])
    except Exception:
        pass


_CPE_WEB_DATA_PATHS = {
    "status": "/goform/getStatus?modules=internetStatus,deviceStatistics,systemInfo,wanAdvCfg,wifiRelay",
    "wifi": "/goform/getWifi?modules=wifiEn,wifiBasicCfg,wifiAdvCfg,wifiPower,wifiTime,wifiWPS,wifiVirSsid",
    "devices": "/goform/getQos?modules=localhost,onlineList,blackList,macFilter",
    "wan": "/goform/getWAN?modules=lanCfg,wanBasicCfg,wanAdvCfg,internetStatus",
    "system": "/goform/getSysTools?modules=loginAuth,lanCfg,softWare,wifiRelay,sysTime,remoteWeb,isWifiClients,systemInfo",
}
_CPE_WEB_DATA_SESSIONS: dict[tuple[str, str, int], dict[str, Any]] = {}
_CPE_WEB_DATA_SESSION_LOCK = threading.Lock()


def _cpe_web_json_request(
    proxy: dict[str, Any],
    path: str,
    *,
    cpe_port: int,
    method: str = "GET",
    body: bytes | None = None,
    cookies: dict[str, str] | None = None,
    timeout: float = 8.0,
) -> tuple[int, dict[str, Any], dict[str, str], str]:
    """Make one CPE request; decode a JSON object and report any redirect target."""
    headers = {
        "Host": str(proxy["cpe_host"]),
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "identity",
    }
    if cookies:
        headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body))
    is_tls = cpe_port in {443, 8443}
    connection_class = http.client.HTTPSConnection if is_tls else http.client.HTTPConnection
    kwargs: dict[str, Any] = {"timeout": timeout}
    if is_tls:
        kwargs["context"] = ssl._create_unverified_context()
    connection = connection_class(proxy["host"], proxy["port"], **kwargs)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(1024 * 1024)
        response_cookies: dict[str, str] = {}
        location = ""
        for name, value in response.getheaders():
            lower = name.lower()
            if lower == "location":
                location = value
                continue
            if lower != "set-cookie":
                continue
            parsed = SimpleCookie()
            try:
                parsed.load(value)
            except Exception:
                continue
            response_cookies.update(
                {cookie_name: morsel.value for cookie_name, morsel in parsed.items()}
            )
        try:
            payload = json.loads(raw.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeError):
            payload = {}
        return (
            response.status,
            payload if isinstance(payload, dict) else {},
            response_cookies,
            location,
        )
    finally:
        connection.close()


# Consumer CPEs lock the admin account after a few bad passwords (Tenda: five
# tries, then three minutes). Page refreshes must never spend those attempts, so
# a rejected password blocks further logins until the credential changes.
_CPE_WEB_LOGIN_BLOCKS: dict[tuple[str, str, int], dict[str, Any]] = {}
_CPE_WEB_LOGIN_BLOCK_LOCK = threading.Lock()
_CPE_WEB_LOGIN_BLOCK_SECONDS = 900.0


def _cpe_login_failure_message(location: str) -> str:
    """Translate a CPE login redirect into the router's own error meaning."""
    code = ""
    if "?" in (location or ""):
        code = location.rsplit("?", 1)[1].strip()
    if code in {"2", "3"}:
        return (
            "The client router already has the maximum number of administrators "
            "signed in. Wait for those sessions to end, then refresh."
        )
    if code.isdigit() and 10 <= int(code) <= 14:
        remaining = int(code) - 10
        if remaining <= 0:
            return (
                "The client router locked out logins after five failed attempts. "
                "Wait about three minutes, save the correct admin password, then refresh."
            )
        attempt_word = "attempt" if remaining == 1 else "attempts"
        return (
            f"The saved client router admin password was rejected — only {remaining} "
            f"{attempt_word} left before the router locks logins for three minutes. "
            "Update the saved password before trying again."
        )
    return (
        "The saved client router admin password was rejected. Update it on this "
        "client, then refresh."
    )


def fetch_customer_cpe_web_data(
    nas_host: str,
    nas_username: str,
    nas_password: str,
    *,
    pppoe_username: str,
    cpe_password: str = "",
    session_cookies: dict[str, str] | None = None,
    cpe_port: int = 80,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Fetch normalized status, WAN, Wi-Fi, system and device data from a CPE web API."""
    result: dict[str, Any] = {
        "ok": False,
        "authenticated": False,
        "vendor": "",
        "model": "",
        "cpe_host": "",
        "status": {},
        "wifi": {},
        "devices": [],
        "wan": {},
        "system": {},
        "error": "",
    }
    if not cpe_password and not session_cookies:
        result["error"] = "Save the client router admin password before fetching router details."
        return result

    session_key = (dial_host(nas_host), pppoe_username, int(cpe_port))
    with _CPE_WEB_LOGIN_BLOCK_LOCK:
        block = dict(_CPE_WEB_LOGIN_BLOCKS.get(session_key) or {})
    blocked = (
        block.get("expires_at", 0) > time.monotonic()
        and block.get("password") == cpe_password
    )

    try:
        with customer_cpe_web_proxy(
            nas_host,
            nas_username,
            nas_password,
            pppoe_username=pppoe_username,
            cpe_port=cpe_port,
            timeout=timeout,
        ) as proxy:
            result["cpe_host"] = str(proxy.get("cpe_host") or "")
            now = time.monotonic()
            with _CPE_WEB_DATA_SESSION_LOCK:
                saved = dict(_CPE_WEB_DATA_SESSIONS.get(session_key) or {})
            cookies = (
                dict(saved.get("cookies") or {})
                if saved.get("expires_at", 0) > now
                else {}
            )
            cookies.update(session_cookies or {})
            status_code, status_payload, new_cookies, _ = _cpe_web_json_request(
                proxy,
                _CPE_WEB_DATA_PATHS["status"],
                cpe_port=cpe_port,
                cookies=cookies,
                timeout=timeout,
            )
            cookies.update(new_cookies)
            if status_code != 200 or not status_payload:
                if not cpe_password:
                    result["error"] = "Open and sign in to the client router, then refresh this data."
                    return result
                if blocked:
                    result["error"] = block.get("message") or (
                        "The saved client router admin password was rejected."
                    )
                    return result
                stok_status, stok, stok_cookies, _ = _cpe_web_json_request(
                    proxy, "/goform/getstok", cpe_port=cpe_port, timeout=timeout
                )
                cookies.update(stok_cookies)
                random_key = str(stok.get("random") or "")
                if stok_status != 200 or not random_key:
                    result["error"] = "The router web API did not provide a login challenge."
                    return result
                encoded = base64.b64encode(cpe_password.encode("utf-8")).decode("ascii")
                digest = hashlib.md5((encoded + random_key).encode("utf-8")).hexdigest()
                login_body = urlencode({"password": digest}).encode("ascii")
                (
                    login_status,
                    login_payload,
                    login_cookies,
                    login_location,
                ) = _cpe_web_json_request(
                    proxy,
                    "/login/Auth",
                    cpe_port=cpe_port,
                    method="POST",
                    body=login_body,
                    cookies=cookies,
                    timeout=timeout,
                )
                cookies.update(login_cookies)
                login_error = login_payload.get("errCode")
                rejected = (
                    login_status not in {200, 302, 303}
                    or "login.html" in login_location
                    or (login_error is not None and str(login_error) != "0")
                )
                if rejected:
                    message = _cpe_login_failure_message(login_location)
                    with _CPE_WEB_LOGIN_BLOCK_LOCK:
                        _CPE_WEB_LOGIN_BLOCKS[session_key] = {
                            "password": cpe_password,
                            "message": message,
                            "expires_at": time.monotonic() + _CPE_WEB_LOGIN_BLOCK_SECONDS,
                        }
                    result["error"] = message
                    return result
                status_code, status_payload, new_cookies, _ = _cpe_web_json_request(
                    proxy,
                    _CPE_WEB_DATA_PATHS["status"],
                    cpe_port=cpe_port,
                    cookies=cookies,
                    timeout=timeout,
                )
                cookies.update(new_cookies)
            if status_code != 200 or not status_payload:
                result["error"] = "The router accepted login but returned no status data."
                return result

            with _CPE_WEB_LOGIN_BLOCK_LOCK:
                _CPE_WEB_LOGIN_BLOCKS.pop(session_key, None)

            modules: dict[str, dict[str, Any]] = {"status": status_payload}
            for group in ("wifi", "devices", "wan", "system"):
                _, payload, fresh, _unused = _cpe_web_json_request(
                    proxy,
                    _CPE_WEB_DATA_PATHS[group],
                    cpe_port=cpe_port,
                    cookies=cookies,
                    timeout=timeout,
                )
                cookies.update(fresh)
                modules[group] = payload
            with _CPE_WEB_DATA_SESSION_LOCK:
                _CPE_WEB_DATA_SESSIONS[session_key] = {
                    "cookies": cookies,
                    "expires_at": time.monotonic() + 600.0,
                }
    except (ConnectionError, OSError, TimeoutError, http.client.HTTPException) as exc:
        result["error"] = str(exc) or "Could not read the client router web API."
        return result

    status = modules["status"]
    wifi_modules = modules["wifi"]
    wan_modules = modules["wan"]
    system_modules = modules["system"]
    statistics = status.get("deviceStastics") or status.get("deviceStatistics") or {}
    system_info = status.get("systemInfo") or system_modules.get("systemInfo") or {}
    wifi = wifi_modules.get("wifiBasicCfg") or {}
    wifi_advanced = wifi_modules.get("wifiAdvCfg") or {}
    wan_advanced = status.get("wanAdvCfg") or wan_modules.get("wanAdvCfg") or {}
    internet = status.get("internetStatus") or wan_modules.get("internetStatus") or {}
    lan = wan_modules.get("lanCfg") or system_modules.get("lanCfg") or {}
    raw_devices = modules["devices"].get("onlineList") or []
    if isinstance(raw_devices, dict):
        raw_devices = list(raw_devices.values())
    devices = []
    for item in raw_devices if isinstance(raw_devices, list) else []:
        if not isinstance(item, dict):
            continue
        devices.append({
            "name": item.get("qosListRemark") or item.get("qosListHostname") or "Unknown device",
            "ip": item.get("qosListIP") or "",
            "mac": item.get("qosListMac") or item.get("qosListMAC") or "",
            "type": item.get("qosListConnectType") or "",
            "download": item.get("qosListDownSpeed") or "",
            "upload": item.get("qosListUpSpeed") or "",
        })
    firmware = (
        system_info.get("softVersion")
        or (system_modules.get("softWare") or {}).get("softVersion")
        or ""
    )
    result.update({
        "ok": True,
        "authenticated": True,
        "vendor": "Tenda" if firmware or "tenda" in str(statistics.get("routerName", "")).lower() else "Router",
        "model": statistics.get("routerName") or "",
        "status": {
            "connected": str(internet.get("wanConnectStatus") or "")[2:3] == "1",
            "uptime_seconds": system_info.get("wanConnectTime") or "",
            "online_devices": statistics.get("statusOnlineNumber") or len(devices),
            "download_kbps": statistics.get("statusDownSpeed") or "",
            "upload_kbps": statistics.get("statusUpSpeed") or "",
        },
        "wifi": {
            "enabled": str((wifi_modules.get("wifiEn") or {}).get("wifiEn")).lower() == "true",
            "ssid": wifi.get("wifiSSID") or "",
            "password": (
                wifi.get("wifiPwd")
                or wifi.get("wifiPassword")
                or wifi.get("wifiPasswd")
                or ""
            ),
            "security": wifi.get("wifiSecurityMode") or "",
            "hidden": str(wifi.get("wifiHideSSID")).lower() == "true",
            "channel": wifi_advanced.get("wifiChannelCurrent") or wifi_advanced.get("wifiChannel") or "",
            "bandwidth_mhz": wifi_advanced.get("wifiBandwidthCurrent") or "",
            "mode": wifi_advanced.get("wifiMode") or "",
            "power": (wifi_modules.get("wifiPower") or {}).get("wifiPower") or "",
            "ssid_5g": wifi.get("wifiSSID_5G") or "",
            "password_5g": wifi.get("wifiPwd_5G") or wifi.get("wifiPassword_5G") or "",
            "security_5g": wifi.get("wifiSecurityMode_5G") or "",
            "enabled_5g": (
                str(wifi.get("wifiEn_5G")).lower() == "true"
                if wifi.get("wifiEn_5G") is not None
                else None
            ),
        },
        "devices": devices,
        "wan": {
            "type": system_info.get("wanType") or wan_advanced.get("wanType") or "",
            "ip": system_info.get("statusWanIP") or "",
            "mask": system_info.get("statusWanMask") or "",
            "gateway": system_info.get("statusWanGaterway") or "",
            "dns1": system_info.get("statusWanDns1") or "",
            "dns2": system_info.get("statusWanDns2") or "",
            "mac": system_info.get("statusWanMAC") or wan_advanced.get("macCurrentWan") or "",
            "speed_mbps": wan_advanced.get("wanSpeedCurrent") or "",
            "mtu": wan_advanced.get("wanMTUCurrent") or wan_advanced.get("wanMTU") or "",
        },
        "system": {
            "firmware": firmware,
            "lan_ip": system_info.get("lanIP") or lan.get("lanIP") or "",
            "router_time": (system_modules.get("sysTime") or {}).get("sysTimecurrentTime") or "",
            "remote_management": (system_modules.get("remoteWeb") or {}).get("remoteWebEn") or "",
        },
        "error": "",
    })
    return result


def configure_customer_cpe_web_wifi(
    nas_host: str,
    nas_username: str,
    nas_password: str,
    *,
    pppoe_username: str,
    cpe_password: str = "",
    wifi_ssid: str = "",
    wifi_password: str = "",
    apply_ssid: bool = True,
    apply_password: bool = True,
    session_cookies: dict[str, str] | None = None,
    cpe_port: int = 80,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """
    Update Wi‑Fi name/password on a consumer CPE (e.g. Tenda) via its web API.

    Reads the live wifiBasicCfg first so unrelated radio options stay unchanged.
    """
    wifi_ssid = (wifi_ssid or "").strip()
    wifi_password = wifi_password or ""
    if not apply_ssid and not apply_password:
        return {"ok": True, "updated": False, "message": "No Wi‑Fi changes requested."}
    if apply_password and wifi_password and len(wifi_password) < 8:
        return {"ok": False, "error": "Wi‑Fi password must be at least 8 characters."}
    if apply_password and wifi_password and apply_ssid and not wifi_ssid:
        return {"ok": False, "error": "Enter a Wi‑Fi name when setting a Wi‑Fi password."}

    current = fetch_customer_cpe_web_data(
        nas_host,
        nas_username,
        nas_password,
        pppoe_username=pppoe_username,
        cpe_password=cpe_password,
        session_cookies=session_cookies,
        cpe_port=cpe_port,
        timeout=timeout,
    )
    if not current.get("ok"):
        return {
            "ok": False,
            "error": current.get("error") or "Could not read Wi‑Fi settings from the client router.",
            "needs_password": "password" in (current.get("error") or "").lower(),
        }

    wifi = dict(current.get("wifi") or {})
    live_ssid = (wifi.get("ssid") or "").strip()
    live_password = wifi.get("password") or ""
    next_ssid = wifi_ssid if apply_ssid and wifi_ssid else live_ssid
    next_password = wifi_password if apply_password and wifi_password else live_password

    if apply_ssid and wifi_ssid and wifi_ssid == live_ssid:
        apply_ssid = False
    if apply_password and wifi_password and live_password and wifi_password == live_password:
        apply_password = False
    if not apply_ssid and not apply_password:
        return {
            "ok": True,
            "updated": False,
            "message": "Wi‑Fi already matches the requested values.",
            "wifi": wifi,
            "cpe_host": current.get("cpe_host") or "",
        }

    if not next_ssid:
        return {"ok": False, "error": "The client router did not report a Wi‑Fi name to update."}

    security = (wifi.get("security") or "wpapsk/wpa2psk").strip() or "wpapsk/wpa2psk"
    hidden = "true" if wifi.get("hidden") else "false"
    enabled = "true" if wifi.get("enabled", True) else "false"
    mode = (wifi.get("mode") or "bgn").strip() or "bgn"
    channel = str(wifi.get("channel") or "auto")
    bandwidth = str(wifi.get("bandwidth_mhz") or "auto")
    power = (wifi.get("power") or "high").strip() or "high"

    form: dict[str, str] = {
        "module1": "wifiEn",
        "wifiEn": enabled,
        "module2": "wifiBasicCfg",
        "wifiSSID": next_ssid,
        "wifiSecurityMode": security,
        "wifiPwd": next_password,
        "wifiHideSSID": hidden,
        "module5": "wifiAdvCfg",
        "wifiMode": mode,
        "wifiChannel": channel if channel.lower() != "auto" else "auto",
        "wifiBandwidth": bandwidth if str(bandwidth).lower() != "auto" else "auto",
        "module6": "wifiPower",
        "wifiPower": power,
    }
    # Keep dual-band radios in sync when the CPE exposes 5 GHz fields.
    ssid_5g = (wifi.get("ssid_5g") or "").strip()
    if ssid_5g:
        form["wifiEn_5G"] = (
            "true"
            if wifi.get("enabled_5g") is None or wifi.get("enabled_5g")
            else "false"
        )
        form["wifiSSID_5G"] = ssid_5g
        form["wifiSecurityMode_5G"] = (wifi.get("security_5g") or security).strip() or security
        form["wifiPwd_5G"] = (
            next_password if apply_password and wifi_password else (wifi.get("password_5g") or next_password)
        )
        form["wifiHideSSID_5G"] = hidden

    session_key = (dial_host(nas_host), pppoe_username, int(cpe_port))
    try:
        with customer_cpe_web_proxy(
            nas_host,
            nas_username,
            nas_password,
            pppoe_username=pppoe_username,
            cpe_port=cpe_port,
            timeout=timeout,
        ) as proxy:
            now = time.monotonic()
            with _CPE_WEB_DATA_SESSION_LOCK:
                saved = dict(_CPE_WEB_DATA_SESSIONS.get(session_key) or {})
            cookies = (
                dict(saved.get("cookies") or {})
                if saved.get("expires_at", 0) > now
                else {}
            )
            cookies.update(session_cookies or {})
            body = urlencode(form).encode("ascii")
            status_code, payload, new_cookies, location = _cpe_web_json_request(
                proxy,
                "/goform/setWifi",
                cpe_port=cpe_port,
                method="POST",
                body=body,
                cookies=cookies,
                timeout=timeout,
            )
            cookies.update(new_cookies)
            with _CPE_WEB_DATA_SESSION_LOCK:
                _CPE_WEB_DATA_SESSIONS[session_key] = {
                    "cookies": cookies,
                    "expires_at": time.monotonic() + 600.0,
                }
            rejected = (
                status_code not in {200, 302, 303}
                or "login.html" in (location or "")
                or (
                    isinstance(payload, dict)
                    and payload.get("errCode") is not None
                    and str(payload.get("errCode")) not in {"0", ""}
                )
            )
            if rejected:
                return {
                    "ok": False,
                    "error": "The client router rejected the Wi‑Fi update.",
                    "cpe_host": proxy.get("cpe_host") or current.get("cpe_host") or "",
                }
    except (ConnectionError, OSError, TimeoutError, http.client.HTTPException) as exc:
        return {
            "ok": False,
            "error": str(exc) or "Could not apply Wi‑Fi settings on the client router.",
            "cpe_host": current.get("cpe_host") or "",
        }

    verified = fetch_customer_cpe_web_data(
        nas_host,
        nas_username,
        nas_password,
        pppoe_username=pppoe_username,
        cpe_password=cpe_password,
        session_cookies=session_cookies,
        cpe_port=cpe_port,
        timeout=timeout,
    )
    verified_wifi = dict(verified.get("wifi") or {}) if verified.get("ok") else wifi
    if apply_ssid and wifi_ssid and (verified_wifi.get("ssid") or "").strip() != wifi_ssid:
        return {
            "ok": False,
            "error": "Wi‑Fi name was sent but could not be confirmed on the client router.",
            "wifi": verified_wifi,
            "cpe_host": verified.get("cpe_host") or current.get("cpe_host") or "",
        }
    if apply_password and wifi_password:
        confirmed = verified_wifi.get("password") or ""
        if confirmed and confirmed != wifi_password:
            return {
                "ok": False,
                "error": "Wi‑Fi password was sent but could not be confirmed on the client router.",
                "wifi": verified_wifi,
                "cpe_host": verified.get("cpe_host") or current.get("cpe_host") or "",
            }

    return {
        "ok": True,
        "updated": True,
        "message": "Wi‑Fi settings updated on the client router.",
        "wifi": verified_wifi,
        "cpe_host": verified.get("cpe_host") or current.get("cpe_host") or "",
    }


CPE_WEB_PORTS = (80, 8080, 443, 8443)


def probe_customer_cpe_web(
    nas_host: str,
    nas_username: str,
    nas_password: str,
    *,
    pppoe_username: str,
    ports: tuple[int, ...] = CPE_WEB_PORTS,
    nas_port: int = 8728,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """
    Preflight for client-router login: which web port answers from the ISP side.

    Consumer CPEs (Tenda, etc.) disable WAN/remote management by default, so the
    ISP MikroTik can ping the client yet every admin port times out. Rather than
    let the browser proxy return a bare 502, this resolves the live PPPoE IP and,
    for each candidate port, installs the same NAS→CPE forward the proxy uses and
    does a fast TCP connect. The first port that accepts is returned.

    Returns keys: ok, session_active, cpe_host, port (int|None), reachable,
    ping_ok, error, hint.
    """
    result: dict[str, Any] = {
        "ok": False,
        "session_active": False,
        "cpe_host": "",
        "port": None,
        "reachable": False,
        "ping_ok": False,
        "error": "",
        "hint": "",
    }

    session = resolve_customer_cpe_session(
        nas_host,
        nas_username,
        nas_password,
        pppoe_username=pppoe_username,
        port=nas_port,
        timeout=min(timeout, 5.0),
    )
    if not session.get("ok"):
        result["error"] = session.get("error") or "Could not read the client's PPPoE session."
        return result
    if not session.get("session_active") or not session.get("address"):
        result["hint"] = session.get("hint") or "The client router is offline."
        return result

    cpe_host = str(session["address"]).strip()
    result["session_active"] = True
    result["cpe_host"] = cpe_host

    connect_timeout = max(2.0, min(timeout, 4.0))
    try:
        with _api_session(
            nas_host,
            nas_username,
            nas_password,
            port=nas_port,
            timeout=timeout,
        ) as nas_sock:
            try:
                source_address = str(nas_sock.getsockname()[0]).strip()
            except (AttributeError, OSError, IndexError):
                source_address = ""
            _ensure_hotspot_bypass(nas_sock, source_address)

            ping = _nas_ping_host(nas_sock, cpe_host, count=2)
            result["ping_ok"] = bool(ping.get("reachable"))

            dial = dial_host(nas_host)
            for port in ports:
                scope = f"probe|{pppoe_username}|{port}|{time.time_ns()}"
                proxy_port = _cpe_proxy_port(cpe_host, scope)
                install_error = _install_cpe_proxy(
                    nas_sock,
                    proxy_port,
                    cpe_host,
                    port,
                    allowed_source=source_address,
                )
                if install_error:
                    result["error"] = install_error
                    continue
                try:
                    with socket.create_connection((dial, proxy_port), timeout=connect_timeout):
                        result["ok"] = True
                        result["reachable"] = True
                        result["port"] = port
                        return result
                except (TimeoutError, OSError):
                    continue
                finally:
                    _uninstall_cpe_proxy(nas_sock, proxy_port)
    except ConnectionError as exc:
        result["error"] = str(exc) or "Could not sign in to the ISP MikroTik."
        return result
    except (TimeoutError, OSError) as exc:
        result["error"] = str(exc) or "Timed out probing the client router."
        return result

    if result["ping_ok"]:
        result["hint"] = (
            "The client is online and the ISP MikroTik can ping the router, but "
            "the router refuses management from the ISP side on ports "
            f"{', '.join(str(p) for p in ports)}. On the client's router "
            "(e.g. Tenda), enable Remote / WAN Web Management — ideally limited to "
            f"the ISP gateway {PPPOE_LOCAL_ADDRESS} — then try again."
        )
    else:
        result["hint"] = (
            "The ISP MikroTik cannot reach the client router even by ping. "
            "Confirm the PPPoE session is up and the router is powered on."
        )
    return result


def _nas_ping_host(
    sock: socket.socket,
    address: str,
    *,
    count: int = 2,
) -> dict[str, Any]:
    """Ping a host from the NAS (RouterOS /ping)."""
    address = (address or "").strip()
    if not address:
        return {"ok": False, "reachable": False, "error": "No address to ping."}
    previous = sock.gettimeout()
    ping_count = max(1, int(count))
    # Keep ping short so status polls cannot starve the web server.
    sock.settimeout(max(float(previous or 3.0), min(6.0, 1.5 + ping_count * 1.5)))
    try:
        replies, terminal = _command(
            sock,
            [
                "/ping",
                f"=address={address}",
                f"=count={ping_count}",
            ],
        )
        if terminal.get("_reply") in {"!trap", "!fatal"}:
            return {
                "ok": False,
                "reachable": False,
                "error": _trap_message(terminal, "Ping failed on the ISP MikroTik."),
            }
        received = 0
        for row in replies:
            # Final summary row often has received= / packet-loss=
            if row.get("received") not in (None, ""):
                received = _parse_int(row.get("received"))
            elif (row.get("status") or "").strip().lower() in {"", "echo reply", "ttl exceeded"}:
                # Individual reply rows
                if "time" in row or "ttl" in row:
                    received += 1
        if received <= 0 and replies:
            # Some builds only return one summary with "received"
            for row in replies:
                received = max(received, _parse_int(row.get("received")))
        return {
            "ok": True,
            "reachable": received > 0,
            "received": received,
            "error": "" if received > 0 else f"NAS cannot ping CPE at {address}.",
        }
    except (TimeoutError, OSError) as exc:
        return {"ok": False, "reachable": False, "error": str(exc) or "Ping timed out."}
    finally:
        sock.settimeout(previous)


def _nas_ssh_exec(
    sock: socket.socket,
    *,
    address: str,
    username: str,
    password: str,
    command: str,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """Run a command on the CPE via NAS /system/ssh-exec (no extra Python deps)."""
    address = (address or "").strip()
    username = (username or "").strip()
    command = (command or "").strip()
    if not address or not username or not command:
        return {"ok": False, "error": "SSH exec needs address, username, and command."}
    previous = sock.gettimeout()
    sock.settimeout(max(3.0, min(float(timeout or 12.0), 12.0)))
    try:
        words = [
            "/system/ssh-exec",
            f"=address={address}",
            f"=user={username}",
            f"=command={command}",
        ]
        # Empty password is valid for factory-default admin.
        words.append(f"=password={password or ''}")
        replies, terminal = _command(sock, words)
        if terminal.get("_reply") in {"!trap", "!fatal"}:
            return {
                "ok": False,
                "error": _trap_message(
                    terminal,
                    "NAS could not SSH into the CPE (enable SSH or fix CPE login).",
                ),
                "output": "",
            }
        output_parts: list[str] = []
        for row in replies:
            for key in ("output", "ret", "message"):
                val = (row.get(key) or "").strip()
                if val:
                    output_parts.append(val)
        for key in ("output", "ret", "message"):
            val = (terminal.get(key) or "").strip()
            if val:
                output_parts.append(val)
        return {"ok": True, "error": "", "output": "\n".join(output_parts).strip()}
    except (TimeoutError, OSError) as exc:
        return {"ok": False, "error": str(exc) or "SSH exec timed out.", "output": ""}
    finally:
        sock.settimeout(previous)


def cpe_firewall_unlock_script() -> str:
    """
    One-time Winbox Terminal script for a CPE that drops WAN management.

    Two common causes of ISP-side timeouts (while LAN Winbox still works):
    1) defconf input drop on WAN / PPPoE
    2) /ip service address= limited to the LAN subnet (sources outside are
       dropped with no reply — looks like a firewall timeout)

    Do NOT use `/ip service set [find] address=...` — on ROS 7 that often
    fails on telnet/www and applies to nothing.

    Guards against pasting into the ISP NAS (both often identity "MikroTik").
    """
    tag = CPE_API_AUTO_TAG
    return (
        ":local ppp [/ip address find where interface~\"pppoe\" and address~\"10.20.\"]\n"
        ":if ([:len $ppp] = 0) do={\n"
        "  :put \"WRONG DEVICE - this is not the client CPE\"\n"
        "  :put \"In Winbox Neighbors open the router whose IP is 10.20.0.x (pppoe-out)\"\n"
        "  :put \"Do NOT use the ISP NAS at 10.10.0.1\"\n"
        "  :error \"not-cpe\"\n"
        "}\n"
        ":put (\"CPE OK - \" . [/ip address get ($ppp->0) address])\n"
        "/ip service set [find name=api] disabled=no port=8728 address=0.0.0.0/0\n"
        "/ip service set [find name=ssh] disabled=no port=22 address=0.0.0.0/0\n"
        "/ip service set [find name=winbox] disabled=no address=0.0.0.0/0\n"
        f'/ip firewall filter remove [find comment~"{tag}"]\n'
        "/ip firewall filter disable [find where chain=input]\n"
        "/ip firewall raw disable [find]\n"
        "/ip firewall filter add chain=input action=accept protocol=tcp "
        f'dst-port=8728,22,8291 comment="{tag}"\n'
        ':put "ispcentric unlock ok - retry Connect in ISPCENTRIC"'
    )


def _cpe_auto_enable_commands() -> str:
    """RouterOS script to enable API and allow it from the ISP PPPoE network."""
    tag = CPE_API_AUTO_TAG
    return (
        ":do { /ip service set [find where name=api] disabled=no port=8728 "
        "address=0.0.0.0/0 } on-error={}; "
        ":do { /ip service set [find where name=ssh] disabled=no port=22 "
        "address=0.0.0.0/0 } on-error={}; "
        ":do { /ip service set [find where name=winbox] disabled=no "
        "address=0.0.0.0/0 } on-error={}; "
        f':do {{ /ip firewall filter remove [find where comment~"{tag}"] }} on-error={{}}; '
        ":do { /ip firewall filter disable [find where chain=input] } on-error={}; "
        ":do { /ip firewall raw disable [find] } on-error={}; "
        ":do { /ip firewall filter add chain=input action=accept protocol=tcp "
        f'dst-port=8728,22,8291 comment="{tag}" }} on-error={{}}; '
        ":put ispcentric-api-ready"
    )


def _ensure_cpe_api_ready_on_session(sock: socket.socket) -> list[str]:
    """Once API is open, make sure api service stays enabled and firewall allows it."""
    notes: list[str] = []
    try:
        for row in _print(sock, "/ip/service", props=".id,name,port,disabled,address"):
            if (row.get("name") or "").strip().lower() != "api":
                continue
            item_id = (row.get(".id") or "").strip()
            if not item_id:
                continue
            props: dict[str, str] = {
                "disabled": "no",
                "port": "8728",
                "address": "0.0.0.0/0",
            }
            terminal = _set(sock, "/ip/service", item_id, **props)
            if terminal.get("_reply") not in {"!trap", "!fatal"}:
                notes.append("ensured CPE API service enabled")
            break
    except Exception:
        pass

    try:
        disabled_drops = 0
        for row in _print(
            sock,
            "/ip/firewall/filter",
            props=".id,chain,action,disabled",
        ):
            if (row.get("chain") or "") != "input":
                continue
            if (row.get("action") or "") != "drop":
                continue
            if str(row.get("disabled") or "").lower() in {"true", "yes"}:
                continue
            item_id = (row.get(".id") or "").strip()
            if not item_id:
                continue
            terminal = _set(sock, "/ip/firewall/filter", item_id, disabled="yes")
            if terminal.get("_reply") not in {"!trap", "!fatal"}:
                disabled_drops += 1
        if disabled_drops:
            notes.append(f"disabled {disabled_drops} CPE input drop rule(s)")
    except Exception:
        pass

    try:
        existing = [
            row
            for row in _print(sock, "/ip/firewall/filter", props=".id,comment")
            if CPE_API_AUTO_TAG in (row.get("comment") or "")
        ]
        if not existing:
            terminal = _add(
                sock,
                "/ip/firewall/filter",
                chain="input",
                protocol="tcp",
                **{"dst-port": "8728,22,8291"},
                action="accept",
                comment=CPE_API_AUTO_TAG,
            )
            if terminal.get("_reply") not in {"!trap", "!fatal"}:
                notes.append("opened CPE firewall for API")
    except Exception:
        pass
    return notes


def prepare_customer_cpe_access(
    nas_host: str,
    nas_username: str,
    nas_password: str,
    *,
    pppoe_username: str,
    cpe_username: str = "",
    cpe_password: str = "",
    pppoe_password: str = "",
    nas_port: int = 8728,
    cpe_port: int = 8728,
    timeout: float = 8.0,
    auto_enable: bool = True,
) -> dict[str, Any]:
    """
    Automatically prepare remote management of a subscriber CPE:
    - find live PPPoE IP on the NAS
    - confirm NAS can ping that IP
    - install temporary NAS→CPE API proxy
    - try CPE logins; if API is off, enable it via NAS SSH-exec
    - ensure CPE API + firewall allow management

    When auto_enable is False (status polls), skip SSH enable so the
    account page stays responsive while the client is surfing.
    """
    steps: list[str] = []
    session = resolve_customer_cpe_session(
        nas_host,
        nas_username,
        nas_password,
        pppoe_username=pppoe_username,
        port=nas_port,
        timeout=min(timeout, 5.0),
    )
    result: dict[str, Any] = {
        "ok": False,
        "prepared": False,
        "session_active": bool(session.get("session_active")),
        "cpe_host": session.get("address") or "",
        "cpe_username": (cpe_username or "").strip() or "admin",
        "cpe_password": cpe_password or "",
        "auth_ok": False,
        "reachable": False,
        "api_enabled": False,
        "proxy_used": False,
        "steps": steps,
        "error": session.get("error") or "",
        "hint": session.get("hint") or "",
    }
    if not session.get("ok"):
        return result
    if not session.get("session_active"):
        result["ok"] = True
        result["hint"] = session.get("hint") or (
            "Client CPE is offline — wait for PPPoE, then retry."
        )
        steps.append("waiting for active PPPoE session")
        return result

    cpe_host = (session.get("address") or "").strip()
    result["cpe_host"] = cpe_host
    steps.append(f"found PPPoE IP {cpe_host}")
    candidates = _cpe_credential_candidates(
        cpe_username=cpe_username,
        cpe_password=cpe_password,
        pppoe_password=pppoe_password,
    )
    proxy_port = _cpe_proxy_port(cpe_host, pppoe_username)

    try:
        with _api_session(
            nas_host,
            nas_username,
            nas_password,
            port=nas_port,
            timeout=timeout,
        ) as nas_sock:
            ping = _nas_ping_host(nas_sock, cpe_host, count=1)
            result["reachable"] = bool(ping.get("reachable"))
            if ping.get("reachable"):
                steps.append("NAS can ping CPE")
            else:
                steps.append(ping.get("error") or "NAS cannot ping CPE yet")
                # Still install proxy — some boards block ICMP but accept TCP.

            proxy_error = _install_cpe_proxy(nas_sock, proxy_port, cpe_host, cpe_port)
            if proxy_error:
                result["error"] = proxy_error
                return result
            result["proxy_used"] = True
            steps.append(f"installed NAS proxy port {proxy_port} → {cpe_host}:{cpe_port}")

            # Try API first (direct then via proxy is handled by callers; here use proxy).
            last_error = ""
            api_timeout = min(timeout, 3.0 if not auto_enable else 6.0)
            for user, password in candidates:
                try:
                    with _api_session(
                        nas_host,
                        user,
                        password,
                        port=proxy_port,
                        timeout=api_timeout,
                    ) as cpe_sock:
                        notes = _ensure_cpe_api_ready_on_session(cpe_sock)
                        steps.extend(notes)
                    result.update(
                        {
                            "ok": True,
                            "prepared": True,
                            "auth_ok": True,
                            "api_enabled": True,
                            "cpe_username": user,
                            "cpe_password": password,
                            "error": "",
                            "hint": "",
                        }
                    )
                    steps.append(f"CPE API ready as {user}")
                    return result
                except ConnectionError as exc:
                    last_error = str(exc) or "CPE login failed."
                    continue
                except (TimeoutError, OSError) as exc:
                    last_error = str(exc) or "CPE API timed out."
                    if "timed out" in last_error.lower() or not last_error.strip():
                        last_error = "Timed out"
                    if not auto_enable:
                        break
                    continue

            if not auto_enable:
                result["ok"] = True
                friendly = last_error or "CPE API not ready yet."
                timed_out = "timed out" in friendly.lower() or friendly.lower() == "timed out"
                if timed_out and result.get("reachable"):
                    result["firewall_blocked"] = True
                    result["error"] = (
                        "CPE firewall is blocking management from the ISP side "
                        "(not a wrong password). Winbox from the client Wi‑Fi still works."
                    )
                    result["hint"] = (
                        "Run the unlock script below once from Winbox on the client Wi‑Fi "
                        "(must print ispcentric unlock ok). Then click Connect & Activate Wi‑Fi."
                    )
                else:
                    if timed_out:
                        friendly = "CPE is online — click Connect & Activate Wi‑Fi to finish setup."
                    result["error"] = friendly
                    result["hint"] = (
                        "PPPoE is up. Use Connect & Activate Wi‑Fi (or save CPE login) "
                        "to manage the radio — surfing is separate from this."
                    )
                steps.append("skipped SSH auto-enable (fast status check)")
                return result

            steps.append("API not reachable yet — enabling via NAS SSH")
            ssh_ok = False
            ssh_last = ""
            enable_cmd = _cpe_auto_enable_commands()
            for user, password in candidates:
                ssh = _nas_ssh_exec(
                    nas_sock,
                    address=cpe_host,
                    username=user,
                    password=password,
                    command=enable_cmd,
                    timeout=min(timeout, 10.0),
                )
                if ssh.get("ok"):
                    ssh_ok = True
                    result["cpe_username"] = user
                    result["cpe_password"] = password
                    steps.append(f"enabled CPE API via SSH as {user}")
                    break
                ssh_last = ssh.get("error") or ssh_last

            if not ssh_ok:
                timed_out = "timed out" in (last_error or "").lower() or "timed out" in (
                    ssh_last or ""
                ).lower()
                if timed_out and result.get("reachable"):
                    result["error"] = (
                        "CPE firewall is blocking management from the ISP side "
                        "(not a wrong password). Winbox from the client Wi‑Fi still works."
                    )
                    result["hint"] = (
                        "Join the client Wi‑Fi, open Winbox → New Terminal, paste the unlock "
                        "script from this page, and confirm it prints: ispcentric unlock ok. "
                        "Then click Connect & Activate Wi‑Fi again."
                    )
                    result["firewall_blocked"] = True
                elif "refused" in (last_error or "").lower() or "refused" in (
                    ssh_last or ""
                ).lower():
                    result["error"] = (
                        "CPE is reachable but API is not accepting ISP connections "
                        "(service address still limited to LAN, or API off)."
                    )
                    result["hint"] = (
                        "In Winbox New Terminal run:\n"
                        "/ip service set [find name=api] disabled=no port=8728 address=0.0.0.0/0\n"
                        "/ip service set [find name=ssh] disabled=no port=22 address=0.0.0.0/0\n"
                        "Then retry Connect."
                    )
                    result["firewall_blocked"] = True
                else:
                    result["error"] = (
                        last_error
                        or ssh_last
                        or "Could not enable CPE API automatically."
                    )
                    result["hint"] = (
                        "CPE is online but API/SSH login failed. "
                        "Save the correct CPE Winbox username/password once — "
                        "the system will enable API and open the firewall automatically after that."
                    )
                return result

            # Brief settle, then re-try API through the same proxy.
            time.sleep(1.0)
            user = result["cpe_username"]
            password = result["cpe_password"]
            try:
                with _api_session(
                    nas_host,
                    user,
                    password,
                    port=proxy_port,
                    timeout=min(timeout, 8.0),
                ) as cpe_sock:
                    notes = _ensure_cpe_api_ready_on_session(cpe_sock)
                    steps.extend(notes)
                result.update(
                    {
                        "ok": True,
                        "prepared": True,
                        "auth_ok": True,
                        "api_enabled": True,
                        "error": "",
                        "hint": "",
                    }
                )
                steps.append("CPE API verified after auto-enable")
                return result
            except Exception as exc:
                result["error"] = str(exc) or last_error or "API still unreachable after enable."
                result["hint"] = (
                    "API enable was sent, but the CPE still blocks management. "
                    "Check the CPE input firewall or reboot the CPE, then refresh."
                )
                return result
    except ConnectionError as exc:
        result["error"] = str(exc) or "Could not sign in to the ISP MikroTik."
        return result
    except (TimeoutError, OSError) as exc:
        result["error"] = str(exc) or "Timed out preparing CPE access."
        return result
    finally:
        try:
            with _api_session(
                nas_host,
                nas_username,
                nas_password,
                port=nas_port,
                timeout=min(timeout, 5.0),
            ) as nas_sock:
                _uninstall_cpe_proxy(nas_sock, proxy_port)
        except Exception:
            pass

    return result


@contextmanager
def _cpe_api_session(
    nas_host: str,
    nas_username: str,
    nas_password: str,
    cpe_host: str,
    cpe_username: str,
    cpe_password: str,
    *,
    nas_port: int = 8728,
    cpe_port: int = 8728,
    timeout: float = 8.0,
    proxy_scope: str = "",
    pppoe_password: str = "",
    auto_prepare: bool = True,
) -> Iterator[socket.socket]:
    """
    Open RouterOS API on a subscriber CPE.

    Direct connect is tried first. When the app cannot route to the PPPoE
    client IP, a temporary dst-nat on the ISP MikroTik forwards NAS:proxy -> CPE:8728.
    When auto_prepare is True, API is enabled on the CPE via NAS SSH if needed.
    """
    nas_host = (nas_host or "").strip()
    cpe_host = (cpe_host or "").strip()
    cpe_username = (cpe_username or "").strip()
    cpe_password = cpe_password or ""
    if not nas_host or not cpe_host or not cpe_username:
        raise ConnectionError("NAS host, CPE host, and CPE username are required.")

    try:
        with _api_session(
            cpe_host,
            cpe_username,
            cpe_password,
            port=cpe_port,
            timeout=min(timeout, 2.5),
        ) as sock:
            _ensure_cpe_api_ready_on_session(sock)
            yield sock
            return
    except (TimeoutError, OSError, ConnectionError):
        pass

    if auto_prepare:
        prep = prepare_customer_cpe_access(
            nas_host,
            nas_username,
            nas_password,
            pppoe_username=proxy_scope or cpe_username,
            cpe_username=cpe_username,
            cpe_password=cpe_password,
            pppoe_password=pppoe_password,
            nas_port=nas_port,
            cpe_port=cpe_port,
            timeout=timeout,
        )
        if prep.get("auth_ok") and prep.get("cpe_username"):
            cpe_username = prep.get("cpe_username") or cpe_username
            if prep.get("cpe_password") is not None:
                cpe_password = prep.get("cpe_password") or ""
        elif prep.get("error"):
            # Keep going — proxy install below may still succeed with saved login.
            pass

    proxy_port = _cpe_proxy_port(cpe_host, proxy_scope or cpe_username)
    with _api_session(
        nas_host,
        nas_username,
        nas_password,
        port=nas_port,
        timeout=timeout,
    ) as nas_sock:
        proxy_error = _install_cpe_proxy(nas_sock, proxy_port, cpe_host, cpe_port)
        if proxy_error:
            raise ConnectionError(proxy_error)

    try:
        with _api_session(
            nas_host,
            cpe_username,
            cpe_password,
            port=proxy_port,
            timeout=timeout,
        ) as sock:
            _ensure_cpe_api_ready_on_session(sock)
            yield sock
    except TimeoutError as exc:
        raise ConnectionError(
            "Could not reach the client CPE through the ISP MikroTik after auto-setup. "
            "Save the correct CPE login once if this is a new device."
        ) from exc
    except ConnectionError:
        raise
    finally:
        try:
            with _api_session(
                nas_host,
                nas_username,
                nas_password,
                port=nas_port,
                timeout=min(timeout, 5.0),
            ) as nas_sock:
                _uninstall_cpe_proxy(nas_sock, proxy_port)
        except Exception:
            pass


@contextmanager
def _device_api_session(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 8.0,
    nas_host: str = "",
    nas_username: str = "",
    nas_password: str = "",
    proxy_scope: str = "",
) -> Iterator[socket.socket]:
    host = (host or "").strip()
    if (nas_host or "").strip():
        with _cpe_api_session(
            nas_host,
            nas_username,
            nas_password,
            host,
            username,
            password,
            nas_port=port,
            cpe_port=port,
            timeout=timeout,
            proxy_scope=proxy_scope or username,
            auto_prepare=True,
        ) as sock:
            yield sock
    else:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            yield sock


def _fetch_identity(sock: socket.socket, host: str) -> dict[str, Any]:
    identity = ""
    version = ""
    board = ""
    serial_number = ""
    software_id = ""
    try:
        for attrs in _print(sock, "/system/identity", props="name"):
            identity = attrs.get("name") or identity
        for attrs in _print(sock, "/system/resource", props="version,board-name"):
            version = attrs.get("version") or version
            board = attrs.get("board-name") or board
        for attrs in _print(
            sock, "/system/routerboard", props="serial-number,model,board-name"
        ):
            serial_number = (attrs.get("serial-number") or "").strip() or serial_number
            board = (attrs.get("board-name") or attrs.get("model") or board or "").strip() or board
        for attrs in _print(sock, "/system/license", props="software-id"):
            software_id = (attrs.get("software-id") or "").strip() or software_id
    except Exception:
        pass

    return {
        "ok": True,
        "host": host,
        "identity": identity,
        "version": version,
        "board": board,
        "serial_number": serial_number,
        "software_id": software_id,
        "name": identity or f"MikroTik {host}",
    }


def _password_from_row(row: dict[str, str]) -> str:
    for key in (
        "passphrase",
        "wpa2-pre-shared-key",
        "wpa-pre-shared-key",
        "wpa3-pre-shared-key",
    ):
        value = row.get(key)
        if value is None:
            continue
        value = str(value).strip()
        if value:
            return value
    return ""


def _is_station(row: dict[str, str]) -> bool:
    return "station" in (row.get("mode") or "").lower()


def _package_by_mode(mode: str) -> dict[str, Any] | None:
    mode = (mode or "").strip().lower()
    for package in WIFI_PACKAGES:
        if package["mode"] == mode:
            return package
    return None


def _detect_wifi_package(sock: socket.socket) -> dict[str, Any] | None:
    """Return the first wireless package that exposes interfaces."""
    previous = sock.gettimeout()
    sock.settimeout(5.0)
    try:
        for package in WIFI_PACKAGES:
            try:
                # Full print — .proplist is unreliable on older RouterOS builds.
                rows = _print(sock, package["iface_path"])
            except (TimeoutError, OSError):
                return None
            if not any(row.get(".id") for row in rows):
                continue
            # Stop on the first package that answers. Probing later packages
            # (especially wifiwave2 on older boards) can desync the API session.
            return package
        return None
    finally:
        sock.settimeout(previous)


def _pick_ssid(rows: list[dict[str, str]]) -> str:
    """Prefer AP SSID; fall back to any interface SSID (station/CAP)."""
    for row in rows:
        if _is_station(row):
            continue
        for key in ("ssid", "configuration.ssid"):
            value = (row.get(key) or "").strip()
            if value:
                return value
    for row in rows:
        for key in ("ssid", "configuration.ssid"):
            value = (row.get(key) or "").strip()
            if value:
                return value
    return ""


def _pick_password(profiles: list[dict[str, str]], profile_names: set[str]) -> str:
    preferred: list[dict[str, str]] = []
    others: list[dict[str, str]] = []
    for row in profiles:
        name = (row.get("name") or "").strip()
        lname = name.lower()
        if (profile_names and name in profile_names) or lname == "default":
            preferred.append(row)
        else:
            others.append(row)
    for row in preferred + others:
        found = _password_from_row(row)
        if found:
            return found
    return ""


def _read_wifi_settings(sock: socket.socket, package: dict[str, Any] | None = None) -> dict[str, str]:
    """Read current SSID/password for a known (or auto-detected) wireless package."""
    previous = sock.gettimeout()
    sock.settimeout(8.0)
    try:
        packages = [package] if package else list(WIFI_PACKAGES)
        for pkg in packages:
            try:
                rows = _print(sock, pkg["iface_path"])
            except (TimeoutError, OSError):
                break
            if not any(row.get(".id") for row in rows):
                continue

            ap_rows = [row for row in rows if row.get(".id") and not _is_station(row)]
            if not ap_rows:
                # Station/CAP radios still expose the current SSID.
                ap_rows = [row for row in rows if row.get(".id") and (row.get("ssid") or "").strip()]
            if not ap_rows and rows:
                ap_rows = [row for row in rows if row.get(".id")]
            if not ap_rows:
                continue

            ssid = _pick_ssid(ap_rows) or _pick_ssid(rows)
            profile_names = {
                (row.get(pkg["profile_key"]) or "").strip()
                for row in ap_rows
                if (row.get(pkg["profile_key"]) or "").strip()
            }
            password = ""
            try:
                profiles = _print(sock, pkg["sec_path"])
            except (TimeoutError, OSError):
                profiles = []
            if profiles:
                password = _pick_password(profiles, profile_names)

            return {
                "wifi_ssid": ssid,
                "wifi_password": password,
                "wifi_mode": pkg["mode"],
                "wifi_enabled": any(
                    (row.get("disabled") or "").lower() not in {"true", "yes"}
                    for row in rows
                    if row.get(".id")
                ),
                "interface_count": len([row for row in rows if row.get(".id")]),
            }
        return {
            "wifi_ssid": "",
            "wifi_password": "",
            "wifi_mode": "",
            "wifi_enabled": False,
            "interface_count": 0,
        }
    finally:
        sock.settimeout(previous)


def read_mikrotik_wifi(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 8.0,
    nas_host: str = "",
    nas_username: str = "",
    nas_password: str = "",
) -> dict[str, Any]:
    """Fresh-login helper to load current Wi‑Fi name/password and radio state."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    empty = {
        "wifi_ssid": "",
        "wifi_password": "",
        "wifi_mode": "",
        "wifi_enabled": False,
        "interface_count": 0,
    }
    if not host or not username:
        return empty
    try:
        with _device_api_session(
            host,
            username,
            password,
            port=port,
            timeout=timeout,
            nas_host=nas_host,
            nas_username=nas_username,
            nas_password=nas_password,
            proxy_scope=username,
        ) as sock:
            package = _detect_wifi_package(sock)
            return _read_wifi_settings(sock, package)
    except Exception:
        return empty


def _cap_path_for_package(package: dict[str, Any] | None) -> str:
    mode = (package or {}).get("mode") or "wireless"
    if mode == "wifi":
        return "/interface/wifi/cap"
    if mode == "wifiwave2":
        return "/interface/wifiwave2/cap"
    return "/interface/wireless/cap"


def _disable_cap_client(sock: socket.socket, package: dict[str, Any] | None) -> None:
    """Best-effort: release CAPsMAN control so local Wi‑Fi can be used as an AP."""
    path = _cap_path_for_package(package)
    try:
        rows = _print(sock, path)
    except (TimeoutError, OSError):
        return
    for row in rows:
        item_id = (row.get(".id") or "").strip()
        words = [f"{path}/set", "=enabled=no"]
        if item_id:
            words.insert(1, f"=.id={item_id}")
        try:
            _command(sock, words)
        except (TimeoutError, OSError):
            return


def set_mikrotik_wifi_enabled(
    host: str,
    username: str,
    password: str,
    *,
    enabled: bool,
    wifi_ssid: str = "",
    wifi_password: str = "",
    port: int = 8728,
    timeout: float = 12.0,
    nas_host: str = "",
    nas_username: str = "",
    nas_password: str = "",
) -> dict[str, Any]:
    """Turn local MikroTik Wi‑Fi radios on or off."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    wifi_ssid = (wifi_ssid or "").strip()
    wifi_password = wifi_password or ""

    if not host or not username:
        return {"ok": False, "error": "Saved router credentials are missing."}

    try:
        with _device_api_session(
            host,
            username,
            password,
            port=port,
            timeout=timeout,
            nas_host=nas_host,
            nas_username=nas_username,
            nas_password=nas_password,
            proxy_scope=username,
        ) as sock:
            package = _detect_wifi_package(sock)
            if not package:
                return {
                    "ok": False,
                    "error": "No Wi‑Fi radio was found on this MikroTik.",
                }

            rows = _print(sock, package["iface_path"])
            radio_rows = [row for row in rows if row.get(".id")]
            if not radio_rows:
                return {
                    "ok": False,
                    "error": "No Wi‑Fi radio was found on this MikroTik.",
                }

            if enabled:
                # CAPsMAN-managed boards keep the local radio disabled until CAP is released.
                _disable_cap_client(sock, package)

            updated = 0
            last_error = ""
            for row in radio_rows:
                item_id = row[".id"]
                props: dict[str, str] = {"disabled": "no" if enabled else "yes"}
                if enabled:
                    mode = (row.get("mode") or "").lower()
                    if "station" in mode:
                        props["mode"] = "ap-bridge"
                    if wifi_ssid and (row.get("ssid") or "").strip() != wifi_ssid:
                        props["ssid"] = wifi_ssid
                terminal = _set(sock, package["iface_path"], item_id, **props)
                if terminal.get("_reply") == "!trap":
                    last_error = terminal.get("message") or last_error
                    continue
                updated += 1

                if enabled and wifi_password and package.get("classic"):
                    profile_name = (row.get(package["profile_key"]) or "default").strip()
                    try:
                        profiles = _print(sock, package["sec_path"])
                    except (TimeoutError, OSError):
                        profiles = []
                    for profile in profiles:
                        name = (profile.get("name") or "").strip()
                        if name != profile_name and not (
                            profile_name == "default" and name.lower() == "default"
                        ):
                            continue
                        pid = profile.get(".id")
                        if not pid:
                            continue
                        pw_terminal = _set_password(sock, package, pid, wifi_password)
                        if pw_terminal.get("_reply") == "!trap":
                            last_error = pw_terminal.get("message") or last_error
                        break

            if updated == 0:
                return {
                    "ok": False,
                    "error": last_error
                    or (
                        "Could not activate Wi‑Fi on the MikroTik."
                        if enabled
                        else "Could not deactivate Wi‑Fi on the MikroTik."
                    ),
                }

            # Re-read final state.
            final = _read_wifi_settings(sock, package)
            return {
                "ok": True,
                "wifi_enabled": bool(final.get("wifi_enabled")) if enabled else False,
                "wifi_ssid": final.get("wifi_ssid") or wifi_ssid,
                "wifi_password": final.get("wifi_password") or wifi_password,
                "message": (
                    "Wi‑Fi activated on the MikroTik."
                    if enabled
                    else "Wi‑Fi deactivated on the MikroTik."
                ),
            }
    except TimeoutError:
        return {
            "ok": False,
            "error": "Timed out while updating Wi‑Fi on the MikroTik.",
        }
    except ConnectionError as exc:
        return {"ok": False, "error": str(exc)}
    except OSError as exc:
        return {
            "ok": False,
            "error": f"Could not reach {host}:8728 to update Wi‑Fi.",
            "detail": str(exc),
        }
    except Exception as exc:
        return {"ok": False, "error": f"Wi‑Fi update failed: {exc}"}


def _set_password(sock: socket.socket, package: dict[str, Any], item_id: str, wifi_password: str) -> dict[str, str]:
    if package["classic"]:
        terminal = _set(sock, package["sec_path"], item_id, **{"wpa2-pre-shared-key": wifi_password})
        if terminal.get("_reply") != "!trap":
            return terminal
        return _set(sock, package["sec_path"], item_id, **{"wpa-pre-shared-key": wifi_password})
    return _set(sock, package["sec_path"], item_id, passphrase=wifi_password)


def _apply_on_package(
    sock: socket.socket,
    package: dict[str, Any],
    *,
    ssid: str,
    wifi_password: str,
    apply_ssid: bool,
    apply_password: bool,
) -> dict[str, Any]:
    """Apply only the requested Wi‑Fi changes on one package."""
    sock.settimeout(4.0)
    try:
        rows = _print(sock, package["iface_path"], props=package["iface_props"])
    except (TimeoutError, OSError) as exc:
        return {"ok": False, "updated": False, "error": f"Could not read {package['mode']} interfaces: {exc}"}

    ap_rows = [row for row in rows if row.get(".id") and not _is_station(row)]
    if not ap_rows:
        return {"ok": False, "updated": False, "error": "", "skip": True}

    used_profiles = {
        (row.get(package["profile_key"]) or "").strip()
        for row in ap_rows
        if (row.get(package["profile_key"]) or "").strip()
    }
    updated = False
    last_error = ""

    if apply_ssid and ssid:
        for row in ap_rows:
            if (row.get("ssid") or "").strip() == ssid:
                continue
            sock.settimeout(20.0)
            try:
                terminal = _set(sock, package["iface_path"], row[".id"], ssid=ssid)
            except (TimeoutError, OSError):
                # Wireless restart can drop the API reply; verify on a fresh call later.
                return {
                    "ok": False,
                    "updated": False,
                    "error": "timeout_verify_ssid",
                    "mode": package["mode"],
                }
            if terminal.get("_reply") == "!trap":
                last_error = terminal.get("message") or f"Failed updating {package['mode']} SSID."
            else:
                updated = True

    if apply_password and wifi_password:
        sock.settimeout(4.0)
        try:
            # Do not request secret properties here — that can hang on some RouterOS builds.
            profiles = _print(sock, package["sec_path"], props=".id,name")
        except (TimeoutError, OSError) as exc:
            return {"ok": False, "updated": False, "error": f"Could not read Wi‑Fi security profiles: {exc}"}

        targets = []
        for row in profiles:
            if not row.get(".id"):
                continue
            name = (row.get("name") or "").strip()
            if used_profiles:
                if name in used_profiles or name.lower() == "default":
                    targets.append(row)
            else:
                targets.append(row)
        if not targets and profiles:
            targets = profiles[:1]
        if not targets:
            return {
                "ok": False,
                "updated": False,
                "error": "No Wi‑Fi security profile found to update the password.",
            }

        for row in targets:
            sock.settimeout(20.0)
            try:
                terminal = _set_password(sock, package, row[".id"], wifi_password)
            except (TimeoutError, OSError):
                return {
                    "ok": False,
                    "updated": False,
                    "error": "timeout_verify_password",
                    "mode": package["mode"],
                }
            if terminal.get("_reply") == "!trap":
                last_error = terminal.get("message") or f"Failed updating {package['mode']} password."
            else:
                updated = True

    if last_error and not updated:
        return {"ok": False, "updated": False, "error": last_error}

    return {
        "ok": True,
        "updated": updated or not (apply_ssid or apply_password),
        "mode": package["mode"],
        "message": "Wi‑Fi settings applied on the router.",
    }


def _verify_wifi(
    host: str,
    username: str,
    password: str,
    *,
    wifi_ssid: str,
    wifi_password: str,
    check_ssid: bool,
    check_password: bool,
    wifi_mode: str = "",
    port: int = 8728,
) -> dict[str, Any]:
    """Re-login and confirm Wi‑Fi values after a possible API timeout."""
    try:
        with _api_session(host, username, password, port=port, timeout=8.0) as sock:
            package = _package_by_mode(wifi_mode) if wifi_mode else _detect_wifi_package(sock)
            current = _read_wifi_settings(sock, package)
    except Exception as exc:
        return {"ok": False, "error": f"Could not verify Wi‑Fi after update: {exc}"}

    if check_ssid and wifi_ssid and current.get("wifi_ssid") != wifi_ssid:
        return {
            "ok": False,
            "error": "Wi‑Fi name was not updated on the router. Check wireless package / API access.",
        }
    if check_password and wifi_password:
        current_pw = current.get("wifi_password") or ""
        if current_pw and current_pw != wifi_password:
            return {
                "ok": False,
                "error": "Wi‑Fi password was not updated on the router.",
            }
        # If the router hides the passphrase, accept the write after reconnect success.
    return {
        "ok": True,
        "updated": True,
        "mode": current.get("wifi_mode") or wifi_mode,
        "message": "Wi‑Fi settings applied on the router.",
        "wifi_ssid": current.get("wifi_ssid") or "",
        "wifi_password": current.get("wifi_password") or "",
    }


def check_mikrotik_reachable(
    host: str,
    *,
    port: int = 8728,
    timeout: float = 1.5,
) -> dict[str, Any]:
    """Fast reachability check for an onboarded MikroTik.

    Probe management ports in parallel, then pick the best channel by priority:
    RouterOS API (8728) → Winbox (8291) → WebFig HTTP → ICMP ping.
    Waiting for all probes avoids racing Winbox ahead of API and flipping
    Connected/Reachable on the same live router.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    host = (host or "").strip()
    if not host:
        return {"online": False, "error": "Missing host.", "via": ""}

    # Host may be stored as "ip:port" from older entries.
    check_host = host
    check_port = port
    if "://" in check_host:
        check_host = check_host.split("://", 1)[1]
    if "/" in check_host:
        check_host = check_host.split("/", 1)[0]
    if check_host.count(":") == 1:
        maybe_host, maybe_port = check_host.rsplit(":", 1)
        if maybe_port.isdigit():
            check_host, check_port = maybe_host, int(maybe_port)

    ports = []
    for candidate in (8728, check_port, 8291, 80, 8080):
        if candidate and candidate not in ports:
            ports.append(candidate)

    via_map = {
        8728: "api",
        8291: "winbox",
        80: "http",
        8080: "http",
    }
    via_rank = {"api": 0, "winbox": 1, "http": 2}

    def _probe(probe_port: int) -> tuple[int, bool, str]:
        try:
            with socket.create_connection((dial_host(check_host), probe_port), timeout=timeout):
                return probe_port, True, ""
        except TimeoutError:
            return probe_port, False, f"{probe_port}: timed out"
        except OSError as exc:
            return probe_port, False, f"{probe_port}: {exc}"

    open_ports: dict[int, str] = {}
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=min(4, len(ports))) as pool:
        futures = [pool.submit(_probe, p) for p in ports]
        for future in as_completed(futures):
            probe_port, ok, err = future.result()
            if ok:
                open_ports[probe_port] = via_map.get(probe_port, f"tcp/{probe_port}")
            elif err:
                errors.append(err)

    if open_ports:
        def _rank(probe_port: int) -> tuple[int, int, int]:
            via = open_ports[probe_port]
            return (via_rank.get(via, 9), 0 if probe_port == 8728 else 1, probe_port)

        best_port = min(open_ports, key=_rank)
        best_via = open_ports[best_port]
        # An open web port proves *something* answers, not that it is the
        # router. A stale saved IP (the factory 192.168.88.1 is the usual
        # culprit) is routed to whatever host owns that address, and reporting
        # it as reachable sends operators hunting a router that was never
        # there. API/Winbox are RouterOS-specific, so only HTTP needs proof.
        if best_via == "http":
            identified = _looks_like_routeros_http(
                dial_host(check_host), best_port, timeout=timeout
            )
            if identified is False:
                return {
                    "online": False,
                    "via": "",
                    "error": (
                        f"{check_host}:{best_port} answers HTTP but is not a MikroTik. "
                        "The saved IP now belongs to another device — update it, "
                        "or connect the router's management tunnel."
                    ),
                    "foreign_http": True,
                }
        return {
            "online": True,
            "via": best_via,
            "port": best_port,
        }

    # ICMP fallback — device may be up with management ports firewalled.
    if _icmp_ping(check_host, timeout=timeout):
        return {"online": True, "via": "ping", "port": 0}

    return {
        "online": False,
        "error": errors[0] if errors else "Unreachable.",
        "via": "",
    }


_ROUTEROS_HTTP_MARKERS = ("routeros", "webfig", "mikrotik")

# A Hotspot-enabled RouterOS answers port 80 with the captive-portal redirect
# instead of WebFig, so the WebFig markers never appear. These belong to the
# RouterOS Hotspot servlet and identify the router just as reliably.
_HOTSPOT_PORTAL_MARKERS = (
    "link-login-only",
    "link-login",
    "link-orig",
    "hotspot",
)


def _serves_hotspot_portal(host: str, port: int = 80, timeout: float = 1.5) -> bool:
    """True when this address answers with a RouterOS Hotspot login redirect."""
    body = _http_probe_body(host, port, timeout=timeout)
    if not body:
        return False
    return any(marker in body for marker in _HOTSPOT_PORTAL_MARKERS)


def _http_probe_body(host: str, port: int, timeout: float = 1.5) -> str:
    """Fetch the root page as lowercase text; empty string when unreachable."""
    request = (
        "GET / HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        "User-Agent: ispcentric-probe\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii", "ignore")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            chunks: list[bytes] = []
            received = 0
            while received < 4096:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                chunks.append(chunk)
                received += len(chunk)
    except (OSError, TimeoutError):
        return ""
    if not chunks:
        return ""
    return b"".join(chunks).decode("utf-8", "replace").lower()


def _looks_like_routeros_http(host: str, port: int, timeout: float = 1.5) -> bool | None:
    """
    Whether the HTTP responder on this address is RouterOS/WebFig.

    Returns None when the answer cannot be determined, so callers keep trusting
    the open port rather than declaring a live router offline on a bad guess.
    """
    body = _http_probe_body(host, port, timeout=timeout)
    if not body:
        return None
    if any(marker in body for marker in _ROUTEROS_HTTP_MARKERS):
        return True
    # A Hotspot router redirects to the payment portal rather than WebFig. That
    # redirect is served by RouterOS itself, so it confirms the router instead
    # of proving the saved IP now belongs to somebody else.
    if any(marker in body for marker in _HOTSPOT_PORTAL_MARKERS):
        return True
    # RouterOS answers the root path; a redirect to an unrelated portal or an
    # error page from another appliance is proof enough that this is not it.
    return False


def _icmp_ping(host: str, timeout: float = 1.5) -> bool:
    """Return True when the host answers ICMP echo (best-effort)."""
    import platform
    import subprocess

    host = (host or "").strip()
    if not host:
        return False
    wait_ms = max(200, int(timeout * 1000))
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(wait_ms), host]
    else:
        # -W is seconds on Linux; macOS uses -W milliseconds for some versions,
        # so keep a short count-based probe.
        sec = max(1, int(round(timeout)))
        cmd = ["ping", "-c", "1", "-W", str(sec), host]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 1.5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if completed.returncode != 0:
        return False
    out = f"{completed.stdout}\n{completed.stderr}".lower()
    # Windows reports "Destination host unreachable" with returncode 0 sometimes.
    if "unreachable" in out or "timed out" in out or "100% loss" in out:
        return False
    return "ttl=" in out or "time=" in out or "bytes from" in out


def _human_uptime(raw: str) -> str:
    """Convert RouterOS uptime (e.g. 1w2d3h4m5s) into a short readable string."""
    text = (raw or "").strip().lower()
    if not text:
        return "—"
    import re

    parts = re.findall(r"(\d+)([wdhms])", text)
    if not parts:
        return raw
    labels = {"w": "w", "d": "d", "h": "h", "m": "m", "s": "s"}
    shown = []
    for value, unit in parts:
        shown.append(f"{int(value)}{labels.get(unit, unit)}")
        if len(shown) >= 3:
            break
    return " ".join(shown) if shown else raw


def _parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _memory_used_pct(free_memory: int, total_memory: int) -> int | None:
    if total_memory <= 0:
        return None
    used = max(0, total_memory - free_memory)
    return max(0, min(100, round((used / total_memory) * 100)))


def _bytes_label(num: int) -> str:
    value = float(max(0, num))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{num} B"


def _bits_per_sec_label(bps: int | float | None) -> str:
    """Human-readable bit rate for live WAN speed."""
    if bps is None:
        return "—"
    try:
        value = float(bps)
    except (TypeError, ValueError):
        return "—"
    if value < 0:
        value = 0.0
    if value < 1000:
        return f"{int(value)} bps"
    if value < 1_000_000:
        return f"{value / 1000:.1f} Kbps"
    if value < 1_000_000_000:
        mbps = value / 1_000_000
        if mbps >= 100:
            return f"{mbps:.0f} Mbps"
        if mbps >= 10:
            return f"{mbps:.1f} Mbps"
        return f"{mbps:.2f} Mbps"
    return f"{value / 1_000_000_000:.2f} Gbps"


def _monitor_interface_speed(sock: socket.socket, interface: str) -> dict[str, Any]:
    """Read live rx/tx bit rates for one interface via monitor-traffic."""
    interface = (interface or "").strip()
    empty = {
        "wan_download_bps": None,
        "wan_upload_bps": None,
        "wan_download_label": "—",
        "wan_upload_label": "—",
        "wan_speed_interface": "",
    }
    if not interface:
        return empty

    previous = sock.gettimeout()
    sock.settimeout(max(float(previous or 5.0), 4.0))
    try:
        replies, terminal = _command(
            sock,
            [
                "/interface/monitor-traffic",
                f"=interface={interface}",
                "=once=",
            ],
        )
        if terminal.get("_reply") in {"!trap", "!fatal"} or not replies:
            return empty
        row = replies[0]
        # On the WAN/uplink port: RX = download, TX = upload.
        rx = _parse_int(row.get("rx-bits-per-second"))
        tx = _parse_int(row.get("tx-bits-per-second"))
        return {
            "wan_download_bps": rx,
            "wan_upload_bps": tx,
            "wan_download_label": _bits_per_sec_label(rx),
            "wan_upload_label": _bits_per_sec_label(tx),
            "wan_speed_interface": interface,
        }
    except (TimeoutError, OSError):
        return empty
    finally:
        sock.settimeout(previous)


def _pct_shares_from_weights(weights: list[int]) -> list[int]:
    """Split 100 across weights (last entry absorbs rounding)."""
    if not weights:
        return []
    grand = sum(max(0, int(w or 0)) for w in weights)
    remaining = 100
    out: list[int] = []
    for index, weight in enumerate(weights):
        if grand <= 0:
            pct = 0
        elif index == len(weights) - 1:
            pct = max(0, remaining)
        else:
            pct = int(round(100.0 * float(max(0, int(weight or 0))) / float(grand)))
            remaining -= pct
        out.append(max(0, min(100, pct)))
    return out


def build_wan_traffic_share(
    samples: list[dict[str, Any]],
    *,
    previous: dict[str, Any] | None = None,
    now: float | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Build WAN share % from per-interface byte counters.

    When ``previous`` holds a recent snapshot ``{t, bytes:{name:int}}``, use the
    byte delta as a live rate. Otherwise fall back to cumulative bytes so the UI
    still shows a useful split without a second RouterOS session.
    """
    import time as _time

    now_ts = float(now if now is not None else _time.time())
    cleaned: list[dict[str, Any]] = []
    bytes_map: dict[str, int] = {}
    for row in samples or []:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        rx = max(0, _parse_int(row.get("rx_byte")))
        tx = max(0, _parse_int(row.get("tx_byte")))
        total = rx + tx
        bytes_map[name] = total
        cleaned.append(
            {
                "name": name,
                "monitor": str(row.get("monitor") or name).strip() or name,
                "rx_byte": rx,
                "tx_byte": tx,
                "bytes": total,
            }
        )

    cache_state = {"t": now_ts, "bytes": bytes_map}
    empty = {"ok": False, "shares": [], "total_bps": 0, "source": ""}
    if len(cleaned) < 1:
        return empty, cache_state

    prev_bytes = (previous or {}).get("bytes") if isinstance(previous, dict) else None
    prev_t = (previous or {}).get("t") if isinstance(previous, dict) else None
    use_rate = False
    dt = 0.0
    if isinstance(prev_bytes, dict) and prev_t is not None:
        try:
            dt = max(0.0, now_ts - float(prev_t))
        except (TypeError, ValueError):
            dt = 0.0
        if 0.4 <= dt <= 120.0:
            use_rate = True

    weights: list[int] = []
    rates: list[int] = []
    for row in cleaned:
        name = row["name"]
        if use_rate:
            prev = _parse_int(prev_bytes.get(name)) if isinstance(prev_bytes, dict) else 0
            delta = max(0, int(row["bytes"]) - prev)
            # bytes/sec → bits/sec
            bps = int(round((float(delta) * 8.0) / dt)) if dt > 0 else 0
            rates.append(bps)
            weights.append(bps)
        else:
            rates.append(0)
            weights.append(int(row["bytes"]))

    # If the delta window was idle on every link, fall back to cumulative bytes
    # so the bar still reflects historical use instead of "— / —".
    source = "rate" if use_rate and sum(weights) > 0 else "bytes"
    if source == "bytes":
        weights = [int(row["bytes"]) for row in cleaned]
        rates = [0 for _ in cleaned]

    pcts = _pct_shares_from_weights(weights)
    grand = sum(weights)
    shares: list[dict[str, Any]] = []
    for index, row in enumerate(cleaned):
        bps = rates[index] if index < len(rates) else 0
        shares.append(
            {
                "name": row["name"],
                "monitor": row["monitor"],
                "bps": bps if source == "rate" else 0,
                "download_bps": None,
                "upload_bps": None,
                "rate_label": _bits_per_sec_label(bps) if source == "rate" else "—",
                "download_label": "—",
                "upload_label": "—",
                "bytes": row["bytes"],
                "bytes_label": _bytes_label(row["bytes"]),
                "pct": pcts[index] if index < len(pcts) else 0,
            }
        )
    return (
        {
            "ok": True,
            "shares": shares,
            "total_bps": grand if source == "rate" else 0,
            "source": source,
        },
        cache_state,
    )


def read_wan_traffic_share(
    host: str,
    username: str,
    password: str,
    *,
    interfaces: list[str],
    port: int = 8728,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """
    Live traffic share across WAN interfaces (percent of combined rx+tx bit rate).

    Prefers ``monitor-traffic`` rates; falls back to ``rx-byte``/``tx-byte`` when
    monitor is empty or unavailable. ``interfaces`` may be physical or PPPoE names.
    """
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    names = [str(n).strip() for n in (interfaces or []) if str(n).strip()]
    names = list(dict.fromkeys(names))
    empty = {"ok": False, "shares": [], "total_bps": 0}
    if not host or not username or len(names) < 1:
        return empty

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            byte_map: dict[str, tuple[int, int]] = {}
            try:
                for row in _print(sock, "/interface", props="name,rx-byte,tx-byte"):
                    iname = (row.get("name") or "").strip()
                    if iname:
                        byte_map[iname] = (
                            max(0, _parse_int(row.get("rx-byte"))),
                            max(0, _parse_int(row.get("tx-byte"))),
                        )
            except (TimeoutError, OSError, ConnectionError):
                byte_map = {}

            samples: list[dict[str, Any]] = []
            live_ok = False
            for name in names:
                speed = _monitor_interface_speed(sock, name)
                rx = speed.get("wan_download_bps")
                tx = speed.get("wan_upload_bps")
                if rx is not None or tx is not None:
                    live_ok = True
                rx_i = max(0, int(rx or 0))
                tx_i = max(0, int(tx or 0))
                total = rx_i + tx_i
                brx, btx = byte_map.get(name, (0, 0))
                samples.append(
                    {
                        "name": name,
                        "bps": total,
                        "download_bps": rx_i if rx is not None else None,
                        "upload_bps": tx_i if tx is not None else None,
                        "rate_label": _bits_per_sec_label(total) if live_ok else "—",
                        "download_label": speed.get("wan_download_label") or "—",
                        "upload_label": speed.get("wan_upload_label") or "—",
                        "rx_byte": brx,
                        "tx_byte": btx,
                        "bytes": brx + btx,
                    }
                )

            grand_live = sum(int(s["bps"] or 0) for s in samples)
            if live_ok and grand_live > 0:
                pcts = _pct_shares_from_weights([int(s["bps"] or 0) for s in samples])
                shares = [
                    {**sample, "pct": pcts[i] if i < len(pcts) else 0}
                    for i, sample in enumerate(samples)
                ]
                return {
                    "ok": True,
                    "shares": shares,
                    "total_bps": grand_live,
                    "source": "monitor",
                }

            # Idle monitor or trap — share from cumulative interface bytes.
            built, _ = build_wan_traffic_share(
                [
                    {
                        "name": s["name"],
                        "monitor": s["name"],
                        "rx_byte": s.get("rx_byte") or 0,
                        "tx_byte": s.get("tx_byte") or 0,
                    }
                    for s in samples
                ]
            )
            if built.get("ok"):
                return built
            return {**empty, "error": "No traffic counters for those interfaces."}
    except TimeoutError:
        return {**empty, "error": "Timed out reading WAN traffic share."}
    except ConnectionError as exc:
        return {**empty, "error": str(exc) or "Login failed."}
    except OSError as exc:
        return {**empty, "error": f"Could not reach {host}:8728. ({exc})"}
    except Exception as exc:
        return {**empty, "error": str(exc) or "Could not read WAN traffic share."}


def _is_ros_true(value: Any) -> bool:
    return str(value or "").strip().lower() in {"true", "yes", "1"}


def _parse_immediate_gateway(value: str) -> tuple[str, str]:
    """Split RouterOS immediate-gw like '192.168.1.1%ether1' into (ip, iface)."""
    text = (value or "").strip()
    if not text:
        return "", ""
    if "%" in text:
        left, right = text.split("%", 1)
        return left.strip(), right.strip()
    # Interface-only gateway (connected / local)
    if any(ch.isalpha() for ch in text):
        return "", text
    return text, ""


def _is_public_ip(ip: str) -> bool:
    text = (ip or "").strip()
    if not text or ":" in text:
        return False
    parts = text.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    octets = [int(p) for p in parts]
    if any(o > 255 for o in octets):
        return False
    a, b = octets[0], octets[1]
    if a == 10 or a == 127 or a == 0:
        return False
    if a == 192 and b == 168:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 169 and b == 254:
        return False
    if a >= 224:
        return False
    return True


# Common upstream gateway OUIs → consumer-facing provider / vendor names.
_GATEWAY_OUI_PROVIDERS = {
    "74249F": "Starlink",  # TIBRO OUI widely used on Starlink kits
    "00FC8B": "Starlink",
    "54D1B0": "Starlink",
    "908D6E": "Starlink",
    "949B2C": "Starlink",
    "982CBC": "Starlink",
    "F4E3FB": "Starlink",
    "001A2B": "Ayecom / Ayecom Wireless",
    "001E13": "Cisco",
    "001E58": "D-Link",
    "002275": "Belkin",
    "0026F2": "Netgear",
    "00E04C": "Realtek",
    "04A151": "Netgear",
    "085700": "TP-Link",
    "0C80FA": "Teltonika",
    "14CC20": "TP-Link",
    "1802AE": "Vivo / Xiaomi",
    "1C3BF3": "Huawei",
    "20F3A3": "Huawei",
    "246968": "TP-Link",
    "28EE52": "TP-Link",
    "308BBD": "Huawei",
    "34CE00": "Xiaomi",
    "3C846A": "TP-Link",
    "48A98A": "Routerboard.com / MikroTik",
    "4C5E0C": "Routerboard.com / MikroTik",
    "50465D": "ASUS",
    "50C7BF": "TP-Link",
    "525400": "QEMU / virtual",
    "58821D": "Huawei",
    "60E327": "TP-Link",
    "6466B3": "TP-Link",
    "6487FF": "Huawei",
    "6C3B6B": "Routerboard.com / MikroTik",
    "744D28": "Routerboard.com / MikroTik",
    "78D294": "Netgear",
    "7C8BCA": "TP-Link",
    "808917": "TP-Link",
    "84183A": "Huawei",
    "88F7BF": "Huawei",
    "948815": "Huawei",
    "9C53CD": "Huawei",
    "A0F3C1": "TP-Link",
    "AC84C6": "TP-Link",
    "B075D5": "Huawei",
    "B0A86E": "Huawei",
    "B4B024": "Huawei",
    "B827EB": "Raspberry Pi",
    "C025A5": "Huawei",
    "C83A35": "Huawei",
    "CC2D21": "Routerboard.com / MikroTik",
    "D4CA6D": "Routerboard.com / MikroTik",
    "DCEF09": "Huawei",
    "E4FAFD": "Huawei",
    "EC172F": "Huawei",
    "F4F26D": "Huawei",
}


def _normalize_mac(mac: str) -> str:
    return "".join(ch for ch in (mac or "").upper() if ch.isalnum())


def _lookup_gateway_provider(mac: str) -> str:
    """Guess internet company / upstream brand from gateway MAC OUI."""
    compact = _normalize_mac(mac)
    if len(compact) < 6:
        return ""
    oui = compact[:6]
    known = _GATEWAY_OUI_PROVIDERS.get(oui)
    if known:
        return known

    # Best-effort online OUI lookup (cached by Django cache when used from views).
    try:
        import json
        import urllib.request

        req = urllib.request.Request(
            f"https://api.macvendors.com/{compact[:8]}",
            headers={"User-Agent": "ISPCENTRIC/1.0"},
        )
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            vendor = (resp.read() or b"").decode("utf-8", errors="ignore").strip()
        if vendor and "not found" not in vendor.lower():
            return vendor.split("\n")[0][:120]
    except Exception:
        pass
    return ""


def _lookup_public_ip_isp(ip: str) -> str:
    """Resolve ISP/org name for a public IP (best-effort)."""
    if not _is_public_ip(ip):
        return ""
    try:
        import json
        import urllib.parse
        import urllib.request

        url = (
            "http://ip-api.com/json/"
            + urllib.parse.quote(ip)
            + "?fields=status,isp,org,as"
        )
        req = urllib.request.Request(url, headers={"User-Agent": "ISPCENTRIC/1.0"})
        with urllib.request.urlopen(req, timeout=1.8) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore") or "{}")
        if payload.get("status") != "success":
            return ""
        for key in ("isp", "org"):
            value = (payload.get(key) or "").strip()
            if value:
                return value[:120]
    except Exception:
        pass
    return ""


def _read_internet_uplink(sock: socket.socket) -> dict[str, Any]:
    """Detect where internet arrives: gateway, logical iface, and physical port."""
    empty = {
        "wan_gateway": "",
        "wan_interface": "",
        "wan_port": "",
        "wan_address": "",
        "wan_source": "",
        "wan_source_label": "—",
        "wan_summary": "Internet source unavailable",
        "wan_port_label": "—",
        "wan_gateway_label": "—",
        "wan_provider": "",
        "wan_provider_label": "—",
        "wan_provider_detected": "",
        "wan_provider_hint": "",
        "wan_download_bps": None,
        "wan_upload_bps": None,
        "wan_download_label": "—",
        "wan_upload_label": "—",
        "wan_speed_interface": "",
    }

    try:
        routes = _print(sock, "/ip/route")
    except (TimeoutError, OSError):
        return empty

    default_route = None
    for row in routes:
        if _is_ros_true(row.get("disabled")):
            continue
        dst = (row.get("dst-address") or "").strip()
        if dst not in {"0.0.0.0/0", "::/0"}:
            continue
        if not _is_ros_true(row.get("active")):
            continue
        default_route = row
        break
    if default_route is None:
        for row in routes:
            if _is_ros_true(row.get("disabled")):
                continue
            if (row.get("dst-address") or "").strip() in {"0.0.0.0/0", "::/0"}:
                default_route = row
                break
    if default_route is None:
        return empty

    gateway = (default_route.get("gateway") or "").strip()
    immediate = (default_route.get("immediate-gw") or "").strip()
    imm_gw, imm_iface = _parse_immediate_gateway(immediate)
    if imm_gw and (not gateway or any(ch.isalpha() for ch in gateway)):
        gateway = imm_gw

    wan_interface = (
        (default_route.get("vrf-interface") or "").strip()
        or imm_iface
        or (gateway if any(ch.isalpha() for ch in gateway) else "")
    )
    if gateway and any(ch.isalpha() for ch in gateway) and not wan_interface:
        wan_interface = gateway
        gateway = imm_gw or ""

    wan_source = "static"
    wan_address = ""

    try:
        dhcp_rows = _print(sock, "/ip/dhcp-client")
    except (TimeoutError, OSError):
        dhcp_rows = []
    for row in dhcp_rows:
        if _is_ros_true(row.get("disabled")):
            continue
        status = (row.get("status") or "").strip().lower()
        iface = (row.get("interface") or "").strip()
        if wan_interface and iface and iface != wan_interface:
            continue
        if status == "bound" or (row.get("address") or "").strip():
            wan_source = "dhcp"
            wan_address = (row.get("address") or "").split("/")[0].strip()
            if not gateway:
                gateway = (row.get("gateway") or "").strip()
            if not wan_interface:
                wan_interface = iface
            break

    try:
        pppoe_rows = _print(sock, "/interface/pppoe-client")
    except (TimeoutError, OSError):
        pppoe_rows = []
    for row in pppoe_rows:
        if _is_ros_true(row.get("disabled")):
            continue
        name = (row.get("name") or "").strip()
        running = _is_ros_true(row.get("running"))
        if wan_interface and name == wan_interface:
            wan_source = "pppoe"
            break
        if running and not wan_interface:
            wan_source = "pppoe"
            wan_interface = name
            break

    if not wan_address:
        try:
            addresses = _print(sock, "/ip/address")
        except (TimeoutError, OSError):
            addresses = []
        for row in addresses:
            if _is_ros_true(row.get("disabled")):
                continue
            iface = (row.get("interface") or "").strip()
            if wan_interface and iface != wan_interface:
                continue
            wan_address = (row.get("address") or "").split("/")[0].strip()
            if wan_address:
                break

    wan_port = wan_interface
    gateway_mac = ""
    if gateway and not any(ch.isalpha() for ch in gateway):
        try:
            arp_rows = _print(sock, "/ip/arp")
        except (TimeoutError, OSError):
            arp_rows = []
        for row in arp_rows:
            if (row.get("address") or "").strip() == gateway:
                gateway_mac = (row.get("mac-address") or "").strip().upper()
                arp_iface = (row.get("interface") or "").strip()
                if arp_iface and not wan_interface:
                    wan_interface = arp_iface
                break

    if gateway_mac:
        try:
            hosts = _print(sock, "/interface/bridge/host")
        except (TimeoutError, OSError):
            hosts = []
        for row in hosts:
            mac = (row.get("mac-address") or "").strip().upper()
            if mac == gateway_mac:
                on_iface = (row.get("on-interface") or "").strip()
                if on_iface:
                    wan_port = on_iface
                break

    if wan_interface.lower().startswith(("ether", "sfp", "qsfp", "wlan")):
        wan_port = wan_interface

    # Detect company / provider from public IP ASN, then gateway equipment OUI.
    detected_provider = ""
    provider_hint = ""
    if _is_public_ip(wan_address):
        detected_provider = _lookup_public_ip_isp(wan_address)
        if detected_provider:
            provider_hint = "Detected from public WAN IP"
    if not detected_provider and gateway_mac:
        detected_provider = _lookup_gateway_provider(gateway_mac)
        if detected_provider:
            provider_hint = "Detected from upstream gateway device"

    # Interface comments sometimes name the ISP.
    if not detected_provider and wan_interface:
        try:
            ifaces = _print(sock, "/interface")
        except (TimeoutError, OSError):
            ifaces = []
        for row in ifaces:
            name = (row.get("name") or "").strip()
            if name in {wan_interface, wan_port}:
                comment = (row.get("comment") or "").strip()
                if comment:
                    detected_provider = comment[:120]
                    provider_hint = "From interface comment"
                    break

    source_labels = {
        "dhcp": "DHCP from upstream",
        "pppoe": "PPPoE uplink",
        "static": "Static / default route",
    }
    source_label = source_labels.get(wan_source, wan_source or "—")

    if detected_provider and wan_port:
        summary = f"{detected_provider} internet entering on {wan_port}"
    elif gateway and wan_port:
        summary = f"Internet from {gateway} entering on {wan_port}"
    elif gateway:
        summary = f"Internet from {gateway}"
    elif wan_port:
        summary = f"Internet entering on {wan_port}"
    else:
        summary = "Internet source unavailable"

    return {
        "wan_gateway": gateway,
        "wan_interface": wan_interface,
        "wan_port": wan_port,
        "wan_address": wan_address,
        "wan_source": wan_source,
        "wan_source_label": source_label,
        "wan_summary": summary,
        "wan_port_label": wan_port or "—",
        "wan_gateway_label": gateway or "—",
        "wan_provider": detected_provider,
        "wan_provider_label": detected_provider or "—",
        "wan_provider_detected": detected_provider,
        "wan_provider_hint": provider_hint,
        "wan_gateway_mac": gateway_mac,
    }


def fetch_mikrotik_live_snapshot(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 6.0,
) -> dict[str, Any]:
    """Pull a simple live health snapshot for the detail dashboard."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not host or not username:
        return {
            "ok": False,
            "online": False,
            "error": "Missing router credentials.",
        }

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            identity = ""
            version = ""
            board = ""
            serial_number = ""
            software_id = ""
            uptime_raw = ""
            cpu_load = None
            free_memory = 0
            total_memory = 0

            for attrs in _print(sock, "/system/identity", props="name"):
                identity = attrs.get("name") or identity

            for attrs in _print(
                sock,
                "/system/resource",
                props="uptime,version,board-name,cpu-load,free-memory,total-memory",
            ):
                uptime_raw = attrs.get("uptime") or uptime_raw
                version = attrs.get("version") or version
                board = attrs.get("board-name") or board
                if attrs.get("cpu-load") not in (None, ""):
                    cpu_load = _parse_int(attrs.get("cpu-load"))
                free_memory = _parse_int(attrs.get("free-memory"))
                total_memory = _parse_int(attrs.get("total-memory"))

            try:
                for attrs in _print(
                    sock, "/system/routerboard", props="serial-number,model,board-name"
                ):
                    serial_number = (attrs.get("serial-number") or "").strip() or serial_number
                    board = (
                        attrs.get("board-name") or attrs.get("model") or board or ""
                    ).strip() or board
                for attrs in _print(sock, "/system/license", props="software-id"):
                    software_id = (attrs.get("software-id") or "").strip() or software_id
            except Exception:
                pass

            # Detect WAN / internet entry before optional wireless probes.
            uplink = _read_internet_uplink(sock)
            speed_iface = (uplink.get("wan_port") or uplink.get("wan_interface") or "").strip()
            speed = _monitor_interface_speed(sock, speed_iface)
            uplink.update(speed)

            interfaces = _print(
                sock,
                "/interface",
                props="name,type,running,disabled",
            )
            ports_up = 0
            ports_total = 0
            wifi_ssids: list[str] = []
            for row in interfaces:
                if (row.get("disabled") or "").lower() in {"true", "yes"}:
                    continue
                iface_type = (row.get("type") or "").lower()
                name = (row.get("name") or "").strip()
                ports_total += 1
                if (row.get("running") or "").lower() in {"true", "yes"}:
                    ports_up += 1
                if iface_type in {"wlan", "wifi", "wifiwave2"} or name.lower().startswith("wlan"):
                    pass

            # Live Wi‑Fi SSIDs (best effort). Avoid wifiwave2 after a hit —
            # some older boards desync the API session on that path.
            for path in ("/interface/wireless", "/interface/wifi", "/interface/wifiwave2"):
                try:
                    rows = _print(sock, path)
                except Exception:
                    rows = []
                for row in rows:
                    ssid = (row.get("ssid") or "").strip()
                    if ssid and ssid not in wifi_ssids:
                        wifi_ssids.append(ssid)
                if wifi_ssids:
                    break

            pppoe_active = 0
            hotspot_active = 0
            try:
                pppoe_active = len(_print(sock, "/ppp/active", props=".id,name"))
            except Exception:
                pppoe_active = 0
            try:
                hotspot_active = len(_print(sock, "/ip/hotspot/active", props=".id,user"))
            except Exception:
                hotspot_active = 0

            memory_pct = _memory_used_pct(free_memory, total_memory)
            online_users = pppoe_active + hotspot_active

            return {
                "ok": True,
                "online": True,
                "host": host,
                "identity": identity or f"MikroTik {host}",
                "board": board or "",
                "serial_number": serial_number or "",
                "software_id": software_id or "",
                "version": version or "",
                "uptime": _human_uptime(uptime_raw),
                "uptime_raw": uptime_raw or "",
                "cpu_load": cpu_load,
                "memory_used_pct": memory_pct,
                "memory_free": _bytes_label(free_memory) if total_memory else "—",
                "memory_total": _bytes_label(total_memory) if total_memory else "—",
                "ports_up": ports_up,
                "ports_total": ports_total,
                "online_users": online_users,
                "pppoe_active": pppoe_active,
                "hotspot_active": hotspot_active,
                "wifi_ssids": wifi_ssids[:4],
                "wifi_label": ", ".join(wifi_ssids[:2]) if wifi_ssids else "—",
                **uplink,
            }
    except TimeoutError:
        return {
            "ok": False,
            "online": False,
            "error": "Connection timed out. Is the router reachable on API port 8728?",
        }
    except ConnectionError as exc:
        return {
            "ok": False,
            "online": False,
            "error": str(exc) or "Login failed. Check the saved username and password.",
            "auth_error": True,
        }
    except OSError as exc:
        return {
            "ok": False,
            "online": False,
            "error": f"Could not reach {host}:8728.",
            "detail": str(exc),
        }
    except Exception as exc:
        return {
            "ok": False,
            "online": False,
            "error": str(exc) or "Could not read live data from the router.",
        }


def fetch_customer_pppoe_usage(
    host: str,
    username: str,
    password: str,
    *,
    pppoe_username: str,
    port: int = 8728,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Live PPPoE session usage for one subscriber username on a MikroTik."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    pppoe_username = (pppoe_username or "").strip()
    empty = {
        "ok": False,
        "online": False,
        "session_active": False,
        "pppoe_username": pppoe_username,
        "address": "",
        "caller_id": "",
        "service": "",
        "uptime": "—",
        "uptime_raw": "",
        "bytes_in": 0,
        "bytes_out": 0,
        "bytes_in_label": "—",
        "bytes_out_label": "—",
        "download_bps": None,
        "upload_bps": None,
        "download_label": "—",
        "upload_label": "—",
        "interface": "",
        "error": "",
    }
    if not host:
        empty["error"] = "No router host configured."
        return empty
    if not pppoe_username:
        empty["error"] = "No PPPoE username on this client."
        return empty

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            active_rows = _print(
                sock,
                "/ppp/active",
                props="name,service,caller-id,address,uptime,encoding",
            )
            session = None
            for row in active_rows:
                if (row.get("name") or "").strip().lower() == pppoe_username.lower():
                    session = row
                    break

            if not session:
                return {
                    **empty,
                    "ok": True,
                    "online": True,
                    "session_active": False,
                    "error": "",
                    "hint": "Subscriber is not online on this router right now.",
                }

            # Prefer the dynamic <pppoe-user> interface for counters + live speed.
            iface_name = ""
            bytes_in = 0
            bytes_out = 0
            candidates = [
                f"<pppoe-{pppoe_username}>",
                f"<pppoe-{session.get('name') or pppoe_username}>",
                pppoe_username,
            ]
            try:
                interfaces = _print(
                    sock,
                    "/interface",
                    props="name,type,rx-byte,tx-byte,running",
                )
            except Exception:
                interfaces = []
            by_name = {(row.get("name") or "").strip(): row for row in interfaces}
            for candidate in candidates:
                if candidate in by_name:
                    iface_name = candidate
                    break
            if not iface_name:
                for row in interfaces:
                    name = (row.get("name") or "").strip()
                    lower = name.lower()
                    if pppoe_username.lower() in lower and "pppoe" in lower:
                        iface_name = name
                        break

            if iface_name and iface_name in by_name:
                iface = by_name[iface_name]
                bytes_in = _parse_int(iface.get("rx-byte"))
                bytes_out = _parse_int(iface.get("tx-byte"))

            speed = _monitor_interface_speed(sock, iface_name) if iface_name else {
                "wan_download_bps": None,
                "wan_upload_bps": None,
                "wan_download_label": "—",
                "wan_upload_label": "—",
            }

            uptime_raw = (session.get("uptime") or "").strip()
            return {
                "ok": True,
                "online": True,
                "session_active": True,
                "pppoe_username": pppoe_username,
                "address": (session.get("address") or "").strip(),
                "caller_id": (session.get("caller-id") or "").strip(),
                "service": (session.get("service") or "").strip() or "pppoe",
                "uptime": _human_uptime(uptime_raw),
                "uptime_raw": uptime_raw,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "bytes_in_label": _bytes_label(bytes_in) if bytes_in or iface_name else "—",
                "bytes_out_label": _bytes_label(bytes_out) if bytes_out or iface_name else "—",
                "download_bps": speed.get("wan_download_bps"),
                "upload_bps": speed.get("wan_upload_bps"),
                "download_label": speed.get("wan_download_label") or "—",
                "upload_label": speed.get("wan_upload_label") or "—",
                "interface": iface_name,
                "error": "",
            }
    except TimeoutError:
        return {**empty, "error": "Connection timed out reaching the router."}
    except OSError as exc:
        return {
            **empty,
            "error": f"Could not reach {host}:8728.",
            "detail": str(exc),
        }
    except Exception as exc:
        return {
            **empty,
            "error": str(exc) or "Could not read subscriber usage from the router.",
        }


def fetch_customer_hotspot_usage(
    host: str,
    username: str,
    password: str,
    *,
    hotspot_mac: str,
    port: int = 8728,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Live Hotspot session usage for one gadget MAC on a MikroTik."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    mac_compact = _mac_compact(hotspot_mac)
    mac_display = (
        ":".join(mac_compact[i : i + 2] for i in range(0, 12, 2))
        if len(mac_compact) == 12
        else (hotspot_mac or "").strip().upper()
    )
    empty = {
        "ok": False,
        "online": False,
        "session_active": False,
        "hotspot_mac": mac_display,
        "pppoe_username": "",
        "address": "",
        "caller_id": mac_display,
        "service": "hotspot",
        "uptime": "—",
        "uptime_raw": "",
        "bytes_in": 0,
        "bytes_out": 0,
        "bytes_in_label": "—",
        "bytes_out_label": "—",
        "download_bps": None,
        "upload_bps": None,
        "download_label": "—",
        "upload_label": "—",
        "interface": "",
        "error": "",
    }
    if not host:
        empty["error"] = "No router host configured."
        return empty
    if len(mac_compact) != 12:
        empty["error"] = "This client has no Hotspot device MAC."
        return empty

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            active_rows = _print(
                sock,
                "/ip/hotspot/active",
                props=(
                    "mac-address,user,address,uptime,bytes-in,bytes-out,"
                    "login-by,server"
                ),
                query={"mac-address": mac_display},
            )
            if not active_rows:
                active_rows = _print(
                    sock,
                    "/ip/hotspot/active",
                    props=(
                        "mac-address,user,address,uptime,bytes-in,bytes-out,"
                        "login-by,server"
                    ),
                )

            session = None
            for row in active_rows:
                row_mac = _mac_compact(
                    row.get("mac-address") or row.get("user") or ""
                )
                if row_mac == mac_compact:
                    session = row
                    break

            if not session:
                return {
                    **empty,
                    "ok": True,
                    "online": True,
                    "session_active": False,
                    "error": "",
                    "hint": "This gadget is not in an active Hotspot session right now.",
                }

            bytes_in = _parse_int(session.get("bytes-in"))
            bytes_out = _parse_int(session.get("bytes-out"))
            uptime_raw = (session.get("uptime") or "").strip()
            return {
                "ok": True,
                "online": True,
                "session_active": True,
                "hotspot_mac": mac_display,
                "pppoe_username": (session.get("user") or "").strip(),
                "address": (session.get("address") or "").strip(),
                "caller_id": mac_display,
                "service": "hotspot",
                "uptime": _human_uptime(uptime_raw),
                "uptime_raw": uptime_raw,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "bytes_in_label": _bytes_label(bytes_in),
                "bytes_out_label": _bytes_label(bytes_out),
                "download_bps": None,
                "upload_bps": None,
                "download_label": "—",
                "upload_label": "—",
                "interface": (session.get("server") or "").strip(),
                "error": "",
            }
    except TimeoutError:
        return {**empty, "error": "Connection timed out reaching the router."}
    except OSError as exc:
        return {
            **empty,
            "error": f"Could not reach {host}:8728.",
            "detail": str(exc),
        }
    except Exception as exc:
        return {
            **empty,
            "error": str(exc) or "Could not read Hotspot usage from the router.",
        }


def fetch_router_bulk_pppoe_usage(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 4.0,
) -> dict[str, Any]:
    """
    One API session: usage snapshot for every active PPPoE session.

    Skips monitor-traffic (too slow for org-wide sampling). Returns
    ``sessions`` keyed by lowercased PPPoE username with byte counters from
    the matching ``<pppoe-…>`` interface when present.
    """
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not host or not username:
        return {"ok": False, "sessions": {}, "error": "Router host or username missing."}
    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            active_rows = _print(
                sock,
                "/ppp/active",
                props="name,service,caller-id,address,uptime",
            )
            try:
                interfaces = _print(
                    sock,
                    "/interface",
                    props="name,type,rx-byte,tx-byte,running",
                )
            except Exception:
                interfaces = []
            by_name = {(row.get("name") or "").strip(): row for row in interfaces}

            sessions: dict[str, dict[str, Any]] = {}
            for row in active_rows:
                pppoe_name = (row.get("name") or "").strip()
                if not pppoe_name:
                    continue
                key = pppoe_name.lower()
                iface_name = ""
                for candidate in (
                    f"<pppoe-{ppoe_name}>",
                    f"<pppoe-{key}>",
                    pppoe_name,
                ):
                    if candidate in by_name:
                        iface_name = candidate
                        break
                if not iface_name:
                    for iface_row in interfaces:
                        name = (iface_row.get("name") or "").strip()
                        lower = name.lower()
                        if key in lower and "pppoe" in lower:
                            iface_name = name
                            break
                bytes_in = 0
                bytes_out = 0
                if iface_name and iface_name in by_name:
                    iface = by_name[iface_name]
                    bytes_in = _parse_int(iface.get("rx-byte"))
                    bytes_out = _parse_int(iface.get("tx-byte"))
                uptime_raw = (row.get("uptime") or "").strip()
                sessions[key] = {
                    "session_active": True,
                    "pppoe_username": pppoe_name,
                    "address": (row.get("address") or "").strip(),
                    "caller_id": (row.get("caller-id") or "").strip(),
                    "uptime": _human_uptime(uptime_raw),
                    "uptime_raw": uptime_raw,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "download_bps": None,
                    "upload_bps": None,
                    "interface": iface_name,
                }
            return {"ok": True, "sessions": sessions, "error": ""}
    except TimeoutError:
        return {"ok": False, "sessions": {}, "error": "Connection timed out."}
    except OSError as exc:
        return {
            "ok": False,
            "sessions": {},
            "error": f"Could not reach {host}:8728.",
            "detail": str(exc),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "sessions": {},
            "error": str(exc) or "Could not read PPPoE sessions.",
        }


def fetch_router_bulk_hotspot_usage(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 4.0,
) -> dict[str, Any]:
    """One API session: usage snapshot for every active Hotspot session by MAC."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not host or not username:
        return {"ok": False, "sessions": {}, "error": "Router host or username missing."}
    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            active_rows = _print(
                sock,
                "/ip/hotspot/active",
                props=(
                    "mac-address,user,address,uptime,bytes-in,bytes-out,"
                    "login-by,server"
                ),
            )
            sessions: dict[str, dict[str, Any]] = {}
            for row in active_rows:
                mac_compact = _mac_compact(
                    row.get("mac-address") or row.get("user") or ""
                )
                if len(mac_compact) != 12:
                    continue
                uptime_raw = (row.get("uptime") or "").strip()
                sessions[mac_compact] = {
                    "session_active": True,
                    "hotspot_mac": mac_compact,
                    "address": (row.get("address") or "").strip(),
                    "uptime": _human_uptime(uptime_raw),
                    "uptime_raw": uptime_raw,
                    "bytes_in": _parse_int(row.get("bytes-in")),
                    "bytes_out": _parse_int(row.get("bytes-out")),
                    "download_bps": None,
                    "upload_bps": None,
                    "interface": (row.get("server") or "").strip(),
                }
            return {"ok": True, "sessions": sessions, "error": ""}
    except TimeoutError:
        return {"ok": False, "sessions": {}, "error": "Connection timed out."}
    except OSError as exc:
        return {
            "ok": False,
            "sessions": {},
            "error": f"Could not reach {host}:8728.",
            "detail": str(exc),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "sessions": {},
            "error": str(exc) or "Could not read Hotspot sessions.",
        }


def _find_cpe_wan_interface(sock: socket.socket) -> str:
    """Prefer a running PPPoE client interface, else the detected internet uplink port."""
    try:
        interfaces = _print(
            sock,
            "/interface",
            props="name,type,running,disabled",
        )
    except Exception:
        interfaces = []

    running_pppoe: list[str] = []
    for row in interfaces:
        if _is_ros_true(row.get("disabled")):
            continue
        name = (row.get("name") or "").strip()
        iface_type = (row.get("type") or "").strip().lower()
        running = _is_ros_true(row.get("running"))
        lower = name.lower()
        if not running:
            continue
        if iface_type == "pppoe-out" or lower.startswith("pppoe-out") or lower.startswith("pppoe"):
            running_pppoe.append(name)
    if running_pppoe:
        # Prefer the default RouterOS name when present.
        for preferred in ("pppoe-out1", "pppoe-out"):
            if preferred in running_pppoe:
                return preferred
        return running_pppoe[0]

    try:
        uplink = _read_internet_uplink(sock)
    except Exception:
        uplink = {}
    return (uplink.get("wan_port") or uplink.get("wan_interface") or "").strip()


def _count_cpe_connected_devices(sock: socket.socket) -> dict[str, Any]:
    """
    Count LAN/Wi‑Fi devices attached to the CPE.
    Prefers unique MACs from DHCP leases + wireless registrations.
    """
    macs: set[str] = set()
    dhcp_bound = 0
    wifi_clients = 0

    try:
        leases = _print(
            sock,
            "/ip/dhcp-server/lease",
            props="mac-address,status,active-mac-address,address",
        )
    except Exception:
        leases = []
    for row in leases:
        status = (row.get("status") or "").strip().lower()
        if status and status != "bound":
            continue
        dhcp_bound += 1
        mac = (
            (row.get("active-mac-address") or row.get("mac-address") or "")
            .strip()
            .upper()
        )
        if mac:
            macs.add(mac)

    for path in (
        "/interface/wireless/registration-table",
        "/interface/wifi/registration",
        "/interface/wifiwave2/registration",
    ):
        try:
            rows = _print(sock, path, props="mac-address,last-ip,interface")
        except Exception:
            rows = []
        if not rows:
            continue
        for row in rows:
            mac = (row.get("mac-address") or "").strip().upper()
            if mac:
                macs.add(mac)
                wifi_clients += 1
        break

    # Bridge host table as a fallback when DHCP/Wi‑Fi tables are empty.
    if not macs:
        try:
            hosts = _print(
                sock,
                "/interface/bridge/host",
                props="mac-address,on-interface,local",
            )
        except Exception:
            hosts = []
        for row in hosts:
            if _is_ros_true(row.get("local")):
                continue
            mac = (row.get("mac-address") or "").strip().upper()
            if mac:
                macs.add(mac)

    devices = len(macs) if macs else max(dhcp_bound, wifi_clients)
    return {
        "devices_connected": devices,
        "dhcp_leases": dhcp_bound,
        "wifi_clients": wifi_clients,
        "devices_label": str(devices),
        "devices_hint": (
            f"{wifi_clients} Wi‑Fi · {dhcp_bound} DHCP"
            if wifi_clients or dhcp_bound
            else "LAN / Wi‑Fi clients on this CPE"
        ),
    }


def read_cpe_live_metrics(
    sock: socket.socket,
) -> dict[str, Any]:
    """Live WAN speed + connected devices from an already-open CPE API session."""
    wan_iface = _find_cpe_wan_interface(sock)
    speed = _monitor_interface_speed(sock, wan_iface) if wan_iface else {
        "wan_download_bps": None,
        "wan_upload_bps": None,
        "wan_download_label": "—",
        "wan_upload_label": "—",
        "wan_speed_interface": "",
    }
    devices = _count_cpe_connected_devices(sock)

    bytes_in = 0
    bytes_out = 0
    if wan_iface:
        try:
            for row in _print(
                sock,
                "/interface",
                props="name,rx-byte,tx-byte",
            ):
                if (row.get("name") or "").strip() == wan_iface:
                    bytes_in = _parse_int(row.get("rx-byte"))
                    bytes_out = _parse_int(row.get("tx-byte"))
                    break
        except Exception:
            pass

    return {
        "cpe_wan_interface": wan_iface,
        "download_bps": speed.get("wan_download_bps"),
        "upload_bps": speed.get("wan_upload_bps"),
        "download_label": speed.get("wan_download_label") or "—",
        "upload_label": speed.get("wan_upload_label") or "—",
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "bytes_in_label": _bytes_label(bytes_in) if bytes_in else "—",
        "bytes_out_label": _bytes_label(bytes_out) if bytes_out else "—",
        **devices,
    }


def fetch_customer_cpe_live_usage(
    nas_host: str,
    nas_username: str,
    nas_password: str,
    *,
    pppoe_username: str,
    cpe_username: str = "",
    cpe_password: str = "",
    pppoe_password: str = "",
    nas_port: int = 8728,
    cpe_port: int = 8728,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """
    Live CPE metrics: speed the client router is receiving, and how many devices
    are connected to that CPE. Auto-prepares CPE API access through the NAS.
    Falls back to NAS PPPoE session data when CPE API is unreachable.
    """
    nas = fetch_customer_pppoe_usage(
        nas_host,
        nas_username,
        nas_password,
        pppoe_username=pppoe_username,
        port=nas_port,
        timeout=min(timeout, 5.0),
    )
    payload = {
        **nas,
        "cpe_reachable": False,
        "cpe_auth_ok": False,
        "cpe_host": (nas.get("address") or "").strip(),
        "devices_connected": None,
        "devices_label": "—",
        "devices_hint": "Preparing CPE access…",
        "speed_source": "nas",
        "prep_steps": [],
    }
    if not nas.get("ok") or not nas.get("session_active"):
        payload["devices_hint"] = "Client offline — no PPPoE session"
        return payload

    cpe_host = (nas.get("address") or "").strip()
    if not cpe_host:
        return payload

    prep = prepare_customer_cpe_access(
        nas_host,
        nas_username,
        nas_password,
        pppoe_username=pppoe_username,
        cpe_username=cpe_username,
        cpe_password=cpe_password,
        pppoe_password=pppoe_password,
        nas_port=nas_port,
        cpe_port=cpe_port,
        timeout=timeout,
    )
    payload["prep_steps"] = list(prep.get("steps") or [])
    payload["cpe_host"] = prep.get("cpe_host") or cpe_host
    payload["cpe_reachable"] = bool(prep.get("reachable") or prep.get("session_active"))
    if prep.get("cpe_username"):
        cpe_username = prep.get("cpe_username") or cpe_username
    if prep.get("cpe_password") is not None and prep.get("auth_ok"):
        cpe_password = prep.get("cpe_password") or ""

    if not prep.get("auth_ok"):
        payload["cpe_error"] = prep.get("error") or "Could not prepare CPE access."
        payload["devices_hint"] = prep.get("hint") or payload["cpe_error"]
        payload["cpe_username"] = cpe_username
        return payload

    try:
        with _cpe_api_session(
            nas_host,
            nas_username,
            nas_password,
            payload["cpe_host"],
            cpe_username,
            cpe_password,
            nas_port=nas_port,
            cpe_port=cpe_port,
            timeout=timeout,
            proxy_scope=pppoe_username,
            pppoe_password=pppoe_password,
            auto_prepare=False,
        ) as sock:
            metrics = read_cpe_live_metrics(sock)
        payload.update(
            {
                "cpe_reachable": True,
                "cpe_auth_ok": True,
                "cpe_username": cpe_username,
                "cpe_password": cpe_password,
                "speed_source": "cpe",
                "interface": metrics.get("cpe_wan_interface") or payload.get("interface") or "",
                "download_bps": metrics.get("download_bps"),
                "upload_bps": metrics.get("upload_bps"),
                "download_label": metrics.get("download_label") or "—",
                "upload_label": metrics.get("upload_label") or "—",
                "bytes_in": metrics.get("bytes_in") or 0,
                "bytes_out": metrics.get("bytes_out") or 0,
                "bytes_in_label": metrics.get("bytes_in_label") or "—",
                "bytes_out_label": metrics.get("bytes_out_label") or "—",
                "devices_connected": metrics.get("devices_connected"),
                "devices_label": metrics.get("devices_label") or "—",
                "devices_hint": metrics.get("devices_hint") or "",
                "dhcp_leases": metrics.get("dhcp_leases") or 0,
                "wifi_clients": metrics.get("wifi_clients") or 0,
                "error": "",
            }
        )
        return payload
    except Exception as exc:
        payload["cpe_error"] = str(exc) or "Could not read CPE live metrics."
        payload["devices_hint"] = payload["cpe_error"]
        return payload


def resolve_customer_cpe_session(
    nas_host: str,
    nas_username: str,
    nas_password: str,
    *,
    pppoe_username: str,
    port: int = 8728,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Find the live PPPoE session IP for the client's CPE behind the ISP MikroTik."""
    usage = fetch_customer_pppoe_usage(
        nas_host,
        nas_username,
        nas_password,
        pppoe_username=pppoe_username,
        port=port,
        timeout=timeout,
    )
    address = (usage.get("address") or "").strip()
    if not usage.get("ok"):
        return {
            "ok": False,
            "session_active": False,
            "address": "",
            "error": usage.get("error") or "Could not read the PPPoE session.",
        }
    if not usage.get("session_active") or not address:
        return {
            "ok": True,
            "session_active": False,
            "address": "",
            "error": "",
            "hint": usage.get("hint")
            or "Client CPE is offline — the PPPoE session is not active.",
        }
    return {
        "ok": True,
        "session_active": True,
        "address": address,
        "caller_id": usage.get("caller_id") or "",
        "error": "",
    }


def _cpe_credential_candidates(
    *,
    cpe_username: str = "",
    cpe_password: str = "",
    pppoe_password: str = "",
) -> list[tuple[str, str]]:
    """Ordered (username, password) pairs to try against the CPE RouterOS API."""
    username = ((cpe_username or "").strip() or "admin")
    candidates: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(user: str, password: str) -> None:
        key = (user, password)
        if key in seen:
            return
        seen.add(key)
        candidates.append(key)

    add(username, cpe_password or "")
    if pppoe_password and pppoe_password != (cpe_password or ""):
        add(username, pppoe_password)
    if username.lower() != "admin":
        add("admin", cpe_password or "")
        if pppoe_password:
            add("admin", pppoe_password)
    add("admin", "")
    return candidates


def access_customer_cpe_wifi(
    nas_host: str,
    nas_username: str,
    nas_password: str,
    *,
    pppoe_username: str,
    cpe_username: str = "",
    cpe_password: str = "",
    pppoe_password: str = "",
    nas_port: int = 8728,
    cpe_port: int = 8728,
    timeout: float = 12.0,
    auto_enable: bool = True,
) -> dict[str, Any]:
    """
    Auto-prepare CPE access through the ISP MikroTik, then read Wi‑Fi settings
    from the subscriber CPE — not from the ISP MikroTik.
    """
    prep = prepare_customer_cpe_access(
        nas_host,
        nas_username,
        nas_password,
        pppoe_username=pppoe_username,
        cpe_username=cpe_username,
        cpe_password=cpe_password,
        pppoe_password=pppoe_password,
        nas_port=nas_port,
        cpe_port=cpe_port,
        timeout=timeout,
        auto_enable=auto_enable,
    )
    base = {
        "ok": True,
        "session_active": bool(prep.get("session_active")),
        "cpe_host": prep.get("cpe_host") or "",
        "cpe_username": prep.get("cpe_username") or ((cpe_username or "").strip() or "admin"),
        "cpe_password": prep.get("cpe_password")
        if prep.get("cpe_password") is not None
        else (cpe_password or ""),
        "auth_ok": False,
        "wifi_ssid": "",
        "wifi_password": "",
        "wifi_mode": "",
        "wifi_enabled": False,
        "interface_count": 0,
        "reachable": bool(prep.get("reachable")),
        "api_enabled": bool(prep.get("api_enabled")),
        "prep_steps": list(prep.get("steps") or []),
        "error": prep.get("error") or "",
        "hint": prep.get("hint") or "",
        "firewall_blocked": bool(prep.get("firewall_blocked")),
    }
    if not prep.get("session_active"):
        return {
            **base,
            "ok": True,
            "error": "",
            "hint": prep.get("hint")
            or "Client CPE is offline — the PPPoE session is not active.",
        }
    if not prep.get("auth_ok"):
        # Keep ok=True when PPPoE is up so the account page never looks "dead".
        firewall_blocked = bool(prep.get("firewall_blocked"))
        err = prep.get("error") or "Could not sign in to the client CPE automatically."
        if not firewall_blocked and "firewall is blocking" in (err or "").lower():
            firewall_blocked = True
        return {
            **base,
            "ok": True,
            "auth_ok": False,
            "firewall_blocked": firewall_blocked,
            "error": err,
            "hint": prep.get("hint")
            or "Save the CPE Winbox username/password once — API will be enabled automatically.",
        }

    cpe_host = (prep.get("cpe_host") or "").strip()
    user = prep.get("cpe_username") or "admin"
    password = prep.get("cpe_password") if prep.get("cpe_password") is not None else ""
    try:
        with _cpe_api_session(
            nas_host,
            nas_username,
            nas_password,
            cpe_host,
            user,
            password,
            nas_port=nas_port,
            cpe_port=cpe_port,
            timeout=timeout,
            proxy_scope=pppoe_username,
            pppoe_password=pppoe_password,
            auto_prepare=False,
        ) as sock:
            package = _detect_wifi_package(sock)
            wifi = _read_wifi_settings(sock, package)
        return {
            **base,
            "ok": True,
            "session_active": True,
            "cpe_host": cpe_host,
            "cpe_username": user,
            "cpe_password": password,
            "auth_ok": True,
            "wifi_ssid": wifi.get("wifi_ssid") or "",
            "wifi_password": wifi.get("wifi_password") or "",
            "wifi_mode": wifi.get("wifi_mode") or "",
            "wifi_enabled": bool(wifi.get("wifi_enabled")),
            "interface_count": int(wifi.get("interface_count") or 0),
            "api_enabled": True,
            "error": "",
            "hint": "",
        }
    except Exception as exc:
        return {
            **base,
            "ok": False,
            "auth_ok": False,
            "error": str(exc) or "Could not read CPE Wi‑Fi after auto-setup.",
            "hint": "CPE access was prepared, but Wi‑Fi read failed. Refresh and try again.",
        }


def fetch_active_pppoe_usernames(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """
    Return lowercased PPPoE usernames currently online on a MikroTik.

    ``blocked`` lists the usernames whose /ppp/secret sits on the blocked
    profile. A dialed session on that profile is dropped before it reaches the
    internet, so having a session is not the same as being able to surf.
    """
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not host or not username:
        return {
            "ok": False,
            "usernames": [],
            "blocked": [],
            "error": "Router host or username missing.",
        }
    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            rows = _print(sock, "/ppp/active", props="name,service")
            names: list[str] = []
            seen: set[str] = set()
            for row in rows:
                name = (row.get("name") or "").strip()
                if not name:
                    continue
                key = name.lower()
                if key in seen:
                    continue
                seen.add(key)
                names.append(key)
            blocked: list[str] = []
            for row in _print(sock, "/ppp/secret", props="name,profile,disabled"):
                name = (row.get("name") or "").strip()
                if not name:
                    continue
                profile = (row.get("profile") or "").strip()
                if profile == PPPOE_BLOCKED_PROFILE_NAME or _is_disabled(row):
                    blocked.append(name.lower())
            return {"ok": True, "usernames": names, "blocked": blocked, "error": ""}
    except TimeoutError:
        return {
            "ok": False,
            "usernames": [],
            "blocked": [],
            "error": "Connection timed out.",
        }
    except ConnectionError as exc:
        return {
            "ok": False,
            "usernames": [],
            "blocked": [],
            "error": str(exc) or "Login failed.",
            "auth_error": True,
        }
    except OSError as exc:
        return {
            "ok": False,
            "usernames": [],
            "blocked": [],
            "error": f"Could not reach {host}:8728.",
            "detail": str(exc),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "usernames": [],
            "blocked": [],
            "error": str(exc) or "Could not read active sessions.",
        }


def fetch_hotspot_client_macs(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Return Hotspot MACs seen on Wi-Fi and those with active internet sessions."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not host or not username:
        return {
            "ok": False,
            "active_macs": [],
            "connected_macs": [],
            "error": "Router host or username missing.",
        }

    def _mac(value: str) -> str:
        compact = "".join(ch for ch in (value or "") if ch.isalnum()).upper()
        return compact if len(compact) == 12 else ""

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            active_macs = {
                mac
                for row in _print(
                    sock,
                    "/ip/hotspot/active",
                    props="mac-address,user",
                )
                if (mac := _mac(row.get("mac-address") or row.get("user") or ""))
            }
            connected_macs = {
                mac
                for row in _print(
                    sock,
                    "/ip/hotspot/host",
                    props="mac-address,authorized",
                )
                if (mac := _mac(row.get("mac-address") or ""))
            }
            connected_macs.update(active_macs)
            return {
                "ok": True,
                "active_macs": sorted(active_macs),
                "connected_macs": sorted(connected_macs),
                "error": "",
            }
    except TimeoutError:
        error = "Connection timed out."
    except ConnectionError as exc:
        error = str(exc) or "Login failed."
    except OSError as exc:
        error = f"Could not reach {host}:8728. {exc}"
    except Exception as exc:  # noqa: BLE001
        error = str(exc) or "Could not read Hotspot sessions."
    return {
        "ok": False,
        "active_macs": [],
        "connected_macs": [],
        "error": error,
    }


def test_mikrotik_api_login(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 5.0,
    include_wifi: bool = True,
) -> dict[str, Any]:
    """Attempt RouterOS API login. Returns identity/board plus current wifi settings when readable.

    Pass include_wifi=False for status/health probes — Wi‑Fi reads often dominate
    latency and are not needed to decide Connected vs auth_failed.
    """
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not host:
        return {"ok": False, "error": "Enter a MikroTik IP address."}
    if not username:
        return {"ok": False, "error": "Enter the router username."}

    try:
        with socket.create_connection((dial_host(host), port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            login_error = _api_login(sock, username, password)
            if login_error:
                return login_error
            result = _fetch_identity(sock, host)
            if include_wifi:
                # Read Wi‑Fi on a dedicated session; keep this short so Connect
                # stays responsive even when wireless packages are slow/unavailable.
                wifi = read_mikrotik_wifi(
                    host, username, password, port=port, timeout=min(timeout, 3.0)
                )
                result["wifi_ssid"] = wifi.get("wifi_ssid") or ""
                result["wifi_password"] = wifi.get("wifi_password") or ""
                result["wifi_mode"] = wifi.get("wifi_mode") or ""
            else:
                result["wifi_ssid"] = ""
                result["wifi_password"] = ""
                result["wifi_mode"] = ""
            return result
    except TimeoutError:
        return {"ok": False, "error": "Connection timed out. Is the router reachable on API port 8728?"}
    except OSError as exc:
        return {
            "ok": False,
            "error": (
                f"Could not reach {host}:8728. Paste the latest ISPCENTRIC tunnel "
                "script in Winbox → New Terminal (it enables API and bypasses Hotspot), "
                "confirm it prints “ispcentric API: enabled and listening on port 8728”, "
                "then retry Connect."
            ),
            "detail": str(exc),
        }
    except Exception as exc:
        return {"ok": False, "error": f"Connection failed: {exc}"}


def configure_mikrotik_wifi(
    host: str,
    username: str,
    password: str,
    *,
    wifi_ssid: str = "",
    wifi_password: str = "",
    wifi_mode: str = "",
    apply_ssid: bool | None = None,
    apply_password: bool | None = None,
    port: int = 8728,
    timeout: float = 20.0,
    nas_host: str = "",
    nas_username: str = "",
    nas_password: str = "",
) -> dict[str, Any]:
    """Apply Wi‑Fi name/password. Fails closed unless values are confirmed on the router."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    wifi_ssid = (wifi_ssid or "").strip()
    wifi_password = wifi_password or ""
    wifi_mode = (wifi_mode or "").strip().lower()

    if not wifi_ssid and not wifi_password:
        return {"ok": True, "updated": False, "message": "No Wi‑Fi changes requested."}
    if not host or not username:
        return {"ok": False, "error": "Router credentials are required to update Wi‑Fi."}
    if wifi_password and not wifi_ssid:
        return {"ok": False, "error": "Enter a Wi‑Fi name when setting a Wi‑Fi password."}
    if wifi_password and len(wifi_password) < 8:
        return {"ok": False, "error": "Wi‑Fi password must be at least 8 characters."}

    try:
        # Fresh connection: read current values and decide what actually needs writing.
        with _device_api_session(
            host,
            username,
            password,
            port=port,
            timeout=timeout,
            nas_host=nas_host,
            nas_username=nas_username,
            nas_password=nas_password,
            proxy_scope=username,
        ) as sock:
            package = _package_by_mode(wifi_mode) if wifi_mode else _detect_wifi_package(sock)
            if not package:
                # Detection may have poisoned the socket on timeout; retry packages on new sessions below.
                package = None
            current = _read_wifi_settings(sock, package) if package else {"wifi_ssid": "", "wifi_password": "", "wifi_mode": ""}

        live_ssid = (current.get("wifi_ssid") or "").strip()
        live_password = current.get("wifi_password") or ""
        if not wifi_mode:
            wifi_mode = (current.get("wifi_mode") or "").strip()

        # Always prefer live router values to avoid unnecessary (and hanging) writes.
        if wifi_ssid and wifi_ssid == live_ssid:
            apply_ssid = False
        elif apply_ssid is None:
            apply_ssid = bool(wifi_ssid) and wifi_ssid != live_ssid

        if not wifi_password:
            apply_password = False
        elif live_password and wifi_password == live_password:
            apply_password = False
        elif apply_password is None:
            apply_password = True

        if not apply_ssid and not apply_password:
            return {
                "ok": True,
                "updated": False,
                "message": "Wi‑Fi already matches the requested values.",
                "wifi_mode": wifi_mode,
            }

        packages = []
        known = _package_by_mode(wifi_mode)
        if known:
            packages.append(known)
        else:
            packages.extend(WIFI_PACKAGES)

        last_error = ""
        for package in packages:
            # Brand-new TCP session per package so a timed-out probe cannot poison later work.
            try:
                with _device_api_session(
                    host,
                    username,
                    password,
                    port=port,
                    timeout=timeout,
                    nas_host=nas_host,
                    nas_username=nas_username,
                    nas_password=nas_password,
                    proxy_scope=username,
                ) as sock:
                    result = _apply_on_package(
                        sock,
                        package,
                        ssid=wifi_ssid,
                        wifi_password=wifi_password,
                        apply_ssid=bool(apply_ssid),
                        apply_password=bool(apply_password),
                    )
            except TimeoutError:
                result = {
                    "ok": False,
                    "updated": False,
                    "error": "timeout_verify_ssid" if apply_ssid else "timeout_verify_password",
                    "mode": package["mode"],
                }
            except ConnectionError as exc:
                last_error = str(exc)
                continue

            if result.get("skip"):
                continue

            err = result.get("error") or ""
            if err in {"timeout_verify_ssid", "timeout_verify_password"}:
                verified = _verify_wifi(
                    host,
                    username,
                    password,
                    wifi_ssid=wifi_ssid,
                    wifi_password=wifi_password,
                    check_ssid=bool(apply_ssid),
                    check_password=bool(apply_password),
                    wifi_mode=package["mode"],
                    port=port,
                )
                if verified.get("ok"):
                    return verified
                last_error = verified.get("error") or "Timed out while updating Wi‑Fi on the router."
                break

            if result.get("ok"):
                if apply_ssid or apply_password:
                    verified = _verify_wifi(
                        host,
                        username,
                        password,
                        wifi_ssid=wifi_ssid,
                        wifi_password=wifi_password,
                        check_ssid=bool(apply_ssid),
                        check_password=bool(apply_password),
                        wifi_mode=package["mode"],
                        port=port,
                    )
                    if verified.get("ok"):
                        return verified
                    return {
                        "ok": False,
                        "error": verified.get("error") or "Wi‑Fi update could not be confirmed.",
                    }
                return result

            last_error = result.get("error") or last_error
            break

        return {
            "ok": False,
            "updated": False,
            "error": last_error
            or "No Wi‑Fi interfaces found on this MikroTik (it may be wired-only).",
        }
    except TimeoutError:
        return {
            "ok": False,
            "error": "Timed out while updating Wi‑Fi on the router. Check API access and try again.",
            "timeout": True,
        }
    except ConnectionError as exc:
        return {"ok": False, "error": str(exc)}
    except OSError as exc:
        return {
            "ok": False,
            "error": f"Could not reach {host}:8728 to update Wi‑Fi.",
            "detail": str(exc),
        }
    except Exception as exc:
        return {"ok": False, "error": f"Wi‑Fi update failed: {exc}"}


def _find_user_id(sock: socket.socket, username: str) -> str:
    """Return RouterOS .id for a local user name."""
    username = (username or "").strip()
    if not username:
        return ""
    for row in _print(sock, "/user", props=".id,name"):
        if (row.get("name") or "").strip() == username:
            return (row.get(".id") or "").strip()
    return ""


def update_mikrotik_login_user(
    host: str,
    current_username: str,
    current_password: str,
    *,
    new_username: str = "",
    new_password: str = "",
    port: int = 8728,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """Change the RouterOS login username and/or password for the active user."""
    host = (host or "").strip()
    current_username = (current_username or "").strip()
    current_password = current_password or ""
    new_username = (new_username or "").strip() or current_username
    new_password = new_password or current_password

    if not host or not current_username:
        return {"ok": False, "error": "Current router credentials are required."}
    if not new_username:
        return {"ok": False, "error": "Enter the router username."}
    if not new_password:
        return {"ok": False, "error": "Enter the router password."}

    username_changed = new_username != current_username
    password_changed = new_password != current_password
    if not username_changed and not password_changed:
        return {"ok": True, "updated": False, "message": "Login credentials already match."}

    try:
        with _api_session(
            host, current_username, current_password, port=port, timeout=timeout
        ) as sock:
            user_id = _find_user_id(sock, current_username)
            if not user_id:
                return {
                    "ok": False,
                    "error": f"Could not find RouterOS user “{current_username}” to update.",
                }

            props: dict[str, str] = {}
            if password_changed:
                props["password"] = new_password
            if username_changed:
                props["name"] = new_username
            terminal = _set(sock, "/user", user_id, **props)
            if terminal.get("_reply") == "!trap":
                return {
                    "ok": False,
                    "error": terminal.get("message")
                    or "RouterOS rejected the login credential change.",
                }
    except TimeoutError:
        return {
            "ok": False,
            "error": "Timed out while updating the MikroTik login user.",
        }
    except ConnectionError as exc:
        return {"ok": False, "error": str(exc)}
    except OSError as exc:
        return {
            "ok": False,
            "error": f"Could not reach {host}:8728 to update login credentials.",
            "detail": str(exc),
        }
    except Exception as exc:
        return {"ok": False, "error": f"Login credential update failed: {exc}"}

    # Confirm the new credentials work.
    verify = test_mikrotik_api_login(
        host, new_username, new_password, port=port, timeout=min(timeout, 6.0)
    )
    if not verify.get("ok"):
        return {
            "ok": False,
            "error": verify.get("error")
            or "Login was changed on the router but could not be verified with the new credentials.",
        }
    return {
        "ok": True,
        "updated": True,
        "message": "MikroTik login credentials updated on the router.",
        "username": new_username,
    }


def apply_mikrotik_access_changes(
    *,
    current_host: str,
    current_username: str,
    current_password: str,
    current_wifi_ssid: str = "",
    current_wifi_password: str = "",
    new_host: str,
    new_username: str,
    new_password: str,
    new_wifi_ssid: str = "",
    new_wifi_password: str = "",
    port: int = 8728,
) -> dict[str, Any]:
    """Apply login + Wi‑Fi changes on the live MikroTik, then confirm access.

    Uses the currently saved session credentials to authenticate, applies requested
    Wi‑Fi and/or login-user updates on the device, and only reports success when
    the new credentials can still log in.
    """
    current_host = (current_host or "").strip()
    current_username = (current_username or "").strip()
    current_password = current_password or ""
    new_host = (new_host or "").strip()
    new_username = (new_username or "").strip()
    new_password = new_password or ""
    current_wifi_ssid = (current_wifi_ssid or "").strip()
    current_wifi_password = current_wifi_password or ""
    new_wifi_ssid = (new_wifi_ssid or "").strip()
    new_wifi_password = new_wifi_password or ""

    if not new_host:
        return {"ok": False, "error": "Enter the MikroTik IP address or hostname."}
    if not new_username:
        return {"ok": False, "error": "Enter the router username."}
    if not new_password:
        return {"ok": False, "error": "Enter the router password."}
    if not current_host or not current_username:
        return {"ok": False, "error": "Saved router credentials are missing."}

    wifi_changed = (new_wifi_ssid != current_wifi_ssid) or (
        new_wifi_password != current_wifi_password
    )
    login_changed = (new_username != current_username) or (new_password != current_password)

    # Prefer the new host (router may already be at the updated IP).
    connect_hosts: list[str] = []
    for candidate in (new_host, current_host):
        if candidate and candidate not in connect_hosts:
            connect_hosts.append(candidate)

    session_host = ""
    session_username = current_username
    session_password = current_password
    authenticated_with_new = False
    last_login_error = ""
    for host in connect_hosts:
        probe = test_mikrotik_api_login(
            host, current_username, current_password, timeout=5.0, port=port
        )
        if probe.get("ok"):
            session_host = host
            break
        last_login_error = probe.get("error") or last_login_error

    if not session_host:
        # Maybe the user already changed the password on the router and is syncing ISPCENTRIC.
        for host in connect_hosts:
            probe = test_mikrotik_api_login(
                host, new_username, new_password, timeout=5.0, port=port
            )
            if probe.get("ok"):
                session_host = host
                session_username = new_username
                session_password = new_password
                authenticated_with_new = True
                break
            last_login_error = probe.get("error") or last_login_error

    if not session_host:
        return {
            "ok": False,
            "error": last_login_error
            or "Could not sign in to the MikroTik with the current saved credentials.",
        }

    notes: list[str] = []

    # 1) Wi‑Fi first, while we still know a working login session.
    if wifi_changed and (new_wifi_ssid or new_wifi_password):
        wifi_result = configure_mikrotik_wifi(
            session_host,
            session_username,
            session_password,
            wifi_ssid=new_wifi_ssid,
            wifi_password=new_wifi_password,
            apply_ssid=bool(new_wifi_ssid) and new_wifi_ssid != current_wifi_ssid,
            apply_password=bool(new_wifi_password)
            and new_wifi_password != current_wifi_password,
            port=port,
        )
        if not wifi_result.get("ok"):
            return {
                "ok": False,
                "error": wifi_result.get("error")
                or "Could not update Wi‑Fi settings on the MikroTik.",
            }
        if wifi_result.get("updated"):
            notes.append("Wi‑Fi updated on the router")
        else:
            notes.append("Wi‑Fi already matched")

    # 2) Login username/password on the device.
    if login_changed and not authenticated_with_new:
        login_result = update_mikrotik_login_user(
            session_host,
            session_username,
            session_password,
            new_username=new_username,
            new_password=new_password,
            port=port,
        )
        if not login_result.get("ok"):
            return {
                "ok": False,
                "error": login_result.get("error")
                or "Could not update the MikroTik login user.",
            }
        if login_result.get("updated"):
            notes.append("Login credentials updated on the router")
        else:
            notes.append("Login credentials already matched")
    elif login_changed and authenticated_with_new:
        notes.append("Login credentials verified on the router")

    # 3) Final verification with the credentials that will be saved.
    final = test_mikrotik_api_login(
        new_host, new_username, new_password, timeout=5.0, port=port
    )
    if not final.get("ok"):
        # Fall back to the host we successfully used during this session.
        if new_host != session_host:
            final = test_mikrotik_api_login(
                session_host, new_username, new_password, timeout=5.0, port=port
            )
        if not final.get("ok"):
            return {
                "ok": False,
                "error": final.get("error")
                or "Changes may have been applied, but the new login could not be verified.",
            }

    if not notes:
        notes.append("Credentials verified on the router")

    return {
        "ok": True,
        "host": new_host,
        "username": new_username,
        "message": "; ".join(notes) + ".",
        "wifi_ssid": final.get("wifi_ssid") or new_wifi_ssid,
        "wifi_password": new_wifi_password,
    }


PPP_SECRET_TAG = "ispcentric-pppoe"
PPPOE_PROFILE_NAME = "ispcentric-pppoe"
# Out-of-period clients stay dialed in (CPE online) but this profile + firewall
# address-list drop stops surfing at the ISP NAS regardless of CPE state.
PPPOE_BLOCKED_PROFILE_NAME = "ispcentric-blocked"
PPPOE_BLOCKED_ADDRESS_LIST = "ispcentric-blocked"
RENEW_HOTSPOT_TAG = "ispcentric-renew"
RENEW_HOTSPOT_NAME = "ispcentric-renew"
RENEW_HOTSPOT_PROFILE = "ispcentric-renew"
RENEW_HOTSPOT_POOL = "ispcentric-renew"
RENEW_HOTSPOT_POOL_RANGES = "192.168.189.10-192.168.189.250"
RENEW_HOTSPOT_ADDRESS = "192.168.189.1"
RENEW_HOTSPOT_POOL_NETWORK = "192.168.189.0/24"
_RENEW_HOTSPOT_POOL_NET = ipaddress.ip_network(RENEW_HOTSPOT_POOL_NETWORK)

# ISP Hotspot on onboarded NAS routers (voucher / Hotspot clients).
ISP_HOTSPOT_TAG = "ispcentric-hotspot"
ISP_HOTSPOT_NAME = "ispcentric-hotspot"
ISP_HOTSPOT_PROFILE = "ispcentric-hotspot"
ISP_HOTSPOT_USER_PROFILE = "ispcentric-hs-default"
ISP_HOTSPOT_POOL = "ispcentric-hs"
ISP_HOTSPOT_POOL_RANGES = "10.50.50.10-10.50.50.250"
ISP_HOTSPOT_ADDRESS = "10.50.50.1"
ISP_HOTSPOT_POOL_NETWORK = "10.50.50.0/24"
_ISP_HOTSPOT_POOL_NET = ipaddress.ip_network(ISP_HOTSPOT_POOL_NETWORK)
# Authenticated Hotspot users are tagged with this list so PPPoE compulsory
# can still allow them while blocking free LAN/DHCP browsing.
ISP_HOTSPOT_OK_LIST = "ispcentric-hotspot-ok"

# Short-lived caches for captive-portal critical path (connect → pay redirect).
# Keys are intentionally narrow so a reconnect after renew still re-resolves.
_CAPTIVE_ORG_CACHE_TTL = 20
_CAPTIVE_SESSION_CACHE_TTL = 15
# PPP IP → customer must outlive brief API blips after block/kick/redial so the
# dst-nat renew page can still auto-fill without a signed CPE token.
_CAPTIVE_PPPOE_IP_CACHE_TTL = 60 * 60 * 6
_CAPTIVE_API_TIMEOUT = 1.5
_CAPTIVE_REDIRECT_CACHE_TTL = 20
_HOTSPOT_STACK_READY_TTL = 1800


def _is_disabled(row: dict[str, str]) -> bool:
    return (row.get("disabled") or "").strip().lower() in {"true", "yes"}


def _pppoe_password_is_readable(stored: str | None) -> bool:
    """
    Whether a /ppp/secret password print can be trusted for comparisons.

    Some RouterOS builds omit the password or mask it as ****. Treating those
    as a mismatch kicks the CPE on every subscription sweep, so the client
    router stuck in a dial-fail loop ("cannot dial-up") while Wi‑Fi devices
    briefly keep surfing on residual sessions.
    """
    value = (stored or "").strip()
    if not value:
        return False
    if set(value) <= {"*"}:
        return False
    return True


def _first_forward_drop_id(sock: socket.socket) -> str:
    """First forward-chain drop rule — insert allows before it when possible."""
    for row in _print(sock, "/ip/firewall/filter", props=".id,chain,action"):
        if (row.get("chain") or "") == "forward" and (row.get("action") or "") == "drop":
            return (row.get(".id") or "").strip()
    return ""


def _first_input_drop_id(sock: socket.socket) -> str:
    """
    First input-chain drop rule — insert allows before it when possible.

    Anchoring an input rule to the forward drop puts it below
    ``defconf: drop all not coming from LAN``, where it never matches.
    """
    for row in _print(sock, "/ip/firewall/filter", props=".id,chain,action"):
        if (row.get("chain") or "") == "input" and (row.get("action") or "") == "drop":
            return (row.get(".id") or "").strip()
    return ""


def _add_filter_rule(sock: socket.socket, rule: dict[str, str], *, place_before: str = "") -> dict[str, str]:
    words = ["/ip/firewall/filter/add"]
    for key, value in rule.items():
        words.append(f"={key}={value}")
    if place_before:
        words.append(f"=place-before={place_before}")
    _, terminal = _command(sock, words)
    return terminal


def _ensure_pppoe_nat(sock: socket.socket) -> None:
    """NAT for dialed PPPoE clients (pool subnet to WAN)."""
    for row in _print(
        sock,
        "/ip/firewall/nat",
        props=".id,chain,action,src-address,comment",
    ):
        comment = row.get("comment") or ""
        if PPP_SECRET_TAG in comment and (row.get("action") or "") == "masquerade":
            return
    _add(
        sock,
        "/ip/firewall/nat",
        chain="srcnat",
        action="masquerade",
        **{
            "src-address": PPPOE_POOL_NETWORK,
            "out-interface-list": "WAN",
            "comment": f"{PPP_SECRET_TAG} NAT",
        },
    )


def _interface_names(sock: socket.socket) -> list[str]:
    """Every interface name RouterOS currently knows about."""
    return [
        (row.get("name") or "").strip()
        for row in _print(sock, "/interface", props="name")
        if (row.get("name") or "").strip()
    ]


def _resolve_lan_interface(
    sock: socket.socket, preferred: str = "", *, exclude: str = ""
) -> str:
    """
    Pick the LAN / bridge interface that serves client devices.

    The saved name (default ``bridgeLocal``) frequently does not exist on the
    device — RouterOS 7 ships a bridge called ``bridge`` — and passing a name
    the router does not have makes every interface-scoped command fail with
    "input does not match any value of interface".
    """
    preferred = (preferred or "").strip()
    exclude = (exclude or "").strip()
    try:
        rows = _print(sock, "/interface", props="name,type,running")
    except Exception:
        # Never let a probe failure block the push; the caller's own commands
        # will surface a real error if the saved name is genuinely wrong.
        return preferred
    names = {(row.get("name") or "").strip() for row in rows if (row.get("name") or "").strip()}
    names.discard(exclude)
    if preferred and preferred in names:
        return preferred
    for candidate in ("bridgeLocal", "bridge", "br-lan", "LAN"):
        if candidate in names:
            return candidate
    bridges = [
        (row.get("name") or "").strip()
        for row in rows
        if (row.get("type") or "").strip().lower() == "bridge"
        and (row.get("name") or "").strip() != exclude
    ]
    if bridges:
        return bridges[0]
    for candidate in ("ether2", "ether3", "ether4", "ether5"):
        if candidate in names:
            return candidate
    if preferred and preferred != exclude:
        return preferred
    return next(iter(sorted(names)), "") or "bridge"


# Legacy name kept for callers that predate Hotspot sharing this resolver.
_resolve_pppoe_lan_interface = _resolve_lan_interface


def _interface_mismatch_error(sock: socket.socket, message: str, interface: str) -> str:
    """Turn RouterOS's opaque interface rejection into an actionable message."""
    try:
        available = _interface_names(sock)
    except Exception:
        available = []
    listing = ", ".join(available[:12]) if available else "none reported"
    return (
        f"{message} The router has no interface named “{interface}”. "
        f"Available interfaces: {listing}. Set the router's LAN bridge to one of these "
        "on the router detail page, then push again."
    )


def _ensure_pppoe_stack(
    sock: socket.socket,
    *,
    lan_interface: str,
    wan_interface: str = "ether1",
    compulsory: bool = False,
    portal_url: str = "",
) -> tuple[str, list[str]]:
    """
    Ensure MikroTik can accept PPPoE dial-ins and route them to the internet.

    When compulsory is True, free LAN/DHCP browsing to the WAN is dropped so only
    dialed PPPoE clients (pool subnet) and authenticated Hotspot clients can
    access the internet.

    Returns (profile_name, notes).
    """
    notes: list[str] = []
    wan_interface = (wan_interface or "ether1").strip() or "ether1"
    requested_lan = (lan_interface or "").strip()
    lan_interface = _resolve_lan_interface(
        sock, lan_interface, exclude=wan_interface
    )
    if requested_lan and requested_lan != lan_interface:
        notes.append(f"LAN interface {requested_lan} not found; using {lan_interface}")

    pool_names = {
        (row.get("name") or "").strip()
        for row in _print(sock, "/ip/pool", props="name")
    }
    if PPPOE_POOL_NAME not in pool_names:
        terminal = _add(
            sock,
            "/ip/pool",
            name=PPPOE_POOL_NAME,
            ranges=PPPOE_POOL_RANGES,
            comment=PPP_SECRET_TAG,
        )
        if terminal.get("_reply") == "!trap":
            raise ConnectionError(
                _trap_message(terminal, "Could not create the PPPoE IP pool on the MikroTik.")
            )
        notes.append("created PPPoE IP pool")

    profile_id = ""
    for row in _print(
        sock,
        "/ppp/profile",
        props=".id,name,local-address,remote-address,dns-server",
    ):
        if (row.get("name") or "").strip() == PPPOE_PROFILE_NAME:
            profile_id = (row.get(".id") or "").strip()
            break

    # use-encryption=no: many CPE routers fail PPPoE when MPPE is required.
    # only-one=yes: local secrets reject a second dial while the first session
    # is still up (credential sharing / multi-device use is blocked).
    profile_props = {
        "name": PPPOE_PROFILE_NAME,
        "local-address": PPPOE_LOCAL_ADDRESS,
        "remote-address": PPPOE_POOL_NAME,
        "dns-server": "8.8.8.8,1.1.1.1",
        "change-tcp-mss": "yes",
        "use-encryption": "no",
        "only-one": "yes",
        "comment": PPP_SECRET_TAG,
    }
    if profile_id:
        terminal = _set(sock, "/ppp/profile", profile_id, **profile_props)
        if terminal.get("_reply") == "!trap":
            soft = {
                "name": PPPOE_PROFILE_NAME,
                "local-address": PPPOE_LOCAL_ADDRESS,
                "remote-address": PPPOE_POOL_NAME,
                "dns-server": "8.8.8.8,1.1.1.1",
                "use-encryption": "no",
                "only-one": "yes",
                "comment": PPP_SECRET_TAG,
            }
            terminal = _set(sock, "/ppp/profile", profile_id, **soft)
            if terminal.get("_reply") == "!trap":
                raise ConnectionError(
                    _trap_message(terminal, "Could not update the PPPoE profile on the MikroTik.")
                )
        notes.append("updated PPPoE profile")
    else:
        terminal = _add(sock, "/ppp/profile", **profile_props)
        if terminal.get("_reply") == "!trap":
            soft = {
                "name": PPPOE_PROFILE_NAME,
                "local-address": PPPOE_LOCAL_ADDRESS,
                "remote-address": PPPOE_POOL_NAME,
                "dns-server": "8.8.8.8,1.1.1.1",
                "use-encryption": "no",
                "only-one": "yes",
                "comment": PPP_SECRET_TAG,
            }
            terminal = _add(sock, "/ppp/profile", **soft)
            if terminal.get("_reply") == "!trap":
                raise ConnectionError(
                    _trap_message(terminal, "Could not create the PPPoE profile on the MikroTik.")
                )
        notes.append("created PPPoE profile")

    notes.extend(_ensure_pppoe_blocked_profile(sock))

    _command(
        sock,
        [
            "/ppp/aaa/set",
            "=use-radius=no",
            "=accounting=no",
            "=use-one-session=yes",
        ],
    )
    notes.append("PPP AAA set to local secrets (one session per account)")

    server_id = ""
    for row in _print(
        sock,
        "/interface/pppoe-server/server",
        props=".id,service-name,interface,disabled,default-profile,comment",
    ):
        iface = (row.get("interface") or "").strip()
        comment = row.get("comment") or ""
        if iface == lan_interface or PPP_SECRET_TAG in comment:
            server_id = (row.get(".id") or "").strip()
            break
        if not server_id and not _is_disabled(row):
            server_id = (row.get(".id") or "").strip()

    server_props = {
        "service-name": "",
        "interface": lan_interface,
        "default-profile": PPPOE_PROFILE_NAME,
        "authentication": "pap,chap,mschap1,mschap2",
        "disabled": "no",
        "comment": PPP_SECRET_TAG,
    }
    if server_id:
        terminal = _set(sock, "/interface/pppoe-server/server", server_id, **server_props)
        if terminal.get("_reply") == "!trap":
            core = {
                "service-name": "",
                "interface": lan_interface,
                "default-profile": PPPOE_PROFILE_NAME,
                "disabled": "no",
                "comment": PPP_SECRET_TAG,
            }
            terminal = _set(sock, "/interface/pppoe-server/server", server_id, **core)
            if terminal.get("_reply") == "!trap":
                raise ConnectionError(
                    _trap_message(
                        terminal,
                        f"Could not enable PPPoE server on {lan_interface}.",
                    )
                )
        notes.append(f"enabled PPPoE server on {lan_interface}")
    else:
        terminal = _add(sock, "/interface/pppoe-server/server", **server_props)
        if terminal.get("_reply") == "!trap":
            core = {
                "service-name": "",
                "interface": lan_interface,
                "default-profile": PPPOE_PROFILE_NAME,
                "disabled": "no",
                "comment": PPP_SECRET_TAG,
            }
            terminal = _add(sock, "/interface/pppoe-server/server", **core)
            if terminal.get("_reply") == "!trap":
                raise ConnectionError(
                    _trap_message(
                        terminal,
                        (
                            f"Could not create PPPoE server on {lan_interface}. "
                            "Clients get no response until a server listens on that LAN."
                        ),
                    )
                )
        notes.append(f"created PPPoE server on {lan_interface}")

    _ensure_interface_list(sock, "WAN")
    _ensure_interface_list(sock, "LAN")
    _ensure_list_member(sock, "WAN", wan_interface)
    _ensure_list_member(sock, "LAN", lan_interface)
    _ensure_masquerade(sock)
    _ensure_pppoe_nat(sock)
    notes.append("ensured WAN NAT for PPPoE clients")

    _command(
        sock,
        [
            "/ip/dns/set",
            "=allow-remote-requests=yes",
            "=servers=1.1.1.1,8.8.8.8",
        ],
    )

    existing_pppoe_filters = [
        row
        for row in _print(sock, "/ip/firewall/filter", props=".id,comment")
        if PPP_SECRET_TAG in (row.get("comment") or "")
    ]
    for row in existing_pppoe_filters:
        item_id = (row.get(".id") or "").strip()
        if item_id:
            _remove(sock, "/ip/firewall/filter", item_id)

    place_before_drop = _first_forward_drop_id(sock)
    billing_ip = _portal_target_ipv4(portal_url) if portal_url else ""

    forward_rules: list[dict[str, str]] = []
    if billing_ip:
        # Expired clients must still reach the pay page and STK APIs.
        forward_rules.append(
            {
                "chain": "forward",
                "action": "accept",
                "src-address-list": PPPOE_BLOCKED_ADDRESS_LIST,
                "dst-address": billing_ip,
                "comment": f"{PPP_SECRET_TAG} blocked to billing",
            }
        )
    forward_rules.extend(
        [
            # Silent DROP makes HTTPS captive probes wait for the OS TCP timeout
            # (often 20–30s) before the device falls back to HTTP — that is the
            # "popup takes forever after dial-in" delay. RST fails those probes
            # in milliseconds so Windows/Android/iOS open the pay page promptly.
            # Plain HTTP never hits this rule: dstnat rewrites it to the billing
            # host first, so it leaves via LAN rather than WAN.
            {
                "chain": "forward",
                "action": "reject",
                "reject-with": "tcp-reset",
                "protocol": "tcp",
                "src-address-list": PPPOE_BLOCKED_ADDRESS_LIST,
                "out-interface-list": "WAN",
                "comment": f"{PPP_SECRET_TAG} reject https fast",
            },
            # Drop remaining expired-client traffic (UDP/ICMP) once tagged.
            {
                "chain": "forward",
                "action": "drop",
                "src-address-list": PPPOE_BLOCKED_ADDRESS_LIST,
                "out-interface-list": "WAN",
                "comment": f"{PPP_SECRET_TAG} block expired",
            },
            {
                "chain": "forward",
                "action": "accept",
                "connection-state": "established,related,untracked",
                "comment": f"{PPP_SECRET_TAG} forward OK",
            },
            {
                "chain": "forward",
                "action": "accept",
                "src-address": PPPOE_POOL_NETWORK,
                "out-interface-list": "WAN",
                "comment": f"{PPP_SECRET_TAG} PPPoE clients to internet",
            },
            {
                "chain": "input",
                "action": "accept",
                "protocol": "tcp",
                "dst-port": "8728",
                "comment": f"{PPP_SECRET_TAG} keep API",
            },
            # A dialed session arrives on a dynamic PPPoE interface, which is not
            # in the LAN interface list, so the default input drop kills its DNS.
            # Without name resolution a client never issues the HTTP request that
            # the expired-client redirect turns into the payment page — the device
            # just reports "no internet" and shows no captive popup.
            {
                "chain": "input",
                "action": "accept",
                "protocol": "udp",
                "dst-port": "53",
                "src-address": PPPOE_POOL_NETWORK,
                "comment": f"{PPP_SECRET_TAG} client DNS",
            },
            {
                "chain": "input",
                "action": "accept",
                "protocol": "tcp",
                "dst-port": "53",
                "src-address": PPPOE_POOL_NETWORK,
                "comment": f"{PPP_SECRET_TAG} client DNS",
            },
        ]
    )
    if compulsory:
        # Hotspot-authenticated clients (tagged by user profile address-list) may
        # share the LAN with free DHCP devices; allow them before the LAN drop.
        forward_rules.extend(
            [
                {
                    "chain": "forward",
                    "action": "accept",
                    "src-address-list": ISP_HOTSPOT_OK_LIST,
                    "out-interface-list": "WAN",
                    "comment": f"{PPP_SECRET_TAG} Hotspot clients to internet",
                },
                {
                    "chain": "forward",
                    "action": "accept",
                    "src-address": ISP_HOTSPOT_POOL_NETWORK,
                    "out-interface-list": "WAN",
                    "comment": f"{PPP_SECRET_TAG} Hotspot pool to internet",
                },
                {
                    "chain": "forward",
                    "action": "drop",
                    "in-interface-list": "LAN",
                    "out-interface-list": "WAN",
                    "comment": f"{PPP_SECRET_TAG} PPPoE compulsory",
                },
            ]
        )
    else:
        forward_rules.append(
            {
                "chain": "forward",
                "action": "accept",
                "in-interface-list": "LAN",
                "out-interface-list": "WAN",
                "comment": f"{PPP_SECRET_TAG} LAN to internet",
            }
        )
    place_before_input_drop = _first_input_drop_id(sock)
    for rule in forward_rules:
        anchor = (
            place_before_input_drop
            if rule.get("chain") == "input"
            else place_before_drop
        )
        terminal = _add_filter_rule(sock, rule, place_before=anchor)
        if terminal.get("_reply") == "!trap" and anchor:
            _add_filter_rule(sock, rule)
    notes.append(
        "PPPoE compulsory firewall (Hotspot clients allowed)"
        if compulsory
        else "LAN forward allow"
    )
    notes.append(f"forward allow {PPPOE_POOL_NETWORK} to WAN")
    if compulsory:
        notes.append(f"forward allow address-list {ISP_HOTSPOT_OK_LIST} to WAN")
        notes.append(f"forward allow {ISP_HOTSPOT_POOL_NETWORK} to WAN")
    notes.append(f"forward reject-tcp address-list {PPPOE_BLOCKED_ADDRESS_LIST}")
    notes.append(f"forward drop address-list {PPPOE_BLOCKED_ADDRESS_LIST}")
    if billing_ip:
        notes.append(f"forward allow blocked clients to billing {billing_ip}")
        notes.extend(_ensure_pppoe_expired_redirect(sock, billing_ip, portal_url))
        # Only hijack probe DNS when Hotspot is not sharing this resolver.
        # Authenticated Hotspot clients use the same NAS DNS; pointing
        # msftconnecttest at billing would make paid surfers look offline.
        if not compulsory:
            dns_added = _ensure_captive_dns(sock, billing_ip, PPP_SECRET_TAG)
            notes.append(
                f"captive probe DNS → {billing_ip}"
                + (f" ({dns_added} host(s))" if dns_added else "")
            )
        else:
            # Stale entries from a previous PPPoE-only push would still break
            # Hotspot NCSI — clear them whenever compulsory mode is on.
            cleared = _clear_captive_dns_hijack(sock, PPP_SECRET_TAG)
            if cleared:
                notes.append("cleared PPPoE captive DNS hijack for Hotspot coexistence")

    return PPPOE_PROFILE_NAME, notes


def _prefer_http_captive_url(url: str) -> str:
    """Captive WebViews stall on HTTPS/HSTS — prefer http:// for pay popups."""
    url = (url or "").strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if (parsed.scheme or "").lower() != "https" or not parsed.hostname:
        return url
    netloc = parsed.hostname
    if parsed.port and parsed.port not in (80, 443):
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse(
        ("http", netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )


def _resolve_absolute_captive_url(url: str = "") -> str:
    """
    Turn a path or blank into an absolute pay URL using PUBLIC_BASE_URL / LAN base.

    Returns "" when no absolute URL can be formed — callers must abort enable.
    """
    url = (url or "").strip()
    if url and urlparse(url).scheme:
        return _prefer_http_captive_url(url)
    base = _billing_portal_base_url()
    if not base:
        return ""
    if not url:
        return _prefer_http_captive_url(base)
    path = url if url.startswith("/") else f"/{url}"
    return _prefer_http_captive_url(f"{base.rstrip('/')}{path}")


def _normalize_hotspot_portal_urls(
    *,
    pay_url: str = "",
    login_url: str = "",
    welcome_url: str = "",
    alogin_url: str = "",
    redirect_url: str = "",
) -> dict[str, str]:
    """Single place to absolutize Hotspot captive URLs (avoids resolve twice)."""
    pay = _resolve_absolute_captive_url(pay_url or login_url or "")
    login = _resolve_absolute_captive_url(login_url) or pay
    welcome = _resolve_absolute_captive_url(
        welcome_url or redirect_url or alogin_url or ""
    )
    alogin = _resolve_absolute_captive_url(alogin_url) or welcome
    redirect = _resolve_absolute_captive_url(redirect_url) or welcome
    return {
        "pay_url": pay,
        "login_url": login,
        "welcome_url": welcome,
        "alogin_url": alogin,
        "redirect_url": redirect,
    }


def _billing_portal_base_url(explicit: str = "") -> str:
    """
    Absolute origin for pay redirects / NAT pushed to MikroTik and CPEs.

    Prefer a usable explicit URL, otherwise the same hosted-aware
    ``public_base_url()`` Hotspot already uses. Raw ``settings.PUBLIC_BASE_URL``
    alone is unsafe: empty/``auto`` yields relative CPE redirects that stick
    phones on ``http://192.168.…/pppoe/…/pay/``, and stale LAN leftovers on a
    VPS are unreachable from subscriber sites.
    """
    candidate = (explicit or "").strip().rstrip("/")
    if candidate:
        try:
            from core.hotspot_portal import (
                _configured_base_is_usable,
                _normalize_configured_base,
            )

            normalized = _normalize_configured_base(candidate) or candidate
            # Full pay URLs (…/pppoe/…/pay) are fine for NAT / walled garden —
            # usability is about the host, not the path.
            if _configured_base_is_usable(normalized):
                return normalized.rstrip("/")
            parsed = urlparse(normalized)
            if (
                parsed.scheme
                and parsed.hostname
                and parsed.path
                and parsed.path not in {"", "/"}
                and _configured_base_is_usable(
                    f"{parsed.scheme}://{parsed.hostname}"
                    + (f":{parsed.port}" if parsed.port else "")
                )
            ):
                return normalized.rstrip("/")
        except Exception:
            pass

    try:
        from core.hotspot_portal import public_base_url

        return (public_base_url() or "").strip().rstrip("/")
    except Exception:
        return (getattr(settings, "PUBLIC_BASE_URL", "") or "").strip().rstrip("/")

def _portal_target_ipv4(portal_url: str) -> str:
    """
    IPv4 the portal is reachable at, resolving a hostname when needed.

    dst-nat needs a literal address, so a domain-based PUBLIC_BASE_URL (the
    normal setup once billing runs on a VPS) has to be resolved here or the
    expired-client redirect would silently never install.
    """
    direct = _routable_ipv4_from_url(portal_url)
    if direct:
        return direct
    try:
        host = (urlparse((portal_url or "").strip()).hostname or "").strip()
        if not host:
            return ""
        resolved = ipaddress.ip_address(socket.gethostbyname(host))
    except (ValueError, OSError):
        return ""
    if resolved.version != 4 or resolved.is_loopback or resolved.is_unspecified:
        return ""
    return str(resolved)


def _portal_http_port(portal_url: str) -> str:
    """
    Port for expired-client HTTP dst-nat.

    Captive probes are always plain HTTP. Even when PUBLIC_BASE_URL is https://,
    dst-nat must land on an HTTP listener (nginx :80 or Django's explicit
    http://host:8000 port) — never 443, which would break the pay popup.
    """
    try:
        parsed = urlparse((portal_url or "").strip())
        scheme = (parsed.scheme or "").lower()
        if scheme == "https":
            return "80"
        if parsed.port:
            return str(parsed.port)
        return "80"
    except Exception:
        return "80"


def _ensure_pppoe_expired_redirect(
    sock: socket.socket,
    billing_ip: str,
    portal_url: str,
) -> list[str]:
    """
    Send plain-HTTP traffic from expired PPPoE sessions to the billing server.

    HTTPS cannot be intercepted without a certificate warning, so this only
    covers port 80 — enough for OS captive probes and neverssl-style checks.
    The billing app then 302s the browser onto the PPPoE pay page.
    """
    notes: list[str] = []
    billing_ip = (billing_ip or "").strip()
    if not billing_ip:
        return notes
    to_port = _portal_http_port(portal_url)

    for row in _print(
        sock,
        "/ip/firewall/nat",
        props=".id,comment,chain,action",
    ):
        comment = row.get("comment") or ""
        if PPP_SECRET_TAG not in comment:
            continue
        if "expired redirect" not in comment and "expired dns" not in comment:
            continue
        item_id = (row.get(".id") or "").strip()
        if item_id:
            _remove(sock, "/ip/firewall/nat", item_id)

    for protocol in ("udp", "tcp"):
        terminal = _add(
            sock,
            "/ip/firewall/nat",
            chain="dstnat",
            protocol=protocol,
            **{
                "src-address-list": PPPOE_BLOCKED_ADDRESS_LIST,
                "dst-port": "53",
                "action": "redirect",
                "to-ports": "53",
                "comment": f"{PPP_SECRET_TAG} expired dns",
            },
        )
        if terminal.get("_reply") == "!trap":
            notes.append(f"warning: could not force {protocol}/53 for expired clients")
        else:
            notes.append(f"expired-client DNS redirect ({protocol}/53)")

    terminal = _add(
        sock,
        "/ip/firewall/nat",
        chain="dstnat",
        protocol="tcp",
        **{
            "src-address-list": PPPOE_BLOCKED_ADDRESS_LIST,
            "dst-port": "80",
            "action": "dst-nat",
            "to-addresses": billing_ip,
            "to-ports": to_port,
            "comment": f"{PPP_SECRET_TAG} expired redirect",
        },
    )
    if terminal.get("_reply") == "!trap":
        notes.append(
            f"warning: could not redirect expired PPPoE HTTP to {billing_ip}:{to_port}"
        )
    else:
        notes.append(f"expired PPPoE HTTP → {billing_ip}:{to_port}")
    return notes


def _pppoe_expired_http_redirect_ok(sock: socket.socket, billing_ip: str = "") -> bool:
    """True when the NAS still has the expired-client HTTP dst-nat rule."""
    billing_ip = (billing_ip or "").strip()
    for row in _print(
        sock,
        "/ip/firewall/nat",
        props=".id,comment,chain,action,to-addresses,dst-port",
    ):
        comment = row.get("comment") or ""
        if PPP_SECRET_TAG not in comment or "expired redirect" not in comment:
            continue
        if (row.get("chain") or "").strip() != "dstnat":
            continue
        if (row.get("action") or "").strip() not in {"dst-nat", "netmap"}:
            continue
        if billing_ip and (row.get("to-addresses") or "").strip() not in {
            billing_ip,
            f"{billing_ip}/32",
        }:
            continue
        return True
    return False


def _ensure_pppoe_fast_captive_reject(sock: socket.socket) -> list[str]:
    """
    RST blocked HTTPS probes so phones fall back to HTTP in milliseconds.

    Without this, Android/iOS wait on a silent DROP (often 20–30s) before the
    captive popup appears — users report "expired but no redirect".
    """
    notes: list[str] = []
    has_reject = False
    has_drop = False
    for row in _print(sock, "/ip/firewall/filter", props=".id,comment,action"):
        comment = row.get("comment") or ""
        if PPP_SECRET_TAG not in comment:
            continue
        if "reject https fast" in comment:
            has_reject = True
        if "block expired" in comment:
            has_drop = True
    place_before = _first_forward_drop_id(sock)
    if not has_reject:
        terminal = _add_filter_rule(
            sock,
            {
                "chain": "forward",
                "action": "reject",
                "reject-with": "tcp-reset",
                "protocol": "tcp",
                "src-address-list": PPPOE_BLOCKED_ADDRESS_LIST,
                "out-interface-list": "WAN",
                "comment": f"{PPP_SECRET_TAG} reject https fast",
            },
            place_before=place_before,
        )
        if terminal.get("_reply") != "!trap":
            notes.append("fast HTTPS reject for expired clients")
        else:
            notes.append("warning: could not install fast HTTPS reject")
    if not has_drop:
        terminal = _add_filter_rule(
            sock,
            {
                "chain": "forward",
                "action": "drop",
                "src-address-list": PPPOE_BLOCKED_ADDRESS_LIST,
                "out-interface-list": "WAN",
                "comment": f"{PPP_SECRET_TAG} block expired",
            },
            place_before=place_before,
        )
        if terminal.get("_reply") != "!trap":
            notes.append("WAN drop for expired clients")
    return notes


def _ensure_pppoe_client_dns_accept(sock: socket.socket) -> list[str]:
    """
    Let dialed PPPoE clients resolve names on the NAS.

    Without this, expired sessions never issue the HTTP probe that dst-nat turns
    into the pay page — devices report "connected, no internet" with no popup.
    """
    notes: list[str] = []
    existing = {
        (
            (row.get("protocol") or "").strip().lower(),
            (row.get("dst-port") or "").strip(),
            (row.get("src-address") or "").strip(),
        )
        for row in _print(
            sock,
            "/ip/firewall/filter",
            props=".id,chain,action,protocol,dst-port,src-address,comment",
        )
        if PPP_SECRET_TAG in (row.get("comment") or "")
        and (row.get("chain") or "").strip() == "input"
        and (row.get("action") or "").strip() == "accept"
        and "client DNS" in (row.get("comment") or "")
    }
    input_anchor = ""
    for row in _print(sock, "/ip/firewall/filter", props=".id,chain,action"):
        if (row.get("chain") or "").strip() != "input":
            continue
        if (row.get("action") or "").strip() == "drop":
            input_anchor = (row.get(".id") or "").strip()
            break
    for protocol in ("udp", "tcp"):
        key = (protocol, "53", PPPOE_POOL_NETWORK)
        if key in existing:
            continue
        terminal = _add_filter_rule(
            sock,
            {
                "chain": "input",
                "action": "accept",
                "protocol": protocol,
                "dst-port": "53",
                "src-address": PPPOE_POOL_NETWORK,
                "comment": f"{PPP_SECRET_TAG} client DNS",
            },
            place_before=input_anchor or "",
        )
        if terminal.get("_reply") != "!trap":
            notes.append(f"PPPoE client DNS accept ({protocol}/53)")
    return notes


def _ensure_pppoe_expired_access(
    sock: socket.socket,
    *,
    portal_url: str = "",
) -> list[str]:
    """
    Ensure blocked PPPoE clients can reach the pay page (billing allow + HTTP redirect).

    Lightweight companion to full stack push — used on expiry so renew works even
    when ensure_stack=False. Retries a few times so a flaky API write cannot leave
    expired clients with "no internet" and no captive popup.
    """
    notes: list[str] = []

    portal = _billing_portal_base_url(portal_url)
    billing_ip = _portal_target_ipv4(portal) if portal else ""
    if not billing_ip:
        notes.append("warning: no billing IP — expired pay redirect not installed")
        return notes

    for attempt in range(1, _CAPTIVE_REPAIR_ATTEMPTS + 1):
        attempt_notes: list[str] = []
        attempt_notes.extend(_ensure_pppoe_client_dns_accept(sock))
        attempt_notes.extend(_ensure_pppoe_expired_redirect(sock, billing_ip, portal))
        attempt_notes.extend(_ensure_pppoe_fast_captive_reject(sock))

        has_billing_allow = any(
            PPP_SECRET_TAG in (row.get("comment") or "")
            and "blocked to billing" in (row.get("comment") or "")
            for row in _print(sock, "/ip/firewall/filter", props=".id,comment")
        )
        if not has_billing_allow:
            place_before = _first_forward_drop_id(sock)
            terminal = _add_filter_rule(
                sock,
                {
                    "chain": "forward",
                    "action": "accept",
                    "src-address-list": PPPOE_BLOCKED_ADDRESS_LIST,
                    "dst-address": billing_ip,
                    "comment": f"{PPP_SECRET_TAG} blocked to billing",
                },
                place_before=place_before,
            )
            if terminal.get("_reply") != "!trap":
                attempt_notes.append(f"blocked clients allowed to billing {billing_ip}")
            else:
                attempt_notes.append(
                    "warning: could not allow blocked clients to billing host"
                )

        notes.extend(attempt_notes)
        if _pppoe_expired_http_redirect_ok(sock, billing_ip):
            if attempt > 1:
                notes.append(f"expired redirect repaired on attempt {attempt}")
            return notes
        notes.append(
            f"expired HTTP redirect missing after attempt {attempt}; correcting…"
        )

    notes.append(
        "warning: expired HTTP redirect still missing after "
        f"{_CAPTIVE_REPAIR_ATTEMPTS} attempts"
    )
    return notes


def repair_router_expired_captive_redirect(
    router,
    *,
    portal_url: str = "",
) -> dict[str, Any]:
    """
    Re-install NAS expired-client redirect rules for one MikroTik.

    Used by the subscription sweep so every router that still has blocked
    clients keeps an instant pay popup even if rules were deleted on-box.
    """
    host = (getattr(router, "api_host", None) or getattr(router, "host", None) or "").strip()
    username = (getattr(router, "username", None) or "").strip()
    password = getattr(router, "password", None) or ""
    if not host or not username:
        return {"ok": False, "skipped": True, "error": "Router host or API user missing."}
    portal = _billing_portal_base_url(portal_url)
    try:
        with _api_session(host, username, password, timeout=8.0) as sock:
            notes = _ensure_pppoe_expired_access(sock, portal_url=portal)
            notes.extend(_ensure_pppoe_blocked_profile(sock))
        return {
            "ok": True,
            "skipped": False,
            "notes": notes,
            "message": "; ".join(notes) if notes else "expired captive redirect ok",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "skipped": False,
            "error": str(exc) or "Could not repair expired redirect.",
        }


def _ensure_pppoe_blocked_profile(sock: socket.socket) -> list[str]:
    """
    PPP profile for out-of-subscription clients.

    Same pool as normal PPPoE (CPE stays online) but tags the session IP with
    an address-list that the NAS firewall drops to WAN.
    """
    notes: list[str] = []
    profile_id = ""
    for row in _print(
        sock,
        "/ppp/profile",
        props=".id,name,local-address,remote-address,address-list",
    ):
        if (row.get("name") or "").strip() == PPPOE_BLOCKED_PROFILE_NAME:
            profile_id = (row.get(".id") or "").strip()
            break

    profile_props = {
        "name": PPPOE_BLOCKED_PROFILE_NAME,
        "local-address": PPPOE_LOCAL_ADDRESS,
        "remote-address": PPPOE_POOL_NAME,
        # Point DNS at the NAS itself. External resolvers are unreachable once
        # the blocked address-list is dropped to WAN, and a browser that cannot
        # resolve a hostname never sends the HTTP request we intercept.
        "dns-server": PPPOE_LOCAL_ADDRESS,
        "change-tcp-mss": "yes",
        "use-encryption": "no",
        "only-one": "yes",
        "address-list": PPPOE_BLOCKED_ADDRESS_LIST,
        "comment": f"{PPP_SECRET_TAG} no-internet",
    }
    soft = {
        "name": PPPOE_BLOCKED_PROFILE_NAME,
        "local-address": PPPOE_LOCAL_ADDRESS,
        "remote-address": PPPOE_POOL_NAME,
        "dns-server": PPPOE_LOCAL_ADDRESS,
        "use-encryption": "no",
        "only-one": "yes",
        "address-list": PPPOE_BLOCKED_ADDRESS_LIST,
        "comment": f"{PPP_SECRET_TAG} no-internet",
    }
    if profile_id:
        terminal = _set(sock, "/ppp/profile", profile_id, **profile_props)
        if terminal.get("_reply") == "!trap":
            terminal = _set(sock, "/ppp/profile", profile_id, **soft)
            if terminal.get("_reply") == "!trap":
                raise ConnectionError(
                    _trap_message(
                        terminal,
                        "Could not update the blocked PPPoE profile on the MikroTik.",
                    )
                )
        notes.append("updated blocked PPPoE profile")
    else:
        terminal = _add(sock, "/ppp/profile", **profile_props)
        if terminal.get("_reply") == "!trap":
            terminal = _add(sock, "/ppp/profile", **soft)
            if terminal.get("_reply") == "!trap":
                raise ConnectionError(
                    _trap_message(
                        terminal,
                        "Could not create the blocked PPPoE profile on the MikroTik.",
                    )
                )
        notes.append("created blocked PPPoE profile")
    return notes


def _plan_speeds_mbps(plan) -> tuple[int, int]:
    """
    Return (upload_mbps, download_mbps) from a billing plan.

    Both are forced to at least 1 when either side is set so RouterOS always
    gets a complete rx/tx pair.
    """
    if plan is None:
        return 0, 0
    upload = int(getattr(plan, "upload_speed_mbps", 0) or 0)
    download = int(
        getattr(plan, "download_speed_mbps", 0)
        or getattr(plan, "speed_mbps", 0)
        or 0
    )
    if upload < 1 and download < 1:
        return 0, 0
    if upload < 1:
        upload = download
    if download < 1:
        download = upload
    return upload, download


def _rate_limit_string(upload_mbps: int, download_mbps: int) -> str:
    """RouterOS rate-limit (rx=upload / tx=download from the router's view)."""
    upload = int(upload_mbps or 0)
    download = int(download_mbps or 0)
    if upload < 1 and download < 1:
        return ""
    if upload < 1:
        upload = download
    if download < 1:
        download = upload
    return f"{upload}M/{download}M"


def _pppoe_speeds_for_customer(customer) -> tuple[int, int]:
    return _plan_speeds_mbps(getattr(customer, "plan", None))


def _pppoe_rate_limit_for_customer(customer) -> str:
    """RouterOS rate-limit string for this customer's package."""
    upload, download = _pppoe_speeds_for_customer(customer)
    return _rate_limit_string(upload, download)


def _pppoe_speed_profile_name(upload_mbps: int, download_mbps: int) -> str:
    """Stable per-package PPP profile name carrying that plan's rate-limit."""
    return f"ispcentric-pppoe-{int(upload_mbps)}u-{int(download_mbps)}d"


def _ensure_pppoe_rate_profile(
    sock: socket.socket,
    *,
    upload_mbps: int,
    download_mbps: int,
) -> str:
    """
    Create/update a PPP profile that shapes traffic to the plan speeds.

    MikroTik applies profile rate-limit as a dynamic simple queue when the
    client dials, which is the reliable way to enforce per-package speeds
    (many RouterOS builds reject rate-limit on /ppp/secret itself).
    """
    upload = int(upload_mbps or 0)
    download = int(download_mbps or 0)
    if upload < 1 or download < 1:
        return PPPOE_PROFILE_NAME

    name = _pppoe_speed_profile_name(upload, download)
    rate_limit = _rate_limit_string(upload, download)
    profile_id = ""
    for row in _print(
        sock,
        "/ppp/profile",
        props=".id,name,rate-limit",
    ):
        if (row.get("name") or "").strip() == name:
            profile_id = (row.get(".id") or "").strip()
            break

    profile_props = {
        "name": name,
        "local-address": PPPOE_LOCAL_ADDRESS,
        "remote-address": PPPOE_POOL_NAME,
        "dns-server": "8.8.8.8,1.1.1.1",
        "change-tcp-mss": "yes",
        "use-encryption": "no",
        "only-one": "yes",
        "rate-limit": rate_limit,
        "comment": f"{PPP_SECRET_TAG} {rate_limit}",
    }
    soft = {
        "name": name,
        "local-address": PPPOE_LOCAL_ADDRESS,
        "remote-address": PPPOE_POOL_NAME,
        "dns-server": "8.8.8.8,1.1.1.1",
        "use-encryption": "no",
        "only-one": "yes",
        "rate-limit": rate_limit,
        "comment": f"{PPP_SECRET_TAG} {rate_limit}",
    }
    # Last resort: profile without rate-limit still lets dial work; secret /
    # simple-queue paths below then carry the shaping.
    bare = {
        "name": name,
        "local-address": PPPOE_LOCAL_ADDRESS,
        "remote-address": PPPOE_POOL_NAME,
        "dns-server": "8.8.8.8,1.1.1.1",
        "use-encryption": "no",
        "only-one": "yes",
        "comment": f"{PPP_SECRET_TAG} {rate_limit}",
    }

    if profile_id:
        terminal = _set(sock, "/ppp/profile", profile_id, **profile_props)
        if terminal.get("_reply") == "!trap":
            terminal = _set(sock, "/ppp/profile", profile_id, **soft)
        if terminal.get("_reply") == "!trap":
            terminal = _set(sock, "/ppp/profile", profile_id, **bare)
        if terminal.get("_reply") == "!trap":
            raise ConnectionError(
                _trap_message(
                    terminal,
                    f"Could not update PPPoE speed profile “{name}” on the MikroTik.",
                )
            )
    else:
        terminal = _add(sock, "/ppp/profile", **profile_props)
        if terminal.get("_reply") == "!trap":
            terminal = _add(sock, "/ppp/profile", **soft)
        if terminal.get("_reply") == "!trap":
            terminal = _add(sock, "/ppp/profile", **bare)
        if terminal.get("_reply") == "!trap":
            raise ConnectionError(
                _trap_message(
                    terminal,
                    f"Could not create PPPoE speed profile “{name}” on the MikroTik.",
                )
            )
    return name


def _ensure_pppoe_simple_queue(
    sock: socket.socket,
    *,
    username: str,
    rate_limit: str,
) -> None:
    """
    Shape active PPPoE session IP(s) with a named simple queue.

    Profile rate-limit covers new dials; this keeps an already-online session
    capped immediately and survives RouterOS builds that ignore profile shaping.
    """
    username = (username or "").strip()
    rate_limit = (rate_limit or "").strip()
    if not username or not rate_limit:
        return

    targets = sorted(
        {
            (row.get("address") or "").strip()
            for row in _print(sock, "/ppp/active", props="name,address")
            if (row.get("name") or "").strip().lower() == username.lower()
            and (row.get("address") or "").strip()
        }
    )
    queue_name = f"ispcentric-rl-{username}"[:63]
    comment = f"{PPP_SECRET_TAG} {rate_limit}"

    existing: dict[str, str] = {}
    for row in _print(
        sock,
        "/queue/simple",
        props=".id,name,target,max-limit,comment",
    ):
        if (row.get("name") or "").strip() == queue_name:
            existing = row
            break

    if not targets:
        # No live session — drop a stale queue so a later dial relies on profile.
        item_id = (existing.get(".id") or "").strip()
        if item_id:
            _remove(sock, "/queue/simple", item_id)
        return

    # One queue covering every concurrent session IP for this username.
    target = ",".join(targets)
    props = {
        "name": queue_name,
        "target": target,
        "max-limit": rate_limit,
        "comment": comment,
    }
    item_id = (existing.get(".id") or "").strip()
    if item_id:
        terminal = _set(sock, "/queue/simple", item_id, **props)
        if terminal.get("_reply") == "!trap":
            # Older builds use limit-at / differently named fields — best-effort.
            soft = {"name": queue_name, "target": target, "max-limit": rate_limit}
            terminal = _set(sock, "/queue/simple", item_id, **soft)
        if terminal.get("_reply") == "!trap":
            return
    else:
        terminal = _add(sock, "/queue/simple", **props)
        if terminal.get("_reply") == "!trap":
            soft = {"name": queue_name, "target": target, "max-limit": rate_limit}
            terminal = _add(sock, "/queue/simple", **soft)
        if terminal.get("_reply") == "!trap":
            return


def _ppp_secret_profile_for_customer(customer, *, disabled: bool) -> str:
    """Speed profile when surfing is allowed; blocked profile when period is inactive."""
    if disabled:
        # Secret disabled entirely — profile unused, keep base for when re-enabled.
        return PPPOE_PROFILE_NAME
    if not _customer_internet_allowed(customer):
        return PPPOE_BLOCKED_PROFILE_NAME
    upload, download = _pppoe_speeds_for_customer(customer)
    if upload >= 1 and download >= 1:
        return _pppoe_speed_profile_name(upload, download)
    return PPPOE_PROFILE_NAME


def _current_ppp_secret_profile(sock: socket.socket, username: str) -> str:
    username = (username or "").strip()
    if not username:
        return ""
    rows = _print(
        sock,
        "/ppp/secret",
        props="name,profile",
        query={"name": username},
    )
    if not rows:
        # Fallback: older RouterOS may ignore exact name queries.
        rows = _print(sock, "/ppp/secret", props="name,profile")
    needle = username.lower()
    for row in rows:
        if (row.get("name") or "").strip().lower() == needle:
            return (row.get("profile") or "").strip()
    return ""


def _customer_internet_allowed(customer) -> bool:
    """Whether this customer should have unrestricted internet (surfing)."""
    try:
        from billing.services import customer_receives_internet

        return bool(customer_receives_internet(customer))
    except Exception:
        return getattr(customer, "status", "") == "active"


def _customer_pppoe_secret_disabled(customer) -> bool:
    """Whether /ppp/secret should be disabled on the ISP MikroTik."""
    try:
        from billing.services import customer_pppoe_secret_disabled

        return bool(customer_pppoe_secret_disabled(customer))
    except Exception:
        return getattr(customer, "status", "") != "active"


def _disconnect_pppoe_sessions(sock: socket.socket, username: str) -> int:
    """Drop active PPP sessions so a password change takes effect immediately."""
    username = (username or "").strip()
    if not username:
        return 0
    removed = 0
    rows = _print(
        sock,
        "/ppp/active",
        props=".id,name",
        query={"name": username},
    )
    if not rows:
        rows = _print(sock, "/ppp/active", props=".id,name")
    for row in rows:
        if (row.get("name") or "").strip().lower() != username.lower():
            continue
        item_id = (row.get(".id") or "").strip()
        if not item_id:
            continue
        terminal = _remove(sock, "/ppp/active", item_id)
        if terminal.get("_reply") != "!trap":
            removed += 1
    return removed


def _active_pppoe_session_is_blocked(sock: socket.socket, username: str) -> bool:
    """Whether this user's current session IP still carries the blocked tag."""
    username = (username or "").strip().lower()
    if not username:
        return False
    active_addresses = {
        (row.get("address") or "").strip()
        for row in _print(sock, "/ppp/active", props="name,address")
        if (row.get("name") or "").strip().lower() == username
    }
    active_addresses.discard("")
    if not active_addresses:
        return False
    return any(
        (row.get("list") or "").strip() == PPPOE_BLOCKED_ADDRESS_LIST
        and (row.get("address") or "").strip() in active_addresses
        for row in _print(sock, "/ip/firewall/address-list", props="list,address")
    )


def _ensure_ppp_secret(
    sock: socket.socket,
    *,
    username: str,
    password: str,
    profile: str = PPPOE_PROFILE_NAME,
    comment: str = "",
    disabled: bool = False,
    rate_limit: str = "",
) -> str:
    """
    Create or update /ppp/secret so a CPE can dial this username/password.

    Always writes the password in a dedicated follow-up set (some RouterOS builds
    drop password when mixed with other properties), then verifies the secret exists.

    Returns 'created' or 'updated'.
    """
    username = (username or "").strip()
    password = password or ""
    if not username:
        raise ConnectionError("PPPoE username is empty.")
    if not password:
        raise ConnectionError("PPPoE password is empty.")

    profile = (profile or PPPOE_PROFILE_NAME).strip() or PPPOE_PROFILE_NAME
    comment = (comment or "").strip() or PPP_SECRET_TAG
    disabled_value = "no" if not disabled else "yes"
    rate_limit = (rate_limit or "").strip()

    # Ensure the per-package speed profile exists before assigning the secret.
    if (
        rate_limit
        and profile not in {PPPOE_PROFILE_NAME, PPPOE_BLOCKED_PROFILE_NAME}
        and profile.startswith("ispcentric-pppoe-")
    ):
        try:
            upload_s, _, download_s = rate_limit.partition("/")
            upload_mbps = int((upload_s or "").rstrip("MmKk").strip() or 0)
            download_mbps = int((download_s or "").rstrip("MmKk").strip() or 0)
            if upload_mbps >= 1 and download_mbps >= 1:
                profile = _ensure_pppoe_rate_profile(
                    sock,
                    upload_mbps=upload_mbps,
                    download_mbps=download_mbps,
                )
        except (TypeError, ValueError):
            pass

    secret_id = ""
    previous_profile = ""
    previous_disabled = ""
    previous_password = ""
    rows = _print(
        sock,
        "/ppp/secret",
        props=".id,name,profile,service,disabled,comment,password",
        query={"name": username},
    )
    if not rows:
        rows = _print(
            sock,
            "/ppp/secret",
            props=".id,name,profile,service,disabled,comment,password",
        )
    for row in rows:
        if (row.get("name") or "").strip().lower() == username.lower():
            secret_id = (row.get(".id") or "").strip()
            previous_profile = (row.get("profile") or "").strip()
            previous_disabled = (row.get("disabled") or "").strip().lower()
            previous_password = row.get("password") or ""
            break

    # service=any: accept dial-in regardless of CPE service-name quirks.
    # only-one=yes: per-secret guard so a second device cannot dial while the
    # first session is still connected (profile-level only-one is the primary).
    base_props = {
        "name": username,
        "service": "any",
        "profile": profile,
        "disabled": disabled_value,
        "comment": comment,
        "only-one": "yes",
    }
    # Older RouterOS builds may not accept only-one on /ppp/secret — profile
    # only-one still enforces single-session.
    core_props = {
        "name": username,
        "service": "any",
        "profile": profile,
        "disabled": disabled_value,
        "comment": comment,
    }

    action = "updated"
    created = False
    if secret_id:
        terminal = _set(sock, "/ppp/secret", secret_id, **base_props)
        if terminal.get("_reply") == "!trap":
            terminal = _set(sock, "/ppp/secret", secret_id, **core_props)
        if terminal.get("_reply") == "!trap":
            raise ConnectionError(
                _trap_message(
                    terminal,
                    f"Could not update PPPoE secret “{username}” on the MikroTik.",
                )
            )
    else:
        terminal = _add(sock, "/ppp/secret", **base_props)
        if terminal.get("_reply") == "!trap":
            terminal = _add(sock, "/ppp/secret", **core_props)
        if terminal.get("_reply") == "!trap":
            raise ConnectionError(
                _trap_message(
                    terminal,
                    f"Could not create PPPoE secret “{username}” on the MikroTik.",
                )
            )
        secret_id = (terminal.get("ret") or "").strip()
        action = "created"
        created = True
        if not secret_id:
            for row in _print(sock, "/ppp/secret", props=".id,name"):
                if (row.get("name") or "").strip().lower() == username.lower():
                    secret_id = (row.get(".id") or "").strip()
                    break

    if not secret_id:
        raise ConnectionError(
            f"PPPoE secret “{username}” was not found on the MikroTik after write."
        )

    # Password MUST be set on its own — never rely on multi-property add/set alone.
    pwd_terminal = _set(sock, "/ppp/secret", secret_id, password=password)
    if pwd_terminal.get("_reply") == "!trap":
        raise ConnectionError(
            _trap_message(
                pwd_terminal,
                f"Could not set PPPoE password for “{username}” on the MikroTik.",
            )
        )

    # Soft-apply rate-limit on the secret when RouterOS accepts it. The
    # per-package PPP profile rate-limit is the primary enforcement path.
    if rate_limit and profile != PPPOE_BLOCKED_PROFILE_NAME:
        rl_terminal = _set(sock, "/ppp/secret", secret_id, **{"rate-limit": rate_limit})
        if rl_terminal.get("_reply") == "!trap":
            # Unknown parameter on older builds — ignore; profile handles it.
            pass

    # Verify the secret is present (password itself is readable on most ROS builds).
    verified = None
    for row in _print(sock, "/ppp/secret", props=".id,name,password,disabled,service,profile"):
        if (row.get("name") or "").strip().lower() != username.lower():
            continue
        verified = row
        break
    if verified is None:
        # Full print fallback if .proplist behaved oddly.
        for row in _print(sock, "/ppp/secret"):
            if (row.get("name") or "").strip().lower() == username.lower():
                verified = row
                break
    if verified is None:
        raise ConnectionError(
            f"PPPoE secret “{username}” missing after install — dial-in would fail."
        )
    stored_password = verified.get("password")
    if (
        _pppoe_password_is_readable(stored_password)
        and stored_password != password
    ):
        # Rare: write did not stick. Retry once, then fail hard.
        _set(sock, "/ppp/secret", secret_id, password=password)
        again = None
        for row in _print(sock, "/ppp/secret"):
            if (row.get("name") or "").strip().lower() == username.lower():
                again = row
                break
        if again is not None and _pppoe_password_is_readable(again.get("password")):
            if again.get("password") != password:
                raise ConnectionError(
                    f"MikroTik stored a different password for “{username}”. "
                    "Re-push PPPoE logins from settings."
                )

    # Kick only when the password actually changed. Masked/empty prints must not
    # count as a change — that used to disconnect every sweep and left CPEs in a
    # "cannot dial-up" loop while LAN devices kept residual surfing.
    password_changed = bool(
        created
        or (
            _pppoe_password_is_readable(previous_password)
            and previous_password != password
        )
    )

    prev_disabled_yes = previous_disabled in {"true", "yes", "y"}
    profile_changed = (not created) and previous_profile != profile
    disabled_changed = (not created) and prev_disabled_yes != bool(disabled)
    # Kick only when access actually changes. Sweeping already-blocked clients
    # every two minutes was tearing down the redialed session that powers the
    # pay page / STK status polls.
    should_kick = bool(
        created or profile_changed or disabled_changed or password_changed
    )

    if rate_limit and profile != PPPOE_BLOCKED_PROFILE_NAME and not disabled:
        _ensure_pppoe_simple_queue(
            sock, username=username, rate_limit=rate_limit
        )
    if should_kick:
        _disconnect_pppoe_sessions(sock, username)
    return action


def _pppoe_customers_for_router(router):
    """Active/suspended PPPoE customers that should exist as secrets on this NAS."""
    from billing.models import Customer

    org_id = getattr(router, "organization_id", None)
    if not org_id:
        return []
    qs = (
        Customer.objects.filter(
            organization_id=org_id,
            service_type=Customer.ServiceType.PPPOE,
        )
        .exclude(pppoe_username="")
        .exclude(pppoe_password="")
        .select_related("plan")
        .order_by("id")
    )
    # Prefer customers assigned to this router; also include unassigned so dial works.
    return [
        customer
        for customer in qs
        if customer.router_id in (None, getattr(router, "pk", None))
    ]


def _sync_organization_pppoe_secrets_on_socket(sock: socket.socket, router) -> int:
    """Write all eligible customer PPP secrets onto an open API session."""
    synced = 0
    for customer in _pppoe_customers_for_router(router):
        username = (customer.pppoe_username or "").strip()
        password = customer.pppoe_password or ""
        if not username or not password:
            continue
        disabled = _customer_pppoe_secret_disabled(customer)
        # Match individual provision: expired/unpaid clients stay on the blocked
        # profile so a policy push never restores free surfing.
        profile = _ppp_secret_profile_for_customer(customer, disabled=disabled)
        previous_profile = _current_ppp_secret_profile(sock, username)
        comment = f"{PPP_SECRET_TAG} {customer.account_number}".strip()
        _ensure_ppp_secret(
            sock,
            username=username,
            password=password,
            profile=profile,
            comment=comment,
            disabled=disabled,
            rate_limit=_pppoe_rate_limit_for_customer(customer),
        )
        if (
            previous_profile
            and previous_profile != profile
            and not disabled
        ):
            # Profile flip only takes effect after the CPE redials.
            _disconnect_pppoe_sessions(sock, username)
        synced += 1
    return synced


_TUNNEL_HOST_CACHE: dict[str, str] = {}
_TUNNEL_HOST_CACHE_AT = 0.0
_TUNNEL_HOST_CACHE_TTL = 30.0


def _tunnel_hosts() -> dict[str, str]:
    """LAN address -> tunnel address, for every router that has a peer."""
    global _TUNNEL_HOST_CACHE, _TUNNEL_HOST_CACHE_AT

    now = time.monotonic()
    if now - _TUNNEL_HOST_CACHE_AT < _TUNNEL_HOST_CACHE_TTL:
        return _TUNNEL_HOST_CACHE
    try:
        from core.models import MikroTikRouter

        mapping: dict[str, str] = {}
        ambiguous: set[str] = set()
        for host, vpn in MikroTikRouter.objects.values_list("host", "vpn_address"):
            host = (host or "").strip()
            vpn = (vpn or "").strip()
            if not host:
                continue
            # Sites routinely keep the factory 192.168.88.1, so the same saved
            # address can belong to several routers. Translating it would send
            # one router's traffic down another's tunnel; leave it alone.
            if host in mapping or host in ambiguous:
                mapping.pop(host, None)
                ambiguous.add(host)
                continue
            if vpn:
                mapping[host] = vpn
        _TUNNEL_HOST_CACHE = mapping
        _TUNNEL_HOST_CACHE_AT = now
    except Exception:
        pass
    return _TUNNEL_HOST_CACHE


def dial_host(host: str) -> str:
    """
    Resolve the address to actually connect to for a router.

    Call sites across the app pass whatever is saved on the router row, which on
    a hosted server is an unroutable LAN address. Translating here means every
    one of them reaches the router over the billing tunnel without having to
    know the tunnel exists.
    """
    host = (host or "").strip()
    if not host or on_router_lan():
        return host
    return _tunnel_hosts().get(host, host)


def on_router_lan() -> bool:
    """
    True when the billing server shares a network with the routers.

    A hosted server never does: the routers' LAN addresses are unroutable from
    it, so guessing 192.168.88.1 or scanning for neighbours only buys a long
    timeout — and on a VPS the scan would probe unrelated datacentre hosts.
    """
    return not bool(getattr(settings, "HOSTED", False))


def _router_api_host_candidates(
    router,
    candidate_hosts: list[str] | None = None,
    *,
    discover: bool = True,
) -> list[str]:
    host = (getattr(router, "host", None) or "").strip()
    tunnel = (getattr(router, "vpn_address", None) or "").strip()
    lan_only = ["192.168.88.1"] if on_router_lan() else []
    hosts: list[str] = []
    dialled: set[str] = set()
    for candidate in [tunnel, host, *lan_only, *(candidate_hosts or [])]:
        value = (candidate or "").strip()
        # Two candidates that dial the same address are one attempt, not two.
        target = dial_host(value)
        if not value or target in dialled:
            continue
        dialled.add(target)
        hosts.append(value)
    if discover and not candidate_hosts and on_router_lan():
        try:
            from core.mikrotik_discovery import discover_mikrotik_devices

            for device in discover_mikrotik_devices(timeout=2.0, full_scan=False) or []:
                ip = (device.get("ip") or device.get("host") or "").strip()
                if ip and ip not in hosts:
                    hosts.append(ip)
        except Exception:
            pass
    return hosts


def unreachable_router_error(router) -> str:
    """Explain a dial failure in terms of what the operator has to change."""
    host = (getattr(router, "host", None) or "").strip() or "the saved address"
    if on_router_lan():
        return f"Could not reach {host}:8728."
    if (getattr(router, "vpn_address", None) or "").strip():
        return (
            f"Could not reach {router.vpn_address}:8728 over the billing tunnel. "
            "Check that WireGuard is up on this router."
        )
    return (
        f"This server is hosted and cannot reach {host}, which is a private LAN "
        "address. Join the router to the billing tunnel: run "
        f"`python manage.py wireguard_peer {getattr(router, 'pk', '')}` on the "
        "server and paste the script it prints into the MikroTik terminal."
    )


def provision_customer_pppoe(
    customer,
    *,
    router=None,
    candidate_hosts: list[str] | None = None,
    ensure_stack: bool = True,
    force_disabled: bool | None = None,
) -> dict[str, Any]:
    """
    Push one customer's PPPoE username/password onto their MikroTik as /ppp/secret.

    Without this step, the CPE dials correctly but MikroTik rejects the login with
    “invalid username or password” / “confirm your username and password”.

    force_disabled: optional override for /ppp/secret disabled flag.
    ensure_stack: when True, also ensure the full PPPoE server stack exists (slow).
      Registration should pass False — the stack is already pushed when the router
      is onboarded / PPPoE settings are applied.
    """
    if customer is None:
        return {"ok": False, "error": "No customer provided."}

    username = (getattr(customer, "pppoe_username", None) or "").strip()
    password = getattr(customer, "pppoe_password", None) or ""
    if not username or not password:
        return {
            "ok": False,
            "error": "Customer is missing a PPPoE username or password.",
        }

    target = router or getattr(customer, "router", None)
    if target is None:
        org = getattr(customer, "organization", None)
        if org is not None:
            from core.models import MikroTikRouter

            routers = list(
                MikroTikRouter.objects.filter(organization=org).order_by("id")
            )
            if len(routers) == 1:
                target = routers[0]
            elif len(routers) > 1:
                results = [
                    provision_customer_pppoe(
                        customer,
                        router=item,
                        candidate_hosts=candidate_hosts,
                        ensure_stack=ensure_stack,
                        force_disabled=force_disabled,
                    )
                    for item in routers
                ]
                ok_results = [item for item in results if item.get("ok")]
                if ok_results:
                    return {
                        "ok": True,
                        "username": username,
                        "routers": ok_results,
                        "message": (
                            f"PPPoE secret “{username}” pushed to "
                            f"{len(ok_results)} MikroTik router(s)."
                        ),
                    }
                first_error = next(
                    (item.get("error") for item in results if item.get("error")),
                    "Could not reach any organization MikroTik.",
                )
                return {"ok": False, "error": first_error, "results": results}
        if target is None:
            return {
                "ok": False,
                "error": (
                    "Assign a MikroTik router to this client so the PPPoE username/password "
                    "can be installed on the NAS."
                ),
            }

    host = (getattr(target, "host", None) or "").strip()
    api_user = (getattr(target, "username", None) or "").strip()
    api_password = getattr(target, "password", None) or ""
    router_id = getattr(target, "pk", None)
    router_name = getattr(target, "name", "") or host
    if not host or not api_user:
        return {
            "ok": False,
            "router_id": router_id,
            "router_name": router_name,
            "error": "Router host or API username is missing.",
        }

    lan_interface = getattr(target, "lan_bridge", None) or "bridgeLocal"
    wan_interface = getattr(target, "wan_interface", None) or "ether1"
    org = getattr(customer, "organization", None)
    compulsory = bool(getattr(org, "pppoe_compulsory", False)) if org else False
    if force_disabled is None:
        disabled = _customer_pppoe_secret_disabled(customer)
    else:
        disabled = bool(force_disabled)
    internet_allowed = _customer_internet_allowed(customer)
    profile = _ppp_secret_profile_for_customer(customer, disabled=disabled)
    comment = f"{PPP_SECRET_TAG} {getattr(customer, 'account_number', '')}".strip()
    rate_limit = _pppoe_rate_limit_for_customer(customer)

    # Registration / secret-only pushes: skip LAN discovery (saves ~2s) and use
    # a tight API probe instead of multi-port reachability.
    hosts = _router_api_host_candidates(
        target,
        candidate_hosts,
        discover=bool(ensure_stack),
    )
    last_error = ""
    working_host = ""
    action = ""
    notes: list[str] = []
    kicked = 0
    probe_timeout = 1.5 if ensure_stack else 0.8

    for candidate in hosts:
        if ensure_stack:
            probe = check_mikrotik_reachable(candidate, timeout=probe_timeout)
            via = (probe.get("via") or "").strip()
            attempt_timeout = 3.0 if via == "ping" else 12.0
            if not probe.get("online") and candidate != host:
                continue
        else:
            # Fast path: only care whether API 8728 answers.
            try:
                with socket.create_connection(
                    (dial_host(candidate), 8728), timeout=probe_timeout
                ):
                    via = "api"
            except OSError:
                if candidate != host:
                    continue
                via = ""
            attempt_timeout = 4.0
        try:
            with _api_session(candidate, api_user, api_password, timeout=attempt_timeout) as sock:
                if ensure_stack:
                    portal_url = _billing_portal_base_url()
                    _, stack_notes = _ensure_pppoe_stack(
                        sock,
                        lan_interface=lan_interface,
                        wan_interface=wan_interface,
                        compulsory=compulsory,
                        portal_url=portal_url,
                    )
                    notes.extend(stack_notes)
                previous_profile = _current_ppp_secret_profile(sock, username)
                session_was_blocked = False
                if ensure_stack or previous_profile:
                    session_was_blocked = _active_pppoe_session_is_blocked(
                        sock, username
                    )
                # When blocking, install pay-page redirect/allow before the kick
                # so the CPE's first redial already has captive NAT in place.
                if profile == PPPOE_BLOCKED_PROFILE_NAME:
                    block_portal = _billing_portal_base_url()
                    notes.extend(
                        _ensure_pppoe_expired_access(sock, portal_url=block_portal)
                    )
                    notes.extend(_ensure_pppoe_blocked_profile(sock))
                action = _ensure_ppp_secret(
                    sock,
                    username=username,
                    password=password,
                    profile=profile,
                    comment=comment,
                    disabled=disabled,
                    rate_limit=rate_limit,
                )
                # Kick when profile changes so the blocked address-list (or restore)
                # takes effect immediately — otherwise established TCP keeps surfing.
                if (previous_profile or "") != profile or (
                    internet_allowed and session_was_blocked
                ):
                    kicked = _disconnect_pppoe_sessions(sock, username)
                    if kicked:
                        notes.append(
                            f"disconnected {kicked} active session(s) to apply "
                            + (
                                "internet block"
                                if profile == PPPOE_BLOCKED_PROFILE_NAME
                                else "internet restore"
                            )
                        )
            working_host = candidate
            break
        except TimeoutError:
            last_error = f"{candidate}: timed out on API port 8728"
        except OSError as exc:
            message = str(exc) or "network error"
            if "timed out" in message.lower() or getattr(exc, "errno", None) in {10060, 110}:
                last_error = f"{candidate}: timed out on API port 8728"
            else:
                last_error = f"{candidate}: {message}"
        except Exception as exc:  # noqa: BLE001
            last_error = f"{candidate}: {exc}"

    if not working_host:
        return {
            "ok": False,
            "router_id": router_id,
            "router_name": router_name,
            "username": username,
            "error": (
                f"{last_error or host}. Could not install the PPPoE login on the MikroTik. "
                "Connect this PC to the router LAN, open MikroTik → Reconnect, then register again "
                "or push PPPoE settings."
            ),
        }

    if working_host != host and hasattr(target, "host"):
        try:
            target.host = working_host
            target.save(update_fields=["host", "updated_at"])
            notes.append(f"updated saved IP to {working_host}")
        except Exception:
            pass

    # Keep the customer linked to the NAS that received the secret.
    if getattr(customer, "router_id", None) != router_id and hasattr(customer, "router_id"):
        try:
            customer.router = target
            customer.save(update_fields=["router"])
        except Exception:
            pass

    verb = "created" if action == "created" else "updated"
    surfing_blocked = (not disabled) and profile == PPPOE_BLOCKED_PROFILE_NAME
    if disabled:
        access_note = " (dial-in disabled — account inactive)."
    elif surfing_blocked:
        access_note = (
            " (dial-in kept on, surfing blocked at NAS — outside subscription period)."
        )
    else:
        access_note = ". The client router can dial with this username and password."
    return {
        "ok": True,
        "router_id": router_id,
        "router_name": router_name,
        "host": working_host,
        "username": username,
        "action": action,
        "disabled": disabled,
        "internet_allowed": internet_allowed and not disabled,
        "profile": profile,
        "kicked": kicked,
        "notes": notes,
        "message": (
            f"PPPoE secret “{username}” {verb} on {router_name or working_host}"
            + access_note
        ),
    }


def _cpe_lan_bridge_name(sock: socket.socket) -> str:
    """Pick a LAN bridge on the CPE for the renew hotspot."""
    for row in _print(sock, "/interface/bridge", props="name,.id"):
        name = (row.get("name") or "").strip()
        if name:
            return name
    return "bridge"


def _cpe_lan_gateway_ip(sock: socket.socket, lan: str) -> str:
    """Return the IPv4 gateway on the CPE LAN bridge (fallback to renew hotspot IP)."""
    lan_l = (lan or "").strip().lower()
    for row in _print(sock, "/ip/address", props="address,interface,.id"):
        iface = (row.get("interface") or "").strip().lower()
        if lan_l and iface != lan_l:
            continue
        address = (row.get("address") or "").strip()
        if "/" in address:
            address = address.split("/", 1)[0].strip()
        if address and not address.startswith("10.20.0."):
            return address
    return RENEW_HOTSPOT_ADDRESS


def _ensure_tagged_pool(sock: socket.socket, *, name: str, ranges: str, comment: str) -> None:
    pool_id = ""
    for row in _print(sock, "/ip/pool", props=".id,name,comment"):
        if (row.get("name") or "").strip() == name or comment in (row.get("comment") or ""):
            pool_id = (row.get(".id") or "").strip()
            break
    props = {"name": name, "ranges": ranges, "comment": comment}
    if pool_id:
        _set(sock, "/ip/pool", pool_id, **props)
    else:
        terminal = _add(sock, "/ip/pool", **props)
        if terminal.get("_reply") == "!trap":
            raise ConnectionError(_trap_message(terminal, "Could not create renew hotspot pool."))


def _ensure_tagged_ip_address(
    sock: socket.socket,
    *,
    address: str,
    interface: str,
    comment: str,
) -> None:
    item_id = ""
    for row in _print(sock, "/ip/address", props=".id,address,interface,comment"):
        if comment in (row.get("comment") or ""):
            item_id = (row.get(".id") or "").strip()
            break
    props = {
        "address": address,
        "interface": interface,
        "comment": comment,
    }
    if item_id:
        _set(sock, "/ip/address", item_id, **props)
    else:
        terminal = _add(sock, "/ip/address", **props)
        if terminal.get("_reply") == "!trap":
            # Address may already exist on the bridge from the CPE LAN — fine.
            pass


# Keep in sync with ispcentric.middleware.CAPTIVE_PROBE_HOSTS / ALLOWED_HOSTS.
CAPTIVE_PROBE_HOSTS = (
    "captive.apple.com",
    "www.apple.com",
    "www.appleiphonecell.com",
    "www.itools.info",
    "www.ibook.info",
    "www.airport.us",
    "www.thinkdifferent.us",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "www.msftconnecttest.com",
    "msftconnecttest.com",
    "www.msftncsi.com",
    "dns.msftncsi.com",
    "ipv6.msftconnecttest.com",
    "detectportal.firefox.com",
    "network-test.debian.org",
    "neverssl.com",
    "example.com",
    "connectivitycheck.platform.hicloud.com",
    "connectivitycheck.platform.hihonorcloud.com",
)

# How many times to re-install expired redirect / CPE portal when a push fails.
_CAPTIVE_REPAIR_ATTEMPTS = 3


def _ensure_captive_dns(sock: socket.socket, gateway_ip: str, comment: str) -> int:
    """Point OS captive-portal probes at the CPE so phones open the renew popup."""
    hosts = CAPTIVE_PROBE_HOSTS
    existing = {
        ((row.get("name") or "").strip().lower(), (row.get("comment") or "")): (row.get(".id") or "").strip()
        for row in _print(sock, "/ip/dns/static", props=".id,name,address,comment")
    }
    added = 0
    for host in hosts:
        key = (host.lower(), comment)
        item_id = existing.get(key) or existing.get((host.lower(), ""))
        attempts = [
            {
                "name": host,
                "address": gateway_ip,
                "comment": comment,
                "ttl": "1m",
            },
            {
                "name": host,
                "address": gateway_ip,
                "ttl": "1m",
            },
            {
                "name": host,
                "address": gateway_ip,
            },
        ]
        terminal, _ = _add_or_set_attempts(sock, "/ip/dns/static", item_id, attempts)
        if terminal.get("_reply") != "!trap" and not item_id:
            added += 1
    # Force CPE to answer DNS for LAN clients.
    try:
        _command(
            sock,
            [
                "/ip/dns/set",
                "=allow-remote-requests=yes",
            ],
        )
    except Exception:
        pass
    return added


CAPTIVE_PORTAL_DHCP_OPTION_NAME = "ispcentric-captive-portal"


def _ensure_captive_portal_dhcp_option(
    sock: socket.socket,
    pay_url: str,
    *,
    comment: str,
) -> list[str]:
    """
    Advertise the payment page through DHCP option 114 (RFC 8910).

    Without this, a phone only discovers the portal when one of its probe URLs
    happens to be plain HTTP, so the sign-in popup is late or never appears on
    devices that probe over HTTPS. Option 114 is read straight from the DHCP
    lease, so Android 11+, iOS 14+ and Windows 11 raise the popup the moment
    the client joins.
    """
    notes: list[str] = []
    pay_url = (pay_url or "").strip()
    if not pay_url:
        return notes

    option_id = ""
    for row in _print(sock, "/ip/dhcp-server/option", props=".id,name,code,value"):
        if (row.get("name") or "").strip() == CAPTIVE_PORTAL_DHCP_OPTION_NAME:
            option_id = (row.get(".id") or "").strip()
            break

    # RouterOS reads a quoted literal as a raw string option value.
    attempts = [
        {
            "name": CAPTIVE_PORTAL_DHCP_OPTION_NAME,
            "code": "114",
            "value": f"'{pay_url}'",
            "comment": comment,
        },
        {
            "name": CAPTIVE_PORTAL_DHCP_OPTION_NAME,
            "code": "114",
            "value": f"'{pay_url}'",
        },
    ]
    terminal, _ = _add_or_set_attempts(
        sock,
        "/ip/dhcp-server/option",
        option_id,
        attempts,
        required=("code", "value"),
    )
    if terminal.get("_reply") == "!trap":
        notes.append("warning: could not publish captive-portal DHCP option 114")
        return notes
    notes.append(f"captive-portal DHCP option 114 → {pay_url}")

    # Attach to every DHCP network without dropping options already in use.
    for row in _print(
        sock, "/ip/dhcp-server/network", props=".id,address,dhcp-option"
    ):
        network_id = (row.get(".id") or "").strip()
        if not network_id:
            continue
        current = [
            item.strip()
            for item in (row.get("dhcp-option") or "").split(",")
            if item.strip()
        ]
        if CAPTIVE_PORTAL_DHCP_OPTION_NAME in current:
            continue
        current.append(CAPTIVE_PORTAL_DHCP_OPTION_NAME)
        result = _set(
            sock,
            "/ip/dhcp-server/network",
            network_id,
            **{"dhcp-option": ",".join(current)},
        )
        if result.get("_reply") != "!trap":
            notes.append(
                f"captive-portal option on DHCP network {row.get('address') or network_id}"
            )
    return notes


def _clear_captive_portal_dhcp_option(sock: socket.socket) -> int:
    """Detach and delete the captive-portal DHCP option when Hotspot is off."""
    removed = 0
    for row in _print(
        sock, "/ip/dhcp-server/network", props=".id,dhcp-option"
    ):
        current = [
            item.strip()
            for item in (row.get("dhcp-option") or "").split(",")
            if item.strip()
        ]
        if CAPTIVE_PORTAL_DHCP_OPTION_NAME not in current:
            continue
        remaining = [
            item for item in current if item != CAPTIVE_PORTAL_DHCP_OPTION_NAME
        ]
        _set(
            sock,
            "/ip/dhcp-server/network",
            (row.get(".id") or "").strip(),
            **{"dhcp-option": ",".join(remaining)},
        )
    for row in _print(sock, "/ip/dhcp-server/option", props=".id,name"):
        if (row.get("name") or "").strip() != CAPTIVE_PORTAL_DHCP_OPTION_NAME:
            continue
        item_id = (row.get(".id") or "").strip()
        if item_id and _remove(sock, "/ip/dhcp-server/option", item_id).get(
            "_reply"
        ) != "!trap":
            removed += 1
    return removed


def _clear_captive_dns_hijack(sock: socket.socket, comment: str) -> int:
    """
    Stop resolving OS captive-probe hostnames to the Hotspot address.

    Hotspot decides how to answer by destination: a foreign IP gets intercepted
    and served login.html, but its own address is treated as a local file
    request, so ``/connecttest.txt`` and ``/generate_204`` 404 and the client
    reports plain "no internet" without ever offering a sign-in page. Letting
    the probes resolve normally restores the interception path.
    """
    wanted = {host.lower() for host in CAPTIVE_PROBE_HOSTS}
    removed = 0
    for row in _print(sock, "/ip/dns/static", props=".id,name,comment"):
        if comment not in (row.get("comment") or ""):
            continue
        if (row.get("name") or "").strip().lower() not in wanted:
            continue
        item_id = (row.get(".id") or "").strip()
        if not item_id:
            continue
        if _remove(sock, "/ip/dns/static", item_id).get("_reply") != "!trap":
            removed += 1
    # LAN clients still need the router as their resolver for normal lookups.
    try:
        _command(sock, ["/ip/dns/set", "=allow-remote-requests=yes"])
    except Exception:
        pass
    return removed


def _clear_https_capture_redirect(sock: socket.socket, *, comment: str) -> int:
    """Drop any tagged ``dstnat`` TCP/443 → 80 rule.

    Such a rule rewrites *every* client's HTTPS to plain HTTP, so it corrupts
    TLS for devices that already authenticated (they pay and then cannot browse)
    and for the billing server's own Safaricom Daraja calls. Captive detection
    does not need it: every major OS probes over HTTP
    (connectivitycheck.gstatic.com, captive.apple.com, msftconnecttest.com), and
    the Hotspot intercepts port 80 natively once an HTTP login method is enabled.
    """
    removed = 0
    for row in _print(
        sock,
        "/ip/firewall/nat",
        props=".id,chain,protocol,dst-port,action,to-ports,comment",
    ):
        if comment not in (row.get("comment") or ""):
            continue
        if not (
            (row.get("chain") or "").strip() == "dstnat"
            and (row.get("protocol") or "").strip() == "tcp"
            and (row.get("dst-port") or "").strip() == "443"
            and (row.get("action") or "").strip() == "redirect"
            and (row.get("to-ports") or "").strip() == "80"
        ):
            continue
        item_id = (row.get(".id") or "").strip()
        if item_id and _remove(sock, "/ip/firewall/nat", item_id).get(
            "_reply"
        ) != "!trap":
            removed += 1
    return removed


def _ensure_hotspot_owns_http_port(
    sock: socket.socket, *, hotspot_address: str, comment: str, portal_url: str = ""
) -> list[str]:
    """
    Send gateway TCP/80 to the billing server so captive probes never hit WebFig.

    Bypassed hosts (billing-server Ethernet) skip Hotspot NAT and would otherwise
    reach RouterOS WebFig on :80. Windows then opens
    ``http://www.msftconnecttest.com/redirect`` and WebFig returns a blank 404.
    Hotspot's own proxy ports also ignore bypassed clients, so we dst-nat
    gateway:80 to the Django portal, which serves the payment redirect.
    """
    notes: list[str] = []
    gateway = (hotspot_address or "").strip()
    if not gateway:
        return notes

    portal_ip = _portal_target_ipv4(portal_url) or _routable_ipv4_from_url(portal_url) or ""
    try:
        from urllib.parse import urlparse

        parsed = urlparse((portal_url or "").strip())
        scheme = (parsed.scheme or "").lower()
        if scheme == "https":
            portal_port = "80"
        elif parsed.port:
            portal_port = str(parsed.port)
        else:
            portal_port = "80"
    except Exception:
        portal_port = "80"
    if not portal_ip:
        notes.append(
            "warning: cannot bind captive HTTP to billing server — "
            "set PUBLIC_BASE_URL to a reachable http://host (LAN IP locally, "
            "public hostname when hosted)"
        )
        return notes

    # Move RouterOS www (WebFig) off port 80 when it is still there.
    for row in _print(sock, "/ip/service", props=".id,name,port,disabled"):
        if (row.get("name") or "").strip() != "www":
            continue
        item_id = (row.get(".id") or "").strip()
        port = (row.get("port") or "").strip()
        if item_id and port == "80":
            terminal = _set(sock, "/ip/service", item_id, port="8081")
            if terminal.get("_reply") != "!trap":
                notes.append("RouterOS WebFig moved to :8081")
            else:
                notes.append("warning: could not move WebFig off port 80")
        elif port and port != "80":
            notes.append(f"RouterOS WebFig already on :{port}")

    # Replace any previous "redirect to Hotspot proxy" rule with dst-nat to Django.
    existing_id = ""
    for row in _print(
        sock,
        "/ip/firewall/nat",
        props=".id,chain,protocol,dst-port,dst-address,action,to-addresses,to-ports,comment",
    ):
        if comment not in (row.get("comment") or ""):
            continue
        if (row.get("chain") or "").strip() != "dstnat":
            continue
        if (row.get("protocol") or "").strip() != "tcp":
            continue
        if (row.get("dst-port") or "").strip() != "80":
            continue
        action = (row.get("action") or "").strip()
        if action not in {"redirect", "dst-nat"}:
            continue
        existing_id = (row.get(".id") or "").strip()
        break

    attempts = [
        {
            "chain": "dstnat",
            "protocol": "tcp",
            # Only the bypassed billing PC needs this workaround. Real Hotspot
            # clients must reach RouterOS's login servlet so $(mac) and
            # $(link-login-only) are substituted into login.html.
            "src-address": portal_ip,
            "dst-address": gateway,
            "dst-port": "80",
            "action": "dst-nat",
            "to-addresses": portal_ip,
            "to-ports": portal_port,
            "comment": comment,
        },
    ]
    terminal, _ = _add_or_set_attempts(
        sock, "/ip/firewall/nat", existing_id, attempts
    )
    if terminal.get("_reply") != "!trap":
        notes.append(f"captive HTTP {gateway}:80 -> {portal_ip}:{portal_port}")
    else:
        notes.append(
            f"warning: could not forward {gateway}:80 to {portal_ip}:{portal_port}"
        )
        return notes

    # Hairpin: LAN clients dialing the gateway must receive replies from the
    # gateway address, not directly from the billing server.
    hairpin_id = ""
    for row in _print(
        sock,
        "/ip/firewall/nat",
        props=".id,chain,action,src-address,dst-address,protocol,dst-port,comment",
    ):
        if comment not in (row.get("comment") or ""):
            continue
        if (row.get("chain") or "").strip() != "srcnat":
            continue
        if (row.get("action") or "").strip() != "masquerade":
            continue
        if (row.get("dst-address") or "").strip() != portal_ip:
            continue
        hairpin_id = (row.get(".id") or "").strip()
        break

    # Derive LAN subnet from gateway (…x.1 → …x.0/24).
    parts = gateway.split(".")
    lan_cidr = (
        f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else "10.10.0.0/24"
    )
    hairpin_attempts = [
        {
            "chain": "srcnat",
            "action": "masquerade",
            "src-address": lan_cidr,
            "dst-address": portal_ip,
            "protocol": "tcp",
            "dst-port": portal_port,
            "comment": comment,
        },
        {
            "chain": "srcnat",
            "action": "masquerade",
            "src-address": lan_cidr,
            "dst-address": portal_ip,
            "comment": comment,
        },
    ]
    terminal, _ = _add_or_set_attempts(
        sock, "/ip/firewall/nat", hairpin_id, hairpin_attempts
    )
    if terminal.get("_reply") != "!trap":
        notes.append(f"captive hairpin NAT for {portal_ip}:{portal_port}")
    else:
        notes.append("warning: could not add captive hairpin NAT")

    # PPPoE-compulsory forward-drop would otherwise block unauthorized LAN
    # clients from reaching the billing server after dst-nat.
    filter_id = ""
    for row in _print(
        sock,
        "/ip/firewall/filter",
        props=".id,chain,action,dst-address,protocol,dst-port,comment",
    ):
        if comment not in (row.get("comment") or ""):
            continue
        if (row.get("chain") or "").strip() != "forward":
            continue
        if (row.get("dst-address") or "").strip() != portal_ip:
            continue
        if (row.get("action") or "").strip() != "accept":
            continue
        filter_id = (row.get(".id") or "").strip()
        break

    filter_attempts = [
        {
            "chain": "forward",
            "action": "accept",
            "dst-address": portal_ip,
            "protocol": "tcp",
            "dst-port": portal_port,
            "comment": comment,
        },
        {
            "chain": "forward",
            "action": "accept",
            "dst-address": portal_ip,
            "comment": comment,
        },
    ]
    terminal, _ = _add_or_set_attempts(
        sock, "/ip/firewall/filter", filter_id, filter_attempts
    )
    if terminal.get("_reply") != "!trap":
        # Ensure this accept sits above the compulsory drop.
        if terminal.get("ret") or filter_id:
            rule_id = (terminal.get("ret") or filter_id or "").strip()
            if rule_id:
                _command(
                    sock,
                    [
                        "/ip/firewall/filter/move",
                        f"=.id={rule_id}",
                        "=destination=0",
                    ],
                )
        notes.append(f"forward allow to billing server {portal_ip}:{portal_port}")
    else:
        notes.append("warning: could not allow forward to billing server")
    return notes


def _remove_tagged_rows(sock: socket.socket, path: str, tag: str) -> int:
    removed = 0
    for row in _print(sock, path, props=".id,name,comment,address"):
        comment = row.get("comment") or ""
        name = row.get("name") or ""
        if tag not in comment and name != tag and name != RENEW_HOTSPOT_NAME:
            continue
        item_id = (row.get(".id") or "").strip()
        if not item_id:
            continue
        terminal = _remove(sock, path, item_id)
        if terminal.get("_reply") != "!trap":
            removed += 1
    return removed


def _fetch_hotspot_pages(sock: socket.socket, portal_url: str) -> list[str]:
    """
    Install CPE Hotspot login pages that bounce phones onto the live pay URL.

    Prefer a thin RouterOS redirect (API write) over fetching the full Django
    page: the phone must land on the billing host for CSRF/cookies, and the
    redirect carries ``?t=`` (account) plus ``mac=$(mac-esc)`` for Hotspot pay.

    Refuses path-only URLs — those become ``http://192.168.…/pppoe/…`` on the
    CPE Hotspot and trap both payment and admin WebFig.

    Notes include ``installed hotspot/login.html`` or ``fetched hotspot/login.html``
    when the critical login page landed; callers must treat a missing login page
    as failure so WAN is not dropped without a popup.
    """
    notes: list[str] = []
    portal_url = _resolve_absolute_captive_url(portal_url)
    if not portal_url:
        notes.append(
            "warning: refused relative/empty Hotspot redirect — "
            "would stick clients on http://192.168.…"
        )
        return notes

    for dst in _STALE_PROBE_FILES:
        if _delete_hotspot_file(sock, dst):
            notes.append(f"removed {dst}")

    pay_html = _captive_pay_redirect_html(portal_url)
    wrote_login = False
    if pay_html:
        for dst in (
            "hotspot/login.html",
            "hotspot/rlogin.html",
            "hotspot/redirect.html",
            "hotspot/status.html",
            "hotspot/alogin.html",
        ):
            if _write_hotspot_html_file(sock, dst, pay_html):
                notes.append(f"installed {dst}")
                if dst == "hotspot/login.html":
                    wrote_login = True
            else:
                notes.append(f"could not write {dst}")

    if wrote_login:
        return notes

    # Fallback when /file contents writes are unsupported: HTTP-fetch the pay URL.
    # Must run while CPE WAN still reaches billing (before renew WAN-drop).
    targets = (
        ("hotspot/login.html", portal_url),
        ("hotspot/redirect.html", portal_url),
        ("hotspot/rlogin.html", portal_url),
        ("hotspot/status.html", portal_url),
        ("hotspot/alogin.html", portal_url),
    )
    for dst, url in targets:
        fetch_words = [
            "/tool/fetch",
            f"=url={url}",
            "=mode=http",
            f"=dst-path={dst}",
            "=keep-result=no",
        ]
        _, fetch_terminal = _command(sock, fetch_words)
        if fetch_terminal.get("_reply") == "!trap":
            notes.append(f"fetch skipped: {dst}")
        else:
            notes.append(f"fetched {dst}")
            if dst == "hotspot/login.html":
                wrote_login = True
    if not wrote_login:
        notes.append("warning: hotspot/login.html missing — captive pay popup will not open")
    return notes


def _ensure_cpe_portal_access(sock: socket.socket, portal_url: str) -> list[str]:
    """
    Let renew-Hotspot clients reach the billing pay page through the CPE.

    Without this, login.html 302s to the pay URL but either:
      * Hotspot re-intercepts the request (no walled garden) and phones stay on
        ``http://192.168.…`` (CPE gateway / 192.168.189.1), or
      * the WAN forward-drop blocks the billing host so payment never loads
        (admin WebFig and client pay both look "broken").
    """
    notes: list[str] = []
    portal = _billing_portal_base_url(portal_url)
    if not portal:
        notes.append("warning: no portal URL — CPE cannot open the pay page")
        return notes

    try:
        parsed = urlparse(portal)
        host = (parsed.hostname or "").strip()
    except Exception:
        host = ""
    if not host:
        notes.append("warning: portal URL has no host — CPE pay redirect skipped")
        return notes

    # Walled garden: unauthenticated Hotspot clients may fetch the pay page.
    _remove_tagged_rows(sock, "/ip/hotspot/walled-garden", RENEW_HOTSPOT_TAG)
    try:
        _remove_tagged_rows(sock, "/ip/hotspot/walled-garden/ip", RENEW_HOTSPOT_TAG)
    except Exception:
        pass

    terminal = _add(
        sock,
        "/ip/hotspot/walled-garden",
        **{
            "dst-host": host,
            "action": "allow",
            "comment": RENEW_HOTSPOT_TAG,
        },
    )
    if terminal.get("_reply") == "!trap":
        notes.append(f"warning: could not walled-garden {host}")
    else:
        notes.append(f"walled garden {host}")

    billing_ip = _portal_target_ipv4(portal)
    if billing_ip:
        terminal = _add(
            sock,
            "/ip/hotspot/walled-garden/ip",
            **{
                "dst-address": billing_ip,
                "action": "accept",
                "comment": RENEW_HOTSPOT_TAG,
            },
        )
        if terminal.get("_reply") != "!trap":
            notes.append(f"walled garden ip {billing_ip}")

        # Accept billing traffic above the renew WAN drop.
        _remove_tagged_rows(sock, "/ip/firewall/filter", f"{RENEW_HOTSPOT_TAG}-allow")
        place_before = ""
        for row in _print(sock, "/ip/firewall/filter", props=".id,chain,action,comment"):
            comment = row.get("comment") or ""
            if f"{RENEW_HOTSPOT_TAG}-block" in comment and (
                row.get("chain") or ""
            ).strip() == "forward":
                place_before = (row.get(".id") or "").strip()
                break
        allow_props = {
            "chain": "forward",
            "action": "accept",
            "dst-address": billing_ip,
            "comment": f"{RENEW_HOTSPOT_TAG}-allow",
        }
        if place_before:
            terminal = _add_filter_rule(sock, allow_props, place_before=place_before)
        else:
            terminal = _add(sock, "/ip/firewall/filter", **allow_props)
        if terminal.get("_reply") == "!trap":
            notes.append(f"warning: could not allow CPE forward to billing {billing_ip}")
        else:
            notes.append(f"CPE forward allow to billing {billing_ip}")
    else:
        notes.append(
            f"warning: could not resolve billing IP for {host} — "
            "pay page may be blocked by the renew WAN drop"
        )
    return notes


def _clear_hotspot_sessions(sock: socket.socket) -> list[str]:
    """
    Drop Hotspot cookies / active / host rows so login.html is served again.

    Cookie login-by (or a leftover authorized host) skips the captive portal while
    the renew WAN drop is active — phones then report "connected, no internet"
    with no pay popup. Always clear before relying on the renew redirect.
    """
    notes: list[str] = []
    cleared = 0
    for path in (
        "/ip/hotspot/cookie",
        "/ip/hotspot/active",
        "/ip/hotspot/host",
    ):
        for row in _print(sock, path, props=".id"):
            item_id = (row.get(".id") or "").strip()
            if not item_id:
                continue
            if _remove(sock, path, item_id).get("_reply") != "!trap":
                cleared += 1
    if cleared:
        notes.append(
            f"cleared {cleared} Hotspot session(s) so the pay popup can open"
        )
    return notes


def _ensure_cpe_wan_block(sock: socket.socket) -> list[str]:
    """
    Block client devices from surfing through the CPE while keeping the CPE online.

    Phones still reach the local Hotspot (input) and get the renew popup.
    Billing allow rules (``{RENEW_HOTSPOT_TAG}-allow``) must stay above this drop.
    """
    notes: list[str] = []
    _remove_tagged_rows(sock, "/ip/firewall/filter", f"{RENEW_HOTSPOT_TAG}-block")
    # Drop all forwarded traffic (LAN → internet). Local CPE services stay reachable.
    # Insert after any billing allow so payment still works.
    place_before = ""
    for row in _print(sock, "/ip/firewall/filter", props=".id,chain,action"):
        if (row.get("chain") or "").strip() != "forward":
            continue
        if (row.get("action") or "").strip() == "drop":
            place_before = (row.get(".id") or "").strip()
            break
    props = {
        "chain": "forward",
        "action": "drop",
        "comment": f"{RENEW_HOTSPOT_TAG}-block",
    }
    if place_before:
        terminal = _add_filter_rule(sock, props, place_before=place_before)
    else:
        terminal = _add(sock, "/ip/firewall/filter", **props)
    if terminal.get("_reply") == "!trap":
        notes.append("WAN block filter skipped")
    else:
        notes.append("client internet blocked on CPE (renew popup only)")
    return notes


def _enable_cpe_renew_hotspot(sock: socket.socket, *, portal_url: str = "") -> list[str]:
    """
    Turn on a local Hotspot + pay redirect on the CPE for instant Wi‑Fi renew.

    Order matters for "connect Wi‑Fi → pay page appears immediately":
      1. Absolute pay URL (abort otherwise — never trap phones on 192.168.…)
      2. Hotspot profile/server without cookie auto-login
      3. Clear probe DNS hijack + leftover Hotspot sessions
      4. Walled garden / billing allow
      5. Install login.html redirect WHILE WAN still works
      6. Drop non-billing WAN
      7. DHCP option 114 + bounce Wi‑Fi so phones re-probe now
    """
    notes: list[str] = []
    portal_url = _resolve_absolute_captive_url(portal_url) or _resolve_absolute_captive_url(
        _billing_portal_base_url()
    )

    if not portal_url or not urlparse(portal_url).scheme:
        raise ConnectionError(
            "Cannot enable CPE renew Hotspot without an absolute pay URL. "
            "Set PUBLIC_BASE_URL to a reachable http://host so phones open "
            "/pppoe/…/pay/ immediately on Wi‑Fi connect."
        )

    lan = _cpe_lan_bridge_name(sock)
    gateway_ip = _cpe_lan_gateway_ip(sock, lan)
    # Prefer the dedicated renew address so Hotspot, pool, and middleware agree.
    # Fall back to the CPE LAN gateway only in profile attempts if RouterOS
    # rejects binding the second subnet as hotspot-address.
    hotspot_address = RENEW_HOTSPOT_ADDRESS

    # Dedicated address so hotspot has a stable captive portal IP even if LAN IP differs.
    _ensure_tagged_ip_address(
        sock,
        address=f"{RENEW_HOTSPOT_ADDRESS}/24",
        interface=lan,
        comment=RENEW_HOTSPOT_TAG,
    )
    _ensure_tagged_pool(
        sock,
        name=RENEW_HOTSPOT_POOL,
        ranges=RENEW_HOTSPOT_POOL_RANGES,
        comment=RENEW_HOTSPOT_TAG,
    )
    notes.append(
        f"renew portal on {lan} ({hotspot_address}"
        + (f", lan-gw {gateway_ip}" if gateway_ip and gateway_ip != hotspot_address else "")
        + ")"
    )

    profile_id = ""
    for row in _print(sock, "/ip/hotspot/profile", props=".id,name,comment"):
        if (row.get("name") or "").strip() == RENEW_HOTSPOT_PROFILE or RENEW_HOTSPOT_TAG in (
            row.get("comment") or ""
        ):
            profile_id = (row.get(".id") or "").strip()
            break

    # http-pap/chap forces unauthenticated clients onto login.html (device captive popup).
    # cookie/https are deliberately absent: cookie would silently re-authorize a
    # phone while WAN is dropped → "connected, cannot provide internet" with no
    # pay sheet; https advertises a self-signed login URL phones refuse.
    address_candidates = [RENEW_HOTSPOT_ADDRESS]
    if gateway_ip and gateway_ip not in address_candidates:
        address_candidates.append(gateway_ip)
    profile_attempts: list[dict[str, str]] = []
    for addr in address_candidates:
        profile_attempts.extend(
            [
                {
                    "name": RENEW_HOTSPOT_PROFILE,
                    "hotspot-address": addr,
                    "html-directory": "hotspot",
                    "login-by": "http-chap,http-pap",
                    "open-status-page": "http-login",
                    "use-radius": "no",
                    "comment": RENEW_HOTSPOT_TAG,
                },
                {
                    "name": RENEW_HOTSPOT_PROFILE,
                    "hotspot-address": addr,
                    "html-directory": "hotspot",
                    "login-by": "http-pap",
                    "open-status-page": "http-login",
                    "comment": RENEW_HOTSPOT_TAG,
                },
            ]
        )
    terminal: dict[str, str] = {"_reply": "!trap"}
    for profile_props in profile_attempts:
        if profile_id:
            terminal = _set(sock, "/ip/hotspot/profile", profile_id, **profile_props)
        else:
            terminal = _add(sock, "/ip/hotspot/profile", **profile_props)
            if terminal.get("_reply") != "!trap":
                profile_id = (terminal.get("ret") or "").strip() or profile_id
        if terminal.get("_reply") != "!trap":
            break
    if terminal.get("_reply") == "!trap":
        raise ConnectionError(
            _trap_message(terminal, "Could not create renew hotspot profile on the CPE.")
        )
    notes.append("renew hotspot profile")

    server_id = ""
    for row in _print(sock, "/ip/hotspot", props=".id,name,interface,comment,disabled"):
        if (row.get("name") or "").strip() == RENEW_HOTSPOT_NAME or RENEW_HOTSPOT_TAG in (
            row.get("comment") or ""
        ):
            server_id = (row.get(".id") or "").strip()
            break

    # Prefer the renew pool so phones get 192.168.189.x (identifiable + middleware
    # safe). Fall back to existing LAN DHCP when the CPE rejects the pool.
    server_attempts = [
        {
            "name": RENEW_HOTSPOT_NAME,
            "interface": lan,
            "address-pool": RENEW_HOTSPOT_POOL,
            "profile": RENEW_HOTSPOT_PROFILE,
            "disabled": "no",
            "comment": RENEW_HOTSPOT_TAG,
        },
        {
            "name": RENEW_HOTSPOT_NAME,
            "interface": lan,
            "profile": RENEW_HOTSPOT_PROFILE,
            "disabled": "no",
            "comment": RENEW_HOTSPOT_TAG,
        },
    ]
    terminal = {"_reply": "!trap"}
    for server_props in server_attempts:
        if server_id:
            terminal = _set(sock, "/ip/hotspot", server_id, **server_props)
        else:
            terminal = _add(sock, "/ip/hotspot", **server_props)
            if terminal.get("_reply") != "!trap":
                server_id = (terminal.get("ret") or "").strip() or server_id
        if terminal.get("_reply") != "!trap":
            break
    if terminal.get("_reply") == "!trap":
        raise ConnectionError(
            _trap_message(terminal, f"Could not enable renew hotspot on CPE interface {lan}.")
        )
    notes.append(f"renew hotspot redirect on {lan}")

    # Do NOT resolve captive probes to the Hotspot IP — that 404s generate_204
    # and suppresses the OS sign-in sheet. Clear any previous hijack rows.
    cleared = _clear_captive_dns_hijack(sock, RENEW_HOTSPOT_TAG)
    if cleared:
        notes.append(f"cleared {cleared} captive DNS hijack(s)")
    if _clear_https_capture_redirect(sock, comment=RENEW_HOTSPOT_TAG):
        notes.append("removed HTTPS-to-HTTP capture rule")
    notes.extend(_clear_hotspot_sessions(sock))
    notes.append("Hotspot intercepts captive HTTP probes")

    # Allow pay page + install login.html BEFORE the blanket WAN drop so
    # /tool/fetch fallback and garden checks still reach billing.
    access_notes = _ensure_cpe_portal_access(sock, portal_url)
    notes.extend(access_notes)
    if not any("walled garden" in n.lower() or "allow" in n.lower() for n in access_notes):
        # Soft warning only — some CPEs use IP garden wording variations.
        if any("warning" in n.lower() for n in access_notes):
            notes.append("warning: billing allow may be incomplete — pay page could loop")

    page_notes = _fetch_hotspot_pages(sock, portal_url)
    notes.extend(page_notes)
    login_ready = any(
        n.startswith("installed hotspot/login.html")
        or n.startswith("fetched hotspot/login.html")
        for n in page_notes
    )
    if not login_ready:
        raise ConnectionError(
            "CPE renew Hotspot enabled but hotspot/login.html was not installed. "
            "Phones would show no internet without a pay popup. "
            + "; ".join(page_notes[-4:])
        )

    notes.extend(_ensure_cpe_wan_block(sock))

    # RFC 8910 option 114: Android 11+ / iOS 14+ / Win11 raise the sign-in
    # popup the moment Wi‑Fi associates — do not wait for an HTTP probe.
    notes.extend(
        _ensure_captive_portal_dhcp_option(
            sock, portal_url, comment=RENEW_HOTSPOT_TAG
        )
    )
    notes.extend(_bounce_cpe_wifi_clients(sock))

    try:
        _command(sock, ["/system/identity/set", "=name=Renew subscription"])
        notes.append("CPE identity set for renew popup")
    except Exception:
        pass

    return notes


def _bounce_wifi_clients(
    sock: socket.socket, *, reason: str = "captive pay popup"
) -> list[str]:
    """
    Drop Wi‑Fi associations so phones re-run captive probes / DHCP option 114.

    Without this, clients keep their old association and never open the pay
    popup until the user toggles Wi‑Fi.
    """
    notes: list[str] = []
    removed = 0
    for path in (
        "/interface/wireless/registration-table",
        "/interface/wifi/registration-table",
        "/caps-man/registration-table",
    ):
        for row in _print(sock, path, props=".id,mac-address"):
            item_id = (row.get(".id") or "").strip()
            if not item_id:
                continue
            terminal = _remove(sock, path, item_id)
            if terminal.get("_reply") != "!trap":
                removed += 1
    if removed:
        notes.append(f"bounced {removed} Wi‑Fi client(s) for {reason}")
    return notes


def _bounce_cpe_wifi_clients(sock: socket.socket) -> list[str]:
    """Drop Wi‑Fi associations so phones re-run captive probes against the renew Hotspot."""
    return _bounce_wifi_clients(sock, reason="captive renew popup")


def _bounce_isp_hotspot_clients(sock: socket.socket) -> list[str]:
    """
    Force Hotspot Wi‑Fi clients to re-probe so the pay page opens immediately.

    Clears leftover Hotspot cookies (cookie login is disabled, but stale cookies
    still confuse some RouterOS builds), clears unauthorized host/active rows,
    then drops Wi‑Fi associations for a fresh DHCP + option 114 / captive probe.
    Paid (authorized) sessions are left alone.
    """
    notes: list[str] = []
    cookies = 0
    for row in _print(sock, "/ip/hotspot/cookie", props=".id"):
        item_id = (row.get(".id") or "").strip()
        if not item_id:
            continue
        if _remove(sock, "/ip/hotspot/cookie", item_id).get("_reply") != "!trap":
            cookies += 1
    if cookies:
        notes.append(f"cleared {cookies} Hotspot cookie(s)")

    cleared = 0
    for path in ("/ip/hotspot/active", "/ip/hotspot/host"):
        for row in _print(sock, path, props=".id,authorized"):
            item_id = (row.get(".id") or "").strip()
            if not item_id:
                continue
            # Leave authorized (paid) sessions alone — only bounce unpaid hosts.
            if (row.get("authorized") or "").strip().lower() in {"true", "yes"}:
                continue
            terminal = _remove(sock, path, item_id)
            if terminal.get("_reply") != "!trap":
                cleared += 1
    if cleared:
        notes.append(f"cleared {cleared} unauthorized Hotspot host(s)")
    notes.extend(_bounce_wifi_clients(sock, reason="Hotspot pay popup"))
    return notes


def repair_hotspot_captive_portal(
    router,
    *,
    organization=None,
    attempts: int | None = None,
) -> dict[str, Any]:
    """
    Re-push ISP Hotspot captive pages / option 114 until login.html is live.

    Used by the subscription sweep so unpaid Wi‑Fi clients keep getting an
    instant pay popup even if a prior push lost portal files on the NAS.
    """
    attempts = int(attempts or _CAPTIVE_REPAIR_ATTEMPTS)
    last: dict[str, Any] = {"ok": False, "skipped": True}
    for attempt in range(1, attempts + 1):
        try:
            last = apply_hotspot_on_router(
                router,
                enabled=True,
                organization=organization,
                reauthenticate=False,
            )
        except Exception as exc:  # noqa: BLE001
            last = {
                "ok": False,
                "skipped": False,
                "error": str(exc) or "Hotspot captive repair failed.",
                "attempt": attempt,
            }
            continue
        if last.get("ok") or last.get("skipped"):
            if attempt > 1 and last.get("ok"):
                notes = list(last.get("notes") or [])
                notes.append(f"Hotspot captive repaired on attempt {attempt}")
                last["notes"] = notes
            return last
        # Permanent config errors will not heal on retry.
        err = (last.get("error") or "").lower()
        if "absolute pay url" in err or "organization is required" in err:
            return last
    return last


def _disable_cpe_renew_hotspot(sock: socket.socket) -> list[str]:
    """Remove the renew Hotspot / DNS / redirects so normal CPE LAN/Wi‑Fi resumes."""
    notes: list[str] = []
    removed = 0
    removed += _remove_tagged_rows(sock, "/ip/hotspot", RENEW_HOTSPOT_TAG)
    removed += _remove_tagged_rows(sock, "/ip/hotspot/profile", RENEW_HOTSPOT_TAG)
    removed += _remove_tagged_rows(sock, "/ip/pool", RENEW_HOTSPOT_TAG)
    removed += _remove_tagged_rows(sock, "/ip/address", RENEW_HOTSPOT_TAG)
    removed += _remove_tagged_rows(sock, "/ip/dns/static", RENEW_HOTSPOT_TAG)
    removed += _remove_tagged_rows(sock, "/ip/firewall/nat", RENEW_HOTSPOT_TAG)
    removed += _remove_tagged_rows(sock, "/ip/firewall/filter", f"{RENEW_HOTSPOT_TAG}-block")
    removed += _remove_tagged_rows(sock, "/ip/firewall/filter", f"{RENEW_HOTSPOT_TAG}-allow")
    removed += _remove_tagged_rows(sock, "/ip/firewall/filter", RENEW_HOTSPOT_TAG)
    removed += _remove_tagged_rows(sock, "/ip/hotspot/walled-garden", RENEW_HOTSPOT_TAG)
    try:
        removed += _remove_tagged_rows(sock, "/ip/hotspot/walled-garden/ip", RENEW_HOTSPOT_TAG)
    except Exception:
        pass
    try:
        removed += _clear_captive_portal_dhcp_option(sock)
    except Exception:
        pass
    if removed:
        notes.append("renew hotspot / redirects removed from CPE")
    try:
        _command(sock, ["/system/identity/set", "=name=ISPCENTRIC CPE"])
    except Exception:
        pass
    return notes


def apply_cpe_renew_portal(
    customer,
    *,
    enabled: bool,
    portal_url: str = "",
    timeout: float = 8.0,
) -> dict[str, Any]:
    """
    Enable or disable the Wi‑Fi captive renew popup on the subscriber CPE.

    Requires an active PPPoE session and working CPE API credentials.
    """
    nas = getattr(customer, "router", None)
    pppoe_username = (getattr(customer, "pppoe_username", None) or "").strip()
    if not nas or not pppoe_username:
        return {
            "ok": False,
            "skipped": True,
            "error": "No MikroTik NAS or PPPoE username — renew portal not applied.",
        }

    session = resolve_customer_cpe_session(
        nas.host,
        nas.username,
        nas.password or "",
        pppoe_username=pppoe_username,
        timeout=timeout,
    )
    if not session.get("session_active"):
        return {
            "ok": False,
            "skipped": True,
            "session_active": False,
            "error": session.get("hint")
            or "CPE is offline — renew Wi‑Fi popup will apply next time they are online before cut-off.",
        }

    cpe_host = (session.get("address") or "").strip()
    last_error = ""
    for user, password in _cpe_credential_candidates(
        cpe_username=getattr(customer, "cpe_username", "") or "admin",
        cpe_password=getattr(customer, "cpe_password", "") or "",
        pppoe_password=getattr(customer, "pppoe_password", "") or "",
    ):
        try:
            with _cpe_api_session(
                nas.host,
                nas.username,
                nas.password or "",
                cpe_host,
                user,
                password,
                timeout=timeout,
                proxy_scope=pppoe_username,
            ) as sock:
                notes = (
                    _enable_cpe_renew_hotspot(sock, portal_url=portal_url)
                    if enabled
                    else _disable_cpe_renew_hotspot(sock)
                )
            # Remember the PPP address while we still know it — dst-nat renew
            # auto-fill uses this after the session is kicked/redialed.
            # Per-IP only (never an org-wide marker): multi-customer orgs would
            # otherwise autofill the wrong account on 192.168.189.x probes.
            if enabled:
                remember_pppoe_customer_session_ip(customer, cpe_host)
            return {
                "ok": True,
                "enabled": enabled,
                "cpe_host": cpe_host,
                "notes": notes,
                "message": (
                    "Renew popup enabled on client Wi‑Fi."
                    if enabled
                    else "Renew popup removed from client Wi‑Fi."
                ),
            }
        except ConnectionError as exc:
            last_error = str(exc) or "CPE login failed."
            continue
        except (TimeoutError, OSError) as exc:
            last_error = str(exc) or f"Could not reach CPE at {cpe_host}."
            break
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc) or "Could not configure renew portal on CPE."
            continue

    return {
        "ok": False,
        "skipped": False,
        "error": last_error
        or "Could not configure the renew Wi‑Fi popup on the client CPE.",
    }


def _captive_cache_get(key: str):
    try:
        from django.core.cache import cache

        return cache.get(key)
    except Exception:
        return None


def _captive_cache_set(key: str, value, ttl: int) -> None:
    try:
        from django.core.cache import cache

        cache.set(key, value, ttl)
    except Exception:
        pass


def _mac_compact(mac_address: str) -> str:
    return "".join(ch for ch in (mac_address or "") if ch.isalnum()).upper()


def _hotspot_router_sees_mac(sock: socket.socket, compact_mac: str) -> bool:
    for path in ("/ip/hotspot/active", "/ip/hotspot/host"):
        for row in _print(sock, path, props="mac-address"):
            row_mac = _mac_compact(row.get("mac-address") or "")
            if row_mac == compact_mac:
                return True
    return False


def find_hotspot_router_for_mac(organization, mac_address: str):
    """
    Return the organization's active MikroTik currently seeing this client MAC.

    An organization can have multiple saved routers. Picking the first row is
    unsafe: a stale/unreachable NAS can receive the customer assignment while
    the payment came through a different Hotspot. The paying device must be
    provisioned on the router whose host/active table contains its MAC.
    """
    from core.models import MikroTikRouter

    compact = _mac_compact(mac_address)
    if len(compact) != 12:
        return None

    org_id = getattr(organization, "pk", None)
    cache_key = f"captive:hs-mac:{org_id}:{compact}"
    cached_id = _captive_cache_get(cache_key)
    if cached_id:
        cached = (
            MikroTikRouter.objects.filter(
                pk=cached_id,
                organization=organization,
                account_status=MikroTikRouter.AccountStatus.ACTIVE,
            )
            .first()
        )
        if cached is not None:
            return cached

    routers = list(
        MikroTikRouter.objects.filter(
            organization=organization,
            account_status=MikroTikRouter.AccountStatus.ACTIVE,
        ).order_by("id")
    )
    # Prefer a router already bound to this MAC customer — usually the live NAS.
    try:
        from billing.models import Customer

        bound_id = (
            Customer.objects.filter(
                organization=organization,
                service_type=Customer.ServiceType.HOTSPOT,
                hotspot_mac__iexact=":".join(
                    compact[i : i + 2] for i in range(0, 12, 2)
                ),
            )
            .exclude(router_id=None)
            .values_list("router_id", flat=True)
            .first()
        )
        if bound_id:
            routers.sort(key=lambda row: 0 if row.pk == bound_id else 1)
    except Exception:
        pass

    for router in routers:
        host = router.api_host
        username = (router.username or "").strip()
        if not host or not username:
            continue
        try:
            with _api_session(
                host, username, router.password or "", timeout=_CAPTIVE_API_TIMEOUT
            ) as sock:
                if _hotspot_router_sees_mac(sock, compact):
                    _captive_cache_set(cache_key, router.pk, _CAPTIVE_SESSION_CACHE_TTL)
                    return router
        except Exception:
            continue
    return None


def is_pppoe_pool_ip(ip: str) -> bool:
    """True when the address sits in the ISPCentric PPPoE client pool."""
    try:
        return ipaddress.ip_address((ip or "").strip()) in _PPPOE_POOL_NET
    except ValueError:
        return False


def is_cpe_renew_pool_ip(ip: str) -> bool:
    """True when the address sits in the CPE renew Hotspot pool (expired PPPoE Wi‑Fi)."""
    try:
        return ipaddress.ip_address((ip or "").strip()) in _RENEW_HOTSPOT_POOL_NET
    except ValueError:
        return False


def is_hotspot_pool_ip(ip: str) -> bool:
    """True when the address sits in the ISPCentric Hotspot client pool."""
    try:
        return ipaddress.ip_address((ip or "").strip()) in _ISP_HOTSPOT_POOL_NET
    except ValueError:
        return False


def _format_hotspot_mac(mac_address: str) -> str:
    compact = _mac_compact(mac_address)
    if len(compact) != 12:
        return ""
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def find_hotspot_mac_for_ip(organization, client_ip: str) -> str:
    """
    Resolve a client MAC from the IP Django sees on a Hotspot request.

    Captive probes sometimes land on the pay page without RouterOS ``mac=``
    substitution. Look up the same IP in Hotspot host/active, DHCP leases, and ARP.
    """
    client_ip = (client_ip or "").strip()
    if not client_ip:
        return ""

    org_id = getattr(organization, "pk", None)
    cache_key = f"captive:hs-ip-mac:{org_id}:{client_ip}"
    cached = _captive_cache_get(cache_key)
    if isinstance(cached, str) and cached:
        return cached

    from core.models import MikroTikRouter

    routers = list(
        MikroTikRouter.objects.filter(
            organization=organization,
            account_status=MikroTikRouter.AccountStatus.ACTIVE,
        ).order_by("id")
    )
    for router in routers:
        host = router.api_host
        username = (router.username or "").strip()
        if not host or not username:
            continue
        try:
            with _api_session(
                host, username, router.password or "", timeout=_CAPTIVE_API_TIMEOUT
            ) as sock:
                for path, props in (
                    ("/ip/hotspot/host", "mac-address,address"),
                    ("/ip/hotspot/active", "mac-address,address"),
                    ("/ip/dhcp-server/lease", "mac-address,address,active-mac-address"),
                    ("/ip/arp", "mac-address,address"),
                ):
                    rows = _print(
                        sock,
                        path,
                        props=props,
                        query={"address": client_ip},
                    )
                    if not rows:
                        rows = _print(sock, path, props=props)
                    for row in rows:
                        if (row.get("address") or "").strip() != client_ip:
                            continue
                        mac = _format_hotspot_mac(
                            row.get("active-mac-address")
                            or row.get("mac-address")
                            or ""
                        )
                        if mac:
                            _captive_cache_set(
                                cache_key, mac, _CAPTIVE_PPPOE_IP_CACHE_TTL
                            )
                            return mac
        except Exception:
            continue
    return ""


def remember_hotspot_mac_for_ip(organization, client_ip: str, mac_address: str) -> None:
    """Cache a known Hotspot client IP → MAC mapping."""
    client_ip = (client_ip or "").strip()
    mac = _format_hotspot_mac(mac_address)
    org_id = getattr(organization, "pk", None)
    if not client_ip or not mac or not org_id:
        return
    _captive_cache_set(
        f"captive:hs-ip-mac:{org_id}:{client_ip}",
        mac,
        _CAPTIVE_PPPOE_IP_CACHE_TTL,
    )


def _fallback_captive_organization():
    """Best-effort org when the client IP cannot be matched to a live NAS session."""
    from accounts.models import Organization

    org = (
        Organization.objects.filter(hotspot_enabled=True)
        .order_by("id")
        .first()
    )
    if org is not None:
        return org
    org = (
        Organization.objects.filter(pppoe_compulsory=True)
        .order_by("id")
        .first()
    )
    if org is not None:
        return org
    return Organization.objects.order_by("id").first()


def _captive_org_candidates():
    """Organizations that own captive Hotspot / PPPoE access."""
    from accounts.models import Organization
    from django.db.models import Q

    # Include every org that can own a captive client: Hotspot, compulsory
    # PPPoE, or any router (pure PPPoE ISPs still need pay redirects).
    return list(
        Organization.objects.filter(
            Q(hotspot_enabled=True)
            | Q(pppoe_compulsory=True)
            | Q(mikrotik_routers__isnull=False)
        )
        .distinct()
        .order_by("id")[:5]
    )


def resolve_captive_organization(client_ip: str = ""):
    """
    Resolve the Organization that should own a captive-portal redirect.

    Prefers a live PPPoE/Hotspot session match on an onboarded router so
    multi-tenant deployments do not land clients on the wrong join_code.
    """
    from core.models import MikroTikRouter

    client_ip = (client_ip or "").strip()
    if not client_ip:
        return _fallback_captive_organization()

    # Single-tenant shortcut first: one captive org cannot be "wrong", and
    # skipping live NAS scans keeps the OS captive popup immediate.
    candidates = _captive_org_candidates()
    if len(candidates) == 1:
        return candidates[0]

    cache_key = f"captive:org-ip:{client_ip}"
    cached_org_id = _captive_cache_get(cache_key)
    if cached_org_id:
        from accounts.models import Organization

        cached = Organization.objects.filter(pk=cached_org_id).first()
        if cached is not None:
            return cached

    routers = (
        MikroTikRouter.objects.filter(
            account_status=MikroTikRouter.AccountStatus.ACTIVE,
        )
        .exclude(organization_id=None)
        .select_related("organization")
        .order_by("id")
    )

    check_pppoe = is_pppoe_pool_ip(client_ip)
    check_hotspot = is_hotspot_pool_ip(client_ip)
    if check_pppoe or check_hotspot:
        for router in routers:
            host = router.api_host
            username = (router.username or "").strip()
            if not host or not username:
                continue
            try:
                with _api_session(
                    host,
                    username,
                    router.password or "",
                    timeout=_CAPTIVE_API_TIMEOUT,
                ) as sock:
                    if check_pppoe:
                        rows = _print(
                            sock,
                            "/ppp/active",
                            props="address",
                            query={"address": client_ip},
                        )
                        if not rows:
                            rows = _print(sock, "/ppp/active", props="address")
                        for row in rows:
                            if (row.get("address") or "").strip() == client_ip:
                                org = router.organization
                                _captive_cache_set(
                                    cache_key, org.pk, _CAPTIVE_ORG_CACHE_TTL
                                )
                                return org
                    if check_hotspot:
                        for path in ("/ip/hotspot/active", "/ip/hotspot/host"):
                            rows = _print(
                                sock,
                                path,
                                props="address",
                                query={"address": client_ip},
                            )
                            if not rows:
                                rows = _print(sock, path, props="address")
                            for row in rows:
                                if (row.get("address") or "").strip() == client_ip:
                                    org = router.organization
                                    _captive_cache_set(
                                        cache_key, org.pk, _CAPTIVE_ORG_CACHE_TTL
                                    )
                                    return org
            except Exception:
                continue

    if len(candidates) == 1:
        return candidates[0]
    return _fallback_captive_organization()


def remember_pppoe_customer_session_ip(customer, session_ip: str) -> None:
    """Cache PPP / CPE-renew client IP → customer for pay-page auto-fill.

    Covers classic PPPoE pool (``10.20.0.x``) and the CPE renew Hotspot pool
    (``192.168.189.x``) so Wi‑Fi probes on an expired CPE still resolve the
    account when ``login.html`` macros are skipped.

    Mapping is always per-IP — never org-wide — so multi-customer ISPs cannot
    autofill the wrong account.
    """
    from billing.models import Customer

    session_ip = (session_ip or "").strip()
    if not session_ip or not (
        is_pppoe_pool_ip(session_ip) or is_cpe_renew_pool_ip(session_ip)
    ):
        return
    if customer is None or not getattr(customer, "pk", None):
        return
    if getattr(customer, "service_type", "") != Customer.ServiceType.PPPOE:
        return
    org_id = getattr(customer, "organization_id", None)
    if not org_id:
        return
    _captive_cache_set(
        f"captive:pppoe-ip:{org_id}:{session_ip}",
        customer.pk,
        _CAPTIVE_PPPOE_IP_CACHE_TTL,
    )


def find_pppoe_customer_for_ip(organization, session_ip: str):
    """
    Resolve a PPPoE Customer from the session IP seen by Django.

    Expired PPPoE clients are dst-nat'd to the billing server, so REMOTE_ADDR
    is the PPP remote address. Match it against /ppp/active on the org's NAS
    to recover the dial-in username, then the Customer row.

    CPE renew Wi‑Fi (``192.168.189.x``) never appears in ``/ppp/active``; those
    IPs resolve via the per-IP renew cache populated when the pay page is opened
    (login.html already carries ``?t=`` for the first hit).
    """
    from billing.models import Customer
    from core.models import MikroTikRouter

    session_ip = (session_ip or "").strip()
    renew_pool = is_cpe_renew_pool_ip(session_ip)
    if not session_ip or not (is_pppoe_pool_ip(session_ip) or renew_pool):
        return None

    org_id = getattr(organization, "pk", None)
    cache_key = f"captive:pppoe-ip:{org_id}:{session_ip}"
    cached_cid = _captive_cache_get(cache_key)
    if cached_cid:
        customer = (
            Customer.objects.filter(
                pk=cached_cid,
                organization=organization,
                service_type=Customer.ServiceType.PPPOE,
            )
            .select_related("plan", "organization", "router")
            .first()
        )
        if customer is not None:
            return customer

    # Renew-pool phones are not PPP peers — skip live NAS scan.
    if renew_pool:
        return None

    routers = list(
        MikroTikRouter.objects.filter(
            organization=organization,
            account_status=MikroTikRouter.AccountStatus.ACTIVE,
        ).order_by("id")
    )
    # Prefer routers already assigned to PPPoE customers — likely the live NAS.
    bound_ids = set(
        Customer.objects.filter(
            organization=organization,
            service_type=Customer.ServiceType.PPPOE,
        )
        .exclude(router_id=None)
        .values_list("router_id", flat=True)
        .distinct()[:20]
    )
    if bound_ids:
        routers.sort(key=lambda row: 0 if row.pk in bound_ids else 1)

    for router in routers:
        host = router.api_host
        username = (router.username or "").strip()
        if not host or not username:
            continue
        try:
            with _api_session(
                host, username, router.password or "", timeout=_CAPTIVE_API_TIMEOUT
            ) as sock:
                rows = _print(
                    sock,
                    "/ppp/active",
                    props="name,address",
                    query={"address": session_ip},
                )
                if not rows:
                    rows = _print(sock, "/ppp/active", props="name,address")
                for row in rows:
                    if (row.get("address") or "").strip() != session_ip:
                        continue
                    ppp_user = (row.get("name") or "").strip()
                    if not ppp_user:
                        continue
                    customer = (
                        Customer.objects.filter(
                            organization=organization,
                            service_type=Customer.ServiceType.PPPOE,
                            pppoe_username__iexact=ppp_user,
                        )
                        .select_related("plan", "organization", "router")
                        .order_by("id")
                        .first()
                    )
                    if customer is not None:
                        if customer.router_id != router.pk:
                            customer.router = router
                            customer.save(update_fields=["router"])
                        remember_pppoe_customer_session_ip(customer, session_ip)
                        return customer
        except Exception:
            continue
    return None


def _pppoe_pay_portal_url(organization, portal_url: str = "", customer=None) -> str:
    """Absolute PPPoE renew/pay URL to install on the CPE Hotspot login page.

    When ``customer`` is provided, append a signed token so the renew page can
    auto-fill that account even when the phone is on CPE Wi‑Fi (not 10.20.0.x).

    Returns an absolute http(s) URL, or "" when no public/LAN base is known —
    never a path-only Location (those trap phones on ``http://192.168.…/pppoe/…``).
    """
    from urllib.parse import urlencode, urlparse, urlunparse

    from django.core import signing
    from django.urls import reverse

    join_code = (getattr(organization, "join_code", None) or "").strip()
    if not join_code:
        return _billing_portal_base_url(portal_url)
    path = reverse("core:pppoe_pay", kwargs={"join_code": join_code})
    explicit = (portal_url or "").strip()
    parsed_explicit = urlparse(explicit)
    explicit_path = (parsed_explicit.path or "").rstrip("/")
    # Caller may already pass the full pay URL (with or without ?t=).
    if (
        explicit
        and "/pppoe/" in explicit_path
        and explicit_path.endswith("/pay")
        and parsed_explicit.scheme
    ):
        url = explicit
    else:
        base = _billing_portal_base_url(explicit if parsed_explicit.scheme else "")
        if not base:
            return ""
        url = f"{base.rstrip('/')}{path}"

    # Captive WebViews stall on HTTPS/HSTS; prefer http:// for the CPE popup.
    url = _prefer_http_captive_url(url)

    if customer is not None and getattr(customer, "pk", None) and getattr(organization, "pk", None):
        token = signing.dumps(
            {
                "cid": customer.pk,
                "org": organization.pk,
                "mode": "pppoe",
            },
            salt="pppoe-payment",
            compress=True,
        )
        params = {"t": token}
        account = (getattr(customer, "account_number", None) or "").strip()
        if account:
            params["account"] = account
        # Replace or append token params without duplicating.
        parsed = urlparse(url)
        from urllib.parse import parse_qsl, urlencode as _urlencode

        q = dict(parse_qsl(parsed.query, keep_blank_values=True))
        q.update(params)
        url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                _urlencode(q),
                parsed.fragment,
            )
        )
    return url


def sync_customer_subscription_access(
    customer,
    *,
    portal_url: str = "",
    provision: bool = True,
    reauthenticate: bool = True,
) -> dict[str, Any]:
    """
    Enforce package period and package speeds on the NAS.

    Outside the subscription period (account still active):
      1. Enable the CPE Wi‑Fi renew Hotspot (pay popup) while the CPE is still
         online so phones get the captive portal without a manual reconnect
      2. Move /ppp/secret to the blocked profile + kick the session so surfing
         stops at the ISP MikroTik
      Calendar packages (daily/weekly/monthly/…) only enter this path at local
      00:00 after the package end date — never at the purchase clock time.
    Account inactive / suspended:
      Disable the PPPoE secret entirely
    Inside the period:
      Restore a per-package PPP/Hotspot profile whose rate-limit matches the
      plan download/upload Mbps, and remove the CPE renew Hotspot
    """
    from billing.models import Customer
    from billing.services import customer_receives_internet

    allowed = customer_receives_internet(customer)
    status_active = getattr(customer, "status", "") == "active"
    portal_result: dict[str, Any] = {"ok": False, "skipped": True}
    provision_result: dict[str, Any] = {"ok": False, "skipped": not provision}

    # Same-request or near-immediate status polls often re-enter after fulfill
    # already pushed access. Reuse that result for a few seconds.
    # Rate-limit is part of the key so a package speed edit is never skipped.
    customer_id = getattr(customer, "pk", None)
    rate_key = _pppoe_rate_limit_for_customer(customer) or _hotspot_rate_limit_for_customer(
        customer
    )
    provision_cache_key = (
        f"captive:provision:{customer_id}:{int(bool(allowed))}:"
        f"{int(bool(reauthenticate))}:{rate_key}"
        if customer_id
        else ""
    )
    if provision and provision_cache_key:
        cached_provision = _captive_cache_get(provision_cache_key)
        if isinstance(cached_provision, dict) and cached_provision.get("ok") is not None:
            return cached_provision

    def _finish(payload: dict[str, Any]) -> dict[str, Any]:
        # Never cache a "blocked" success when the CPE renew popup failed —
        # otherwise status polls / sweeps skip re-pushing login.html for 8s+.
        if provision and provision_cache_key and payload.get("ok"):
            portal = payload.get("portal") or {}
            if (
                not payload.get("allowed")
                and status_active
                and not portal.get("ok")
            ):
                return payload
            _captive_cache_set(provision_cache_key, payload, 8)
        return payload

    if getattr(customer, "service_type", "") == Customer.ServiceType.HOTSPOT:
        router = getattr(customer, "router", None)
        detected_router = find_hotspot_router_for_mac(
            customer.organization,
            getattr(customer, "hotspot_mac", "") or "",
        )
        if detected_router is not None:
            router = detected_router
            if customer.router_id != detected_router.pk:
                customer.router = detected_router
                customer.save(update_fields=["router"])
        if router is None:
            from core.models import MikroTikRouter

            router = (
                MikroTikRouter.objects.filter(
                    organization_id=customer.organization_id,
                    account_status=MikroTikRouter.AccountStatus.ACTIVE,
                )
                .order_by("id")
                .first()
            )
        if not provision or router is None:
            return {
                "ok": not provision,
                "allowed": allowed,
                "portal": portal_result,
                "provision": provision_result,
                "message": "No active MikroTik is available for Hotspot authorization.",
            }
        provision_result = authorize_hotspot_customer(
            customer,
            router=router,
            reauthenticate=reauthenticate,
        )
        # Offline/skipped pushes report ok=True; treat those as not provisioned
        # so payment UI can retry authorization without charging again.
        provisioned = bool(
            provision_result.get("ok") and not provision_result.get("skipped")
        )
        return _finish(
            {
                "ok": provisioned,
                "allowed": allowed,
                "portal": portal_result,
                "provision": provision_result,
                "offline": bool(provision_result.get("skipped")),
                "message": (
                    "Paid device authorized automatically."
                    if allowed and provisioned
                    else (
                        provision_result.get("message")
                        or "Hotspot access is blocked or could not be synchronized."
                    )
                ),
            }
        )

    pay_url = _pppoe_pay_portal_url(
        getattr(customer, "organization", None),
        portal_url,
        customer=customer,
    )

    if not allowed:
        if provision:
            if status_active:
                # Enable CPE renew popup FIRST while WAN still works (HTML fetch).
                # Then block+kick on the NAS so surfing stops and phones re-probe.
                # Loop corrections: CPE API / file writes often flake once on busy
                # routers; without retries phones stay on "no internet" with no popup.
                portal_result = {"ok": False, "skipped": True}
                for attempt in range(1, _CAPTIVE_REPAIR_ATTEMPTS + 1):
                    try:
                        portal_result = apply_cpe_renew_portal(
                            customer, enabled=True, portal_url=pay_url
                        )
                    except Exception as exc:  # noqa: BLE001
                        portal_result = {
                            "ok": False,
                            "skipped": False,
                            "error": str(exc) or "CPE renew portal failed.",
                            "attempt": attempt,
                        }
                    if portal_result.get("ok") or portal_result.get("skipped"):
                        break
                provision_result = provision_customer_pppoe(
                    customer,
                    ensure_stack=False,
                    force_disabled=False,
                )
                # If CPE was offline during the first attempts, retry after the
                # blocked redial so the popup still appears for Wi‑Fi clients.
                if not portal_result.get("ok") and not portal_result.get("skipped"):
                    for attempt in range(1, _CAPTIVE_REPAIR_ATTEMPTS + 1):
                        try:
                            retry = apply_cpe_renew_portal(
                                customer, enabled=True, portal_url=pay_url
                            )
                            portal_result = retry
                            if retry.get("ok") or retry.get("skipped"):
                                break
                        except Exception:
                            pass
            else:
                provision_result = provision_customer_pppoe(
                    customer,
                    ensure_stack=False,
                    force_disabled=True,
                )
    else:
        if provision:
            # Clear the CPE renew Hotspot / WAN-block FIRST while the PPP
            # session is still up (even on the blocked profile). Provisioning
            # kicks the session so a post-kick clear often fails with "CPE
            # offline", leaving phones trapped behind the renew popup and the
            # CPE stuck redialing.
            portal_result = {"ok": False, "skipped": True}
            for attempt in range(1, _CAPTIVE_REPAIR_ATTEMPTS + 1):
                try:
                    portal_result = apply_cpe_renew_portal(
                        customer, enabled=False, portal_url=pay_url
                    )
                except Exception as exc:  # noqa: BLE001
                    portal_result = {
                        "ok": False,
                        "skipped": False,
                        "error": str(exc) or "Could not clear CPE renew portal.",
                        "attempt": attempt,
                    }
                if portal_result.get("ok") or portal_result.get("skipped"):
                    break
            provision_result = provision_customer_pppoe(
                customer,
                ensure_stack=False,
                force_disabled=False,
            )
            # If the CPE was briefly offline before the kick, try once more
            # after the speed profile is restored (redial may already be up).
            if not portal_result.get("ok") and not portal_result.get("skipped"):
                for attempt in range(1, _CAPTIVE_REPAIR_ATTEMPTS + 1):
                    try:
                        retry = apply_cpe_renew_portal(
                            customer, enabled=False, portal_url=pay_url
                        )
                        portal_result = retry
                        if retry.get("ok") or retry.get("skipped"):
                            break
                    except Exception:
                        pass

    nas_blocked = bool(
        not allowed
        and status_active
        and provision_result.get("ok")
        and provision_result.get("profile") == PPPOE_BLOCKED_PROFILE_NAME
    )
    portal_ok = bool(portal_result.get("ok"))
    # Surfing can be blocked on the NAS even if CPE popup failed, but overall
    # success for expired active clients requires the Wi‑Fi pay redirect.
    if not allowed and status_active and provision:
        overall_ok = bool(provision_result.get("ok")) and (
            portal_ok or bool(portal_result.get("skipped"))
        )
        # Hard-fail (and count as error in sweeps) when portal attempted & failed.
        if not portal_ok and not portal_result.get("skipped"):
            overall_ok = False
    else:
        overall_ok = bool(
            provision_result.get("ok") or not provision or portal_ok
        )
    message = (
        "Internet allowed for subscription period."
        if allowed
        else (
            "Surfing blocked on the ISP MikroTik"
            + (" outside subscription period." if nas_blocked else ".")
            + (
                " CPE renew pay popup is live."
                if portal_ok
                else (
                    " CPE renew pay popup pending (CPE offline)."
                    if portal_result.get("skipped")
                    else " CPE renew pay popup failed — Wi‑Fi clients may not see pay."
                )
            )
        )
    )
    return _finish(
        {
            "ok": overall_ok,
            "allowed": allowed,
            "portal": portal_result,
            "provision": provision_result,
            "message": message,
        }
    )


def _persist_resolved_lan_bridge(router, resolved_lan: str, notes: list[str]) -> None:
    """Save the LAN bridge the router actually has, so later pushes stop failing."""
    resolved_lan = (resolved_lan or "").strip()
    if not resolved_lan or not hasattr(router, "lan_bridge"):
        return
    if (getattr(router, "lan_bridge", "") or "").strip() == resolved_lan:
        return
    try:
        router.lan_bridge = resolved_lan
        router.save(update_fields=["lan_bridge", "updated_at"])
        notes.append(f"updated saved LAN bridge to {resolved_lan}")
    except Exception:
        pass


def _hotspot_portal_urls_for_org(organization) -> dict[str, str]:
    """Absolute Hotspot portal URLs for an organization (empty when unavailable)."""
    if organization is None:
        return {}
    join_code = (getattr(organization, "join_code", None) or "").strip()
    if not join_code:
        return {}
    try:
        from core.hotspot_portal import hotspot_portal_urls

        return hotspot_portal_urls(join_code)
    except Exception:
        return {}


def apply_pppoe_enforcement_on_router(
    router,
    *,
    compulsory: bool,
    candidate_hosts: list[str] | None = None,
    hotspot_fallback: bool | None = None,
) -> dict[str, Any]:
    """
    Push PPPoE pool/server + compulsory firewall policy to one MikroTik.

    When compulsory is True, also provision Hotspot fallback so devices that
    are not dialed in via PPPoE are redirected to the payment portal instead
    of being silently dropped.
    """
    if router is None:
        return {"ok": False, "error": "No router provided."}

    host = (getattr(router, "host", None) or "").strip()
    username = (getattr(router, "username", None) or "").strip()
    password = getattr(router, "password", None) or ""
    router_id = getattr(router, "pk", None)
    router_name = getattr(router, "name", "") or host
    if not host or not username:
        return {
            "ok": False,
            "router_id": router_id,
            "router_name": router_name,
            "error": "Router host or username is missing.",
        }

    lan_interface = getattr(router, "lan_bridge", None) or "bridgeLocal"
    wan_interface = getattr(router, "wan_interface", None) or "ether1"
    org = getattr(router, "organization", None)
    enable_hotspot_fallback = (
        bool(compulsory) if hotspot_fallback is None else bool(hotspot_fallback)
    )

    hosts = _router_api_host_candidates(router, candidate_hosts)

    last_error = ""
    working_host = ""
    notes: list[str] = []
    resolved_lan = ""

    secrets_synced = 0
    for candidate in hosts:
        probe = check_mikrotik_reachable(candidate, timeout=1.5)
        via = (probe.get("via") or "").strip()
        # Fail fast on hosts that only answer ping — API is usually firewalled.
        attempt_timeout = 3.0 if via == "ping" else 12.0
        if not probe.get("online") and candidate != host:
            # Still try saved host even when probe fails; skip weak discovered misses.
            continue
        try:
            with _api_session(
                candidate, username, password, timeout=attempt_timeout
            ) as sock:
                portal_url = _billing_portal_base_url()
                lan_interface = _resolve_lan_interface(
                    sock, lan_interface, exclude=wan_interface
                )
                resolved_lan = lan_interface
                _, notes = _ensure_pppoe_stack(
                    sock,
                    lan_interface=lan_interface,
                    wan_interface=wan_interface,
                    compulsory=bool(compulsory),
                    portal_url=portal_url,
                )
                secrets_synced = _sync_organization_pppoe_secrets_on_socket(sock, router)
                if secrets_synced:
                    notes.append(f"synced {secrets_synced} PPPoE secret(s)")
            working_host = candidate
            break
        except TimeoutError:
            last_error = f"{candidate}: timed out on API port 8728"
        except OSError as exc:
            message = str(exc) or "network error"
            if "timed out" in message.lower() or getattr(exc, "errno", None) in {10060, 110}:
                last_error = f"{candidate}: timed out on API port 8728"
            else:
                last_error = f"{candidate}: {message}"
        except Exception as exc:  # noqa: BLE001
            last_error = f"{candidate}: {exc}"

    if not working_host:
        unreachable = last_error or f"{host}: timed out"
        return {
            "ok": False,
            "router_id": router_id,
            "router_name": router_name,
            "timeout": True,
            "error": (
                f"{unreachable}. This PC cannot reach the MikroTik API right now. "
                "Plug into ether2–ether5 (LAN), open the router detail page, click Reconnect, "
                "then push PPPoE enforcement again."
            )
            if on_router_lan()
            else f"{unreachable}. {unreachable_router_error(router)}",
        }

    # The tunnel address is not the router's own IP, so never write it over it.
    tunnel = (getattr(router, "vpn_address", None) or "").strip()
    host_changed = bool(working_host and working_host not in (host, tunnel))
    if host_changed and hasattr(router, "host"):
        try:
            router.host = working_host
            router.save(update_fields=["host", "updated_at"])
            notes.append(f"updated saved IP to {working_host}")
        except Exception:
            pass

    _persist_resolved_lan_bridge(router, resolved_lan, notes)

    hotspot_result: dict[str, Any] | None = None
    if enable_hotspot_fallback and org is not None:
        # Compulsory mode without Hotspot silently drops free LAN users.
        # Auto-enable the org flag and push the captive portal as fallback.
        if not getattr(org, "hotspot_enabled", False):
            try:
                org.hotspot_enabled = True
                org.save(update_fields=["hotspot_enabled"])
                notes.append("enabled organization Hotspot fallback")
            except Exception:
                pass
        urls = _hotspot_portal_urls_for_org(org)
        redirect_url = (getattr(org, "hotspot_redirect_url", "") or "").strip()
        if getattr(org, "hotspot_use_welcome_page", True):
            redirect_url = urls.get("welcome_url") or redirect_url
            if redirect_url and org.hotspot_redirect_url != redirect_url:
                try:
                    org.hotspot_redirect_url = redirect_url
                    org.save(update_fields=["hotspot_redirect_url"])
                except Exception:
                    pass
        hotspot_result = apply_hotspot_on_router(
            router,
            enabled=True,
            organization=org,
            reauthenticate=False,
            redirect_url=redirect_url if redirect_url else urls.get("welcome_url", ""),
            login_url=urls.get("login_url", ""),
            alogin_url=urls.get("alogin_url", ""),
            pay_url=urls.get("pay_url", ""),
            welcome_url=urls.get("welcome_url", ""),
            candidate_hosts=candidate_hosts,
        )
        if hotspot_result.get("ok") and not hotspot_result.get("skipped"):
            notes.append("Hotspot fallback portal provisioned")
            notes.extend(list(hotspot_result.get("notes") or [])[:6])
        elif hotspot_result.get("skipped"):
            notes.append(
                hotspot_result.get("message")
                or "Hotspot fallback skipped (router offline)"
            )
        else:
            notes.append(
                hotspot_result.get("error")
                or "Hotspot fallback could not be provisioned"
            )

    portal_base_is_loopback = False
    try:
        from core.hotspot_portal import is_loopback_url

        portal_base_is_loopback = is_loopback_url(_billing_portal_base_url())
    except Exception:
        portal_base_is_loopback = False

    return {
        "ok": True,
        "router_id": router_id,
        "router_name": router_name,
        "host": working_host,
        "host_changed": host_changed,
        "compulsory": bool(compulsory),
        "secrets_synced": secrets_synced,
        "lan_bridge": resolved_lan or lan_interface,
        "hotspot": hotspot_result,
        "hotspot_fallback": bool(enable_hotspot_fallback),
        "portal_base_is_loopback": portal_base_is_loopback,
        "notes": notes,
        "message": (
            "Free LAN browsing blocked; paid PPPoE clients surf automatically and "
            "other devices are sent to the Hotspot payment portal."
            if compulsory
            else "LAN browsing allowed again alongside PPPoE clients."
        ),
    }


def apply_pppoe_enforcement_for_organization(organization, *, compulsory: bool | None = None) -> dict[str, Any]:
    """Apply PPPoE enforcement firewall policy on every router for an organization."""
    if organization is None:
        return {"ok": False, "applied": 0, "failed": 0, "results": [], "error": "No organization."}

    if compulsory is None:
        compulsory = bool(getattr(organization, "pppoe_compulsory", False))

    from core.models import MikroTikRouter

    routers = list(
        MikroTikRouter.objects.filter(organization=organization).only(
            "id",
            "name",
            "host",
            "username",
            "password",
            "lan_bridge",
            "wan_interface",
            "account_status",
        )
    )
    if not routers:
        return {
            "ok": True,
            "compulsory": bool(compulsory),
            "applied": 0,
            "failed": 0,
            "router_count": 0,
            "results": [],
        }

    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: list[dict[str, Any]] = []
    workers = min(6, len(routers))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(apply_pppoe_enforcement_on_router, router, compulsory=bool(compulsory))
            for router in routers
        ]
        for future in as_completed(futures):
            results.append(future.result())

    applied = sum(1 for item in results if item.get("ok"))
    failed = len(results) - applied
    return {
        "ok": failed == 0,
        "compulsory": bool(compulsory),
        "applied": applied,
        "failed": failed,
        "router_count": len(routers),
        "results": results,
    }


def _ros_duration_minutes(minutes: int) -> str:
    minutes = max(0, int(minutes or 0))
    if minutes <= 0:
        return "0s"
    if minutes % 60 == 0 and minutes >= 60:
        hours = minutes // 60
        if hours % 24 == 0:
            return f"{hours // 24}d"
        return f"{hours}h"
    return f"{minutes}m"


def _ros_duration_hours(hours: int) -> str:
    hours = max(0, int(hours or 0))
    if hours <= 0:
        return "0s"
    if hours % 24 == 0:
        return f"{hours // 24}d"
    return f"{hours}h"


def _hotspot_rate_limit_from_org(organization) -> str:
    upload = int(getattr(organization, "hotspot_default_upload_mbps", 0) or 0)
    download = int(getattr(organization, "hotspot_default_download_mbps", 0) or 0)
    return _rate_limit_string(upload, download) or "5M/10M"


def _hotspot_speeds_for_customer(customer, organization=None) -> tuple[int, int]:
    """Prefer the customer's package speeds; fall back to org Hotspot defaults."""
    upload, download = _plan_speeds_mbps(getattr(customer, "plan", None))
    if upload >= 1 and download >= 1:
        return upload, download
    org = organization or getattr(customer, "organization", None)
    org_upload = int(getattr(org, "hotspot_default_upload_mbps", 0) or 0) if org else 0
    org_download = int(getattr(org, "hotspot_default_download_mbps", 0) or 0) if org else 0
    if org_upload < 1 and org_download < 1:
        return 5, 10
    if org_upload < 1:
        org_upload = org_download
    if org_download < 1:
        org_download = org_upload
    return org_upload, org_download


def _hotspot_rate_limit_for_customer(customer, organization=None) -> str:
    upload, download = _hotspot_speeds_for_customer(customer, organization)
    return _rate_limit_string(upload, download)


def _hotspot_speed_profile_name(upload_mbps: int, download_mbps: int) -> str:
    return f"ispcentric-hs-{int(upload_mbps)}u-{int(download_mbps)}d"


def _hotspot_customers_for_router(router):
    from billing.models import Customer

    org_id = getattr(router, "organization_id", None)
    if not org_id:
        return []
    qs = (
        Customer.objects.filter(
            organization_id=org_id,
            service_type=Customer.ServiceType.HOTSPOT,
        )
        .select_related("plan")
        .order_by("id")
    )
    return [
        customer
        for customer in qs
        if customer.router_id in (None, getattr(router, "pk", None))
    ]


def _lan_ipv4_for_interface(sock: socket.socket, lan: str) -> str:
    lan_l = (lan or "").strip().lower()
    for row in _print(sock, "/ip/address", props="address,interface"):
        iface = (row.get("interface") or "").strip().lower()
        if lan_l and iface != lan_l:
            continue
        address = (row.get("address") or "").strip()
        if "/" in address:
            address = address.split("/", 1)[0].strip()
        if address and not address.startswith("10.20.0."):
            return address
    return ISP_HOTSPOT_ADDRESS


def _remove_isp_hotspot_tagged(sock: socket.socket, path: str) -> int:
    """Remove only ISPCENTRIC Hotspot rows (never the CPE renew Hotspot)."""
    removed = 0
    for row in _print(sock, path, props=".id,name,comment"):
        comment = row.get("comment") or ""
        name = (row.get("name") or "").strip()
        if ISP_HOTSPOT_TAG not in comment and name not in {
            ISP_HOTSPOT_NAME,
            ISP_HOTSPOT_PROFILE,
            ISP_HOTSPOT_USER_PROFILE,
            ISP_HOTSPOT_POOL,
        }:
            continue
        item_id = (row.get(".id") or "").strip()
        if not item_id:
            continue
        terminal = _remove(sock, path, item_id)
        if terminal.get("_reply") != "!trap":
            removed += 1
    return removed


def _ensure_hotspot_walled_garden(sock: socket.socket, redirect_url: str) -> list[str]:
    """Allow the payment/welcome host before Hotspot auth (DNS + HTTP/IP)."""
    notes: list[str] = []
    host = ""
    try:
        from urllib.parse import urlparse
        import ipaddress

        parsed = urlparse((redirect_url or "").strip())
        host = (parsed.hostname or "").strip().lower()
    except Exception:
        host = ""
    if not host or host in {"localhost", "127.0.0.1", "::1"}:
        return notes

    existing = {
        ((row.get("dst-host") or "").strip().lower(), (row.get("comment") or "")): (
            row.get(".id") or ""
        ).strip()
        for row in _print(sock, "/ip/hotspot/walled-garden", props=".id,dst-host,action,comment")
    }
    for dst_host in {host, f"*.{host}"}:
        key = (dst_host.lower(), ISP_HOTSPOT_TAG)
        item_id = existing.get(key) or existing.get((dst_host.lower(), ""))
        attempts = [
            {
                "dst-host": dst_host,
                "action": "allow",
                "comment": ISP_HOTSPOT_TAG,
            },
            {
                "dst-host": dst_host,
                "action": "allow",
            },
        ]
        terminal, _ = _add_or_set_attempts(
            sock,
            "/ip/hotspot/walled-garden",
            item_id,
            attempts,
            required=("dst-host",),
        )
        if terminal.get("_reply") != "!trap":
            notes.append(f"walled garden {dst_host}")

    # IP URLs need walled-garden/ip (Host-header matching alone is unreliable).
    try:
        import ipaddress

        ipaddress.ip_address(host)
        is_ip = True
    except Exception:
        is_ip = False
    if is_ip:
        existing_ip = {
            ((row.get("dst-address") or "").strip(), (row.get("comment") or "")): (
                row.get(".id") or ""
            ).strip()
            for row in _print(
                sock,
                "/ip/hotspot/walled-garden/ip",
                props=".id,dst-address,action,comment",
            )
        }
        item_id = existing_ip.get((host, ISP_HOTSPOT_TAG)) or existing_ip.get((host, ""))
        attempts = [
            {
                "dst-address": host,
                "action": "accept",
                "comment": ISP_HOTSPOT_TAG,
            },
            {
                "dst-address": f"{host}/32",
                "action": "accept",
                "comment": ISP_HOTSPOT_TAG,
            },
            {
                "dst-address": host,
                "action": "accept",
            },
        ]
        terminal, _ = _add_or_set_attempts(
            sock,
            "/ip/hotspot/walled-garden/ip",
            item_id,
            attempts,
            required=("dst-address",),
        )
        if terminal.get("_reply") != "!trap":
            notes.append(f"walled garden ip {host}")
    return notes


def _routable_ipv4_from_url(url: str) -> str:
    """Return the IPv4 literal a portal URL points at, or "" for names/loopback."""
    try:
        host = (urlparse((url or "").strip()).hostname or "").strip()
        address = ipaddress.ip_address(host)
    except ValueError:
        return ""
    if address.version != 4 or address.is_loopback or address.is_unspecified:
        return ""
    return str(address)


def _arp_mac_for_ip(sock: socket.socket, ip: str) -> str:
    for row in _print(sock, "/ip/arp", props="address,mac-address"):
        if (row.get("address") or "").strip() != ip:
            continue
        mac = (row.get("mac-address") or "").strip().upper()
        if mac:
            return mac
    return ""


def _ensure_static_dhcp_lease(sock: socket.socket, ip: str, mac: str) -> list[str]:
    """Pin the server to its current address so the Hotspot bypass keeps matching."""
    notes: list[str] = []
    item_id = ""
    dynamic = False
    for row in _print(
        sock, "/ip/dhcp-server/lease", props=".id,address,mac-address,dynamic"
    ):
        same_ip = (row.get("address") or "").strip() == ip
        same_mac = (row.get("mac-address") or "").strip().upper() == mac
        if not (same_ip or same_mac):
            continue
        item_id = (row.get(".id") or "").strip()
        dynamic = (row.get("dynamic") or "").strip().lower() == "true"
        break

    # A dynamic lease rejects most /set props until RouterOS converts it.
    if item_id and dynamic:
        _, terminal = _command(
            sock, ["/ip/dhcp-server/lease/make-static", f"=.id={item_id}"]
        )
        if terminal.get("_reply") == "!trap":
            notes.append(f"warning: could not reserve {ip} on DHCP")
            return notes

    attempts = [
        {
            "address": ip,
            "mac-address": mac,
            "comment": ISP_HOTSPOT_TAG,
        },
        {
            "address": ip,
            "mac-address": mac,
        },
    ]
    terminal, _ = _add_or_set_attempts(
        sock, "/ip/dhcp-server/lease", item_id, attempts
    )
    if terminal.get("_reply") == "!trap":
        notes.append(f"warning: could not reserve {ip} on DHCP")
    else:
        notes.append(f"DHCP reservation {ip} -> {mac}")
    return notes


def _ensure_hotspot_server_allowlist(sock: socket.socket, ip: str) -> list[str]:
    """Permit the bypassed billing server through PPPoE compulsory filtering."""
    item_id = ""
    for row in _print(
        sock,
        "/ip/firewall/address-list",
        props=".id,list,address,comment",
    ):
        if (
            (row.get("list") or "").strip() == ISP_HOTSPOT_OK_LIST
            and (row.get("address") or "").strip() == ip
        ):
            item_id = (row.get(".id") or "").strip()
            break

    attempts = [
        {
            "list": ISP_HOTSPOT_OK_LIST,
            "address": ip,
            "comment": ISP_HOTSPOT_TAG,
        },
        {
            "list": ISP_HOTSPOT_OK_LIST,
            "address": ip,
        },
    ]
    terminal, _ = _add_or_set_attempts(
        sock, "/ip/firewall/address-list", item_id, attempts
    )
    if terminal.get("_reply") == "!trap":
        return [f"warning: could not allow billing server {ip} through firewall"]
    return [f"firewall allowlist for billing server {ip}"]


def _ensure_daraja_walled_garden(sock: socket.socket) -> list[str]:
    """Allow Safaricom Daraja hosts before Hotspot auth (no full server bypass)."""
    notes: list[str] = []
    hosts = (
        "api.safaricom.co.ke",
        "*.safaricom.co.ke",
        "sandbox.safaricom.co.ke",
    )
    existing = {
        ((row.get("dst-host") or "").strip().lower(), (row.get("comment") or "")): (
            row.get(".id") or ""
        ).strip()
        for row in _print(
            sock, "/ip/hotspot/walled-garden", props=".id,dst-host,action,comment"
        )
    }
    for dst_host in hosts:
        key = (dst_host.lower(), ISP_HOTSPOT_TAG)
        item_id = existing.get(key) or existing.get((dst_host.lower(), ""))
        attempts = [
            {
                "dst-host": dst_host,
                "action": "allow",
                "comment": ISP_HOTSPOT_TAG,
            },
            {
                "dst-host": dst_host,
                "action": "allow",
            },
        ]
        terminal, _ = _add_or_set_attempts(
            sock,
            "/ip/hotspot/walled-garden",
            item_id,
            attempts,
            required=("dst-host",),
        )
        if terminal.get("_reply") != "!trap":
            notes.append(f"walled garden {dst_host}")
    return notes


# Legacy tunnel-script Hotspot bypasses that opened free internet for every
# RFC1918 client. Must be stripped whenever Hotspot is pushed.
_HOTSPOT_LAN_WIDE_BYPASS_ADDRESSES = frozenset(
    {
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    }
)


def _remove_lan_wide_hotspot_bypasses(sock: socket.socket) -> list[str]:
    """
    Delete Hotspot ip-bindings that bypass whole private ranges.

    Older WireGuard install scripts added type=bypassed for 10/8, 172.16/12 and
    192.168/16 so the billing PC could reach API 8728. That also skipped captive
    portal for every unpaid Wi‑Fi client. Remove them by comment and by address.
    """
    notes: list[str] = []
    removed = 0
    try:
        rows = _print(
            sock,
            "/ip/hotspot/ip-binding",
            props=".id,address,type,comment",
        )
    except Exception:  # noqa: BLE001
        return notes
    for row in rows:
        comment = (row.get("comment") or "").strip()
        address = (row.get("address") or "").strip()
        binding_type = (row.get("type") or "").strip().lower()
        item_id = (row.get(".id") or "").strip()
        if not item_id:
            continue
        legacy_comment = "ispcentric-hotspot-bypass" in comment
        wide_address = (
            binding_type == "bypassed"
            and address in _HOTSPOT_LAN_WIDE_BYPASS_ADDRESSES
        )
        if not (legacy_comment or wide_address):
            continue
        _remove(sock, "/ip/hotspot/ip-binding", item_id)
        removed += 1
    if removed:
        notes.append(
            f"removed {removed} LAN-wide Hotspot bypass binding(s) "
            "(paid access is per-MAC only)"
        )
    return notes


def _ensure_hotspot_server_bypass(sock: socket.socket, portal_url: str) -> list[str]:
    """
    Exempt the ISPCentric server itself from Hotspot authentication.

    The server normally sits on the same LAN as the captive clients, so without an
    ip-binding the Hotspot intercepts its own outbound traffic too. Safaricom
    Daraja calls then die mid-TLS handshake (UNEXPECTED_EOF_WHILE_READING) and
    every M-Pesa payment fails.

    Also allow Safaricom hosts in the walled garden so STK remains reachable if
    the bypass binding is missing temporarily.

    Never bypass whole LAN ranges here — only this one billing-server address.
    """
    notes: list[str] = []
    notes.extend(_remove_lan_wide_hotspot_bypasses(sock))
    server_ip = _routable_ipv4_from_url(portal_url)
    if not server_ip:
        return notes

    mac = _arp_mac_for_ip(sock, server_ip)
    item_id = ""
    for row in _print(
        sock, "/ip/hotspot/ip-binding", props=".id,address,mac-address,type,comment"
    ):
        if (row.get("address") or "").strip() == server_ip or (
            mac and (row.get("mac-address") or "").strip().upper() == mac
        ):
            item_id = (row.get(".id") or "").strip()
            break

    attempts: list[dict[str, str]] = []
    if mac:
        attempts.append(
            {
                "address": server_ip,
                "mac-address": mac,
                "type": "bypassed",
                "comment": ISP_HOTSPOT_TAG,
            }
        )
    attempts.extend(
        [
            {
                "address": server_ip,
                "type": "bypassed",
                "comment": ISP_HOTSPOT_TAG,
            },
            {
                "address": server_ip,
                "type": "bypassed",
            },
        ]
    )
    terminal, _ = _add_or_set_attempts(
        sock, "/ip/hotspot/ip-binding", item_id, attempts
    )
    if terminal.get("_reply") == "!trap":
        notes.append(
            f"warning: could not bypass Hotspot for the billing server {server_ip} — "
            "M-Pesa STK Push may fail with TLS errors"
        )
    else:
        notes.append(f"Hotspot bypass for billing server {server_ip}")

    notes.extend(_ensure_daraja_walled_garden(sock))
    notes.extend(_ensure_hotspot_server_allowlist(sock, server_ip))

    if mac:
        notes.extend(_ensure_static_dhcp_lease(sock, server_ip, mac))
    else:
        notes.append(
            f"warning: {server_ip} is not in the router ARP table — "
            "give the billing server a static IP so the Hotspot bypass keeps matching"
        )
    return notes


def _ensure_isp_hotspot_user_profile(sock: socket.socket, organization) -> list[str]:
    notes: list[str] = []
    rate_limit = _hotspot_rate_limit_from_org(organization)
    idle = _ros_duration_minutes(int(getattr(organization, "hotspot_idle_timeout_minutes", 15) or 0))
    session = _ros_duration_hours(int(getattr(organization, "hotspot_voucher_validity_hours", 24) or 24))

    profile_id = ""
    for row in _print(sock, "/ip/hotspot/user/profile", props=".id,name,comment"):
        if (row.get("name") or "").strip() == ISP_HOTSPOT_USER_PROFILE:
            profile_id = (row.get(".id") or "").strip()
            break

    # session-timeout here is only the outer ceiling shared by every device.
    # What a customer actually bought is enforced per user via limit-uptime, so
    # this value must never be mistaken for the package length.
    #
    # add-mac-cookie is off: a stored cookie lets a device log back in without
    # its Hotspot user being re-checked, which would keep an expired package
    # online.
    attempts = [
        {
            "name": ISP_HOTSPOT_USER_PROFILE,
            "session-timeout": session,
            "idle-timeout": idle,
            "keepalive-timeout": "2m",
            "status-autorefresh": "1m",
            "shared-users": "1",
            "add-mac-cookie": "no",
            "rate-limit": rate_limit,
            "address-list": ISP_HOTSPOT_OK_LIST,
            "comment": ISP_HOTSPOT_TAG,
        },
        {
            "name": ISP_HOTSPOT_USER_PROFILE,
            "session-timeout": session,
            "idle-timeout": idle,
            "add-mac-cookie": "no",
            "rate-limit": rate_limit,
            "address-list": ISP_HOTSPOT_OK_LIST,
            "comment": ISP_HOTSPOT_TAG,
        },
        {
            "name": ISP_HOTSPOT_USER_PROFILE,
            "rate-limit": rate_limit,
            "address-list": ISP_HOTSPOT_OK_LIST,
            "comment": ISP_HOTSPOT_TAG,
        },
        {
            "name": ISP_HOTSPOT_USER_PROFILE,
            "rate-limit": rate_limit,
            "comment": ISP_HOTSPOT_TAG,
        },
        {
            "name": ISP_HOTSPOT_USER_PROFILE,
            "rate-limit": rate_limit,
            "address-list": ISP_HOTSPOT_OK_LIST,
        },
        {
            "name": ISP_HOTSPOT_USER_PROFILE,
            "rate-limit": rate_limit,
        },
        {
            "name": ISP_HOTSPOT_USER_PROFILE,
        },
    ]
    terminal, _ = _add_or_set_attempts(
        sock, "/ip/hotspot/user/profile", profile_id, attempts
    )
    if terminal.get("_reply") != "!trap":
        notes.append(f"Hotspot user profile ({rate_limit})")
        return notes
    raise ConnectionError(
        _trap_message(terminal, "Could not create Hotspot user profile on the MikroTik.")
    )


def _ensure_hotspot_rate_profile(
    sock: socket.socket,
    *,
    organization,
    upload_mbps: int,
    download_mbps: int,
) -> str:
    """
    Per-package Hotspot user profile with rate-limit.

    The shared default profile stays as a fallback; each plan gets its own
    profile so a 5 Mbps voucher is not capped the same as a 50 Mbps one.
    """
    upload = int(upload_mbps or 0)
    download = int(download_mbps or 0)
    if upload < 1 or download < 1:
        return ISP_HOTSPOT_USER_PROFILE

    name = _hotspot_speed_profile_name(upload, download)
    rate_limit = _rate_limit_string(upload, download)
    idle = _ros_duration_minutes(
        int(getattr(organization, "hotspot_idle_timeout_minutes", 15) or 0)
    )
    session = _ros_duration_hours(
        int(getattr(organization, "hotspot_voucher_validity_hours", 24) or 24)
    )

    profile_id = ""
    for row in _print(sock, "/ip/hotspot/user/profile", props=".id,name"):
        if (row.get("name") or "").strip() == name:
            profile_id = (row.get(".id") or "").strip()
            break

    attempts = [
        {
            "name": name,
            "session-timeout": session,
            "idle-timeout": idle,
            "keepalive-timeout": "2m",
            "status-autorefresh": "1m",
            "shared-users": "1",
            "add-mac-cookie": "no",
            "rate-limit": rate_limit,
            "address-list": ISP_HOTSPOT_OK_LIST,
            "comment": f"{ISP_HOTSPOT_TAG} {rate_limit}",
        },
        {
            "name": name,
            "idle-timeout": idle,
            "add-mac-cookie": "no",
            "rate-limit": rate_limit,
            "address-list": ISP_HOTSPOT_OK_LIST,
            "comment": f"{ISP_HOTSPOT_TAG} {rate_limit}",
        },
        {
            "name": name,
            "rate-limit": rate_limit,
            "address-list": ISP_HOTSPOT_OK_LIST,
            "comment": f"{ISP_HOTSPOT_TAG} {rate_limit}",
        },
        {
            "name": name,
            "rate-limit": rate_limit,
            "comment": f"{ISP_HOTSPOT_TAG} {rate_limit}",
        },
        {
            "name": name,
            "rate-limit": rate_limit,
        },
    ]
    terminal, _ = _add_or_set_attempts(
        sock, "/ip/hotspot/user/profile", profile_id, attempts
    )
    if terminal.get("_reply") == "!trap":
        # Fall back to the org default profile rather than failing authorize.
        return ISP_HOTSPOT_USER_PROFILE
    return name


def _ensure_hotspot_user(
    sock: socket.socket,
    *,
    username: str,
    password: str,
    comment: str,
    disabled: bool = False,
    limit_uptime: str = "",
    profile: str = "",
) -> str:
    username = (username or "").strip()
    password = password or ""
    if not username:
        raise ConnectionError("Hotspot device identity is empty.")

    user_id = ""
    # Filter server-side by name so a router with thousands of MAC users does
    # not stream its whole /ip/hotspot/user table for a single authorization.
    rows = _print(
        sock,
        "/ip/hotspot/user",
        props=".id,name,comment,disabled",
        query={"name": username},
    )
    if not rows:
        rows = _print(sock, "/ip/hotspot/user", props=".id,name,comment,disabled")
    for row in rows:
        if (row.get("name") or "").strip().lower() == username.lower():
            user_id = (row.get(".id") or "").strip()
            break

    disabled_value = "yes" if disabled else "no"
    tag = comment or ISP_HOTSPOT_TAG
    profile_name = (profile or "").strip() or ISP_HOTSPOT_USER_PROFILE
    # limit-uptime is the router-side hard cap on what this MAC bought. It is
    # cumulative across sessions, so reconnecting cannot extend the package, and
    # it survives the billing server going offline. RouterOS reads "0s" as
    # "no cap", which is only ever passed for a user that is also disabled.
    uptime_cap = (limit_uptime or "").strip() or "0s"
    attempts = [
        {
            "name": username,
            "password": password,
            "profile": profile_name,
            "limit-uptime": uptime_cap,
            "disabled": disabled_value,
            "comment": tag,
        },
        {
            "name": username,
            "password": password,
            "profile": profile_name,
            "limit-uptime": uptime_cap,
            "disabled": disabled_value,
        },
        {
            "name": username,
            "password": password,
            "disabled": disabled_value,
        },
    ]
    terminal, _ = _add_or_set_attempts(sock, "/ip/hotspot/user", user_id, attempts)
    if terminal.get("_reply") == "!trap":
        raise ConnectionError(
            _trap_message(
                terminal,
                f"Could not {'update' if user_id else 'create'} Hotspot user “{username}”.",
            )
        )
    return "updated" if user_id else "created"


def _hotspot_customer_access_fields(customer, *, organization=None, now=None):
    """Return (mac, disabled, limit_uptime, comment) for a Hotspot customer."""
    from django.utils import timezone

    from billing.services import (
        customer_receives_internet,
        subscription_access_deadline,
    )

    mac = (getattr(customer, "hotspot_mac", None) or "").strip().upper()
    if not mac:
        return "", True, "", ""
    org = organization or getattr(customer, "organization", None)
    disabled = not customer_receives_internet(customer, org)
    limit_uptime = ""
    # Cap online time until the real access deadline (midnight for calendar
    # packages). Using raw package_end would cut Wi‑Fi mid-afternoon while
    # PPPoE still had the rest of the day.
    deadline = subscription_access_deadline(customer)
    if not disabled and deadline is not None:
        stamp = timezone.localtime(now or timezone.now())
        if timezone.is_naive(stamp):
            stamp = timezone.make_aware(stamp, timezone.get_current_timezone())
        remaining = int((deadline - stamp).total_seconds())
        limit_uptime = f"{max(remaining, 1)}s"
    comment = f"{ISP_HOTSPOT_TAG} {getattr(customer, 'account_number', '')}".strip()
    return mac, disabled, limit_uptime, comment


def _expire_hotspot_mac_sessions(
    sock: socket.socket,
    mac: str,
    *,
    disabled: bool,
    reauthenticate: bool,
    active_rows: list[dict[str, str]] | None = None,
    host_rows: list[dict[str, str]] | None = None,
) -> None:
    """Expire Hotspot active/host rows for one MAC when access changes."""
    mac = (mac or "").strip().upper()
    if not mac:
        return
    tables = (
        ("/ip/hotspot/active", active_rows),
        ("/ip/hotspot/host", host_rows),
    )
    for path, preset in tables:
        rows = preset
        if rows is None:
            # Single-MAC path: filter server-side instead of streaming every
            # active/host row on a busy NAS.
            rows = _print(
                sock,
                path,
                props=".id,mac-address,authorized",
                query={"mac-address": mac},
            )
            if not rows:
                rows = _print(sock, path, props=".id,mac-address,authorized")
        for row in rows:
            if (row.get("mac-address") or "").strip().upper() != mac:
                continue
            authorized = (row.get("authorized") or "").strip().lower() == "true"
            should_remove = disabled or (
                reauthenticate and path == "/ip/hotspot/host" and not authorized
            )
            item_id = (row.get(".id") or "").strip()
            if should_remove and item_id:
                _remove(sock, path, item_id)


def _apply_hotspot_customer_on_socket(
    sock: socket.socket,
    customer,
    *,
    reauthenticate: bool = True,
    now=None,
    active_rows: list[dict[str, str]] | None = None,
    host_rows: list[dict[str, str]] | None = None,
) -> bool:
    """Create/update one Hotspot MAC user and expire its stale sessions."""
    # Heal routers that still have the old tunnel-script LAN-wide bypasses.
    _remove_lan_wide_hotspot_bypasses(sock)
    mac, disabled, limit_uptime, comment = _hotspot_customer_access_fields(
        customer, now=now
    )
    if not mac:
        return False
    org = getattr(customer, "organization", None)
    upload, download = _hotspot_speeds_for_customer(customer, org)
    profile = _ensure_hotspot_rate_profile(
        sock,
        organization=org,
        upload_mbps=upload,
        download_mbps=download,
    )
    _ensure_hotspot_user(
        sock,
        username=mac,
        password="",
        comment=comment,
        disabled=disabled,
        limit_uptime=limit_uptime,
        profile=profile,
    )
    _expire_hotspot_mac_sessions(
        sock,
        mac,
        disabled=disabled,
        reauthenticate=reauthenticate,
        active_rows=active_rows,
        host_rows=host_rows,
    )
    return True


def _sync_organization_hotspot_users_on_socket(
    sock: socket.socket,
    router,
    *,
    reauthenticate: bool = True,
) -> int:
    # Remove credential-era users; passwordless users are identified only by MAC.
    for row in _print(sock, "/ip/hotspot/user", props=".id,name,comment"):
        comment = row.get("comment") or ""
        if ISP_HOTSPOT_TAG not in comment:
            continue
        name = (row.get("name") or "").strip()
        compact = name.replace(":", "").replace("-", "")
        is_mac = len(compact) == 12 and all(ch in "0123456789abcdefABCDEF" for ch in compact)
        if not is_mac:
            item_id = (row.get(".id") or "").strip()
            if item_id:
                _remove(sock, "/ip/hotspot/user", item_id)

    from django.utils import timezone

    now = timezone.now()
    # Print active/host tables once — per-customer reprints were O(customers × rows).
    active_rows = _print(
        sock, "/ip/hotspot/active", props=".id,mac-address,authorized"
    )
    host_rows = _print(sock, "/ip/hotspot/host", props=".id,mac-address,authorized")
    synced = 0
    for customer in _hotspot_customers_for_router(router):
        if _apply_hotspot_customer_on_socket(
            sock,
            customer,
            reauthenticate=reauthenticate,
            now=now,
            active_rows=active_rows,
            host_rows=host_rows,
        ):
            synced += 1
    return synced


def _hotspot_stack_ready_key(router_id) -> str:
    return f"captive:hs-stack-ready:{router_id}"


def _mark_hotspot_stack_ready(router_id) -> None:
    if router_id:
        _captive_cache_set(_hotspot_stack_ready_key(router_id), 1, _HOTSPOT_STACK_READY_TTL)


def _hotspot_stack_is_ready(router_id) -> bool:
    return bool(router_id and _captive_cache_get(_hotspot_stack_ready_key(router_id)))


def authorize_hotspot_customer(
    customer,
    *,
    router=None,
    reauthenticate: bool = True,
) -> dict[str, Any]:
    """
    Fast path: push one Hotspot MAC user without rebuilding the full stack.

    Used after payment / subscription sync when the ISP Hotspot profile already
    exists on the NAS. Falls back to a full stack push when the router has not
    been marked ready yet (first authorize after restart, or cold cache).
    """
    if customer is None:
        return {"ok": False, "error": "No customer provided.", "skipped": False}

    org = getattr(customer, "organization", None)
    target = router or getattr(customer, "router", None)
    if target is None and org is not None:
        target = find_hotspot_router_for_mac(
            org, getattr(customer, "hotspot_mac", "") or ""
        )
    if target is None and org is not None:
        from core.models import MikroTikRouter

        target = (
            MikroTikRouter.objects.filter(
                organization_id=org.pk,
                account_status=MikroTikRouter.AccountStatus.ACTIVE,
            )
            .order_by("id")
            .first()
        )
    if target is None:
        return {
            "ok": False,
            "skipped": False,
            "error": "No active MikroTik is available for Hotspot authorization.",
        }

    router_id = getattr(target, "pk", None)
    if not _hotspot_stack_is_ready(router_id):
        # Cold cache / first authorize: ensure portal pages + profile exist once.
        result = apply_hotspot_on_router(
            target,
            enabled=True,
            organization=org,
            reauthenticate=reauthenticate,
        )
        if result.get("ok") and not result.get("skipped"):
            _mark_hotspot_stack_ready(router_id)
        return result

    host = (getattr(target, "host", None) or "").strip()
    username = (getattr(target, "username", None) or "").strip()
    password = getattr(target, "password", None) or ""
    router_name = getattr(target, "name", "") or host
    if not host or not username:
        return {
            "ok": False,
            "skipped": False,
            "router_id": router_id,
            "router_name": router_name,
            "error": "Router host or username is missing.",
        }

    hosts = _router_api_host_candidates(target)
    last_error = ""
    any_reachable = False
    # Single probe per candidate — the old pre-scan then per-candidate re-probe
    # doubled the reachability round-trips on the payment-authorize hot path.
    for candidate in hosts:
        probe = check_mikrotik_reachable(candidate, timeout=1.5)
        online = bool(probe.get("online"))
        any_reachable = any_reachable or online
        via = (probe.get("via") or "").strip()
        attempt_timeout = 3.0 if via == "ping" else 8.0
        if not online and candidate != host:
            continue
        try:
            with _api_session(
                candidate, username, password, timeout=attempt_timeout
            ) as sock:
                applied = _apply_hotspot_customer_on_socket(
                    sock, customer, reauthenticate=reauthenticate
                )
            if not applied:
                return {
                    "ok": False,
                    "skipped": False,
                    "router_id": router_id,
                    "router_name": router_name,
                    "error": "Hotspot device MAC is missing.",
                }
            return {
                "ok": True,
                "skipped": False,
                "router_id": router_id,
                "router_name": router_name,
                "host": candidate,
                "users_synced": 1,
                "fast_path": True,
                "notes": ["authorized single Hotspot MAC (stack skipped)"],
                "message": "Paid device authorized automatically.",
            }
        except TimeoutError:
            last_error = f"{candidate}: timed out on API port 8728"
        except OSError as exc:
            message = str(exc) or "network error"
            if "timed out" in message.lower() or getattr(exc, "errno", None) in {
                10060,
                110,
            }:
                last_error = f"{candidate}: timed out on API port 8728"
            else:
                last_error = f"{candidate}: {message}"
        except Exception as exc:  # noqa: BLE001
            # Profile/server missing — invalidate ready flag and fall back once.
            lower = str(exc).lower()
            if "no such item" in lower or "profile" in lower or "hotspot" in lower:
                _captive_cache_set(_hotspot_stack_ready_key(router_id), 0, 1)
                result = apply_hotspot_on_router(
                    target,
                    enabled=True,
                    organization=org,
                    reauthenticate=reauthenticate,
                )
                if result.get("ok") and not result.get("skipped"):
                    _mark_hotspot_stack_ready(router_id)
                return result
            last_error = f"{candidate}: {exc}"

    if not any_reachable:
        # Router simply isn't connected right now — don't treat this as a failed
        # authorization so the payment UI can retry without charging again.
        return {
            "ok": True,
            "skipped": True,
            "router_id": router_id,
            "router_name": router_name,
            "reason": "offline",
            "timeout": True,
            "message": f"{router_name} is offline / not reachable — Hotspot push skipped.",
            "users_synced": 0,
            "notes": [f"skipped offline router ({host or 'no host'})"],
        }

    return {
        "ok": False,
        "skipped": False,
        "router_id": router_id,
        "router_name": router_name,
        "error": last_error or "Could not authorize Hotspot access on the MikroTik.",
    }


def _write_hotspot_html_file(sock: socket.socket, dst_path: str, html: str) -> bool:
    """Write HTML into the router Hotspot folder via API (no HTTP fetch required)."""
    dst_path = (dst_path or "").strip()
    html = html or ""
    if not dst_path or not html:
        return False
    file_id = ""
    for row in _print(sock, "/file", props=".id,name"):
        if (row.get("name") or "").strip() == dst_path:
            file_id = (row.get(".id") or "").strip()
            break
    if file_id:
        terminal = _set(sock, "/file", file_id, contents=html)
        return terminal.get("_reply") != "!trap"
    terminal = _add(sock, "/file", name=dst_path, contents=html)
    return terminal.get("_reply") != "!trap"


def _captive_pay_redirect_html(pay_url: str) -> str:
    """Hotspot login page that HTTP-redirects every OS to the payment page."""
    pay_url = (pay_url or "").strip()
    if not pay_url:
        return ""
    # Keep an existing query string (e.g. signed ?t= for PPPoE account auto-fill).
    # Only strip a trailing slash on the path, not after query params.
    if "?" in pay_url:
        path_part, query_part = pay_url.split("?", 1)
        base = f"{path_part.rstrip('?')}?{query_part}"
        sep = "&"
    else:
        base = pay_url.rstrip("/")
        sep = "?"
    # Pass MikroTik session vars so the payment page can identify the device.
    # Put mac first so it survives if other substituted fields contain '&'.
    # Prefer $(mac) (widely substituted); keep $(mac-esc) as a second param.
    target = (
        f"{base}{sep}"
        f"mac=$(mac)"
        f"&dst=$(link-orig-esc)"
        f"&username=$(username-esc)"
        f"&link-login-only=$(link-login-only-esc)"
        f"&error=$(error-esc)"
    )
    # RouterOS macros ($(mac), …) must stay literal in Location/meta/JS — do not
    # HTML-entity-encode '&' or substitution breaks on the CPE.
    # A real 302 is required for non-browser captive clients such as Windows NCSI;
    # they do not execute the JavaScript/meta-refresh in a 200 HTML response.
    # Keep the HTML as a fallback for captive browsers with unusual redirect handling
    # (older Android WebView, some Huawei/Samsung captive sheets).
    return (
        "$(if http-status == 302)Payment required$(endif)\n"
        f'$(if http-header == "Location"){target}$(endif)\n'
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<meta http-equiv="refresh" content="0;url={target}">\n'
        '<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">\n'
        '<meta http-equiv="Pragma" content="no-cache">\n'
        '<meta http-equiv="Expires" content="0">\n'
        "<title>Pay to connect</title>\n"
        "<script>\n"
        "(function(){\n"
        f"var u={target!r};\n"
        "try{window.top.location.replace(u);}catch(e){}\n"
        "try{window.location.replace(u);}catch(e){}\n"
        "setTimeout(function(){window.location.href=u;},50);\n"
        "})();\n"
        "</script>\n"
        "</head>\n"
        "<body>\n"
        "<p>Opening payment page…</p>\n"
        f'<p><a href="{target}">Continue to payment</a></p>\n'
        f'<noscript><meta http-equiv="refresh" content="0;url={target}"></noscript>\n'
        "</body>\n"
        "</html>\n"
    )


def _captive_alogin_html(welcome_url: str) -> str:
    """Post-login Hotspot page that sends clients to the continue-browsing welcome page."""
    welcome_url = (welcome_url or "").strip()
    if not welcome_url:
        return ""
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        '<meta charset="utf-8">\n'
        f'<meta http-equiv="refresh" content="0; url={welcome_url}">\n'
        '<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">\n'
        "<title>Connected</title>\n"
        f"<script>window.location.replace({welcome_url!r});</script>\n"
        "</head>\n"
        "<body>\n"
        "<p>You are online.</p>\n"
        f'<p><a href="{welcome_url}">Continue browsing</a></p>\n'
        "</body>\n"
        "</html>\n"
    )


# Files RouterOS would serve verbatim for OS captive-probe paths. They must not
# exist: an extensionless file is sent as application/octet-stream (phones
# download it) and a .txt file is sent as text/plain (the redirect never runs).
# Removing them lets Hotspot fall back to login.html, which is the only place
# RouterOS substitutes $(mac), $(link-login-only) and friends.
_STALE_PROBE_FILES = (
    "hotspot/redirect",
    "hotspot/hotspot-detect.html",
    "hotspot/generate_204",
    "hotspot/connecttest.txt",
    "hotspot/ncsi.txt",
)


def _delete_hotspot_file(sock: socket.socket, dst_path: str) -> bool:
    """Remove a file from the router Hotspot folder. True when it was deleted."""
    dst_path = (dst_path or "").strip()
    if not dst_path:
        return False
    for row in _print(sock, "/file", props=".id,name"):
        if (row.get("name") or "").strip() != dst_path:
            continue
        file_id = (row.get(".id") or "").strip()
        if not file_id:
            return False
        terminal = _remove(sock, "/file", file_id)
        return terminal.get("_reply") != "!trap"
    return False


def _fetch_isp_hotspot_pages(
    sock: socket.socket,
    *,
    login_url: str = "",
    alogin_url: str = "",
    pay_url: str = "",
    welcome_url: str = "",
) -> list[str]:
    """
    Install captive payment redirect + post-login welcome HTML on the router.

    Prefers writing HTML via the API so the router does not need to download from
    PUBLIC_BASE_URL (which often fails when Django only listens on 127.0.0.1).

    Notes include ``installed hotspot/login.html`` when the critical login page
    landed; callers must treat a missing login page as failure so Hotspot is
    not left without an instant pay popup.
    """
    notes: list[str] = []
    pay = _resolve_absolute_captive_url(pay_url or login_url or "")
    welcome = _resolve_absolute_captive_url(welcome_url or alogin_url or "") or (
        welcome_url or alogin_url or ""
    ).strip()

    if not pay:
        notes.append(
            "warning: refused relative/empty Hotspot pay URL — "
            "login.html not installed (would stick clients on http://10.50.50.…)"
        )
        return notes

    pay_html = _captive_pay_redirect_html(pay)
    alogin_html = _captive_alogin_html(welcome) if welcome else ""

    for dst in _STALE_PROBE_FILES:
        if _delete_hotspot_file(sock, dst):
            notes.append(f"removed {dst}")

    if pay_html:
        # login.html serves the unauthenticated client; rlogin.html is the same
        # page reached via the RADIUS/redirect path. Both get macro substitution.
        for dst in ("hotspot/login.html", "hotspot/rlogin.html"):
            if _write_hotspot_html_file(sock, dst, pay_html):
                notes.append(f"installed {dst}")
            else:
                notes.append(f"could not write {dst}")

        # redirect.html is how RouterOS bounces an *authorized* client to the
        # site it originally asked for. Overwriting it sends paying customers
        # back to the pay page, so leave the built-in page in place.
        if _delete_hotspot_file(sock, "hotspot/redirect.html"):
            notes.append("removed hotspot/redirect.html")

    if alogin_html:
        # Both pages are only reached once the client is logged in, so they point
        # at the welcome page rather than the pay page.
        for dst in ("hotspot/alogin.html", "hotspot/status.html"):
            if _write_hotspot_html_file(sock, dst, alogin_html):
                notes.append(f"installed {dst}")
            else:
                notes.append(f"could not write {dst}")

    # Optional fallback: try HTTP fetch when API write failed and a URL is available.
    missing_login = not any(
        n.startswith("installed hotspot/login.html") for n in notes
    )
    fetch_src = pay or _resolve_absolute_captive_url(login_url)
    if missing_login and fetch_src:
        fetch_words = [
            "/tool/fetch",
            f"=url={fetch_src}",
            "=mode=http",
            "=dst-path=hotspot/login.html",
            "=keep-result=no",
        ]
        try:
            _, terminal = _command(sock, fetch_words)
            if terminal.get("_reply") != "!trap":
                notes.append("installed hotspot/login.html via fetch")
                missing_login = False
            else:
                notes.append("could not fetch hotspot/login.html")
        except Exception:
            notes.append("could not fetch hotspot/login.html")

    if missing_login:
        notes.append(
            "warning: payment login page was not installed — "
            "set PUBLIC_BASE_URL to a reachable http://host and push Hotspot again"
        )
    return notes


def _disable_isp_hotspot_stack(sock: socket.socket) -> list[str]:
    notes: list[str] = []
    removed = 0
    removed += _remove_isp_hotspot_tagged(sock, "/ip/hotspot/user")
    removed += _remove_isp_hotspot_tagged(sock, "/ip/hotspot/user/profile")
    removed += _remove_isp_hotspot_tagged(sock, "/ip/hotspot")
    removed += _remove_isp_hotspot_tagged(sock, "/ip/hotspot/profile")
    removed += _remove_isp_hotspot_tagged(sock, "/ip/hotspot/walled-garden")
    removed += _remove_isp_hotspot_tagged(sock, "/ip/hotspot/ip-binding")
    removed += _remove_isp_hotspot_tagged(sock, "/ip/firewall/address-list")
    removed += _remove_isp_hotspot_tagged(sock, "/ip/dns/static")
    removed += _remove_isp_hotspot_tagged(sock, "/ip/firewall/nat")
    removed += _remove_isp_hotspot_tagged(sock, "/ip/pool")
    removed += _remove_isp_hotspot_tagged(sock, "/ip/address")
    removed += _clear_captive_portal_dhcp_option(sock)
    if removed:
        notes.append("ISP Hotspot removed from MikroTik")
    else:
        notes.append("no ISP Hotspot config to remove")
    return notes


def _ensure_hotspot_wireless_on_lan(
    sock: socket.socket, *, lan_bridge: str, ssid: str = ""
) -> list[str]:
    """Bridge enabled MikroTik access-point radios into the Hotspot LAN."""
    notes: list[str] = []
    existing_ports = {
        (row.get("interface") or "").strip(): (
            row.get(".id") or ""
        ).strip()
        for row in _print(
            sock,
            "/interface/bridge/port",
            props=".id,interface,bridge,disabled",
        )
        if (row.get("bridge") or "").strip() == lan_bridge
    }

    radios: list[str] = []
    for path in ("/interface/wireless", "/interface/wifi"):
        for row in _print(
            sock,
            path,
            props=".id,name,mode,disabled,master-interface,ssid",
        ):
            name = (row.get("name") or "").strip()
            mode = (row.get("mode") or "").strip().lower()
            disabled = (row.get("disabled") or "").strip().lower() == "true"
            master = (row.get("master-interface") or "").strip()
            if (
                name
                and not disabled
                and not master
                and mode in {"ap", "ap-bridge"}
            ):
                radios.append(name)
                if ssid and path == "/interface/wireless":
                    item_id = (row.get(".id") or "").strip()
                    current = (row.get("ssid") or "").strip()
                    if item_id and current != ssid:
                        terminal = _set(
                            sock,
                            path,
                            item_id,
                            **{
                                "ssid": ssid,
                                "hide-ssid": "no",
                                "security-profile": "default",
                            },
                        )
                        if terminal.get("_reply") != "!trap":
                            notes.append(f"wireless SSID set to {ssid}")

    for radio in dict.fromkeys(radios):
        if radio in existing_ports:
            notes.append(f"wireless {radio} already on {lan_bridge}")
            continue
        terminal = _add(
            sock,
            "/interface/bridge/port",
            interface=radio,
            bridge=lan_bridge,
            comment=ISP_HOTSPOT_TAG,
        )
        if terminal.get("_reply") == "!trap":
            notes.append(f"warning: could not bridge wireless {radio} to {lan_bridge}")
        else:
            notes.append(f"wireless {radio} bridged to {lan_bridge}")
    return notes


def _ensure_isp_hotspot_stack(
    sock: socket.socket,
    *,
    lan_interface: str,
    organization,
    wan_interface: str = "ether1",
    redirect_url: str = "",
    login_url: str = "",
    alogin_url: str = "",
    pay_url: str = "",
    welcome_url: str = "",
    wifi_ssid: str = "",
) -> list[str]:
    """
    Enable Hotspot on the ISP MikroTik LAN so Wi‑Fi/LAN clients authenticate.

    Order for "connect Wi‑Fi → Hotspot pay page immediately":
      1. Absolute http pay URL (abort otherwise)
      2. Hotspot profile/server + prefer 10.50.50 pool when dedicated
      3. Clear probe DNS hijack; walled garden / HTTP bind
      4. Install login.html → /hotspot/…/pay/
      5. DHCP option 114 + bounce unauthorized clients for instant popup
    """
    notes: list[str] = []

    urls = _normalize_hotspot_portal_urls(
        pay_url=pay_url,
        login_url=login_url,
        welcome_url=welcome_url,
        alogin_url=alogin_url,
        redirect_url=redirect_url,
    )
    pay_url = urls["pay_url"]
    login_url = urls["login_url"]
    welcome_url = urls["welcome_url"]
    alogin_url = urls["alogin_url"]
    redirect_url = urls["redirect_url"]
    if not pay_url:
        raise ConnectionError(
            "Cannot enable ISP Hotspot without an absolute pay URL. "
            "Set PUBLIC_BASE_URL to a reachable http://host so phones open "
            "/hotspot/…/pay/ immediately on Wi‑Fi connect."
        )

    requested_lan = (lan_interface or "").strip()
    # The saved bridge name is often stale; RouterOS rejects interface-scoped
    # commands outright when it does not exist.
    lan = _resolve_lan_interface(sock, requested_lan, exclude=wan_interface)
    if requested_lan and requested_lan != lan:
        notes.append(f"LAN interface {requested_lan} not found; using {lan}")
    hotspot_address = _lan_ipv4_for_interface(sock, lan)
    use_dedicated_pool = hotspot_address == ISP_HOTSPOT_ADDRESS

    # Prefer the onboarded router's Wi‑Fi name, then a short org-based SSID so
    # clients can tell this apart from a third-party AP like Tenda_0C8890.
    ssid = (wifi_ssid or "").strip()
    if ssid.lower() in {"", "mikrotik", "wifi", "hotspot"}:
        ssid = ""
    if not ssid and organization is not None:
        raw = (getattr(organization, "name", "") or "Hotspot").strip()
        cleaned = "".join(
            ch if ch.isalnum() else "-" for ch in raw.upper()
        )
        while "--" in cleaned:
            cleaned = cleaned.replace("--", "-")
        cleaned = cleaned.strip("-")[:20] or "HOTSPOT"
        ssid = f"{cleaned}-PAY"[:32]
    notes.extend(
        _ensure_hotspot_wireless_on_lan(sock, lan_bridge=lan, ssid=ssid)
    )

    # Dedicated address/pool only when the LAN has no usable IPv4 yet.
    if use_dedicated_pool:
        _ensure_tagged_ip_address(
            sock,
            address=f"{ISP_HOTSPOT_ADDRESS}/24",
            interface=lan,
            comment=ISP_HOTSPOT_TAG,
        )
        _ensure_tagged_pool(
            sock,
            name=ISP_HOTSPOT_POOL,
            ranges=ISP_HOTSPOT_POOL_RANGES,
            comment=ISP_HOTSPOT_TAG,
        )
        notes.append(f"Hotspot address {ISP_HOTSPOT_ADDRESS} on {lan}")
    else:
        notes.append(f"Hotspot on {lan} ({hotspot_address})")

    notes.extend(_ensure_isp_hotspot_user_profile(sock, organization))


    profile_id = ""
    for row in _print(sock, "/ip/hotspot/profile", props=".id,name,comment"):
        if (row.get("name") or "").strip() == ISP_HOTSPOT_PROFILE or ISP_HOTSPOT_TAG in (
            row.get("comment") or ""
        ):
            profile_id = (row.get(".id") or "").strip()
            break

    # http-pap/http-chap are what make RouterOS serve login.html to an
    # unauthenticated client, and mac stays first so a paid device reconnects
    # without seeing the portal again.
    #
    # cookie/mac-cookie are deliberately absent. A cookie login replays an
    # earlier successful login instead of re-checking the Hotspot user, so a
    # device whose package has lapsed would silently get back online for the
    # lifetime of the cookie. Only mac login is billed, because it resolves the
    # per-MAC user and therefore honours disabled and limit-uptime.
    #
    # https is deliberately absent. Enabling it makes RouterOS advertise
    # link-login-only as https://<gateway>/login, and the portal navigates the
    # browser straight there after payment. The only certificate available for a
    # private gateway address is self-signed, so that navigation dead-ends on a
    # full-page certificate warning at the exact moment the customer should be
    # getting online. HTTP probe interception is what actually triggers portal
    # detection, so nothing is lost by keeping the login endpoint plain HTTP.
    profile_attempts = [
        {
            "name": ISP_HOTSPOT_PROFILE,
            "hotspot-address": hotspot_address,
            "html-directory": "hotspot",
            "login-by": "mac,http-chap,http-pap",
            "open-status-page": "http-login",
            "use-radius": "no",
            "comment": ISP_HOTSPOT_TAG,
        },
        {
            "name": ISP_HOTSPOT_PROFILE,
            "hotspot-address": hotspot_address,
            "html-directory": "hotspot",
            "login-by": "mac,http-pap",
            "open-status-page": "http-login",
            "use-radius": "no",
            "comment": ISP_HOTSPOT_TAG,
        },
        {
            "name": ISP_HOTSPOT_PROFILE,
            "hotspot-address": hotspot_address,
            "html-directory": "hotspot",
            "login-by": "mac,http-chap",
            "comment": ISP_HOTSPOT_TAG,
        },
        {
            "name": ISP_HOTSPOT_PROFILE,
            "hotspot-address": hotspot_address,
            "html-directory": "hotspot",
            "login-by": "http-pap",
        },
        {
            "name": ISP_HOTSPOT_PROFILE,
            "hotspot-address": hotspot_address,
            "html-directory": "hotspot",
        },
    ]
    terminal, profile_id = _add_or_set_attempts(
        sock, "/ip/hotspot/profile", profile_id, profile_attempts
    )
    if terminal.get("_reply") == "!trap":
        raise ConnectionError(
            _trap_message(terminal, "Could not create Hotspot profile on the MikroTik.")
        )
    notes.append("Hotspot profile ready")

    server_id = ""
    for row in _print(sock, "/ip/hotspot", props=".id,name,interface,comment,disabled"):
        if (row.get("name") or "").strip() == ISP_HOTSPOT_NAME or ISP_HOTSPOT_TAG in (
            row.get("comment") or ""
        ):
            server_id = (row.get(".id") or "").strip()
            break

    # Prefer the dedicated 10.50.50 pool so phones get an identifiable Hotspot IP
    # (middleware → /hotspot/…/pay/). Fall back to existing LAN DHCP when the
    # router is already using another LAN subnet.
    pooled = {
        "name": ISP_HOTSPOT_NAME,
        "interface": lan,
        "address-pool": ISP_HOTSPOT_POOL,
        "profile": ISP_HOTSPOT_PROFILE,
        "disabled": "no",
        "comment": ISP_HOTSPOT_TAG,
    }
    unpooled = {
        "name": ISP_HOTSPOT_NAME,
        "interface": lan,
        "profile": ISP_HOTSPOT_PROFILE,
        "disabled": "no",
        "comment": ISP_HOTSPOT_TAG,
    }
    server_attempts = (
        [pooled, unpooled, {k: v for k, v in unpooled.items() if k != "comment"},
         {"name": ISP_HOTSPOT_NAME, "interface": lan, "disabled": "no"}]
        if use_dedicated_pool
        else [unpooled, pooled,
              {"name": ISP_HOTSPOT_NAME, "interface": lan, "profile": ISP_HOTSPOT_PROFILE,
               "disabled": "no"},
              {"name": ISP_HOTSPOT_NAME, "interface": lan, "disabled": "no"}]
    )
    terminal, server_id = _add_or_set_attempts(
        sock, "/ip/hotspot", server_id, server_attempts
    )
    if terminal.get("_reply") == "!trap":
        message = _trap_message(
            terminal, f"Could not enable Hotspot on interface {lan}."
        )
        if "any value of interface" in message.lower():
            raise ConnectionError(_interface_mismatch_error(sock, message, lan))
        raise ConnectionError(message)
    notes.append(f"Hotspot server on {lan}")

    garden_url = pay_url or redirect_url or login_url or welcome_url or alogin_url

    if _clear_captive_dns_hijack(sock, ISP_HOTSPOT_TAG):
        notes.append("captive probe hostnames resolve normally again")
    if _clear_https_capture_redirect(sock, comment=ISP_HOTSPOT_TAG):
        notes.append("removed HTTPS-to-HTTP capture rule")
    notes.extend(
        _ensure_hotspot_owns_http_port(
            sock,
            hotspot_address=hotspot_address,
            comment=ISP_HOTSPOT_TAG,
            portal_url=garden_url,
        )
    )
    notes.append("Hotspot intercepts captive HTTP probes")

    notes.extend(_ensure_hotspot_walled_garden(sock, garden_url))
    if redirect_url and redirect_url != garden_url:
        notes.extend(_ensure_hotspot_walled_garden(sock, redirect_url))
    notes.extend(_ensure_hotspot_server_bypass(sock, garden_url))

    # login.html BEFORE option 114 so we never advertise a broken portal.
    page_notes = _fetch_isp_hotspot_pages(
        sock,
        login_url=login_url,
        alogin_url=alogin_url,
        pay_url=pay_url or login_url,
        welcome_url=welcome_url or redirect_url or alogin_url,
    )
    notes.extend(page_notes)
    login_ready = any(
        n.startswith("installed hotspot/login.html") for n in page_notes
    )
    if not login_ready:
        raise ConnectionError(
            "ISP Hotspot enabled but hotspot/login.html was not installed. "
            "Phones would show no internet without a pay popup. "
            + "; ".join(page_notes[-4:])
        )

    # RFC 8910 option 114: Android 11+ / iOS 14+ / Win11 raise the sign-in
    # popup the moment Wi‑Fi associates — do not wait for an HTTP probe.
    notes.extend(
        _ensure_captive_portal_dhcp_option(
            sock, pay_url or garden_url, comment=ISP_HOTSPOT_TAG
        )
    )
    notes.extend(_bounce_isp_hotspot_clients(sock))
    return notes


def apply_hotspot_on_router(
    router,
    *,
    enabled: bool,
    organization=None,
    reauthenticate: bool = True,
    redirect_url: str = "",
    login_url: str = "",
    alogin_url: str = "",
    pay_url: str = "",
    welcome_url: str = "",
    candidate_hosts: list[str] | None = None,
) -> dict[str, Any]:
    """Push or remove ISP Hotspot configuration on one onboarded MikroTik."""
    if router is None:
        return {"ok": False, "error": "No router provided."}

    org = organization or getattr(router, "organization", None)
    host = (getattr(router, "host", None) or "").strip()
    username = (getattr(router, "username", None) or "").strip()
    password = getattr(router, "password", None) or ""
    router_id = getattr(router, "pk", None)
    router_name = getattr(router, "name", "") or host
    if not host or not username:
        return {
            "ok": False,
            "router_id": router_id,
            "router_name": router_name,
            "error": "Router host or username is missing.",
        }
    if enabled and org is None:
        return {
            "ok": False,
            "router_id": router_id,
            "router_name": router_name,
            "error": "Organization is required to enable Hotspot.",
        }

    if enabled and not (pay_url or login_url or redirect_url or welcome_url):
        # Background callers (the subscription sweep, payment provisioning) push
        # without URLs. Deriving them here keeps the captive HTTP binding, walled
        # garden, portal pages and DHCP option 114 in place instead of quietly
        # degrading the portal on every sweep.
        derived = _hotspot_portal_urls_for_org(org)
        login_url = login_url or derived.get("login_url", "")
        alogin_url = alogin_url or derived.get("alogin_url", "")
        pay_url = pay_url or derived.get("pay_url", "")
        welcome_url = welcome_url or derived.get("welcome_url", "")
        if not redirect_url and getattr(org, "hotspot_use_welcome_page", True):
            redirect_url = derived.get("welcome_url", "")

    if enabled:
        # Resolve once here; _ensure_isp_hotspot_stack will normalize again
        # idempotently. Early abort avoids opening API sessions with no pay URL.
        urls = _normalize_hotspot_portal_urls(
            pay_url=pay_url,
            login_url=login_url,
            welcome_url=welcome_url,
            alogin_url=alogin_url,
            redirect_url=redirect_url,
        )
        pay_url = urls["pay_url"]
        login_url = urls["login_url"]
        welcome_url = urls["welcome_url"]
        alogin_url = urls["alogin_url"]
        redirect_url = urls["redirect_url"]
        if not pay_url:
            return {
                "ok": False,
                "router_id": router_id,
                "router_name": router_name,
                "error": (
                    "Cannot enable Hotspot without an absolute pay URL. "
                    "Set PUBLIC_BASE_URL to a reachable http://host so phones "
                    "open /hotspot/…/pay/ immediately on Wi‑Fi connect."
                ),
            }

    if getattr(router, "account_status", "") == "suspended":
        return {
            "ok": True,
            "skipped": True,
            "router_id": router_id,
            "router_name": router_name,
            "reason": "suspended",
            "message": f"{router_name} is suspended — Hotspot push skipped.",
            "users_synced": 0,
            "notes": ["skipped suspended router"],
        }

    lan_interface = getattr(router, "lan_bridge", None) or "bridgeLocal"
    wan_interface = getattr(router, "wan_interface", None) or "ether1"
    hosts = _router_api_host_candidates(router, candidate_hosts)
    compulsory = bool(getattr(org, "pppoe_compulsory", False)) if org else False

    # Fast offline skip: if the saved host (and common fallbacks) are down, don't
    # treat this as a failed push — the router simply isn't connected right now.
    any_reachable = False
    for candidate in hosts[:4]:
        probe = check_mikrotik_reachable(candidate, timeout=1.2)
        if probe.get("online"):
            any_reachable = True
            break
    if not any_reachable:
        return {
            "ok": True,
            "skipped": True,
            "router_id": router_id,
            "router_name": router_name,
            "host": host,
            "reason": "offline",
            "timeout": True,
            "message": f"{router_name} is offline / not reachable — Hotspot push skipped.",
            "users_synced": 0,
            "notes": [f"skipped offline router ({host or 'no host'})"],
        }

    last_error = ""
    last_timeout = False
    working_host = ""
    notes: list[str] = []
    users_synced = 0
    resolved_lan = ""

    for candidate in hosts:
        probe = check_mikrotik_reachable(candidate, timeout=1.5)
        via = (probe.get("via") or "").strip()
        attempt_timeout = 3.0 if via == "ping" else 14.0
        if not probe.get("online") and candidate != host:
            continue
        try:
            with _api_session(
                candidate, username, password, timeout=attempt_timeout
            ) as sock:
                if enabled:
                    # Resolve once here so every later interface-scoped call in
                    # this session uses a name the router actually has.
                    lan_interface = _resolve_lan_interface(
                        sock, lan_interface, exclude=wan_interface
                    )
                    resolved_lan = lan_interface
                    notes = _ensure_isp_hotspot_stack(
                        sock,
                        lan_interface=lan_interface,
                        organization=org,
                        wan_interface=wan_interface,
                        redirect_url=redirect_url,
                        login_url=login_url,
                        alogin_url=alogin_url,
                        pay_url=pay_url,
                        welcome_url=welcome_url or redirect_url,
                        wifi_ssid=(getattr(router, "wifi_ssid", None) or "").strip(),
                    )
                    users_synced = _sync_organization_hotspot_users_on_socket(
                        sock,
                        router,
                        reauthenticate=reauthenticate,
                    )
                    if users_synced:
                        notes.append(f"synced {users_synced} Hotspot user(s)")
                    else:
                        notes.append("no Hotspot clients to sync yet")
                    if compulsory:
                        # Refresh firewall so Hotspot-authenticated clients bypass
                        # the PPPoE compulsory LAN drop. Keep portal_url so the
                        # expired-client billing allow / HTTP redirect survive —
                        # a bare re-push used to wipe them and leave only the
                        # silent WAN drop (slow captive popup).
                        portal_url = _billing_portal_base_url(
                            pay_url or redirect_url or login_url or welcome_url or ""
                        )
                        _, fw_notes = _ensure_pppoe_stack(
                            sock,
                            lan_interface=lan_interface,
                            wan_interface=wan_interface,
                            compulsory=True,
                            portal_url=portal_url,
                        )
                        notes.extend(fw_notes)
                    # Re-apply after PPPoE filter rewrite so captive HTTP forward
                    # allow + hairpin NAT stay above the compulsory drop.
                    garden = (
                        pay_url
                        or redirect_url
                        or login_url
                        or welcome_url
                        or ""
                    )
                    hotspot_address = _lan_ipv4_for_interface(sock, lan_interface)
                    notes.extend(
                        _ensure_hotspot_owns_http_port(
                            sock,
                            hotspot_address=hotspot_address,
                            comment=ISP_HOTSPOT_TAG,
                            portal_url=garden,
                        )
                    )
                else:
                    notes = _disable_isp_hotspot_stack(sock)
            working_host = candidate
            break
        except TimeoutError:
            last_timeout = True
            last_error = f"{candidate}: timed out on API port 8728"
        except OSError as exc:
            message = str(exc) or "network error"
            if "timed out" in message.lower() or getattr(exc, "errno", None) in {10060, 110}:
                last_timeout = True
                last_error = f"{candidate}: timed out on API port 8728"
            else:
                last_timeout = False
                last_error = f"{candidate}: {message}"
        except Exception as exc:  # noqa: BLE001
            message = str(exc) or "failed"
            lower = message.lower()
            last_timeout = "timed out" in lower or "cannot connect" in lower
            last_error = f"{candidate}: {message}"

    if not working_host:
        detail = last_error or f"{host}: timed out"
        # Still offline after attempts — skip rather than fail the whole org push.
        if last_timeout:
            return {
                "ok": True,
                "skipped": True,
                "router_id": router_id,
                "router_name": router_name,
                "host": host,
                "reason": "offline",
                "timeout": True,
                "message": (
                    f"{router_name} is offline / not reachable — Hotspot push skipped."
                    if on_router_lan()
                    else f"{router_name}: {unreachable_router_error(router)}"
                ),
                "users_synced": 0,
                "notes": [detail],
            }
        if "invalid user name or password" in detail.lower() or "cannot log in" in detail.lower():
            error = (
                f"{detail}. Update the saved API username/password on the router detail page "
                "(or click Reconnect), then push Hotspot again."
            )
        elif on_router_lan():
            error = (
                f"{detail}. Fix the router setting above, then push Hotspot again. "
                "If this keeps failing, open MikroTik → the router → Reconnect."
            )
        else:
            error = f"{detail}. {unreachable_router_error(router)}"
        return {
            "ok": False,
            "router_id": router_id,
            "router_name": router_name,
            "timeout": False,
            "error": error,
        }

    # The tunnel address is not the router's own IP, so never write it over it.
    tunnel = (getattr(router, "vpn_address", None) or "").strip()
    host_changed = bool(working_host and working_host not in (host, tunnel))
    if host_changed and hasattr(router, "host"):
        try:
            router.host = working_host
            router.save(update_fields=["host", "updated_at"])
            notes.append(f"updated saved IP to {working_host}")
        except Exception:
            pass

    _persist_resolved_lan_bridge(router, resolved_lan, notes)

    if enabled:
        _mark_hotspot_stack_ready(router_id)
    else:
        _captive_cache_set(_hotspot_stack_ready_key(router_id), 0, 1)

    return {
        "ok": True,
        "router_id": router_id,
        "router_name": router_name,
        "host": working_host,
        "host_changed": host_changed,
        "enabled": bool(enabled),
        "lan_bridge": resolved_lan or lan_interface,
        "users_synced": users_synced,
        "notes": notes,
        "message": (
            "Hotspot portal enabled on the LAN. PPPoE clients dial in; other devices use Hotspot login."
            if enabled and compulsory
            else (
                "Hotspot portal enabled on the LAN. Clients must log in before surfing."
                if enabled
                else "Hotspot portal removed from this MikroTik."
            )
        ),
    }


def apply_hotspot_for_organization(
    organization,
    *,
    enabled: bool | None = None,
    redirect_url: str = "",
    login_url: str = "",
    alogin_url: str = "",
    pay_url: str = "",
    welcome_url: str = "",
) -> dict[str, Any]:
    """Push Hotspot config to every onboarded MikroTik for an organization."""
    if organization is None:
        return {"ok": False, "applied": 0, "failed": 0, "results": [], "error": "No organization."}

    if enabled is None:
        enabled = bool(getattr(organization, "hotspot_enabled", False))

    redirect = (redirect_url or getattr(organization, "hotspot_redirect_url", "") or "").strip()
    login = (login_url or "").strip()
    alogin = (alogin_url or "").strip()
    pay = (pay_url or "").strip()
    welcome = (welcome_url or redirect or "").strip()

    from core.models import MikroTikRouter

    routers = list(
        MikroTikRouter.objects.filter(organization=organization).only(
            "id",
            "name",
            "host",
            "username",
            "password",
            "lan_bridge",
            "wan_interface",
            "organization_id",
            "account_status",
        )
    )
    if not routers:
        return {
            "ok": True,
            "enabled": bool(enabled),
            "applied": 0,
            "failed": 0,
            "router_count": 0,
            "results": [],
        }

    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: list[dict[str, Any]] = []
    workers = min(6, len(routers))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(
                apply_hotspot_on_router,
                router,
                enabled=bool(enabled),
                organization=organization,
                redirect_url=redirect,
                login_url=login,
                alogin_url=alogin,
                pay_url=pay,
                welcome_url=welcome,
            )
            for router in routers
        ]
        for future in as_completed(futures):
            results.append(future.result())

    applied = sum(1 for item in results if item.get("ok") and not item.get("skipped"))
    skipped = sum(1 for item in results if item.get("skipped"))
    failed = sum(1 for item in results if not item.get("ok"))
    users_total = sum(int(item.get("users_synced") or 0) for item in results)
    return {
        "ok": failed == 0,
        "enabled": bool(enabled),
        "applied": applied,
        "skipped": skipped,
        "failed": failed,
        "router_count": len(routers),
        "users_synced": users_total,
        "results": results,
    }


_PORT_TYPES = {
    "ether",
    "sfp",
    "sfp-sfpplus",
    "qsfp28",
    "wlan",
    "wifi",
    "wifiwave2",
    "bond",
}


def _is_manageable_port(row: dict[str, str]) -> bool:
    name = (row.get("name") or "").strip().lower()
    iface_type = (row.get("type") or "").strip().lower()
    if not name:
        return False
    if iface_type in _PORT_TYPES:
        return True
    return name.startswith(("ether", "sfp", "wlan", "wifi", "bond"))


def _flag_yes(value: Any) -> bool:
    return str(value or "").strip().lower() in {"true", "yes", "1"}


def _pppoe_parent_map(sock: socket.socket) -> dict[str, str]:
    """Map PPPoE client interface name → physical parent port."""
    mapping: dict[str, str] = {}
    try:
        rows = _print(
            sock,
            "/interface/pppoe-client",
            props="name,interface,disabled",
        )
    except Exception:
        return mapping
    for row in rows:
        if _flag_yes(row.get("disabled")):
            continue
        name = (row.get("name") or "").strip()
        parent = (row.get("interface") or "").strip()
        if name and parent:
            mapping[name] = parent
    return mapping


def _resolve_wan_to_physical(iface: str, pppoe_parents: dict[str, str] | None = None) -> str:
    """
    Map a default-route interface to a physical port when possible.

    Fibre / Safaricom / many Kenyan ISPs dial PPPoE, so the active default route
    is often `pppoe-out1` while the cable is still on ether1.
    """
    iface = (iface or "").strip()
    if not iface:
        return ""
    parents = pppoe_parents or {}
    if iface in parents:
        return parents[iface]
    lower = iface.lower()
    if lower.startswith("pppoe"):
        return parents.get(iface, "")
    return iface


def _default_route_wan(sock: socket.socket) -> str:
    """Best-effort physical WAN port from the active default route (DHCP or PPPoE)."""
    pppoe_parents = _pppoe_parent_map(sock)
    try:
        routes = _print(
            sock,
            "/ip/route",
            props="dst-address,gateway,immediate-gw,active,disabled,distance",
        )
    except (TimeoutError, OSError, ConnectionError):
        # Fall back to first PPPoE parent if routes are unavailable.
        if pppoe_parents:
            return next(iter(pppoe_parents.values()))
        return ""

    candidates: list[tuple[int, str]] = []
    for row in routes:
        if _flag_yes(row.get("disabled")):
            continue
        dst = (row.get("dst-address") or "").strip()
        if dst not in {"0.0.0.0/0", "::/0"}:
            continue
        if not _flag_yes(row.get("active")):
            continue
        immediate = (row.get("immediate-gw") or "").strip()
        gateway = (row.get("gateway") or "").strip()
        iface = ""
        for raw in (immediate, gateway):
            raw = (raw or "").strip()
            if not raw:
                continue
            if "%" in raw:
                iface = raw.split("%", 1)[-1].strip()
            elif "/" not in raw and ":" not in raw:
                # Interface name (pppoe-out1, ether1) — not an IPv4/IPv6 address.
                try:
                    ipaddress.ip_address(raw.split("%", 1)[0])
                except ValueError:
                    iface = raw
            if iface:
                break
        if not iface and immediate:
            # e.g. 192.168.1.1%ether1
            parts = immediate.replace("%", " ").split()
            for part in reversed(parts):
                token = part.strip()
                if not token:
                    continue
                try:
                    ipaddress.ip_address(token)
                    continue
                except ValueError:
                    iface = token
                    break
        if iface:
            try:
                distance = int(str(row.get("distance") or "1").strip() or "1")
            except ValueError:
                distance = 1
            physical = _resolve_wan_to_physical(iface, pppoe_parents) or iface
            candidates.append((distance, physical))
    if not candidates:
        if pppoe_parents:
            return next(iter(pppoe_parents.values()))
        return ""
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1]


def _port_uplink_hints(
    sock: socket.socket,
) -> dict[str, dict[str, str]]:
    """
    Per-physical-port uplink hints: dhcp / pppoe and related interface name.

    Keys are physical (or bond) interface names.
    """
    hints: dict[str, dict[str, str]] = {}
    pppoe_parents = _pppoe_parent_map(sock)
    for pppoe_name, parent in pppoe_parents.items():
        hints[parent] = {"kind": "pppoe", "uplink": pppoe_name}
    try:
        for row in _print(sock, "/ip/dhcp-client", props="interface,disabled"):
            if _flag_yes(row.get("disabled")):
                continue
            iface = (row.get("interface") or "").strip()
            if not iface:
                continue
            # PPPoE wins when both somehow exist on the same parent.
            if iface in hints and hints[iface].get("kind") == "pppoe":
                continue
            hints[iface] = {"kind": "dhcp", "uplink": iface}
    except Exception:
        pass
    return hints


def list_mikrotik_ports(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 6.0,
) -> dict[str, Any]:
    """List physical / wireless ports that can be enabled, disabled, or assigned a role."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not host or not username:
        return {"ok": False, "error": "Missing router credentials.", "ports": [], "suggested_wan": ""}

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            rows = _print(
                sock,
                "/interface",
                props=".id,name,type,running,disabled,comment,rx-byte,tx-byte",
            )
            bytes_by_name: dict[str, tuple[int, int]] = {}
            for row in rows:
                iname = (row.get("name") or "").strip()
                if iname:
                    bytes_by_name[iname] = (
                        max(0, _parse_int(row.get("rx-byte"))),
                        max(0, _parse_int(row.get("tx-byte"))),
                    )
            bridge_of: dict[str, str] = {}
            try:
                for brow in _print(
                    sock, "/interface/bridge/port", props="interface,bridge"
                ):
                    iface = (brow.get("interface") or "").strip()
                    bridge = (brow.get("bridge") or "").strip()
                    if iface and bridge:
                        bridge_of[iface] = bridge
            except (TimeoutError, OSError, ConnectionError):
                bridge_of = {}

            uplink_hints = _port_uplink_hints(sock)
            suggested_wan = _default_route_wan(sock)
            ports: list[dict[str, Any]] = []
            for row in rows:
                if not _is_manageable_port(row):
                    continue
                name = (row.get("name") or "").strip()
                iface_type = (row.get("type") or "").strip() or "ether"
                disabled = _flag_yes(row.get("disabled"))
                running = _flag_yes(row.get("running"))
                bridge = bridge_of.get(name, "")
                hint = uplink_hints.get(name) or {}
                traffic_iface = (hint.get("uplink") or "").strip() or name
                rx_byte, tx_byte = bytes_by_name.get(traffic_iface) or bytes_by_name.get(
                    name, (0, 0)
                )
                ports.append(
                    {
                        "id": (row.get(".id") or "").strip(),
                        "name": name,
                        "type": iface_type,
                        "disabled": disabled,
                        "running": running and not disabled,
                        "comment": (row.get("comment") or "").strip(),
                        "bridge": bridge,
                        "is_bridged": bool(bridge),
                        "is_wireless": iface_type.lower()
                        in {"wlan", "wifi", "wifiwave2"}
                        or name.lower().startswith(("wlan", "wifi")),
                        "uplink_kind": hint.get("kind") or "",
                        "uplink_iface": hint.get("uplink") or "",
                        "traffic_iface": traffic_iface,
                        "rx_byte": rx_byte,
                        "tx_byte": tx_byte,
                    }
                )

            def _sort_key(item: dict[str, Any]) -> tuple:
                n = item["name"].lower()
                # ether1 before ether10
                prefix = "".join(ch for ch in n if not ch.isdigit())
                digits = "".join(ch for ch in n if ch.isdigit())
                return (prefix, int(digits) if digits else 0, n)

            ports.sort(key=_sort_key)
            return {
                "ok": True,
                "ports": ports,
                "host": host,
                "suggested_wan": suggested_wan,
            }
    except TimeoutError:
        return {
            "ok": False,
            "error": "Connection timed out. Is the router reachable on API port 8728?",
            "ports": [],
            "suggested_wan": "",
        }
    except ConnectionError as exc:
        return {
            "ok": False,
            "error": str(exc) or "Login failed. Check the saved username and password.",
            "ports": [],
            "suggested_wan": "",
        }
    except OSError as exc:
        return {
            "ok": False,
            "error": f"Could not reach {host}:8728. ({exc})",
            "ports": [],
            "suggested_wan": "",
        }


def apply_mikrotik_single_wan(
    host: str,
    username: str,
    password: str,
    *,
    wan_interface: str,
    port: int = 8728,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """
    Light sync when an operator marks one port as Internet.

    Puts the physical port (and its PPPoE client, if any) on the WAN list.
    Does not unbridge or rewrite DHCP — clean-uplink / failover own those.
    """
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    wan_interface = (wan_interface or "").strip()
    if not host or not username:
        return {"ok": False, "error": "Missing router credentials."}
    if not wan_interface:
        return {"ok": False, "error": "WAN interface is required."}

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            names = _iface_names(sock)
            if wan_interface not in names:
                return {
                    "ok": False,
                    "error": f"Port “{wan_interface}” was not found on the router.",
                }
            _ensure_interface_list(sock, "WAN")
            _ensure_uplink_list_member(sock, wan_interface)
            pppoe_name = _find_pppoe_client_for_wan(sock, wan_interface)
            if pppoe_name and pppoe_name != wan_interface and pppoe_name in names:
                _ensure_uplink_list_member(sock, pppoe_name)
            return {
                "ok": True,
                "wan_interface": wan_interface,
                "pppoe": pppoe_name or "",
                "uplink_kind": "pppoe" if pppoe_name else "dhcp_or_static",
                "message": (
                    f"Internet port {wan_interface} added to WAN list"
                    + (f" (via {pppoe_name})" if pppoe_name else "")
                    + "."
                ),
            }
    except TimeoutError:
        return {"ok": False, "error": "Connection timed out while syncing WAN port."}
    except ConnectionError as exc:
        return {
            "ok": False,
            "error": str(exc) or "Login failed. Check the saved username and password.",
        }
    except OSError as exc:
        return {"ok": False, "error": f"Could not reach {host}:8728. ({exc})"}


def set_mikrotik_port_enabled(
    host: str,
    username: str,
    password: str,
    *,
    interface_name: str,
    enabled: bool,
    port: int = 8728,
    timeout: float = 6.0,
) -> dict[str, Any]:
    """Enable or disable a RouterOS interface by name."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    interface_name = (interface_name or "").strip()
    if not host or not username:
        return {"ok": False, "error": "Missing router credentials."}
    if not interface_name:
        return {"ok": False, "error": "Select a port to update."}

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            rows = _print(
                sock,
                "/interface",
                props=".id,name,type,disabled",
            )
            match = None
            for row in rows:
                if (row.get("name") or "").strip() == interface_name:
                    match = row
                    break
            if not match:
                return {"ok": False, "error": f"Port “{interface_name}” was not found on the router."}
            if not _is_manageable_port(match):
                return {
                    "ok": False,
                    "error": f"“{interface_name}” is not a manageable port.",
                }

            item_id = (match.get(".id") or "").strip()
            if not item_id:
                return {"ok": False, "error": f"Could not resolve port id for “{interface_name}”."}

            terminal = _set(
                sock,
                "/interface",
                item_id,
                disabled="no" if enabled else "yes",
            )
            if terminal.get("_reply") in {"!trap", "!fatal"}:
                return {
                    "ok": False,
                    "error": _trap_message(
                        terminal,
                        f"Could not {'enable' if enabled else 'disable'} {interface_name}.",
                    ),
                }

            return {
                "ok": True,
                "name": interface_name,
                "enabled": enabled,
                "message": (
                    f"Port {interface_name} enabled."
                    if enabled
                    else f"Port {interface_name} disabled."
                ),
            }
    except TimeoutError:
        return {
            "ok": False,
            "error": "Connection timed out. Is the router reachable on API port 8728?",
        }
    except ConnectionError as exc:
        return {
            "ok": False,
            "error": str(exc) or "Login failed. Check the saved username and password.",
        }
    except OSError as exc:
        return {
            "ok": False,
            "error": f"Could not reach {host}:8728. ({exc})",
        }


def _iface_names(sock: socket.socket) -> set[str]:
    return {
        (row.get("name") or "").strip()
        for row in _print(sock, "/interface", props="name")
        if (row.get("name") or "").strip()
    }


def _unbridge_interfaces(sock: socket.socket, interfaces: list[str]) -> list[dict[str, str]]:
    """Remove ports from their bridge; return list of {interface, bridge} for restore."""
    removed: list[dict[str, str]] = []
    for iface in interfaces:
        for row in _print(sock, "/interface/bridge/port", props=".id,interface,bridge"):
            if (row.get("interface") or "").strip() != iface:
                continue
            item_id = (row.get(".id") or "").strip()
            bridge = (row.get("bridge") or "").strip()
            if not item_id:
                break
            terminal = _remove(sock, "/interface/bridge/port", item_id)
            if terminal.get("_reply") not in {"!trap", "!fatal"} and bridge:
                removed.append({"interface": iface, "bridge": bridge})
            break
    return removed


def _restore_bridged_interfaces(
    sock: socket.socket,
    entries: list[dict[str, str]],
    *,
    lan_bridge_fallback: str = "bridgeLocal",
) -> int:
    """Re-add previously unbridged ports to their bridge. Returns count restored."""
    restored = 0
    for entry in entries or []:
        iface = (entry.get("interface") or "").strip()
        bridge = (entry.get("bridge") or "").strip() or lan_bridge_fallback
        if not iface or not bridge:
            continue
        if _bridge_port_id(sock, iface):
            continue
        terminal = _add(
            sock,
            "/interface/bridge/port",
            interface=iface,
            bridge=bridge,
            comment=UPLINK_TAG,
        )
        if terminal.get("_reply") not in {"!trap", "!fatal"}:
            restored += 1
    return restored


def _clear_tagged_uplink(sock: socket.socket) -> dict[str, int]:
    """Remove ispcentric-uplink bond / DHCP / route / mangle / list leftovers."""
    routing_tables = 0
    try:
        for row in _print(sock, "/routing/table", props=".id,name,comment"):
            comment = row.get("comment") or ""
            name = (row.get("name") or "").strip()
            if UPLINK_TAG not in comment and not name.startswith("ispcentric-w"):
                continue
            item_id = (row.get(".id") or "").strip()
            if not item_id:
                continue
            if _remove(sock, "/routing/table", item_id).get("_reply") not in {
                "!trap",
                "!fatal",
            }:
                routing_tables += 1
    except Exception:
        pass
    return {
        "bonding": _remove_comment_tagged(sock, "/interface/bonding", UPLINK_TAG),
        "dhcp_client": _remove_comment_tagged(sock, "/ip/dhcp-client", UPLINK_TAG),
        "routes": _remove_comment_tagged(sock, "/ip/route", UPLINK_TAG),
        "list_members": _remove_comment_tagged(sock, "/interface/list/member", UPLINK_TAG),
        "mangle": _remove_comment_tagged(sock, "/ip/firewall/mangle", UPLINK_TAG),
        "routing_tables": routing_tables,
    }


def _ensure_uplink_list_member(sock: socket.socket, interface: str) -> None:
    _ensure_interface_list(sock, "WAN")
    for row in _print(sock, "/interface/list/member", props=".id,list,interface,comment"):
        if (row.get("list") or "").strip() != "WAN":
            continue
        if (row.get("interface") or "").strip() != interface:
            continue
        # Prefer tagged member for our managed uplinks.
        item_id = (row.get(".id") or "").strip()
        if item_id and UPLINK_TAG not in (row.get("comment") or ""):
            _set(sock, "/interface/list/member", item_id, comment=UPLINK_TAG)
        return
    _add(
        sock,
        "/interface/list/member",
        list="WAN",
        interface=interface,
        comment=UPLINK_TAG,
    )


def _ensure_failover_pppoe_client(
    sock: socket.socket,
    physical_port: str,
    *,
    distance: int,
    add_default_route: bool = True,
) -> dict[str, str] | None:
    """
    If a PPPoE client sits on physical_port, set its default-route-distance.

    Returns the set/add terminal dict (with optional `_pppoe` name), or None
    when no PPPoE client exists.
    """
    physical_port = (physical_port or "").strip()
    if not physical_port:
        return None
    try:
        rows = _print(
            sock,
            "/interface/pppoe-client",
            props=".id,name,interface,disabled,comment",
        )
    except Exception:
        return None
    for row in rows:
        if (row.get("interface") or "").strip() != physical_port:
            continue
        if _flag_yes(row.get("disabled")):
            continue
        item_id = (row.get(".id") or "").strip()
        pppoe_name = (row.get("name") or "").strip()
        if not item_id:
            out = {"_reply": "!done"}
            if pppoe_name:
                out["_pppoe"] = pppoe_name
            return out
        route_flag = "yes" if add_default_route else "no"
        # RouterOS 6/7: default-route-distance on pppoe-client.
        attempts = [
            {
                "disabled": "no",
                "add-default-route": route_flag,
                "default-route-distance": str(distance),
                "use-peer-dns": "no",
            },
            {
                "disabled": "no",
                "add-default-route": route_flag,
                "default-route-distance": str(distance),
            },
            {
                "disabled": "no",
                "add-default-route": route_flag,
            },
        ]
        last = {"_reply": "!trap", "message": "Could not update PPPoE client."}
        for props in attempts:
            last = _set(sock, "/interface/pppoe-client", item_id, **props)
            if last.get("_reply") not in {"!trap", "!fatal"}:
                if pppoe_name:
                    last = dict(last)
                    last["_pppoe"] = pppoe_name
                return last
            # Strip unknown parameters and retry once more via message sniff.
            unknown = _unknown_parameter_name(last.get("message") or "")
            if unknown:
                props = {k: v for k, v in props.items() if k != unknown}
                last = _set(sock, "/interface/pppoe-client", item_id, **props)
                if last.get("_reply") not in {"!trap", "!fatal"}:
                    if pppoe_name:
                        last = dict(last)
                        last["_pppoe"] = pppoe_name
                    return last
        return last
    return None


def _ensure_failover_uplink(
    sock: socket.socket,
    interface: str,
    *,
    distance: int,
    add_default_route: bool = True,
) -> dict[str, str]:
    """Configure failover uplink via PPPoE when present, otherwise DHCP."""
    pppoe_result = _ensure_failover_pppoe_client(
        sock,
        interface,
        distance=distance,
        add_default_route=add_default_route,
    )
    if pppoe_result is not None:
        out = dict(pppoe_result)
        out["_kind"] = "pppoe"
        out["_interface"] = interface
        out["_distance"] = str(distance)
        return out
    dhcp_result = _ensure_failover_dhcp_client(
        sock,
        interface,
        distance=distance,
        add_default_route=add_default_route,
    )
    out = dict(dhcp_result)
    out["_kind"] = "dhcp"
    out["_interface"] = interface
    out["_distance"] = str(distance)
    return out


def _default_route_gateway_for_interface(sock: socket.socket, interface: str) -> str:
    """Best-effort next-hop for a WAN interface from live default routes."""
    interface = (interface or "").strip()
    if not interface:
        return ""
    marker = f"%{interface}"
    for row in _print(
        sock,
        "/ip/route",
        props="dst-address,gateway,immediate-gw,active,disabled",
    ):
        dst = (row.get("dst-address") or "").strip()
        if dst not in {"0.0.0.0/0", "::/0"}:
            continue
        if _flag_yes(row.get("disabled")):
            continue
        gateway = (row.get("gateway") or "").strip()
        immediate = (row.get("immediate-gw") or "").strip()
        if gateway == interface or immediate == interface:
            return interface
        if gateway.endswith(marker):
            return gateway.split("%", 1)[0].strip() or interface
        if immediate.endswith(marker):
            return immediate.split("%", 1)[0].strip() or interface
        if gateway.lower().startswith("pppoe") and interface.lower().startswith("pppoe"):
            if gateway == interface:
                return gateway
    return ""


def _ensure_failover_checked_route(
    sock: socket.socket,
    *,
    gateway: str,
    distance: int,
) -> dict[str, str]:
    """Install a tagged default route with check-gateway=ping for real failover."""
    gateway = (gateway or "").strip()
    if not gateway:
        return {"_reply": "!trap", "message": "Missing failover gateway."}
    distance_s = str(distance)
    for row in _print(
        sock,
        "/ip/route",
        props=".id,dst-address,gateway,distance,comment",
    ):
        if UPLINK_TAG not in (row.get("comment") or ""):
            continue
        if (row.get("dst-address") or "").strip() not in {"0.0.0.0/0", "::/0"}:
            continue
        if (row.get("gateway") or "").strip() != gateway:
            continue
        item_id = (row.get(".id") or "").strip()
        if not item_id:
            continue
        return _set(
            sock,
            "/ip/route",
            item_id,
            distance=distance_s,
            comment=UPLINK_TAG,
            **{"check-gateway": "ping"},
        )
    attempts = [
        {
            "dst-address": "0.0.0.0/0",
            "gateway": gateway,
            "distance": distance_s,
            "comment": UPLINK_TAG,
            "check-gateway": "ping",
        },
        {
            "dst-address": "0.0.0.0/0",
            "gateway": gateway,
            "distance": distance_s,
            "comment": UPLINK_TAG,
        },
    ]
    last = {"_reply": "!trap", "message": "Could not add failover route."}
    for props in attempts:
        last = _add(sock, "/ip/route", **props)
        if last.get("_reply") not in {"!trap", "!fatal"}:
            return last
        unknown = _unknown_parameter_name(last.get("message") or "")
        if unknown and unknown in props:
            props = {k: v for k, v in props.items() if k != unknown}
            last = _add(sock, "/ip/route", **props)
            if last.get("_reply") not in {"!trap", "!fatal"}:
                return last
    return last


def _disable_client_default_route(
    sock: socket.socket,
    *,
    kind: str,
    interface: str,
    pppoe_name: str = "",
) -> None:
    """Stop DHCP/PPPoE from installing competing dynamic defaults."""
    if kind == "pppoe":
        target = (pppoe_name or "").strip()
        for row in _print(
            sock,
            "/interface/pppoe-client",
            props=".id,name,interface",
        ):
            name = (row.get("name") or "").strip()
            parent = (row.get("interface") or "").strip()
            if target and name != target and parent != interface:
                continue
            if not target and parent != interface:
                continue
            item_id = (row.get(".id") or "").strip()
            if item_id:
                _set(sock, "/interface/pppoe-client", item_id, **{"add-default-route": "no"})
            return
        return
    for row in _print(sock, "/ip/dhcp-client", props=".id,interface"):
        if (row.get("interface") or "").strip() != interface:
            continue
        item_id = (row.get(".id") or "").strip()
        if item_id:
            _set(sock, "/ip/dhcp-client", item_id, **{"add-default-route": "no"})
        return


def _install_failover_gateway_checks(
    sock: socket.socket,
    uplink_results: list[dict[str, str]],
) -> list[dict[str, str]]:
    """
    Prefer ping-checked static defaults so failover works when the link stays
    up but the ISP path dies (not only on carrier loss).
    """
    installed: list[dict[str, str]] = []
    for item in uplink_results:
        interface = (item.get("_interface") or "").strip()
        kind = (item.get("_kind") or "").strip()
        try:
            distance = int(item.get("_distance") or "1")
        except ValueError:
            distance = 1
        gateway = ""
        pppoe_name = (item.get("_pppoe") or "").strip()
        if kind == "pppoe":
            gateway = pppoe_name or _find_pppoe_client_for_wan(sock, interface)
        else:
            gateways = _detect_dhcp_gateways(sock, interface)
            gateway = gateways[0] if gateways else ""
            if not gateway:
                gateway = _default_route_gateway_for_interface(sock, interface)
        if not gateway:
            continue
        terminal = _ensure_failover_checked_route(
            sock, gateway=gateway, distance=distance
        )
        if terminal.get("_reply") in {"!trap", "!fatal"}:
            continue
        _disable_client_default_route(
            sock,
            kind=kind or "dhcp",
            interface=interface,
            pppoe_name=pppoe_name or gateway,
        )
        installed.append(
            {
                "interface": interface,
                "gateway": gateway,
                "distance": str(distance),
                "kind": kind or "dhcp",
            }
        )
    return installed


def _disable_member_dhcp_clients(sock: socket.socket, members: list[str]) -> list[str]:
    """Disable DHCP clients on bond member ports so only the bond owns the WAN."""
    notes: list[str] = []
    wanted = {m.strip() for m in members if (m or "").strip()}
    if not wanted:
        return notes
    for row in _print(sock, "/ip/dhcp-client", props=".id,interface,disabled"):
        iface = (row.get("interface") or "").strip()
        if iface not in wanted:
            continue
        item_id = (row.get(".id") or "").strip()
        if not item_id or _flag_yes(row.get("disabled")):
            continue
        terminal = _set(sock, "/ip/dhcp-client", item_id, disabled="yes")
        if terminal.get("_reply") not in {"!trap", "!fatal"}:
            notes.append(iface)
    return notes


def _move_member_pppoe_to_bond(
    sock: socket.socket,
    members: list[str],
    bond_name: str,
) -> list[str]:
    """
    Reattach the first member PPPoE client onto the bond interface.

    Same-provider bonding must dial on the bond, not on a slave port.
    Extra member PPPoE clients are disabled so they cannot fight the bond.
    """
    wanted = {m.strip() for m in members if (m or "").strip()}
    moved: list[str] = []
    try:
        rows = _print(
            sock,
            "/interface/pppoe-client",
            props=".id,name,interface,disabled",
        )
    except Exception:
        return moved
    for row in rows:
        parent = (row.get("interface") or "").strip()
        if parent not in wanted:
            continue
        item_id = (row.get(".id") or "").strip()
        name = (row.get("name") or "").strip()
        if not item_id:
            continue
        if not moved:
            terminal = _set(
                sock,
                "/interface/pppoe-client",
                item_id,
                interface=bond_name,
                disabled="no",
                **{
                    "add-default-route": "yes",
                    "default-route-distance": "1",
                    "use-peer-dns": "no",
                },
            )
            if terminal.get("_reply") in {"!trap", "!fatal"}:
                # Older RouterOS may reject distance / peer-dns — retry minimal move.
                terminal = _set(
                    sock,
                    "/interface/pppoe-client",
                    item_id,
                    interface=bond_name,
                    disabled="no",
                    **{"add-default-route": "yes"},
                )
            if terminal.get("_reply") not in {"!trap", "!fatal"}:
                moved.append(name or parent)
            continue
        if not _flag_yes(row.get("disabled")):
            _set(sock, "/interface/pppoe-client", item_id, disabled="yes")
    return moved


def _create_bonding_interface(
    sock: socket.socket,
    *,
    bond_name: str,
    bond_mode: str,
    members: list[str],
) -> tuple[dict[str, str], str]:
    """Create bonding with link-monitoring; fall back when RouterOS rejects options."""
    slaves = ",".join(members)
    primary = members[0] if members else ""
    attempts: list[dict[str, str]] = []
    base = {
        "name": bond_name,
        "mode": bond_mode,
        "slaves": slaves,
        "comment": UPLINK_TAG,
    }
    monitored = {
        **base,
        "link-monitoring": "mii",
        "miimon": "100",
        "down-delay": "200ms",
        "up-delay": "200ms",
    }
    if bond_mode == "active-backup" and primary:
        attempts.append({**monitored, "primary": primary})
        attempts.append({**base, "primary": primary, "link-monitoring": "mii", "miimon": "100"})
        attempts.append({**base, "primary": primary})
    attempts.extend(
        [
            monitored,
            {**base, "link-monitoring": "mii", "miimon": "100"},
            dict(base),
        ]
    )
    # Deduplicate while preserving order.
    seen: set[tuple[tuple[str, str], ...]] = set()
    unique_attempts: list[dict[str, str]] = []
    for props in attempts:
        key = tuple(sorted(props.items()))
        if key in seen:
            continue
        seen.add(key)
        unique_attempts.append(props)

    last = {"_reply": "!trap", "message": f"Could not create bonding interface {bond_name}."}
    used_mode = bond_mode
    for props in unique_attempts:
        last = _add(sock, "/interface/bonding", **props)
        if last.get("_reply") not in {"!trap", "!fatal"}:
            return last, used_mode
        unknown = _unknown_parameter_name(last.get("message") or "")
        if unknown:
            trimmed = {k: v for k, v in props.items() if k != unknown}
            last = _add(sock, "/interface/bonding", **trimmed)
            if last.get("_reply") not in {"!trap", "!fatal"}:
                return last, used_mode

    # LACP often fails without switch support — fall back to balance-xor.
    if bond_mode == "802.3ad":
        used_mode = "balance-xor"
        fallback_last, fallback_mode = _create_bonding_interface(
            sock,
            bond_name=bond_name,
            bond_mode=used_mode,
            members=members,
        )
        return fallback_last, fallback_mode
    return last, used_mode


def _ensure_failover_dhcp_client(
    sock: socket.socket,
    interface: str,
    *,
    distance: int,
    add_default_route: bool = True,
) -> dict[str, str]:
    """Ensure a DHCP client on the WAN interface (optionally with a default route).

    Existing (non-ISPCENTRIC) clients are reused and distance is updated without
    retagging them — so Clear will not delete the original WAN DHCP client.
    Only newly created clients are tagged with UPLINK_TAG.
    """
    route_flag = "yes" if add_default_route else "no"
    for row in _print(
        sock,
        "/ip/dhcp-client",
        props=".id,interface,disabled,comment,default-route-distance,add-default-route",
    ):
        if (row.get("interface") or "").strip() != interface:
            continue
        item_id = (row.get(".id") or "").strip()
        if not item_id:
            return {"_reply": "!done"}
        props: dict[str, str] = {
            "disabled": "no",
            "add-default-route": route_flag,
            "use-peer-dns": "no",
            "default-route-distance": str(distance),
        }
        # Only keep / apply our tag on clients we already own.
        if UPLINK_TAG in (row.get("comment") or ""):
            props["comment"] = UPLINK_TAG
        return _set(sock, "/ip/dhcp-client", item_id, **props)
    return _add(
        sock,
        "/ip/dhcp-client",
        interface=interface,
        disabled="no",
        comment=UPLINK_TAG,
        **{
            "add-default-route": route_flag,
            "use-peer-dns": "no",
            "default-route-distance": str(distance),
        },
    )


def _ensure_bond_dhcp_client(sock: socket.socket, interface: str) -> dict[str, str]:
    """DHCP on the bond interface. Prefer create/reuse with UPLINK_TAG (bond iface is ours)."""
    for row in _print(sock, "/ip/dhcp-client", props=".id,interface,disabled,comment"):
        if (row.get("interface") or "").strip() != interface:
            continue
        item_id = (row.get(".id") or "").strip()
        if not item_id:
            return {"_reply": "!done"}
        return _set(
            sock,
            "/ip/dhcp-client",
            item_id,
            disabled="no",
            comment=UPLINK_TAG,
            **{"add-default-route": "yes", "use-peer-dns": "no", "default-route-distance": "1"},
        )
    return _add(
        sock,
        "/ip/dhcp-client",
        interface=interface,
        disabled="no",
        comment=UPLINK_TAG,
        **{"add-default-route": "yes", "use-peer-dns": "no", "default-route-distance": "1"},
    )


def apply_mikrotik_uplink_bond(
    host: str,
    username: str,
    password: str,
    *,
    member_ports: list[str],
    bond_name: str = DEFAULT_BOND_NAME,
    bond_mode: str = "balance-xor",
    port: int = 8728,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """
    Bond two or more ports for the same provider.

    Creates /interface/bonding with link monitoring, slaves the selected ports,
    moves PPPoE onto the bond when present (else DHCP on the bond), and adds the
    bond to the WAN interface list.
    """
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    bond_name = (bond_name or DEFAULT_BOND_NAME).strip() or DEFAULT_BOND_NAME
    bond_mode = (bond_mode or "balance-xor").strip() or "balance-xor"
    if bond_mode not in BOND_MODES:
        bond_mode = "balance-xor"
    members = [p.strip() for p in (member_ports or []) if (p or "").strip()]
    members = list(dict.fromkeys(members))

    if not host or not username:
        return {"ok": False, "error": "Missing router credentials."}
    if len(members) < 2:
        return {"ok": False, "error": "Select at least two ports to bond (same provider)."}
    if bond_name in members:
        return {"ok": False, "error": "Bond interface name cannot match a member port."}

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            names = _iface_names(sock)
            missing = [p for p in members if p not in names]
            if missing:
                return {
                    "ok": False,
                    "error": f"Port(s) not found on router: {', '.join(missing)}.",
                }

            _clear_tagged_uplink(sock)
            # If a leftover bond with the same name exists without our tag, remove it only when owned.
            for row in _print(sock, "/interface/bonding", props=".id,name,comment"):
                if (row.get("name") or "").strip() != bond_name:
                    continue
                comment = row.get("comment") or ""
                item_id = (row.get(".id") or "").strip()
                if item_id and (UPLINK_TAG in comment or CLEAN_UPLINK_TAG in comment):
                    _remove(sock, "/interface/bonding", item_id)
                elif item_id:
                    return {
                        "ok": False,
                        "error": (
                            f"Interface “{bond_name}” already exists on the router. "
                            "Rename it in RouterOS or choose another bond name."
                        ),
                    }

            unbridged = _unbridge_interfaces(sock, members)
            terminal, bond_mode = _create_bonding_interface(
                sock,
                bond_name=bond_name,
                bond_mode=bond_mode,
                members=members,
            )
            if terminal.get("_reply") in {"!trap", "!fatal"}:
                if unbridged:
                    _restore_bridged_interfaces(sock, unbridged)
                return {
                    "ok": False,
                    "error": _trap_message(
                        terminal,
                        f"Could not create bonding interface {bond_name}.",
                    ),
                }

            disabled_dhcp = _disable_member_dhcp_clients(sock, members)
            moved_pppoe = _move_member_pppoe_to_bond(sock, members, bond_name)
            uplink_kind = "pppoe" if moved_pppoe else "dhcp"
            if not moved_pppoe:
                dhcp = _ensure_bond_dhcp_client(sock, bond_name)
                if dhcp.get("_reply") in {"!trap", "!fatal"}:
                    return {
                        "ok": False,
                        "error": _trap_message(
                            dhcp,
                            f"Bond created, but DHCP client failed on {bond_name}.",
                        ),
                        "bond_name": bond_name,
                        "members": members,
                        "unbridged": unbridged,
                    }

            _ensure_uplink_list_member(sock, bond_name)
            for pppoe_name in moved_pppoe:
                if pppoe_name and pppoe_name != bond_name:
                    _ensure_uplink_list_member(sock, pppoe_name)

            return {
                "ok": True,
                "mode": "bond",
                "bond_name": bond_name,
                "bond_mode": bond_mode,
                "members": members,
                "wan_interface": bond_name,
                "unbridged": unbridged,
                "disabled_member_dhcp": disabled_dhcp,
                "moved_pppoe": moved_pppoe,
                "uplink_kind": uplink_kind,
                "message": (
                    f"Bonded {', '.join(members)} as {bond_name} "
                    f"({bond_mode}) for the same provider"
                    + (
                        f"; PPPoE moved to {bond_name}."
                        if moved_pppoe
                        else "."
                    )
                ),
            }
    except TimeoutError:
        return {
            "ok": False,
            "error": "Connection timed out while configuring bonding.",
        }
    except ConnectionError as exc:
        return {
            "ok": False,
            "error": str(exc) or "Login failed. Check the saved username and password.",
        }
    except OSError as exc:
        return {
            "ok": False,
            "error": f"Could not reach {host}:8728. ({exc})",
        }


def _balance_table_name(index: int) -> str:
    return f"ispcentric-w{index}"


def _ensure_balance_routing_table(sock: socket.socket, table_name: str) -> dict[str, str]:
    """Create a ROS7 FIB routing table used by PCC marks (best-effort on ROS6)."""
    table_name = (table_name or "").strip()
    if not table_name:
        return {"_reply": "!trap", "message": "Missing routing table name."}
    try:
        for row in _print(sock, "/routing/table", props=".id,name,comment"):
            if (row.get("name") or "").strip() == table_name:
                return {"_reply": "!done", "name": table_name}
    except Exception as exc:
        return {"_reply": "!trap", "message": str(exc) or "Routing tables unavailable."}
    terminal = _add(
        sock,
        "/routing/table",
        name=table_name,
        fib="yes",
        comment=UPLINK_TAG,
    )
    if terminal.get("_reply") in {"!trap", "!fatal"}:
        terminal = _add(
            sock,
            "/routing/table",
            name=table_name,
            comment=UPLINK_TAG,
        )
    return terminal


def _add_balance_default_route(
    sock: socket.socket,
    *,
    gateway: str,
    distance: int,
    routing_table: str = "",
) -> dict[str, str]:
    """Install a ping-checked default route, optionally in a named routing table."""
    gateway = (gateway or "").strip()
    if not gateway:
        return {"_reply": "!trap", "message": "Missing balance gateway."}
    distance_s = str(max(1, int(distance)))
    attempts: list[dict[str, str]] = []
    if routing_table:
        attempts.append(
            {
                "dst-address": "0.0.0.0/0",
                "gateway": gateway,
                "distance": distance_s,
                "check-gateway": "ping",
                "routing-table": routing_table,
                "comment": UPLINK_TAG,
            }
        )
        attempts.append(
            {
                "dst-address": "0.0.0.0/0",
                "gateway": gateway,
                "distance": distance_s,
                "check-gateway": "ping",
                "routing-mark": routing_table,
                "comment": UPLINK_TAG,
            }
        )
    attempts.append(
        {
            "dst-address": "0.0.0.0/0",
            "gateway": gateway,
            "distance": distance_s,
            "check-gateway": "ping",
            "comment": UPLINK_TAG,
        }
    )
    attempts.append(
        {
            "dst-address": "0.0.0.0/0",
            "gateway": gateway,
            "distance": distance_s,
            "comment": UPLINK_TAG,
        }
    )
    last = {"_reply": "!trap", "message": "Could not add balance route."}
    for props in attempts:
        last = _add(sock, "/ip/route", **props)
        if last.get("_reply") not in {"!trap", "!fatal"}:
            return last
        unknown = _unknown_parameter_name(last.get("message") or "")
        if unknown and unknown in props:
            trimmed = {k: v for k, v in props.items() if k != unknown}
            last = _add(sock, "/ip/route", **trimmed)
            if last.get("_reply") not in {"!trap", "!fatal"}:
                return last
    return last


def _pcc_slot_counts(mbps_list: list[int], *, max_slots: int = 24) -> list[int]:
    """
    Convert Mbps (or relative weights) into PCC slot counts.

    Example: [100, 20] → [5, 1] so ~83% of new connections use the first WAN.
    """
    from functools import reduce
    from math import gcd

    vals = [max(1, min(10000, int(m or 1))) for m in (mbps_list or [])]
    if not vals:
        return []
    g = reduce(gcd, vals)
    vals = [v // g for v in vals]
    total = sum(vals)
    if total <= max_slots:
        return vals

    scaled = [max(1, int(round(v * max_slots / float(total)))) for v in vals]
    while sum(scaled) > max_slots:
        i = max(range(len(scaled)), key=lambda j: scaled[j])
        if scaled[i] <= 1:
            break
        scaled[i] -= 1
    while sum(scaled) < max_slots:
        i = max(
            range(len(scaled)),
            key=lambda j: (vals[j] / float(scaled[j])) if scaled[j] else vals[j],
        )
        scaled[i] += 1
    g2 = reduce(gcd, scaled) if scaled else 1
    return [v // g2 for v in scaled]


def _install_balance_pcc(
    sock: socket.socket,
    members: list[dict[str, str]],
) -> dict[str, Any]:
    """
    Weighted PCC multi-WAN for different providers.

    - Per-WAN FIB / routing-mark table with ping-checked default
    - Main table: fastest WAN at distance 1, others 2/3/… (no ECMP fight with PCC)
    - PCC uses both-addresses-and-ports so busy CDNs still spread
    - Dead WANs drop via check-gateway=ping; unmarked traffic fails over to next
    """
    count = len(members)
    if count < 2:
        return {"ok": False, "error": "Need at least two WAN members for balance."}

    # Fastest first so distance-1 main route and index 0 prefer the strong ISP.
    ordered = sorted(
        members,
        key=lambda m: (-int(m.get("weight") or 1), str(m.get("interface") or "")),
    )
    for index, item in enumerate(ordered):
        item["index"] = str(index)

    slot_counts = _pcc_slot_counts([int(m.get("weight") or 1) for m in ordered])
    total_slots = sum(slot_counts)
    if total_slots < 2:
        return {"ok": False, "error": "Invalid balance weights."}

    tables_ok = 0
    routes_ok = 0
    for rank, item in enumerate(ordered):
        index = int(item.get("index") or 0)
        table = _balance_table_name(index)
        gateway = (item.get("gateway") or "").strip()
        if not gateway:
            continue
        table_term = _ensure_balance_routing_table(sock, table)
        if table_term.get("_reply") not in {"!trap", "!fatal"}:
            tables_ok += 1
        # Own table always distance 1.
        marked = _add_balance_default_route(
            sock, gateway=gateway, distance=1, routing_table=table
        )
        if marked.get("_reply") not in {"!trap", "!fatal"}:
            routes_ok += 1
        # Main FIB: strongest preferred; weaker are standby if marks miss / WAN dies.
        main = _add_balance_default_route(
            sock, gateway=gateway, distance=rank + 1, routing_table=""
        )
        if main.get("_reply") not in {"!trap", "!fatal"}:
            routes_ok += 1

    # Prefer both-addresses-and-ports; fall back to both-addresses on older ROS.
    pcc_classifier = "both-addresses-and-ports"
    slot_index = 0
    for item_index, item in enumerate(ordered):
        index = int(item.get("index") or 0)
        wan_iface = (item.get("wan_iface") or item.get("interface") or "").strip()
        table = _balance_table_name(index)
        conn_mark = f"ispcentric-c{index}"
        if not wan_iface:
            continue
        _add(
            sock,
            "/ip/firewall/mangle",
            chain="input",
            **{
                "in-interface": wan_iface,
                "action": "mark-connection",
                "new-connection-mark": conn_mark,
                "passthrough": "yes",
                "comment": UPLINK_TAG,
            },
        )
        _add(
            sock,
            "/ip/firewall/mangle",
            chain="output",
            **{
                "connection-mark": conn_mark,
                "action": "mark-routing",
                "new-routing-mark": table,
                "passthrough": "yes",
                "comment": UPLINK_TAG,
            },
        )
        member_slots = slot_counts[item_index] if item_index < len(slot_counts) else 1
        for _ in range(max(1, member_slots)):
            props = {
                "dst-address-type": "!local",
                "in-interface-list": "!WAN",
                "connection-mark": "no-mark",
                "connection-state": "new",
                "per-connection-classifier": f"{pcc_classifier}:{total_slots}/{slot_index}",
                "action": "mark-connection",
                "new-connection-mark": conn_mark,
                "passthrough": "yes",
                "comment": UPLINK_TAG,
            }
            terminal = _add(sock, "/ip/firewall/mangle", chain="prerouting", **props)
            if terminal.get("_reply") in {"!trap", "!fatal"}:
                # Older RouterOS: drop connection-state and/or ports classifier.
                for fallback in (
                    {
                        **props,
                        "per-connection-classifier": (
                            f"both-addresses:{total_slots}/{slot_index}"
                        ),
                    },
                    {
                        k: v
                        for k, v in {
                            **props,
                            "per-connection-classifier": (
                                f"both-addresses:{total_slots}/{slot_index}"
                            ),
                        }.items()
                        if k != "connection-state"
                    },
                ):
                    terminal = _add(
                        sock, "/ip/firewall/mangle", chain="prerouting", **fallback
                    )
                    if terminal.get("_reply") not in {"!trap", "!fatal"}:
                        break
            slot_index += 1
        _add(
            sock,
            "/ip/firewall/mangle",
            chain="prerouting",
            **{
                "in-interface-list": "!WAN",
                "connection-mark": conn_mark,
                "action": "mark-routing",
                "new-routing-mark": table,
                "passthrough": "yes",
                "comment": UPLINK_TAG,
            },
        )

    mangle_rows = _rows_with_comment_tag(sock, "/ip/firewall/mangle", UPLINK_TAG)
    return {
        "ok": True,
        "tables": tables_ok,
        "routes": routes_ok,
        "mangle_rules": len(mangle_rows),
        "members": [m.get("interface") for m in ordered],
        "slot_counts": slot_counts,
        "total_slots": total_slots,
        "preferred": (ordered[0].get("interface") if ordered else ""),
    }


def _resolve_balance_member_gateway(
    sock: socket.socket,
    *,
    interface: str,
    kind: str,
    pppoe_name: str = "",
) -> tuple[str, str]:
    """Return (wan_iface_for_mangle, gateway) for one balance member."""
    interface = (interface or "").strip()
    pppoe_name = (pppoe_name or "").strip()
    if kind == "pppoe":
        wan_iface = pppoe_name or _find_pppoe_client_for_wan(sock, interface) or interface
        return wan_iface, wan_iface
    gateways = _detect_dhcp_gateways(sock, interface)
    gateway = gateways[0] if gateways else ""
    if not gateway:
        gateway = _default_route_gateway_for_interface(sock, interface)
    return interface, gateway or ""


def apply_mikrotik_uplink_balance(
    host: str,
    username: str,
    password: str,
    *,
    member_ports: list[str],
    member_weights: dict[str, int] | None = None,
    port: int = 8728,
    timeout: float = 14.0,
) -> dict[str, Any]:
    """
    PCC load-balance across different ISP uplinks.

    Uses the same port roles as failover (Internet + Backup internet). When
    ``member_weights`` maps port → Mbps, connections are split in that ratio
    (e.g. 100/20 → ~5:1). Otherwise each member gets an equal share.
    """
    import time as _time

    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    members = [p.strip() for p in (member_ports or []) if (p or "").strip()]
    members = list(dict.fromkeys(members))
    weights_in = member_weights if isinstance(member_weights, dict) else {}

    if not host or not username:
        return {"ok": False, "error": "Missing router credentials."}
    if len(members) < 2:
        return {
            "ok": False,
            "error": "Select at least two ports (Internet + Backup internet) to balance.",
        }

    def _weight_for(name: str) -> int:
        raw = weights_in.get(name, weights_in.get(name.lower(), 100))
        try:
            return max(1, min(10000, int(raw)))
        except (TypeError, ValueError):
            return 100

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            names = _iface_names(sock)
            missing = [p for p in members if p not in names]
            if missing:
                return {
                    "ok": False,
                    "error": f"Port(s) not found on router: {', '.join(missing)}.",
                }

            _clear_tagged_uplink(sock)
            unbridged = _unbridge_interfaces(sock, members)

            uplink_results: list[dict[str, str]] = []
            for index, iface in enumerate(members):
                # Do not let DHCP/PPPoE install competing ECMP defaults — we
                # own ping-checked static routes for balance.
                terminal = _ensure_failover_uplink(
                    sock, iface, distance=1, add_default_route=False
                )
                if terminal.get("_reply") in {"!trap", "!fatal"}:
                    if unbridged:
                        _restore_bridged_interfaces(sock, unbridged)
                    return {
                        "ok": False,
                        "error": _trap_message(
                            terminal,
                            f"Could not configure balance uplink on {iface}.",
                        ),
                    }
                terminal = dict(terminal)
                terminal["_index"] = str(index)
                uplink_results.append(terminal)
                _ensure_uplink_list_member(sock, iface)
                pppoe_name = (terminal.get("_pppoe") or "").strip() or _find_pppoe_client_for_wan(
                    sock, iface
                )
                if pppoe_name and pppoe_name != iface:
                    _ensure_uplink_list_member(sock, pppoe_name)

            _time.sleep(1.2)

            balance_members: list[dict[str, str]] = []
            missing_gw: list[str] = []
            for item in uplink_results:
                iface = (item.get("_interface") or "").strip()
                kind = (item.get("_kind") or "dhcp").strip()
                pppoe_name = (item.get("_pppoe") or "").strip()
                index = int(item.get("_index") or "0")
                wan_iface, gateway = _resolve_balance_member_gateway(
                    sock,
                    interface=iface,
                    kind=kind,
                    pppoe_name=pppoe_name,
                )
                if not gateway:
                    missing_gw.append(iface)
                    continue
                _disable_client_default_route(
                    sock,
                    kind=kind,
                    interface=iface,
                    pppoe_name=pppoe_name or gateway,
                )
                balance_members.append(
                    {
                        "interface": iface,
                        "wan_iface": wan_iface,
                        "gateway": gateway,
                        "index": str(index),
                        "kind": kind,
                        "weight": str(_weight_for(iface)),
                    }
                )

            if len(balance_members) < 2:
                return {
                    "ok": False,
                    "error": (
                        "Could not learn gateways on enough WAN ports for balance. "
                        "Confirm both links have internet (DHCP or PPPoE), then retry."
                        + (
                            f" Missing gateway on: {', '.join(missing_gw)}."
                            if missing_gw
                            else ""
                        )
                    ),
                    "unbridged": unbridged,
                }

            pcc = _install_balance_pcc(sock, balance_members)
            if not pcc.get("ok"):
                return {
                    "ok": False,
                    "error": pcc.get("error") or "Could not install PCC balance rules.",
                    "unbridged": unbridged,
                }

            labels = list(pcc.get("members") or [m["interface"] for m in balance_members])
            weights_out = {
                m["interface"]: int(m.get("weight") or 100) for m in balance_members
            }
            # Reorder weights_out keys to match preferred order for UI.
            weights_ordered = {name: weights_out.get(name, 100) for name in labels}
            for name, val in weights_out.items():
                weights_ordered.setdefault(name, val)
            slots = pcc.get("slot_counts") or []
            preferred = (pcc.get("preferred") or (labels[0] if labels else "")).strip()
            equal = len(set(slots)) <= 1 if slots else True
            if equal:
                share_text = "equal connections via PCC; fastest link preferred if one dies"
            else:
                ratio = ":".join(str(s) for s in slots)
                mbps_bits = ", ".join(
                    f"{name} {weights_ordered.get(name, 100)} Mbps" for name in labels
                )
                share_text = (
                    f"weighted {ratio} toward {preferred or 'fastest'} "
                    f"({mbps_bits}); ping-checks drop a dead ISP"
                )

            return {
                "ok": True,
                "mode": "balance",
                "ports": labels,
                "wan_interface": preferred or (labels[0] if labels else ""),
                "unbridged": unbridged,
                "gateways": {m["interface"]: m["gateway"] for m in balance_members},
                "weights": weights_ordered,
                "slot_counts": slots,
                "preferred": preferred,
                "mangle_rules": pcc.get("mangle_rules") or 0,
                "message": (
                    f"Load balance ready across {', '.join(labels)} "
                    f"({share_text})."
                    + (
                        f" Waiting on gateway for: {', '.join(missing_gw)}."
                        if missing_gw
                        else ""
                    )
                ),
            }
    except TimeoutError:
        return {
            "ok": False,
            "error": "Connection timed out while configuring load balance.",
        }
    except ConnectionError as exc:
        return {
            "ok": False,
            "error": str(exc) or "Login failed. Check the saved username and password.",
        }
    except OSError as exc:
        return {
            "ok": False,
            "error": f"Could not reach {host}:8728. ({exc})",
        }


def apply_mikrotik_uplink_failover(
    host: str,
    username: str,
    password: str,
    *,
    primary_port: str,
    backup_ports: list[str],
    port: int = 8728,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """
    Configure primary + backup WAN ports for different providers.

    Prefers PPPoE when present, otherwise DHCP, with rising default-route
    distances. When gateways are known, installs ping-checked static defaults so
    failover also triggers if the ISP path dies while the cable stays up.
    """
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    primary_port = (primary_port or "").strip()
    backups = [p.strip() for p in (backup_ports or []) if (p or "").strip()]
    backups = [p for p in dict.fromkeys(backups) if p != primary_port]

    if not host or not username:
        return {"ok": False, "error": "Missing router credentials."}
    if not primary_port:
        return {"ok": False, "error": "Choose a primary WAN port."}
    if not backups:
        return {"ok": False, "error": "Choose at least one backup WAN port."}

    ordered = [primary_port, *backups]

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            names = _iface_names(sock)
            missing = [p for p in ordered if p not in names]
            if missing:
                return {
                    "ok": False,
                    "error": f"Port(s) not found on router: {', '.join(missing)}.",
                }

            _clear_tagged_uplink(sock)
            unbridged = _unbridge_interfaces(sock, ordered)

            uplink_results: list[dict[str, str]] = []
            for index, iface in enumerate(ordered):
                distance = 1 + (index * 10)
                terminal = _ensure_failover_uplink(
                    sock, iface, distance=distance
                )
                if terminal.get("_reply") in {"!trap", "!fatal"}:
                    if unbridged:
                        _restore_bridged_interfaces(sock, unbridged)
                    return {
                        "ok": False,
                        "error": _trap_message(
                            terminal,
                            f"Could not configure failover uplink on {iface}.",
                        ),
                    }
                uplink_results.append(terminal)
                # Put physical + PPPoE (if any) into WAN list.
                _ensure_uplink_list_member(sock, iface)
                pppoe_name = (terminal.get("_pppoe") or "").strip() or _find_pppoe_client_for_wan(
                    sock, iface
                )
                if pppoe_name and pppoe_name != iface:
                    _ensure_uplink_list_member(sock, pppoe_name)

            checked_routes = _install_failover_gateway_checks(sock, uplink_results)

            # Best-effort: also ping-check any remaining static defaults.
            for row in _print(
                sock,
                "/ip/route",
                props=".id,dst-address,gateway,distance,dynamic,comment,active",
            ):
                dst = (row.get("dst-address") or "").strip()
                if dst not in {"0.0.0.0/0", "::/0"}:
                    continue
                item_id = (row.get(".id") or "").strip()
                if not item_id or _flag_yes(row.get("dynamic")):
                    continue
                _set(sock, "/ip/route", item_id, **{"check-gateway": "ping"})

            checked_label = ""
            if checked_routes:
                checked_label = (
                    f" Ping-check enabled on {len(checked_routes)} "
                    f"gateway{'s' if len(checked_routes) != 1 else ''}."
                )

            return {
                "ok": True,
                "mode": "failover",
                "primary": primary_port,
                "backups": backups,
                "ports": ordered,
                "wan_interface": primary_port,
                "unbridged": unbridged,
                "checked_routes": checked_routes,
                "message": (
                    f"Failover ready: primary {primary_port}, "
                    f"backup {', '.join(backups)}."
                    f"{checked_label}"
                ),
            }
    except TimeoutError:
        return {
            "ok": False,
            "error": "Connection timed out while configuring failover.",
        }
    except ConnectionError as exc:
        return {
            "ok": False,
            "error": str(exc) or "Login failed. Check the saved username and password.",
        }
    except OSError as exc:
        return {
            "ok": False,
            "error": f"Could not reach {host}:8728. ({exc})",
        }


def clear_mikrotik_uplink_multi(
    host: str,
    username: str,
    password: str,
    *,
    restore_bridged: list[dict[str, str]] | None = None,
    lan_bridge: str = "bridgeLocal",
    port: int = 8728,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Remove bonded / failover uplink objects tagged by ISPCENTRIC."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not host or not username:
        return {"ok": False, "error": "Missing router credentials."}

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            removed = _clear_tagged_uplink(sock)
            restored = _restore_bridged_interfaces(
                sock,
                restore_bridged or [],
                lan_bridge_fallback=lan_bridge or "bridgeLocal",
            )
            return {
                "ok": True,
                "removed": removed,
                "restored_bridge_ports": restored,
                "message": "Bonded / failover / balance uplink settings cleared on the MikroTik.",
            }
    except TimeoutError:
        return {"ok": False, "error": "Connection timed out while clearing uplink settings."}
    except ConnectionError as exc:
        return {
            "ok": False,
            "error": str(exc) or "Login failed. Check the saved username and password.",
        }
    except OSError as exc:
        return {"ok": False, "error": f"Could not reach {host}:8728. ({exc})"}


def read_mikrotik_uplink_multi(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 6.0,
) -> dict[str, Any]:
    """Best-effort read of bonded / failover uplink state from the router."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not host or not username:
        return {"ok": False, "error": "Missing router credentials."}

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            bonds: list[dict[str, Any]] = []
            for row in _print(
                sock,
                "/interface/bonding",
                props=".id,name,mode,slaves,running,disabled,comment,link-monitoring,primary",
            ):
                if UPLINK_TAG not in (row.get("comment") or ""):
                    continue
                slaves_raw = (row.get("slaves") or "").strip()
                bonds.append(
                    {
                        "name": (row.get("name") or "").strip(),
                        "mode": (row.get("mode") or "").strip(),
                        "slaves": [s.strip() for s in slaves_raw.split(",") if s.strip()],
                        "running": _flag_yes(row.get("running")),
                        "disabled": _flag_yes(row.get("disabled")),
                        "link_monitoring": (row.get("link-monitoring") or "").strip(),
                        "primary": (row.get("primary") or "").strip(),
                    }
                )

            failover_clients: list[dict[str, Any]] = []
            for row in _print(
                sock,
                "/ip/dhcp-client",
                props=".id,interface,status,default-route-distance,disabled,comment,add-default-route",
            ):
                comment = row.get("comment") or ""
                distance = (row.get("default-route-distance") or "").strip() or "1"
                # Include tagged clients, or any client with a non-default distance
                # (failover often reuses the original untagged WAN DHCP client).
                if UPLINK_TAG not in comment and distance in {"", "0", "1"}:
                    continue
                failover_clients.append(
                    {
                        "interface": (row.get("interface") or "").strip(),
                        "status": (row.get("status") or "").strip(),
                        "distance": distance,
                        "disabled": _flag_yes(row.get("disabled")),
                        "kind": "dhcp",
                        "add_default_route": not (
                            (row.get("add-default-route") or "").strip().lower()
                            in {"no", "false"}
                        ),
                    }
                )

            try:
                pppoe_rows = _print(
                    sock,
                    "/interface/pppoe-client",
                    props=".id,name,interface,disabled,default-route-distance,add-default-route,running",
                )
            except Exception:
                pppoe_rows = []
            for row in pppoe_rows:
                if _flag_yes(row.get("disabled")):
                    continue
                distance = (row.get("default-route-distance") or "").strip() or "1"
                failover_clients.append(
                    {
                        "interface": (row.get("interface") or "").strip(),
                        "pppoe": (row.get("name") or "").strip(),
                        "status": "running" if _flag_yes(row.get("running")) else "down",
                        "distance": distance,
                        "disabled": False,
                        "kind": "pppoe",
                        "add_default_route": not (
                            (row.get("add-default-route") or "").strip().lower()
                            in {"no", "false"}
                        ),
                    }
                )

            failover_clients.sort(
                key=lambda item: int(item["distance"]) if str(item["distance"]).isdigit() else 99
            )

            checked_routes: list[dict[str, Any]] = []
            for row in _print(
                sock,
                "/ip/route",
                props="dst-address,gateway,distance,check-gateway,active,disabled,comment",
            ):
                if UPLINK_TAG not in (row.get("comment") or ""):
                    continue
                if (row.get("dst-address") or "").strip() not in {"0.0.0.0/0", "::/0"}:
                    continue
                checked_routes.append(
                    {
                        "gateway": (row.get("gateway") or "").strip(),
                        "distance": (row.get("distance") or "").strip() or "1",
                        "check_gateway": (row.get("check-gateway") or "").strip(),
                        "active": _flag_yes(row.get("active")),
                        "disabled": _flag_yes(row.get("disabled")),
                    }
                )
            checked_routes.sort(
                key=lambda item: int(item["distance"]) if str(item["distance"]).isdigit() else 99
            )

            mode = "single"
            if bonds:
                mode = "bond"
            else:
                distances = {
                    str(c.get("distance") or "1")
                    for c in failover_clients
                    if not c.get("disabled")
                }
                if len(checked_routes) >= 2 or len(distances) >= 2:
                    mode = "failover"

            healthy = False
            if mode == "bond":
                healthy = any(b.get("running") and not b.get("disabled") for b in bonds)
            elif mode == "failover":
                healthy = any(r.get("active") and not r.get("disabled") for r in checked_routes) or any(
                    not c.get("disabled") for c in failover_clients
                )

            return {
                "ok": True,
                "mode": mode,
                "bonds": bonds,
                "failover_clients": failover_clients,
                "checked_routes": checked_routes,
                "healthy": healthy,
            }
    except Exception as exc:
        return {"ok": False, "error": str(exc) or "Could not read uplink state."}
