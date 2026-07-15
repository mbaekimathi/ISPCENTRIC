"""MikroTik RouterOS API: login, identity, and Wi‑Fi configuration."""

from __future__ import annotations

import hashlib
import socket
import time
from contextlib import contextmanager
from typing import Any, Iterator


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
    """Run a RouterOS API command. Returns (replies, done/trap attrs)."""
    _write_sentence(sock, words)
    replies: list[dict[str, str]] = []
    terminal: dict[str, str] = {}
    while True:
        sentence = _read_sentence(sock)
        if not sentence:
            break
        attrs = _attrs(sentence)
        reply = attrs.get("_reply") or (sentence[0] if sentence else "")
        if reply == "!re":
            replies.append(attrs)
        if reply in {"!done", "!trap", "!fatal"}:
            terminal = attrs
            terminal["_reply"] = reply
            break
    return replies, terminal


def _print(sock: socket.socket, path: str, *, props: str = "") -> list[dict[str, str]]:
    words = [f"{path}/print"]
    if props:
        words.append(f"=.proplist={props}")
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


def _rows_with_tag(sock: socket.socket, path: str, *, props: str = ".id,comment") -> list[dict[str, str]]:
    tag = CLEAN_UPLINK_TAG
    matched: list[dict[str, str]] = []
    for row in _print(sock, path, props=props):
        comment = row.get("comment") or ""
        if tag in comment:
            matched.append(row)
    return matched


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


def _ensure_pppoe_nat(sock: socket.socket) -> None:
    """NAT for dialed PPPoE clients (pool subnet → WAN)."""
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


def _first_forward_drop_id(sock: socket.socket) -> str:
    """First forward-chain drop rule — insert allows before it when possible."""
    for row in _print(sock, "/ip/firewall/filter", props=".id,chain,action"):
        if (row.get("chain") or "") == "forward" and (row.get("action") or "") == "drop":
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


def _ensure_filter_rules(sock: socket.socket, *, mode: str, provider_gateway: str) -> None:
    """Install tagged filter rules. Existing non-tagged rules are left alone.

    Intentionally does NOT drop all WAN→router or forward-the-rest traffic.
    Those rules locked operators out when they managed the MikroTik from the
    Starlink/provider side of ether1. Clean uplink focuses on DNS/NAT and
    blocking the provider admin page instead.
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

    if mode == "behind" and provider_gateway:
        rules.insert(
            1,
            {
                "chain": "forward",
                "action": "drop",
                "dst-address": provider_gateway,
                "comment": f"{CLEAN_UPLINK_TAG} block provider admin",
            },
        )

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
            with socket.create_connection((host, port), timeout=connect_timeout):
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
    lan_network: str = "10.10.0.0/24",
    lan_gateway: str = "10.10.0.1",
    lan_pool_ranges: str = "10.10.0.10-10.10.0.200",
) -> list[str]:
    """
    Make MikroTik route internet cleanly:

    - WAN (Starlink) on wan_interface via DHCP
    - LAN on a different subnet (default 10.10.0.0/24) with DHCP for clients
    - NAT masquerade out WAN
    """
    wan_interface = (wan_interface or "ether1").strip()
    lan_bridge = (lan_bridge or "bridgeLocal").strip()
    notes: list[str] = []

    # DHCP client belongs on WAN only — never on the LAN bridge.
    for row in _print(sock, "/ip/dhcp-client", props=".id,interface"):
        iface = (row.get("interface") or "").strip()
        item_id = (row.get(".id") or "").strip()
        if iface == lan_bridge and item_id:
            _remove(sock, "/ip/dhcp-client", item_id)
            notes.append(f"removed DHCP client from {lan_bridge}")
        elif iface == wan_interface and item_id:
            _set(
                sock,
                "/ip/dhcp-client",
                item_id,
                disabled="no",
                **{"add-default-route": "yes", "use-peer-dns": "no"},
            )

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

    # LAN must not share the Starlink/WAN subnet.
    for row in _print(sock, "/ip/address", props=".id,address,interface"):
        iface = (row.get("interface") or "").strip()
        address = (row.get("address") or "").strip()
        item_id = (row.get(".id") or "").strip()
        if iface != lan_bridge or not item_id:
            continue
        if address.startswith("10.10.0."):
            continue
        _remove(sock, "/ip/address", item_id)
        notes.append(f"removed conflicting LAN address {address}")

    has_lan_ip = any(
        (row.get("interface") or "").strip() == lan_bridge
        and (row.get("address") or "").startswith("10.10.0.")
        for row in _print(sock, "/ip/address", props="address,interface")
    )
    if not has_lan_ip:
        _add(
            sock,
            "/ip/address",
            address=f"{lan_gateway}/24",
            interface=lan_bridge,
            comment=CLEAN_UPLINK_TAG,
        )
        notes.append(f"set LAN {lan_gateway}/24 on {lan_bridge}")

    pool_names = {
        (row.get("name") or "").strip()
        for row in _print(sock, "/ip/pool", props="name")
    }
    if "ispcentric-lan" not in pool_names:
        _add(
            sock,
            "/ip/pool",
            name="ispcentric-lan",
            ranges=lan_pool_ranges,
            comment=CLEAN_UPLINK_TAG,
        )
        notes.append("added LAN DHCP pool")

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
        (row.get("address") or "").startswith("10.10.0.")
        for row in _print(sock, "/ip/dhcp-server/network", props="address")
    )
    if not has_net:
        _add(
            sock,
            "/ip/dhcp-server/network",
            address=lan_network,
            gateway=lan_gateway,
            **{"dns-server": lan_gateway, "comment": CLEAN_UPLINK_TAG},
        )
        notes.append("added LAN DHCP network")

    _ensure_interface_list(sock, "WAN")
    _ensure_interface_list(sock, "LAN")
    _ensure_list_member(sock, "WAN", wan_interface)
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

    # Provider-admin drop can stay, but keep it disabled while diagnosing passthrough.
    for row in _print(sock, "/ip/firewall/filter", props=".id,comment,disabled"):
        if "block provider admin" in (row.get("comment") or ""):
            item_id = (row.get(".id") or "").strip()
            if item_id and (row.get("disabled") or "").lower() not in {"true", "yes"}:
                _set(sock, "/ip/firewall/filter", item_id, disabled="yes")
                notes.append("paused provider-admin block")

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
                "block provider admin" in (row.get("comment") or "") for row in filter_hits
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
    provider_gateway: str = "192.168.1.1",
    separate_wan: bool = True,
    restore_wan_to_bridge: bool = False,
    port: int = 8728,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """
    Apply or remove clean-uplink rules on RouterOS.

    Runs in phases and reconnects after unbridging WAN, because that change
    often drops the active API TCP session and caused timeouts.
    """
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    mode = (mode or "bypass").strip().lower()
    if mode not in {"bypass", "behind"}:
        mode = "bypass"
    wan_interface = (wan_interface or "ether1").strip()
    lan_bridge = (lan_bridge or "bridgeLocal").strip()
    provider_gateway = (provider_gateway or "").strip()

    if not host or not username:
        return {"ok": False, "error": "Router credentials are required."}
    if not wan_interface:
        return {"ok": False, "error": "WAN interface is required."}
    if not lan_bridge:
        return {"ok": False, "error": "LAN bridge is required."}
    if mode == "behind" and enabled and not provider_gateway:
        return {"ok": False, "error": "Provider gateway IP is required for behind-provider mode."}

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

        # Unbridging often kills the current API TCP session — wait, then continue.
        if wan_was_bridged:
            time.sleep(1.5)
            _wait_for_api(host, port=port)

        # Phase 2: lists, DHCP, DNS, NAT, firewall (fresh session).
        last_error = ""
        for attempt in range(1, 4):
            try:
                with _api_session(
                    host, username, password, port=port, timeout=timeout
                ) as sock:
                    _ensure_interface_list(sock, "WAN")
                    _ensure_interface_list(sock, "LAN")
                    _ensure_list_member(sock, "WAN", wan_interface)
                    _ensure_list_member(sock, "LAN", lan_bridge)
                    ensure_mikrotik_lan_passthrough(
                        sock,
                        wan_interface=wan_interface,
                        lan_bridge=lan_bridge,
                    )
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
                        sock, mode=mode, provider_gateway=provider_gateway
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

        mode_label = "Starlink Bypass" if mode == "bypass" else "Behind provider router"
        return {
            "ok": True,
            "enabled": True,
            "mode": mode,
            "wan_was_bridged": wan_was_bridged,
            "message": (
                f"Clean uplink enabled ({mode_label}). "
                "MikroTik will pass internet and block provider settings pages."
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
        "192.168.88.1",
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
        except ConnectionError as exc:
            message = str(exc) or "Login failed."
            low = message.lower()
            auth_failed = any(
                token in low
                for token in (
                    "invalid user",
                    "password",
                    "cannot log in",
                    "login failed",
                    "authentication",
                    "bad name",
                )
            )
            # Wrong password on preferred host still try other IPs — the saved
            # address may point at a different device. Stop only when this was
            # the last candidate.
            if auth_failed and candidate == hosts[-1]:
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
            last_error = f"{candidate}: {exc}"
            continue
        except Exception as exc:
            last_error = f"{candidate}: {exc}"
            continue

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
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        login_error = _api_login(sock, username, password)
        if login_error:
            raise ConnectionError(login_error.get("error") or "Login failed.")
        yield sock


def _fetch_identity(sock: socket.socket, host: str) -> dict[str, Any]:
    identity = ""
    version = ""
    board = ""
    try:
        for attrs in _print(sock, "/system/identity", props="name"):
            identity = attrs.get("name") or identity
        for attrs in _print(sock, "/system/resource", props="version,board-name"):
            version = attrs.get("version") or version
            board = attrs.get("board-name") or board
    except Exception:
        pass

    return {
        "ok": True,
        "host": host,
        "identity": identity,
        "version": version,
        "board": board,
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
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
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
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
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

    Prefer RouterOS API (8728), then Winbox (8291) and WebFig HTTP.
    Falls back to ICMP ping so routers with API disabled still show online.
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
    for candidate in (check_port, 8728, 8291, 80, 8080):
        if candidate and candidate not in ports:
            ports.append(candidate)

    via_map = {
        8728: "api",
        8291: "winbox",
        80: "http",
        8080: "http",
    }

    def _probe(probe_port: int) -> tuple[int, bool, str]:
        try:
            with socket.create_connection((check_host, probe_port), timeout=timeout):
                return probe_port, True, ""
        except TimeoutError:
            return probe_port, False, f"{probe_port}: timed out"
        except OSError as exc:
            return probe_port, False, f"{probe_port}: {exc}"

    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=min(4, len(ports))) as pool:
        futures = [pool.submit(_probe, p) for p in ports]
        for future in as_completed(futures):
            probe_port, ok, err = future.result()
            if ok:
                # Cancel remaining work isn't critical; return first success.
                return {
                    "online": True,
                    "via": via_map.get(probe_port, f"tcp/{probe_port}"),
                    "port": probe_port,
                }
            if err:
                errors.append(err)

    # ICMP fallback — device may be up with management ports firewalled.
    if _icmp_ping(check_host, timeout=timeout):
        return {"online": True, "via": "ping", "port": 0}

    return {
        "online": False,
        "error": errors[0] if errors else "Unreachable.",
        "via": "",
    }


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


def _monitor_wan_speeds(
    sock: socket.socket,
    speed_interfaces: list[dict[str, Any]] | None = None,
    *,
    fallback_interface: str = "",
) -> dict[str, Any]:
    """Monitor one or more WAN ports; return flat primary fields plus wan_speeds list."""
    targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in speed_interfaces or []:
        iface = str(item.get("interface") or "").strip()
        if not iface or iface in seen:
            continue
        seen.add(iface)
        role = str(item.get("role") or "primary").strip().lower() or "primary"
        label = str(item.get("label") or "").strip() or iface
        targets.append({"role": role, "interface": iface, "label": label})

    if not targets:
        fallback = (fallback_interface or "").strip()
        if fallback:
            targets.append(
                {
                    "role": "primary",
                    "interface": fallback,
                    "label": f"WAN · {fallback}",
                }
            )

    wan_speeds: list[dict[str, Any]] = []
    for target in targets:
        # Bond members are useful context but primary/secondary matter most for UX;
        # still measure every configured target the caller asked for.
        measured = _monitor_interface_speed(sock, target["interface"])
        wan_speeds.append(
            {
                "role": target["role"],
                "interface": target["interface"],
                "label": target["label"],
                "download_bps": measured.get("wan_download_bps"),
                "upload_bps": measured.get("wan_upload_bps"),
                "download_label": measured.get("wan_download_label") or "—",
                "upload_label": measured.get("wan_upload_label") or "—",
            }
        )

    primary = next((row for row in wan_speeds if row["role"] == "primary"), None)
    if primary is None and wan_speeds:
        primary = wan_speeds[0]

    return {
        "wan_download_bps": primary.get("download_bps") if primary else None,
        "wan_upload_bps": primary.get("upload_bps") if primary else None,
        "wan_download_label": (primary.get("download_label") if primary else None) or "—",
        "wan_upload_label": (primary.get("upload_label") if primary else None) or "—",
        "wan_speed_interface": (primary.get("interface") if primary else "") or "",
        "wan_speeds": wan_speeds,
    }


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
    speed_interfaces: list[dict[str, Any]] | None = None,
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

            # Detect WAN / internet entry before optional wireless probes.
            uplink = _read_internet_uplink(sock)
            fallback_iface = (
                uplink.get("wan_port") or uplink.get("wan_interface") or ""
            ).strip()
            # Prefer configured WAN ports (primary + secondary); fall back to detected.
            speed = _monitor_wan_speeds(
                sock,
                speed_interfaces,
                fallback_interface=fallback_iface,
            )
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


def fetch_pppoe_active_usernames(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 4.0,
) -> dict[str, Any]:
    """Return active PPPoE usernames on a MikroTik (one API call for many clients)."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not host:
        return {
            "ok": False,
            "online": False,
            "usernames": [],
            "error": "No router host configured.",
        }
    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            rows = _print(sock, "/ppp/active", props="name")
            names = sorted(
                {
                    (row.get("name") or "").strip().lower()
                    for row in rows
                    if (row.get("name") or "").strip()
                }
            )
            return {"ok": True, "online": True, "usernames": names, "error": ""}
    except TimeoutError:
        return {
            "ok": False,
            "online": False,
            "usernames": [],
            "error": "Connection timed out reaching the router.",
        }
    except OSError as exc:
        return {
            "ok": False,
            "online": False,
            "usernames": [],
            "error": f"Could not reach {host}:8728.",
            "detail": str(exc),
        }
    except Exception as exc:
        return {
            "ok": False,
            "online": False,
            "usernames": [],
            "error": str(exc) or "Could not read active PPPoE sessions.",
        }


PPP_SECRET_TAG = "ispcentric-pppoe"
PPPOE_PROFILE_NAME = "ispcentric-pppoe"
PPPOE_POOL_NAME = "ispcentric-pppoe"
PPPOE_SERVICE_NAME = "ispcentric"
PPPOE_LOCAL_ADDRESS = "10.20.0.1"
PPPOE_POOL_RANGES = "10.20.0.10-10.20.0.250"
PPPOE_POOL_NETWORK = "10.20.0.0/24"


def _pppoe_rate_limit(download_mbps: int | None, upload_mbps: int | None) -> str:
    """MikroTik PPP rate-limit: rx/tx (client download/upload)."""
    down = int(download_mbps or 0)
    up = int(upload_mbps or 0)
    if down <= 0 and up <= 0:
        return ""
    if down <= 0:
        down = up
    if up <= 0:
        up = down
    return f"{down}M/{up}M"


def _is_disabled(row: dict[str, str]) -> bool:
    return (row.get("disabled") or "").strip().lower() in {"true", "yes"}


def _command_succeeded(terminal: dict[str, str]) -> bool:
    return terminal.get("_reply") == "!done"


def _ppp_username_match(stored: str, wanted: str) -> bool:
    """Match PPP secret names; numeric usernames may differ by leading zeros on RouterOS."""
    stored = (stored or "").strip()
    wanted = (wanted or "").strip()
    if not stored or not wanted:
        return False
    if stored == wanted or stored.lower() == wanted.lower():
        return True
    if wanted.isdigit() and stored.isdigit():
        return stored.lstrip("0") == wanted.lstrip("0")
    return False


def _find_ppp_secret_row(sock: socket.socket, username: str) -> dict[str, str] | None:
    """Find a /ppp/secret row by username (exact, normalized, filter query)."""
    username = (username or "").strip()
    if not username:
        return None

    rows = _print(sock, "/ppp/secret", props=".id,name,disabled,profile,service,comment")
    for row in rows:
        if _ppp_username_match(row.get("name") or "", username):
            return row

    for variant in _ppp_username_variants(username):
        if variant == username:
            continue
        replies, terminal = _command(
            sock,
            [
                "/ppp/secret/print",
                f"?name={variant}",
                "=.proplist=.id,name,disabled,profile,service,comment",
            ],
        )
        if _command_succeeded(terminal) and replies:
            row = replies[0]
            if _ppp_username_match(row.get("name") or "", username):
                return row

    return None


def _ppp_username_variants(username: str) -> list[str]:
    """Alternate forms RouterOS may store for numeric PPPoE usernames."""
    username = (username or "").strip()
    variants = [username]
    if username.isdigit():
        stripped = username.lstrip("0") or "0"
        if stripped not in variants:
            variants.append(stripped)
        if not username.startswith("0") and len(username) < 12:
            variants.append(f"0{username}")
    return variants


def _secret_row_by_id(sock: socket.socket, item_id: str) -> dict[str, str] | None:
    item_id = (item_id or "").strip()
    if not item_id:
        return None
    for row in _print(sock, "/ppp/secret", props=".id,name,disabled,profile,service"):
        if (row.get(".id") or "").strip() == item_id:
            return row
    return None


def _router_ppp_secret_name(pppoe_username: str, existing: dict[str, str] | None) -> str:
    """Username string to store on MikroTik (keep existing name on update; normalize new phone IDs)."""
    if existing:
        return (existing.get("name") or pppoe_username).strip()
    username = (pppoe_username or "").strip()
    if username.isdigit() and username.startswith("0"):
        stripped = username.lstrip("0")
        if stripped:
            return stripped
    return username


def _upsert_ppp_secret_on_sock(
    sock: socket.socket,
    *,
    pppoe_username: str,
    pppoe_password: str,
    profile_name: str,
    rate_limit: str = "",
    disabled: bool = False,
) -> dict[str, Any]:
    """Create or update one PPP secret on an open API session."""
    pppoe_username = (pppoe_username or "").strip()
    pppoe_password = (pppoe_password or "").strip()
    rate_limit = (rate_limit or "").strip()

    if not pppoe_username:
        return {"ok": False, "error": "PPPoE username is required."}
    if not pppoe_password:
        return {"ok": False, "error": "PPPoE password is required."}

    existing = _find_ppp_secret_row(sock, pppoe_username)
    existing_id = (existing.get(".id") or "").strip() if existing else ""
    router_name = _router_ppp_secret_name(pppoe_username, existing)

    def build_props(*, include_rate: bool) -> dict[str, str]:
        props = {
            "name": router_name,
            "password": pppoe_password,
            "service": "pppoe",
            "profile": profile_name,
            "disabled": "yes" if disabled else "no",
            "comment": PPP_SECRET_TAG,
        }
        if include_rate and rate_limit:
            props["rate-limit"] = rate_limit
        return props

    def write_secret(props: dict[str, str]) -> dict[str, str]:
        if existing_id:
            return _set(sock, "/ppp/secret", existing_id, **props)
        return _add(sock, "/ppp/secret", **props)

    terminal = write_secret(build_props(include_rate=True))
    was_update = bool(existing_id)
    if not _command_succeeded(terminal):
        terminal = write_secret(build_props(include_rate=False))

    if not _command_succeeded(terminal):
        return {
            "ok": False,
            "error": _trap_message(
                terminal,
                f"Could not save PPPoE secret “{pppoe_username}” on the MikroTik.",
            ),
        }

    row = None
    ret_id = (terminal.get("ret") or "").strip()
    if ret_id:
        row = _secret_row_by_id(sock, ret_id)
    if not row and was_update and existing_id:
        row = _secret_row_by_id(sock, existing_id)
    if not row:
        row = _find_ppp_secret_row(sock, pppoe_username)

    if not row and _command_succeeded(terminal):
        # Router accepted the write (!done) but name lookup failed (often leading-zero phone usernames).
        return {
            "ok": True,
            "pppoe_username": router_name,
            "created": not was_update,
            "updated": was_update,
            "verified": False,
        }

    if not row:
        reply = terminal.get("_reply") or "unknown"
        detail = (terminal.get("message") or "").strip()
        err = (
            f"Router did not confirm PPPoE secret “{pppoe_username}” "
            f"(API reply: {reply}"
        )
        if detail:
            err += f" — {detail}"
        err += "). Open PPP → Secrets in Winbox and sync again."
        return {"ok": False, "error": err}

    actual_name = (row.get("name") or "").strip()
    if disabled is False and _is_disabled(row):
        return {
            "ok": False,
            "error": f"Secret “{actual_name or pppoe_username}” exists but is disabled on the MikroTik.",
        }

    return {
        "ok": True,
        "pppoe_username": actual_name or pppoe_username,
        "created": not bool(existing_id),
        "updated": bool(existing_id),
    }


def _resolve_pppoe_lan_interface(sock: socket.socket, preferred: str = "") -> str:
    """Pick the LAN / bridge interface where client devices dial PPPoE."""
    preferred = (preferred or "").strip()
    rows = _print(sock, "/interface", props="name,type,running")
    names = {(row.get("name") or "").strip() for row in rows if (row.get("name") or "").strip()}
    if preferred and preferred in names:
        return preferred
    for candidate in ("bridgeLocal", "bridge", "br-lan", "LAN"):
        if candidate in names:
            return candidate
    bridges = [
        (row.get("name") or "").strip()
        for row in rows
        if (row.get("type") or "").strip().lower() == "bridge"
    ]
    if bridges:
        return bridges[0]
    for candidate in ("ether2", "ether3", "ether4", "ether5"):
        if candidate in names:
            return candidate
    return preferred or (next(iter(names), "") or "bridge")


def _ensure_pppoe_stack(
    sock: socket.socket,
    *,
    lan_interface: str,
    wan_interface: str = "ether1",
    compulsory: bool = False,
) -> tuple[str, list[str]]:
    """
    Ensure MikroTik can accept PPPoE dial-ins and route them to the internet.

    Returns (profile_name, notes).
    """
    notes: list[str] = []
    lan_interface = _resolve_pppoe_lan_interface(sock, lan_interface)
    wan_interface = (wan_interface or "ether1").strip() or "ether1"

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

    profile_props = {
        "name": PPPOE_PROFILE_NAME,
        "local-address": PPPOE_LOCAL_ADDRESS,
        "remote-address": PPPOE_POOL_NAME,
        "dns-server": "8.8.8.8,1.1.1.1",
        "change-tcp-mss": "yes",
        # Windows PPPoE uses MS-CHAPv2 — encryption must be allowed or auth is rejected.
        "use-encryption": "yes",
        "only-one": "default",
        "comment": PPP_SECRET_TAG,
    }
    if profile_id:
        terminal = _set(sock, "/ppp/profile", profile_id, **profile_props)
        if terminal.get("_reply") == "!trap":
            # Retry without optional attributes some builds reject.
            soft = {
                "name": PPPOE_PROFILE_NAME,
                "local-address": PPPOE_LOCAL_ADDRESS,
                "remote-address": PPPOE_POOL_NAME,
                "dns-server": "8.8.8.8,1.1.1.1",
                "use-encryption": "yes",
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
                "use-encryption": "yes",
                "comment": PPP_SECRET_TAG,
            }
            terminal = _add(sock, "/ppp/profile", **soft)
            if terminal.get("_reply") == "!trap":
                raise ConnectionError(
                    _trap_message(terminal, "Could not create the PPPoE profile on the MikroTik.")
                )
        notes.append("created PPPoE profile")

    # Always authenticate against local PPP secrets (not RADIUS).
    _command(
        sock,
        [
            "/ppp/aaa/set",
            "=use-radius=no",
            "=accounting=no",
        ],
    )
    notes.append("PPP AAA set to local secrets")

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

    # Empty service-name = clients dial without needing a matching service name.
    # Explicit auth list so Windows MSCHAPv2 is accepted.
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
            # Older builds may not accept authentication= as a combined string — core props only.
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
                            "Clients get “no response from remote server” until a server listens on that LAN."
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

    # Replace only our PPPoE-tagged forward rules (leave clean-uplink rules alone).
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

    forward_rules: list[dict[str, str]] = [
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
    ]
    if compulsory:
        # Block free LAN/DHCP browsing; dialed PPPoE clients use the pool subnet rule above.
        forward_rules.append(
            {
                "chain": "forward",
                "action": "drop",
                "in-interface-list": "LAN",
                "out-interface-list": "WAN",
                "comment": f"{PPP_SECRET_TAG} PPPoE compulsory",
            }
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
    for rule in forward_rules:
        terminal = _add_filter_rule(sock, rule, place_before=place_before_drop)
        if terminal.get("_reply") == "!trap" and place_before_drop:
            _add_filter_rule(sock, rule)
    notes.append("PPPoE compulsory firewall" if compulsory else "LAN forward allow")
    notes.append(f"forward allow {PPPOE_POOL_NETWORK} → WAN")

    return PPPOE_PROFILE_NAME, notes


def provision_mikrotik_pppoe_client(
    host: str,
    username: str,
    password: str,
    *,
    pppoe_username: str,
    pppoe_password: str,
    lan_interface: str = "bridgeLocal",
    wan_interface: str = "ether1",
    rate_limit: str = "",
    disabled: bool = False,
    compulsory: bool = False,
    port: int = 8728,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """
    Make a registered PPPoE client able to dial and surf:

    - PPPoE server on LAN
    - profile + IP pool
    - NAT to internet
    - PPP secret for this username/password
    """
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    pppoe_username = (pppoe_username or "").strip()
    pppoe_password = (pppoe_password or "").strip()
    rate_limit = (rate_limit or "").strip()

    if not host or not username:
        return {"ok": False, "error": "Router credentials are required."}
    if not pppoe_username:
        return {"ok": False, "error": "PPPoE username is required."}
    if not pppoe_password:
        return {"ok": False, "error": "PPPoE password is required."}
    if " " in pppoe_username:
        return {
            "ok": False,
            "error": "PPPoE username cannot contain spaces — use a single username string.",
        }

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            profile_name, notes = _ensure_pppoe_stack(
                sock,
                lan_interface=lan_interface,
                wan_interface=wan_interface,
                compulsory=compulsory,
            )

            # Strip accidental spaces — common cause of “confirm username and password”.
            pppoe_username = pppoe_username.strip()
            pppoe_password = pppoe_password.strip()

            secret_result = _upsert_ppp_secret_on_sock(
                sock,
                pppoe_username=pppoe_username,
                pppoe_password=pppoe_password,
                profile_name=profile_name,
                rate_limit=rate_limit,
                disabled=disabled,
            )
            if not secret_result.get("ok"):
                return {**secret_result, "notes": notes}

            saved_name = secret_result.get("pppoe_username") or pppoe_username
            lan = _resolve_pppoe_lan_interface(sock, lan_interface)
            return {
                "ok": True,
                "created": secret_result.get("created"),
                "updated": secret_result.get("updated"),
                "pppoe_username": saved_name,
                "profile": profile_name,
                "lan_interface": lan,
                "notes": notes,
                "message": (
                    f"PPPoE ready: secret “{saved_name}” is on the MikroTik "
                    f"(server on {lan}). Dial with this exact username and password."
                ),
            }
    except TimeoutError:
        return {
            "ok": False,
            "error": (
                "No response from remote server while provisioning PPPoE. "
                "Confirm this PC can reach the MikroTik on API port 8728, then try Sync again."
            ),
        }
    except OSError as exc:
        return {
            "ok": False,
            "error": (
                f"No response from remote server ({host}:8728). "
                "Check power, LAN cable, saved IP, and that RouterOS API is enabled."
            ),
            "detail": str(exc),
        }
    except ConnectionError as exc:
        return {"ok": False, "error": str(exc) or "Could not log in to the MikroTik."}
    except Exception as exc:
        msg = str(exc) or "Could not provision PPPoE on the MikroTik."
        low = msg.lower()
        if "no response" in low or "timed out" in low:
            return {
                "ok": False,
                "error": (
                    "No response from remote server. "
                    "Reconnect to the MikroTik API, then click Sync secrets again."
                ),
                "detail": msg,
            }
        return {"ok": False, "error": msg}


def upsert_mikrotik_pppoe_secret(
    host: str,
    username: str,
    password: str,
    *,
    pppoe_username: str,
    pppoe_password: str,
    profile: str = "",
    rate_limit: str = "",
    disabled: bool = False,
    lan_interface: str = "bridgeLocal",
    wan_interface: str = "ether1",
    compulsory: bool = False,
    port: int = 8728,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """Backward-compatible wrapper — provisions full PPPoE access + secret."""
    return provision_mikrotik_pppoe_client(
        host,
        username,
        password,
        pppoe_username=pppoe_username,
        pppoe_password=pppoe_password,
        lan_interface=lan_interface,
        wan_interface=wan_interface,
        rate_limit=rate_limit,
        disabled=disabled,
        compulsory=compulsory,
        port=port,
        timeout=timeout,
    )


def sync_pppoe_customers_on_router(router, customers) -> list[dict[str, Any]]:
    """
    Provision PPPoE once per router, then upsert all client secrets in one API session.
    """
    customers = [c for c in customers if c and (c.pppoe_username or "").strip()]
    if not router or not customers:
        return []

    if getattr(router, "account_status", "") == "suspended":
        return [
            {
                "ok": False,
                "customer_id": getattr(c, "pk", None),
                "customer_name": getattr(c, "full_name", ""),
                "error": "The assigned MikroTik account is suspended.",
            }
            for c in customers
        ]

    org = getattr(customers[0], "organization", None)
    compulsory = bool(getattr(org, "pppoe_compulsory", False))
    lan_interface = getattr(router, "lan_bridge", None) or "bridgeLocal"
    wan_interface = getattr(router, "wan_interface", None) or "ether1"
    host = (router.host or "").strip()
    api_user = (router.username or "").strip()
    api_password = router.password or ""

    results: list[dict[str, Any]] = []
    try:
        with _api_session(host, api_user, api_password, timeout=15.0) as sock:
            profile_name, notes = _ensure_pppoe_stack(
                sock,
                lan_interface=lan_interface,
                wan_interface=wan_interface,
                compulsory=compulsory,
            )
            lan = _resolve_pppoe_lan_interface(sock, lan_interface)

            for customer in customers:
                plan = getattr(customer, "plan", None)
                rate_limit = ""
                if plan is not None:
                    rate_limit = _pppoe_rate_limit(
                        getattr(plan, "download_speed_mbps", None),
                        getattr(plan, "upload_speed_mbps", None),
                    )
                disabled = getattr(customer, "status", "") != "active"
                secret_result = _upsert_ppp_secret_on_sock(
                    sock,
                    pppoe_username=customer.pppoe_username or "",
                    pppoe_password=customer.pppoe_password or "",
                    profile_name=profile_name,
                    rate_limit=rate_limit,
                    disabled=disabled,
                )
                payload = {
                    **secret_result,
                    "customer_id": customer.pk,
                    "customer_name": customer.full_name,
                    "router_id": router.pk,
                    "router_name": router.name,
                    "notes": notes,
                }
                if secret_result.get("ok"):
                    saved_name = secret_result.get("pppoe_username") or customer.pppoe_username
                    if saved_name and saved_name != (customer.pppoe_username or "").strip():
                        customer.pppoe_username = saved_name
                        customer.save(update_fields=["pppoe_username"])
                    payload["message"] = (
                        f"PPPoE ready: secret “{saved_name}” on {router.name} "
                        f"(server on {lan})."
                    )
                results.append(payload)
    except TimeoutError:
        err = (
            "No response from remote server while syncing PPPoE. "
            "Confirm API port 8728 is reachable, then sync again."
        )
        for customer in customers:
            results.append(
                {
                    "ok": False,
                    "customer_id": customer.pk,
                    "customer_name": customer.full_name,
                    "error": err,
                }
            )
    except OSError as exc:
        err = f"No response from remote server ({host}:8728). Check API access."
        for customer in customers:
            results.append(
                {
                    "ok": False,
                    "customer_id": customer.pk,
                    "customer_name": customer.full_name,
                    "error": err,
                    "detail": str(exc),
                }
            )
    except ConnectionError as exc:
        err = str(exc) or "Could not log in to the MikroTik."
        for customer in customers:
            results.append(
                {
                    "ok": False,
                    "customer_id": customer.pk,
                    "customer_name": customer.full_name,
                    "error": err,
                }
            )
    except Exception as exc:
        err = str(exc) or "Could not provision PPPoE on the MikroTik."
        for customer in customers:
            results.append(
                {
                    "ok": False,
                    "customer_id": customer.pk,
                    "customer_name": customer.full_name,
                    "error": err,
                }
            )
    return results


def sync_customer_pppoe_to_router(customer) -> dict[str, Any]:
    """Push one customer's PPPoE access onto their assigned MikroTik."""
    router = getattr(customer, "router", None)
    if not router:
        return {
            "ok": False,
            "error": "Assign a MikroTik router to this client before syncing PPPoE credentials.",
            "missing_router": True,
        }
    batch = sync_pppoe_customers_on_router(router, [customer])
    if not batch:
        return {"ok": False, "error": "Could not sync PPPoE credentials."}
    result = batch[0]
    if result.get("ok"):
        result["router_id"] = router.pk
        result["router_name"] = router.name
        result["customer_id"] = getattr(customer, "pk", None)
    return result


def disconnect_pppoe_active_session(
    host: str,
    username: str,
    password: str,
    *,
    pppoe_username: str,
    port: int = 8728,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Remove matching /ppp/active sessions so a disable takes effect immediately."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    pppoe_username = (pppoe_username or "").strip()
    if not host:
        return {"ok": False, "removed": 0, "error": "No router host configured."}
    if not pppoe_username:
        return {"ok": False, "removed": 0, "error": "No PPPoE username on this client."}

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            rows = _print(sock, "/ppp/active", props=".id,name")
            removed = 0
            target = pppoe_username.lower()
            for row in rows:
                name = (row.get("name") or "").strip()
                item_id = (row.get(".id") or "").strip()
                if not item_id or name.lower() != target:
                    continue
                terminal = _remove(sock, "/ppp/active", item_id)
                if _command_succeeded(terminal):
                    removed += 1
            return {
                "ok": True,
                "removed": removed,
                "error": "",
                "message": (
                    f"Disconnected {removed} active session{'s' if removed != 1 else ''}."
                    if removed
                    else "No active PPPoE session to disconnect."
                ),
            }
    except TimeoutError:
        return {
            "ok": False,
            "removed": 0,
            "error": "Connection timed out reaching the router.",
        }
    except OSError as exc:
        return {
            "ok": False,
            "removed": 0,
            "error": f"Could not reach {host}:8728.",
            "detail": str(exc),
        }
    except Exception as exc:
        return {
            "ok": False,
            "removed": 0,
            "error": str(exc) or "Could not disconnect the PPPoE session.",
        }


def test_mikrotik_api_login(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 8728,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Attempt RouterOS API login. Returns identity/board plus current wifi settings when readable."""
    host = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not host:
        return {"ok": False, "error": "Enter a MikroTik IP address."}
    if not username:
        return {"ok": False, "error": "Enter the router username."}

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            login_error = _api_login(sock, username, password)
            if login_error:
                return login_error
            result = _fetch_identity(sock, host)
            # Read Wi‑Fi on a dedicated session; keep this short so Connect
            # stays responsive even when wireless packages are slow/unavailable.
            wifi = read_mikrotik_wifi(
                host, username, password, port=port, timeout=min(timeout, 3.0)
            )
            result["wifi_ssid"] = wifi.get("wifi_ssid") or ""
            result["wifi_password"] = wifi.get("wifi_password") or ""
            result["wifi_mode"] = wifi.get("wifi_mode") or ""
            result["wifi_enabled"] = bool(wifi.get("wifi_enabled"))
            return result
    except TimeoutError:
        return {"ok": False, "error": "Connection timed out. Is the router reachable on API port 8728?"}
    except OSError as exc:
        return {
            "ok": False,
            "error": f"Could not reach {host}:8728. Enable RouterOS API or check the IP.",
            "detail": str(exc),
        }
    except Exception as exc:
        return {"ok": False, "error": f"Connection failed: {exc}"}


def resolve_mikrotik_api_login(
    host: str,
    username: str,
    password: str,
    *,
    candidate_hosts: list[str] | None = None,
    discover: bool = True,
    port: int = 8728,
    timeout: float = 4.0,
) -> dict[str, Any]:
    """Login using the preferred IP, then auto-try discovered MikroTik IPs until one works.

    Always returns the working ``host`` so the UI/database can store the right address.
    """
    preferred = (host or "").strip()
    username = (username or "").strip()
    password = password or ""
    if not username:
        return {"ok": False, "error": "Enter the router username."}

    discovered: list[dict] = []
    if discover:
        try:
            from core.mikrotik_discovery import discover_mikrotik_devices, rank_mikrotik_hosts

            discovered = discover_mikrotik_devices(timeout=2.0, full_scan=False)
            hosts = rank_mikrotik_hosts(
                preferred,
                discovered=discovered,
                extra_hosts=candidate_hosts or [],
                limit=12,
            )
        except Exception:
            from core.mikrotik_discovery import rank_mikrotik_hosts

            hosts = rank_mikrotik_hosts(
                preferred,
                discovered=[],
                extra_hosts=candidate_hosts or [],
                limit=12,
            )
    else:
        from core.mikrotik_discovery import rank_mikrotik_hosts

        hosts = rank_mikrotik_hosts(
            preferred,
            discovered=[],
            extra_hosts=candidate_hosts or [],
            limit=12,
        )

    if not hosts:
        return {
            "ok": False,
            "error": "No MikroTik IP to try. Select a found router or type its LAN IP.",
        }

    last_error = "Could not log in on any candidate MikroTik IP."
    auth_failures = 0
    reach_failures = 0
    discovered_hosts = [
        (d.get("host") or "").strip()
        for d in discovered
        if (d.get("host") or "").strip()
    ]
    pending_boards = [
        ((d.get("board") or d.get("identity") or "MikroTik").strip())
        for d in discovered
        if (d.get("source") or "") == "mndp-pending" or d.get("needs_api")
    ]

    for candidate in hosts:
        # Prefer a short reachability check before a full login timeout.
        attempt_timeout = timeout
        if candidate != preferred:
            attempt_timeout = min(timeout, 3.0)

        result = test_mikrotik_api_login(
            candidate,
            username,
            password,
            port=port,
            timeout=attempt_timeout,
        )
        if result.get("ok"):
            working = (result.get("host") or candidate).strip()
            result["host"] = working
            result["host_changed"] = bool(preferred and working.lower() != preferred.lower())
            result["resolved_from"] = preferred or ""
            result["tried_hosts"] = hosts
            if result["host_changed"]:
                result["message"] = (
                    f"Connected using {working} "
                    f"(preferred IP {preferred} was unreachable or rejected login)."
                )
            return result

        error = (result.get("error") or "").strip() or "Login failed."
        last_error = f"{candidate}: {error}"
        low = error.lower()
        if any(
            token in low
            for token in (
                "invalid user",
                "password",
                "cannot log in",
                "login failed",
                "authentication",
                "bad name",
                "wrong user",
            )
        ):
            auth_failures += 1
        else:
            reach_failures += 1

    if pending_boards and reach_failures and not auth_failures:
        board = pending_boards[0]
        guess = discovered_hosts[0] if discovered_hosts else ""
        where = f" (likely {guess})" if guess else ""
        return {
            "ok": False,
            "error": (
                f"Found {board}{where} on the network, but RouterOS API port 8728 is closed. "
                "Open Winbox -> Neighbors -> connect by MAC, then enable API: "
                "IP -> Services -> api (and allow your LAN). After that, click Connect again."
            ),
            "needs_api": True,
            "tried_hosts": hosts,
            "discovered_hosts": discovered_hosts,
        }

    if discovered_hosts and reach_failures and not auth_failures:
        shown = ", ".join(discovered_hosts[:3])
        return {
            "ok": False,
            "error": (
                f"Found MikroTik at {shown}, but API port 8728 is closed or blocked. "
                "In Winbox (Neighbors -> connect by MAC if needed): "
                "IP -> Services -> enable api, then try Connect again."
            ),
            "tried_hosts": hosts,
            "discovered_hosts": discovered_hosts,
        }

    if auth_failures and not reach_failures:
        return {
            "ok": False,
            "error": (
                "Username or password was rejected on every reachable MikroTik. "
                "Use the same Winbox login, then try again."
            ),
            "auth_error": True,
            "tried_hosts": hosts,
        }

    return {
        "ok": False,
        "error": (
            "No reachable MikroTik API found on this LAN. "
            "Plug this PC into a MikroTik LAN port, enable API "
            "(IP -> Services -> api), then pick the router from the live scan."
        ),
        "tried_hosts": hosts,
    }

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
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
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
                with _api_session(host, username, password, port=port, timeout=timeout) as sock:
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
        return {"ok": False, "error": "Missing router credentials.", "ports": []}

    try:
        with _api_session(host, username, password, port=port, timeout=timeout) as sock:
            rows = _print(
                sock,
                "/interface",
                props=".id,name,type,running,disabled,comment",
            )
            ports: list[dict[str, Any]] = []
            for row in rows:
                if not _is_manageable_port(row):
                    continue
                name = (row.get("name") or "").strip()
                iface_type = (row.get("type") or "").strip() or "ether"
                disabled = _flag_yes(row.get("disabled"))
                running = _flag_yes(row.get("running"))
                ports.append(
                    {
                        "id": (row.get(".id") or "").strip(),
                        "name": name,
                        "type": iface_type,
                        "disabled": disabled,
                        "running": running and not disabled,
                        "comment": (row.get("comment") or "").strip(),
                    }
                )

            def _sort_key(item: dict[str, Any]) -> tuple:
                n = item["name"].lower()
                # ether1 before ether10
                prefix = "".join(ch for ch in n if not ch.isdigit())
                digits = "".join(ch for ch in n if ch.isdigit())
                return (prefix, int(digits) if digits else 0, n)

            ports.sort(key=_sort_key)
            return {"ok": True, "ports": ports, "host": host}
    except TimeoutError:
        return {
            "ok": False,
            "error": "Connection timed out. Is the router reachable on API port 8728?",
            "ports": [],
        }
    except ConnectionError as exc:
        return {
            "ok": False,
            "error": str(exc) or "Login failed. Check the saved username and password.",
            "ports": [],
        }
    except OSError as exc:
        return {
            "ok": False,
            "error": f"Could not reach {host}:8728. ({exc})",
            "ports": [],
        }


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
    """Remove ispcentric-uplink bond / DHCP / route / list-member leftovers."""
    return {
        "bonding": _remove_comment_tagged(sock, "/interface/bonding", UPLINK_TAG),
        "dhcp_client": _remove_comment_tagged(sock, "/ip/dhcp-client", UPLINK_TAG),
        "routes": _remove_comment_tagged(sock, "/ip/route", UPLINK_TAG),
        "list_members": _remove_comment_tagged(sock, "/interface/list/member", UPLINK_TAG),
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


def _ensure_failover_dhcp_client(
    sock: socket.socket,
    interface: str,
    *,
    distance: int,
) -> dict[str, str]:
    """Ensure a DHCP client that installs a default route at the given distance.

    Existing (non-ISPCENTRIC) clients are reused and distance is updated without
    retagging them — so Clear will not delete the original WAN DHCP client.
    Only newly created clients are tagged with UPLINK_TAG.
    """
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
            "add-default-route": "yes",
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
            "add-default-route": "yes",
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

    Creates /interface/bonding, slaves the selected ports, DHCP on the bond,
    and adds the bond to the WAN interface list.
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
            slaves = ",".join(members)
            terminal = _add(
                sock,
                "/interface/bonding",
                name=bond_name,
                mode=bond_mode,
                slaves=slaves,
                comment=UPLINK_TAG,
            )
            if terminal.get("_reply") in {"!trap", "!fatal"}:
                # LACP often fails without switch support — fall back to balance-xor.
                if bond_mode == "802.3ad":
                    bond_mode = "balance-xor"
                    terminal = _add(
                        sock,
                        "/interface/bonding",
                        name=bond_name,
                        mode=bond_mode,
                        slaves=slaves,
                        comment=UPLINK_TAG,
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

            return {
                "ok": True,
                "mode": "bond",
                "bond_name": bond_name,
                "bond_mode": bond_mode,
                "members": members,
                "wan_interface": bond_name,
                "unbridged": unbridged,
                "message": (
                    f"Bonded {', '.join(members)} as {bond_name} "
                    f"({bond_mode}) for the same provider."
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

    Uses DHCP default-route-distance so traffic prefers the primary and fails
    over when that link drops.
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

            for index, iface in enumerate(ordered):
                distance = 1 + (index * 10)
                terminal = _ensure_failover_dhcp_client(
                    sock, iface, distance=distance
                )
                if terminal.get("_reply") in {"!trap", "!fatal"}:
                    if unbridged:
                        _restore_bridged_interfaces(sock, unbridged)
                    return {
                        "ok": False,
                        "error": _trap_message(
                            terminal,
                            f"Could not configure DHCP failover on {iface}.",
                        ),
                    }
                _ensure_uplink_list_member(sock, iface)

            # Best-effort: ping-check any default routes we just tagged via DHCP comment.
            # RouterOS often creates dynamic DHCP routes; set check-gateway where possible.
            for row in _print(
                sock,
                "/ip/route",
                props=".id,dst-address,gateway,distance,dynamic,comment,active",
            ):
                dst = (row.get("dst-address") or "").strip()
                if dst not in {"0.0.0.0/0", "::/0"}:
                    continue
                item_id = (row.get(".id") or "").strip()
                if not item_id:
                    continue
                if _flag_yes(row.get("dynamic")):
                    continue
                _set(sock, "/ip/route", item_id, **{"check-gateway": "ping"})

            return {
                "ok": True,
                "mode": "failover",
                "primary": primary_port,
                "backups": backups,
                "ports": ordered,
                "wan_interface": primary_port,
                "unbridged": unbridged,
                "message": (
                    f"Failover ready: primary {primary_port}, "
                    f"backup {', '.join(backups)}."
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
                "message": "Bonded / failover uplink settings cleared on the MikroTik.",
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
                props=".id,name,mode,slaves,running,disabled,comment",
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
                    }
                )

            failover_clients: list[dict[str, Any]] = []
            for row in _print(
                sock,
                "/ip/dhcp-client",
                props=".id,interface,status,default-route-distance,disabled,comment",
            ):
                if UPLINK_TAG not in (row.get("comment") or ""):
                    continue
                failover_clients.append(
                    {
                        "interface": (row.get("interface") or "").strip(),
                        "status": (row.get("status") or "").strip(),
                        "distance": (row.get("default-route-distance") or "").strip() or "1",
                        "disabled": _flag_yes(row.get("disabled")),
                    }
                )
            failover_clients.sort(
                key=lambda item: int(item["distance"]) if str(item["distance"]).isdigit() else 99
            )

            mode = "single"
            if bonds:
                mode = "bond"
            elif len(failover_clients) >= 2:
                mode = "failover"

            return {
                "ok": True,
                "mode": mode,
                "bonds": bonds,
                "failover_clients": failover_clients,
            }
    except Exception as exc:
        return {"ok": False, "error": str(exc) or "Could not read uplink state."}
