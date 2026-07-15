"""Discover live MikroTik routers on the local network (MNDP + verified LAN probe)."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MNDP_PORT = 5678
MNDP_TLV_MAC = 1
MNDP_TLV_IDENTITY = 5
MNDP_TLV_VERSION = 7
MNDP_TLV_PLATFORM = 8
MNDP_TLV_BOARD = 12
MNDP_TLV_INTERFACE = 16
MNDP_TLV_IPV4 = 17
DEFAULT_GATEWAY_CANDIDATES = ("192.168.88.1",)
BOARD_MODEL_HINTS = [
    # Longer / more specific needles first.
    ("hap ax3", "hap_ax3"),
    ("hap ax²", "hap_ax2"),
    ("hap ax2", "hap_ax2"),
    ("hap ac³", "hap_ac3"),
    ("hap ac3", "hap_ac3"),
    ("hap ac²", "hap_ac2"),
    ("hap ac2", "hap_ac2"),
    ("hap lite", "hap_lite"),
    ("rb951ui", "rb951"),
    ("rb951g", "rb951"),
    ("rb951", "rb951"),
    ("951ui", "rb951"),
    ("l009ui", "l009"),
    ("l009", "l009"),
    ("rb2011", "rb2011"),
    ("rb3011", "rb3011"),
    ("rb4011", "rb4011"),
    ("rb5009", "rb5009"),
    ("rb750gr3", "rb750gr3"),
    ("rb760igs", "rb760igs"),
    ("hex s", "rb760igs"),
    ("hex", "rb750gr3"),
    ("rb760", "rb760igs"),
    ("ccr2216", "ccr2216"),
    ("ccr2116", "ccr2116"),
    ("ccr2004", "ccr2004"),
    ("audience", "audience"),
    ("chr", "chr"),
]


def _guess_model(board: str) -> str:
    text = (board or "").lower().replace("_", " ").replace("-", "")
    compact = text.replace(" ", "")
    for needle, model in BOARD_MODEL_HINTS:
        needle_compact = needle.lower().replace(" ", "").replace("-", "")
        if needle in text or needle_compact in compact:
            return model
    return "other"


def guess_model(board: str) -> str:
    """Public alias for board-name → onboard model value."""
    return _guess_model(board)


def _device(
    host: str,
    *,
    name: str = "",
    identity: str = "",
    board: str = "",
    version: str = "",
    platform: str = "MikroTik",
    mac: str = "",
    model: str = "other",
    source: str = "",
) -> dict:
    host = (host or "").strip()
    return {
        "host": host,
        "name": name or identity or f"MikroTik {host}",
        "identity": identity or "",
        "board": board or "",
        "version": version or "",
        "platform": platform or "MikroTik",
        "mac": (mac or "").upper(),
        "model": model or _guess_model(board),
        "source": source or "",
        "alive": True,
    }


def _parse_mndp_packet(data: bytes, source_ip: str) -> dict | None:
    if len(data) < 8:
        return None

    offset = 4
    fields: dict[int, bytes] = {}
    while offset + 4 <= len(data):
        tlv_type, tlv_len = struct.unpack_from("!HH", data, offset)
        offset += 4
        if tlv_len < 0 or offset + tlv_len > len(data):
            break
        fields[tlv_type] = data[offset : offset + tlv_len]
        offset += tlv_len

    identity = fields.get(MNDP_TLV_IDENTITY, b"").decode("utf-8", errors="ignore").strip()
    platform = fields.get(MNDP_TLV_PLATFORM, b"").decode("utf-8", errors="ignore").strip()
    board = fields.get(MNDP_TLV_BOARD, b"").decode("utf-8", errors="ignore").strip()
    version = fields.get(MNDP_TLV_VERSION, b"").decode("utf-8", errors="ignore").strip()
    mac_raw = fields.get(MNDP_TLV_MAC, b"")
    mac = ":".join(f"{b:02X}" for b in mac_raw) if len(mac_raw) == 6 else ""

    # Prefer IPv4 advertised inside MNDP (type 17). UDP source can be 0.0.0.0 on Windows.
    advertised_ip = ""
    ipv4_raw = fields.get(MNDP_TLV_IPV4, b"")
    if len(ipv4_raw) == 4:
        advertised_ip = ".".join(str(b) for b in ipv4_raw)

    host = ""
    for candidate in (advertised_ip, source_ip):
        value = (candidate or "").strip()
        if value and _is_private_ipv4(value):
            host = value
            break

    if not host:
        return None
    if not identity and not board and not platform:
        return None
    if platform and "mikrotik" not in platform.lower() and not board and not identity:
        return None

    return _device(
        host,
        name=identity or f"MikroTik {host}",
        identity=identity,
        board=board,
        version=version,
        platform=platform or "MikroTik",
        mac=mac,
        model=_guess_model(board),
        source="mndp",
    )


def discover_mndp(timeout: float = 3.0) -> list[dict]:
    """Broadcast an MNDP refresh and collect RouterOS replies on UDP/5678."""
    found: dict[str, dict] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        primary = _primary_ipv4()
        bound = False
        # Binding to the LAN IP avoids Windows reporting 0.0.0.0 as the sender.
        for bind_host in ((primary, MNDP_PORT) if primary else None, ("", MNDP_PORT), ("", 0)):
            if bind_host is None:
                continue
            try:
                sock.bind(bind_host)
                bound = True
                break
            except OSError:
                continue
        if not bound:
            return []

        sock.settimeout(0.25)
        probe = b"\x00\x00\x00\x00"
        targets = [("255.255.255.255", MNDP_PORT)]
        if primary:
            try:
                network = ipaddress.IPv4Network(f"{primary}/24", strict=False)
                targets.append((str(network.broadcast_address), MNDP_PORT))
            except ValueError:
                pass
        for _ in range(3):
            for target in targets:
                try:
                    sock.sendto(probe, target)
                except OSError:
                    continue
            time.sleep(0.05)

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            parsed = _parse_mndp_packet(data, addr[0])
            if not parsed:
                # MikroTik fingerprint without a usable IP still means one is online —
                # keep a pending marker so callers can force a LAN probe.
                pending = _parse_mndp_fingerprint(data)
                if pending:
                    found.setdefault("__pending__", pending)
                continue
            found[parsed["host"]] = parsed
    finally:
        sock.close()

    pending = found.pop("__pending__", None)
    devices = list(found.values())
    if pending and not devices:
        devices.append(pending)
    return devices


def _parse_mndp_fingerprint(data: bytes) -> dict | None:
    """Return a host-less MikroTik marker when MNDP has identity/board but no IP yet."""
    if len(data) < 8:
        return None
    offset = 4
    fields: dict[int, bytes] = {}
    while offset + 4 <= len(data):
        tlv_type, tlv_len = struct.unpack_from("!HH", data, offset)
        offset += 4
        if tlv_len < 0 or offset + tlv_len > len(data):
            break
        fields[tlv_type] = data[offset : offset + tlv_len]
        offset += tlv_len

    identity = fields.get(MNDP_TLV_IDENTITY, b"").decode("utf-8", errors="ignore").strip()
    platform = fields.get(MNDP_TLV_PLATFORM, b"").decode("utf-8", errors="ignore").strip()
    board = fields.get(MNDP_TLV_BOARD, b"").decode("utf-8", errors="ignore").strip()
    version = fields.get(MNDP_TLV_VERSION, b"").decode("utf-8", errors="ignore").strip()
    mac_raw = fields.get(MNDP_TLV_MAC, b"")
    mac = ":".join(f"{b:02X}" for b in mac_raw) if len(mac_raw) == 6 else ""
    if not identity and not board and not (platform and "mikrotik" in platform.lower()):
        return None
    return {
        "host": "",
        "name": identity or "MikroTik (IP pending)",
        "identity": identity,
        "board": board,
        "version": version,
        "platform": platform or "MikroTik",
        "mac": mac,
        "model": _guess_model(board),
        "source": "mndp-pending",
        "alive": True,
    }


def _arp_ipv4_neighbors() -> list[str]:
    """Live IPv4 neighbors from the OS ARP table (helps when MNDP IP is missing)."""
    hosts: list[str] = []
    seen: set[str] = set()
    try:
        out = subprocess.check_output(
            ["arp", "-a"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2.5,
            errors="ignore",
        )
    except (OSError, subprocess.SubprocessError):
        return []

    for match in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", out):
        ip = match.group(1)
        if not _is_private_ipv4(ip):
            continue
        if ip in seen:
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts[:80]

def _is_private_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if addr.is_unspecified or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return False
    return bool(addr.is_private)


def _primary_ipv4() -> str | None:
    """Best guess for this PC's LAN address (works when hostname lookup fails)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
        if _is_private_ipv4(ip):
            return ip
    except OSError:
        pass
    return None


def _default_gateway_ipv4() -> str | None:
    """Read the IPv4 default gateway from the OS routing table when possible."""
    try:
        out = subprocess.check_output(
            ["route", "print", "-4"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2.5,
            errors="ignore",
        )
    except (OSError, subprocess.SubprocessError):
        out = ""

    if out:
        in_active = False
        for line in out.splitlines():
            low = line.lower().strip()
            if "active routes" in low:
                in_active = True
                continue
            if "persistent routes" in low:
                break
            if not in_active:
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gateway = parts[2]
                if _is_private_ipv4(gateway):
                    return gateway

    try:
        out = subprocess.check_output(
            ["ipconfig"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2.5,
            errors="ignore",
        )
    except (OSError, subprocess.SubprocessError):
        out = ""

    for line in out.splitlines():
        if "default gateway" not in line.lower():
            continue
        match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        if match and _is_private_ipv4(match.group(1)):
            return match.group(1)

    # Last resort: assume .1 on the PC's /24.
    primary = _primary_ipv4()
    if primary:
        try:
            network = ipaddress.IPv4Network(f"{primary}/24", strict=False)
            guess = str(network.network_address + 1)
            if _is_private_ipv4(guess):
                return guess
        except ValueError:
            pass
    return None


def _local_private_subnets() -> list[ipaddress.IPv4Network]:
    """Only real private LAN interfaces — never WAN / public ranges."""
    nets: list[ipaddress.IPv4Network] = []
    seen: set[str] = set()

    def add_ip(ip: str) -> None:
        if not _is_private_ipv4(ip):
            return
        try:
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        except ValueError:
            return
        key = str(network)
        if key in seen:
            return
        seen.add(key)
        nets.append(network)

    primary = _primary_ipv4()
    if primary:
        add_ip(primary)

    gateway = _default_gateway_ipv4()
    if gateway:
        add_ip(gateway)

    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            add_ip(info[4][0])
    except OSError:
        pass

    # Prefer the subnet we are actually on.
    if primary:
        nets.sort(key=lambda net: 0 if ipaddress.IPv4Address(primary) in net else 1)

    return nets[:3]


def _local_ipv4_candidates(limit: int = 260, *, quick: bool = False) -> list[str]:
    """Build IPv4 candidates on private LAN subnets only.

    quick=True probes gateways / common MikroTik defaults only (no full /24).
    """
    hosts: list[str] = []
    seen: set[str] = set()

    def add(ip: str) -> None:
        if not _is_private_ipv4(ip):
            return
        if ip not in seen:
            seen.add(ip)
            hosts.append(ip)

    gateway = _default_gateway_ipv4()
    if gateway:
        add(gateway)

    # Classic MikroTik defaults (single hosts, not whole foreign /24s)
    for ip in ("192.168.88.1", "192.168.0.1", "192.168.1.1"):
        add(ip)

    for network in _local_private_subnets():
        base = int(network.network_address)
        for offset in (1, 2, 3, 10, 20, 50, 88, 100, 200, 254):
            add(str(ipaddress.IPv4Address(base + offset)))
        if quick:
            continue
        for host in network.hosts():
            add(str(host))
            if len(hosts) >= limit:
                return hosts[:limit]
    return hosts[:limit]


def _probe_port(host: str, port: int, timeout: float = 0.18) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_http_mikrotik(host: str, timeout: float = 0.45) -> dict | None:
    """Accept only strong RouterOS / WebFig fingerprints."""
    for port in (80, 8080):
        url = f"http://{host}:{port}/"
        req = Request(url, headers={"User-Agent": "ISPCENTRIC-MikroTik-Discovery/1.0"})
        try:
            with urlopen(req, timeout=timeout) as resp:
                body = resp.read(4096).decode("utf-8", errors="ignore").lower()
                server = (resp.headers.get("Server") or "").lower()
                strong = (
                    "mikrotik" in server
                    or "routeros" in server
                    or "mikrotik" in body
                    or "routeros" in body
                    or "webfig" in body
                )
                if not strong:
                    continue
                return _device(host, source="http")
        except (HTTPError, URLError, TimeoutError, OSError):
            continue
    return None


def discover_http_and_api(
    hosts: Iterable[str] | None = None,
    max_workers: int = 64,
    *,
    quick: bool = False,
) -> list[dict]:
    """Find MikroTik hosts. Port-open alone is not enough — require HTTP/MNDP proof later."""
    targets = list(hosts or _local_ipv4_candidates(quick=quick))
    found: dict[str, dict] = {}
    workers = min(max_workers, max(1, len(targets)))

    def check(host: str) -> dict | None:
        api_open = _probe_port(host, 8728)
        winbox_open = _probe_port(host, 8291)
        http_hit = _probe_http_mikrotik(host)

        if http_hit:
            if api_open:
                http_hit["source"] = "api+http"
            elif winbox_open:
                http_hit["source"] = "winbox+http"
            return http_hit

        # API/Winbox open without HTTP proof: still keep as a candidate so we can
        # try login with credentials (user may have typed a stale/wrong IP).
        if api_open:
            return _device(host, source="api")
        if winbox_open:
            return _device(host, source="winbox")
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check, host): host for host in targets}
        for fut in as_completed(futures):
            try:
                item = fut.result()
            except Exception:
                continue
            if item and item.get("host"):
                found[item["host"]] = item
    return list(found.values())


def _merge_devices(*groups: list[dict]) -> list[dict]:
    """Merge discoveries into one row per host IP (and collapse same MAC)."""
    by_host: dict[str, dict] = {}
    source_rank = {
        "mndp": 4,
        "api+http": 3,
        "winbox+http": 3,
        "http": 2,
        "api": 1,
        "winbox": 1,
    }

    def prefer(existing: dict, incoming: dict) -> dict:
        new_rank = source_rank.get(incoming.get("source") or "", 0)
        old_rank = source_rank.get(existing.get("source") or "", 0)
        if new_rank >= old_rank:
            merged = {**existing, **{k: v for k, v in incoming.items() if v not in ("", None, False)}}
            # Keep richer identity fields
            for key in ("identity", "board", "version", "mac", "name", "model"):
                if existing.get(key) and not merged.get(key):
                    merged[key] = existing[key]
            return merged
        for key in ("identity", "board", "version", "mac", "name", "model"):
            if incoming.get(key) and not existing.get(key):
                existing[key] = incoming[key]
        return existing

    for group in groups:
        for item in group:
            host = (item.get("host") or "").strip()
            if not host:
                continue
            host_key = host.lower()
            if host_key in by_host:
                by_host[host_key] = prefer(by_host[host_key], item)
            else:
                by_host[host_key] = dict(item)

    # Collapse duplicates that share the same MAC but different host keys (rare)
    by_mac: dict[str, str] = {}
    drop: set[str] = set()
    for host_key, item in by_host.items():
        mac = (item.get("mac") or "").strip().upper()
        if not mac:
            continue
        if mac in by_mac:
            keep = by_mac[mac]
            by_host[keep] = prefer(by_host[keep], item)
            drop.add(host_key)
        else:
            by_mac[mac] = host_key

    for host_key in drop:
        by_host.pop(host_key, None)

    return sorted(by_host.values(), key=lambda d: (d.get("name") or "", d.get("host") or ""))


def discover_mikrotik_devices(timeout: float = 3.0, *, full_scan: bool = False) -> list[dict]:
    """Discover currently connected MikroTik devices (deduped, verified).

    full_scan=False (default): MNDP + gateway/common-host probe only — fast enough for polling.
    full_scan=True: also walks local /24s (slower; use on explicit Refresh).
    """
    mndp_result: list[dict] = []
    scan_result: list[dict] = []
    mndp_timeout = min(timeout, 2.0) if not full_scan else timeout
    scan_join = (timeout + 0.8) if not full_scan else (timeout + 3.0)

    def run_mndp():
        nonlocal mndp_result
        mndp_result = discover_mndp(timeout=mndp_timeout)

    def run_scan(hosts: list[str] | None = None, *, quick: bool = True):
        nonlocal scan_result
        scan_result = discover_http_and_api(
            hosts=hosts,
            max_workers=32 if full_scan else 16,
            quick=quick,
        )

    t1 = threading.Thread(target=run_mndp, daemon=True)
    t1.start()
    t1.join(mndp_timeout + 1.0)

    pending = [d for d in mndp_result if not (d.get("host") or "").strip()]
    resolved_mndp = [d for d in mndp_result if (d.get("host") or "").strip()]

    # Always probe ARP neighbors + LAN candidates. If MNDP lacked an IP, expand scan.
    force_deep = bool(pending) or full_scan
    probe_hosts = _local_ipv4_candidates(quick=not force_deep)
    for ip in _arp_ipv4_neighbors():
        if ip not in probe_hosts:
            probe_hosts.append(ip)
    for device in resolved_mndp:
        host = (device.get("host") or "").strip()
        if host and host not in probe_hosts:
            probe_hosts.insert(0, host)

    t2 = threading.Thread(
        target=run_scan,
        kwargs={"hosts": probe_hosts, "quick": not force_deep},
        daemon=True,
    )
    t2.start()
    t2.join(scan_join)

    merged = _merge_devices(resolved_mndp, scan_result)

    # If MNDP found live neighbors, drop weak API-only guesses that weren't also HTTP-confirmed
    # and aren't already in the MNDP set — avoids phantom duplicates on the LAN.
    mndp_hosts = {(d.get("host") or "").lower() for d in resolved_mndp if d.get("host")}
    if mndp_hosts:
        cleaned = []
        for item in merged:
            host = (item.get("host") or "").lower()
            source = item.get("source") or ""
            if host in mndp_hosts:
                cleaned.append(item)
                continue
            if source in {"api+http", "winbox+http", "http", "mndp"}:
                cleaned.append(item)
        merged = cleaned

    # Final hard dedupe by host
    unique: dict[str, dict] = {}
    for item in merged:
        host = (item.get("host") or "").strip().lower()
        if host:
            unique[host] = item
    devices = sorted(unique.values(), key=lambda d: (d.get("name") or "", d.get("host") or ""))

    # Neighbor seen (MNDP) but no management IP/API yet — keep a marker for the UI.
    if pending and not devices:
        marker = dict(pending[0])
        marker["needs_api"] = True
        marker["alive"] = True
        marker["model"] = _guess_model(marker.get("board") or marker.get("identity") or "")
        # Best-effort guess: first private ARP neighbor that isn't this PC/gateway.
        gateway = _default_gateway_ipv4() or ""
        primary = _primary_ipv4() or ""
        for ip in _arp_ipv4_neighbors():
            if ip in {gateway, primary} or ip.endswith(".255"):
                continue
            marker["host"] = ip
            marker["host_guess"] = True
            break
        devices.append(marker)
    return devices

def annotate_onboarded(devices: list[dict], onboarded_hosts: Iterable[str]) -> list[dict]:
    """Mark each live device as onboarded or new."""
    known = {(h or "").strip().lower() for h in onboarded_hosts if h}
    out = []
    for device in devices:
        host = (device.get("host") or "").strip()
        if not host:
            continue
        item = dict(device)
        item["onboarded"] = host.lower() in known
        item["alive"] = True
        out.append(item)
    out.sort(key=lambda d: (bool(d.get("onboarded")), d.get("name") or "", d.get("host") or ""))
    return out


def rank_mikrotik_hosts(
    preferred_host: str = "",
    *,
    discovered: Iterable[dict] | None = None,
    extra_hosts: Iterable[str] | None = None,
    limit: int = 12,
) -> list[str]:
    """Ordered unique IP list: preferred → discovered MikroTiks → LAN defaults."""
    hosts: list[str] = []
    seen: set[str] = set()
    local_nets = _local_private_subnets()

    def on_local_lan(ip: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return False
        return any(addr in net for net in local_nets)

    def add(ip: str) -> None:
        value = (ip or "").strip()
        if not value or not _is_private_ipv4(value):
            return
        key = value.lower()
        if key in seen:
            return
        seen.add(key)
        hosts.append(value)

    preferred = (preferred_host or "").strip()
    if preferred:
        add(preferred)

    ranked_discovered = sorted(
        list(discovered or []),
        key=lambda d: (
            0 if (d.get("source") or "") == "mndp" else 1,
            0 if on_local_lan((d.get("host") or "").strip()) else 1,
            0 if (d.get("source") or "") in {"api+http", "winbox+http", "http", "api"} else 1,
            d.get("host") or "",
        ),
    )
    for device in ranked_discovered:
        add(device.get("host") or "")

    for host in extra_hosts or []:
        add(host)

    # Only try LAN-relevant defaults — never spray unrelated nets like 10.0.0.1
    # when this PC is clearly on 192.168.1.x.
    gateway = _default_gateway_ipv4()
    if gateway:
        add(gateway)
    add("192.168.88.1")
    for network in local_nets:
        base = int(network.network_address)
        for offset in (1, 88, 254):
            add(str(ipaddress.IPv4Address(base + offset)))

    return hosts[:limit]


def filter_not_onboarded(devices: list[dict], onboarded_hosts: Iterable[str]) -> list[dict]:
    """Return only devices that are not yet onboarded."""
    return [d for d in annotate_onboarded(devices, onboarded_hosts) if not d.get("onboarded")]


def devices_to_json(devices: list[dict]) -> str:
    return json.dumps(devices)
