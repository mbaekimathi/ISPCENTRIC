"""Discover live MikroTik routers on the local network (MNDP + verified LAN probe)."""

from __future__ import annotations

import ipaddress
import json
import socket
import struct
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

BOARD_MODEL_HINTS = [
    ("hap ax3", "hap_ax3"),
    ("hap ax2", "hap_ax2"),
    ("hap ac3", "hap_ac3"),
    ("hap ac2", "hap_ac2"),
    ("hap lite", "hap_lite"),
    ("l009", "l009"),
    ("rb2011", "rb2011"),
    ("rb3011", "rb3011"),
    ("rb750gr3", "rb750gr3"),
    ("hex s", "rb760igs"),
    ("hex", "rb750gr3"),
    ("rb760", "rb760igs"),
    ("rb4011", "rb4011"),
    ("rb5009", "rb5009"),
    ("ccr2004", "ccr2004"),
    ("ccr2116", "ccr2116"),
    ("ccr2216", "ccr2216"),
    ("chr", "chr"),
    ("audience", "audience"),
]


def _guess_model(board: str) -> str:
    text = (board or "").lower()
    for needle, model in BOARD_MODEL_HINTS:
        if needle in text:
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

    if not identity and not board and not platform:
        return None
    if platform and "mikrotik" not in platform.lower() and not board and not identity:
        return None

    return _device(
        source_ip,
        name=identity or f"MikroTik {source_ip}",
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
        try:
            sock.bind(("", MNDP_PORT))
        except OSError:
            sock.bind(("", 0))

        sock.settimeout(0.25)
        probe = b"\x00\x00\x00\x00"
        for _ in range(3):
            try:
                sock.sendto(probe, ("255.255.255.255", MNDP_PORT))
            except OSError:
                break
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
                continue
            # Always key MNDP by host so one router = one row
            found[parsed["host"]] = parsed
    finally:
        sock.close()
    return list(found.values())


def _is_private_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return bool(addr.is_private)


def _local_private_subnets() -> list[ipaddress.IPv4Network]:
    """Only real private LAN interfaces — never WAN / public ranges."""
    nets: list[ipaddress.IPv4Network] = []
    seen: set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not _is_private_ipv4(ip):
                continue
            try:
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            except ValueError:
                continue
            key = str(network)
            if key in seen:
                continue
            seen.add(key)
            nets.append(network)
    except OSError:
        pass
    return nets[:2]


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

    # Classic MikroTik defaults (single hosts, not whole foreign /24s)
    for ip in ("192.168.88.1", "192.168.0.1", "192.168.1.1", "10.0.0.1"):
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

        # API/Winbox open without HTTP proof: keep as weak candidate only if API port is open.
        # Final list prefers MNDP; weak candidates are dropped when MNDP already found devices.
        if api_open:
            return _device(host, source="api")
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
        "winbox": 0,
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

    def run_scan():
        nonlocal scan_result
        scan_result = discover_http_and_api(
            max_workers=32 if full_scan else 16,
            quick=not full_scan,
        )

    t1 = threading.Thread(target=run_mndp, daemon=True)
    t2 = threading.Thread(target=run_scan, daemon=True)
    t1.start()
    t2.start()
    t1.join(mndp_timeout + 1.0)
    t2.join(scan_join)

    merged = _merge_devices(mndp_result, scan_result)

    # If MNDP found live neighbors, drop weak API-only guesses that weren't also HTTP-confirmed
    # and aren't already in the MNDP set — avoids phantom duplicates on the LAN.
    mndp_hosts = {(d.get("host") or "").lower() for d in mndp_result if d.get("host")}
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
    return sorted(unique.values(), key=lambda d: (d.get("name") or "", d.get("host") or ""))


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


def filter_not_onboarded(devices: list[dict], onboarded_hosts: Iterable[str]) -> list[dict]:
    """Return only devices that are not yet onboarded."""
    return [d for d in annotate_onboarded(devices, onboarded_hosts) if not d.get("onboarded")]


def devices_to_json(devices: list[dict]) -> str:
    return json.dumps(devices)
