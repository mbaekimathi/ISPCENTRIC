"""MikroTik RouterOS API: login, identity, and Wi‑Fi configuration."""

from __future__ import annotations

import hashlib
import socket
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
