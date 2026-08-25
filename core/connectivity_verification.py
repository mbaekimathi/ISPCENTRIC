"""
Correction-loop checks for MikroTik NAS and subscriber CPE communication.

Used by management commands and tests to verify the billing server can reach
the ISP MikroTik API and (for PPPoE) the client router behind it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from billing.models import Customer


def _tunnel_unreachable_hint(router) -> str:
    from core.mikrotik_connect import _router_uses_dedicated_tunnel, on_router_lan
    from core.wireguard import configured, inspect_server_peer, server_on_tunnel

    if not _router_uses_dedicated_tunnel(router):
        if on_router_lan():
            return (
                "Plug this PC into the router LAN or fix the saved host/credentials, "
                "then MikroTik -> Reconnect."
            )
        return "Check router host and API credentials on the router detail page."

    if not configured():
        return (
            "WireGuard is not configured in .env (WIREGUARD_ENDPOINT, "
            "WIREGUARD_SERVER_PUBLIC_KEY). Remote NAS cannot be reached."
        )
    if not server_on_tunnel():
        return (
            "This PC is not on the billing WireGuard tunnel — tunnel NAS "
            f"({getattr(router, 'api_host', '') or router.host}) is only reachable "
            "from the VPS or after pasting the tunnel script on the MikroTik."
        )

    public_key = (getattr(router, "vpn_public_key", None) or "").strip()
    if public_key:
        peer = inspect_server_peer(public_key)
        if peer.get("checked") and not peer.get("present"):
            return (
                "Tunnel peer is missing on VPS wg0 — run "
                "`manage.py wireguard_peer --sync-server`, then MikroTik → Reconnect."
            )
        if peer.get("checked") and peer.get("present") and peer.get("handshake_age_sec") is None:
            return (
                "VPS has the WireGuard peer but there is no handshake — paste the "
                "tunnel script on the MikroTik and open UDP to WIREGUARD_ENDPOINT."
            )

    return (
        "Tunnel router unreachable — paste the WireGuard script on the MikroTik, "
        "confirm the peer is on VPS wg0 (`wg show`), and restart WireGuard if needed."
    )


def evaluate_nas_connectivity(router, *, timeout: float = 2.5) -> dict:
    """Probe TCP reachability and RouterOS API login for one NAS."""
    from core.mikrotik_connect import (
        check_mikrotik_reachable,
        sweep_log_text,
        test_mikrotik_api_login,
    )

    host = (getattr(router, "api_host", None) or getattr(router, "host", None) or "").strip()
    username = (getattr(router, "username", None) or "").strip()
    password = getattr(router, "password", None) or ""

    details: dict = {
        "router_id": getattr(router, "pk", None),
        "router_name": getattr(router, "name", "") or host,
        "host": host,
        "username": username,
    }

    if not host:
        return {
            "ok": False,
            "reachable": False,
            "api_ok": False,
            "error": "Router host is missing.",
            "hint": "Set host or WireGuard tunnel address on the router detail page.",
            "details": details,
        }
    if not username:
        return {
            "ok": False,
            "reachable": False,
            "api_ok": False,
            "error": "Router API username is missing.",
            "details": details,
        }

    probe = check_mikrotik_reachable(host, timeout=timeout)
    details.update(
        {
            "probe_online": bool(probe.get("online")),
            "probe_via": (probe.get("via") or "").strip(),
            "probe_error": sweep_log_text(probe.get("error") or ""),
        }
    )

    if not probe.get("online"):
        hint = _tunnel_unreachable_hint(router)
        return {
            "ok": False,
            "reachable": False,
            "api_ok": False,
            "error": sweep_log_text(probe.get("error") or f"{host}: unreachable"),
            "hint": hint,
            "details": details,
        }

    via = (probe.get("via") or "").strip()
    if via != "api":
        return {
            "ok": False,
            "reachable": True,
            "api_ok": False,
            "error": f"{host}: online via {via or 'ping'} but RouterOS API (8728) is closed.",
            "hint": (
                "Enable IP -> Services -> api on port 8728 with Allowed From empty, "
                "or re-paste the ISPCENTRIC tunnel script."
            ),
            "details": details,
        }

    login = test_mikrotik_api_login(
        host,
        username,
        password,
        timeout=timeout,
        include_wifi=False,
    )
    details.update(
        {
            "identity": (login.get("identity") or login.get("board") or "").strip(),
            "serial_number": (login.get("serial_number") or "").strip(),
        }
    )
    if login.get("ok"):
        return {
            "ok": True,
            "reachable": True,
            "api_ok": True,
            "error": "",
            "hint": "",
            "details": details,
        }

    return {
        "ok": False,
        "reachable": True,
        "api_ok": False,
        "error": sweep_log_text(login.get("error") or "API login failed."),
        "hint": "Update saved API username/password, then MikroTik -> Reconnect.",
        "details": details,
    }


def evaluate_cpe_connectivity(customer, *, timeout: float = 6.0, deep: bool = False) -> dict:
    """
    Check PPPoE session on NAS and optional CPE API reachability via NAS proxy.

    deep=False: NAS session lookup only (fast).
    deep=True: also run prepare_customer_cpe_access (ping + proxy + login try).
    """
    from core.mikrotik_connect import (
        prepare_customer_cpe_access,
        resolve_customer_cpe_session,
        sweep_log_text,
    )

    service_type = getattr(customer, "service_type", "")
    router = getattr(customer, "router", None)
    pppoe_username = (getattr(customer, "pppoe_username", None) or "").strip()

    details: dict = {
        "customer_id": getattr(customer, "pk", None),
        "account_number": getattr(customer, "account_number", "") or "",
        "service_type": service_type,
    }

    if service_type != Customer.ServiceType.PPPOE:
        return {
            "ok": True,
            "skipped": True,
            "nas_ok": True,
            "session_active": False,
            "cpe_ok": False,
            "error": "",
            "hint": "Hotspot clients have no CPE router check.",
            "details": details,
        }

    if not router:
        return {
            "ok": False,
            "skipped": False,
            "nas_ok": False,
            "session_active": False,
            "cpe_ok": False,
            "error": "No MikroTik NAS assigned to this client.",
            "hint": "Assign a router on the client detail page.",
            "details": details,
        }

    if not pppoe_username:
        return {
            "ok": False,
            "skipped": False,
            "nas_ok": False,
            "session_active": False,
            "cpe_ok": False,
            "error": "Client has no PPPoE username.",
            "details": details,
        }

    nas = evaluate_nas_connectivity(router, timeout=min(timeout, 3.0))
    details["nas"] = nas.get("details") or {}
    if not nas.get("api_ok"):
        return {
            "ok": False,
            "skipped": False,
            "nas_ok": False,
            "session_active": False,
            "cpe_ok": False,
            "error": nas.get("error") or "NAS unreachable.",
            "hint": nas.get("hint") or "",
            "details": details,
        }

    host = (router.api_host or router.host or "").strip()
    session = resolve_customer_cpe_session(
        host,
        router.username,
        router.password or "",
        pppoe_username=pppoe_username,
        timeout=min(timeout, 4.0),
    )
    session_active = bool(session.get("session_active"))
    cpe_address = (session.get("address") or "").strip()
    details.update(
        {
            "session_active": session_active,
            "cpe_address": cpe_address,
            "caller_id": (session.get("caller_id") or "").strip(),
        }
    )

    if not session.get("ok"):
        return {
            "ok": False,
            "skipped": False,
            "nas_ok": True,
            "session_active": False,
            "cpe_ok": False,
            "error": sweep_log_text(session.get("error") or "Could not read PPPoE session."),
            "hint": "",
            "details": details,
        }

    if not session_active:
        return {
            "ok": True,
            "skipped": True,
            "nas_ok": True,
            "session_active": False,
            "cpe_ok": False,
            "error": "",
            "hint": sweep_log_text(
                session.get("hint")
                or "CPE offline — PPPoE not dialed. Power on the client router."
            ),
            "details": details,
        }

    if not deep:
        # Session up ≠ remote management. Shallow mode only proves PPPoE is dialed.
        return {
            "ok": True,
            "skipped": False,
            "nas_ok": True,
            "session_active": True,
            "cpe_ok": False,
            "session_only": True,
            "management_ok": False,
            "error": "",
            "hint": (
                "PPPoE session is up, but remote CPE management was not tested. "
                "Re-run with --deep or diagnose_cpe_access."
            ),
            "details": details,
        }

    prep = prepare_customer_cpe_access(
        host,
        router.username,
        router.password or "",
        pppoe_username=pppoe_username,
        customer=customer,
        cpe_username=getattr(customer, "cpe_username", "") or "",
        cpe_password=getattr(customer, "cpe_password", "") or "",
        pppoe_password=getattr(customer, "pppoe_password", "") or "",
        timeout=timeout,
        auto_enable=True,
    )
    details["cpe_prep"] = {
        "prepared": prep.get("prepared"),
        "auth_ok": prep.get("auth_ok"),
        "proxy_used": prep.get("proxy_used"),
        "firewall_blocked": bool(prep.get("firewall_blocked")),
        "steps": prep.get("steps") or [],
    }
    cpe_ok = bool(prep.get("ok") and prep.get("auth_ok"))
    if cpe_ok:
        return {
            "ok": True,
            "skipped": False,
            "nas_ok": True,
            "session_active": True,
            "cpe_ok": True,
            "session_only": False,
            "management_ok": True,
            "error": "",
            "hint": "",
            "details": details,
        }

    hint = (
        "Check CPE admin password on the client detail page or enable API "
        "on the client router."
    )
    if prep.get("firewall_blocked"):
        hint = (
            "CPE firewall/services block WAN management. Paste the unlock script "
            "from the client detail page via LAN Winbox, then retry."
        )
    return {
        "ok": False,
        "skipped": False,
        "nas_ok": True,
        "session_active": True,
        "cpe_ok": False,
        "session_only": False,
        "management_ok": False,
        "error": sweep_log_text(prep.get("error") or "CPE API login failed."),
        "hint": hint,
        "details": details,
    }


@dataclass
class LoopAttempt:
    attempt: int
    ok: bool
    reachable: bool = False
    api_ok: bool = False
    session_active: bool = False
    cpe_ok: bool = False
    error: str = ""
    hint: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class LoopOutcome:
    target: str
    router: object | None = None
    customer: Customer | None = None
    passed: bool = False
    attempts: list[LoopAttempt] = field(default_factory=list)
    last_evaluation: dict = field(default_factory=dict)


def run_nas_connectivity_loop(
    router,
    *,
    loops: int = 3,
    settle: float = 1.5,
    repair: bool = False,
    sleep_fn: Callable[[float], None] | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> LoopOutcome:
    """Retry NAS probe/login; optionally run recover_mikrotik_connection between attempts."""
    loops = max(1, int(loops))
    settle = max(0.0, float(settle))
    sleep = sleep_fn or time.sleep
    log = log_fn or (lambda _msg: None)

    outcome = LoopOutcome(target="nas", router=router, passed=False)

    for attempt in range(1, loops + 1):
        evaluation = evaluate_nas_connectivity(router)
        outcome.attempts.append(
            LoopAttempt(
                attempt=attempt,
                ok=bool(evaluation.get("ok")),
                reachable=bool(evaluation.get("reachable")),
                api_ok=bool(evaluation.get("api_ok")),
                error=evaluation.get("error") or "",
                hint=evaluation.get("hint") or "",
                details=evaluation.get("details") or {},
            )
        )
        outcome.last_evaluation = evaluation
        log(
            f"  attempt {attempt}/{loops}: reachable={evaluation.get('reachable')} "
            f"api_ok={evaluation.get('api_ok')} "
            f"host={((evaluation.get('details') or {}).get('host') or '')}"
        )

        if evaluation.get("ok"):
            outcome.passed = True
            break

        if repair and attempt < loops:
            from core.mikrotik_connect import (
                _router_api_host_candidates,
                recover_mikrotik_connection,
            )

            candidates = _router_api_host_candidates(router, discover=False)
            recover = recover_mikrotik_connection(
                router.host,
                router.username,
                router.password or "",
                router=router,
                candidate_hosts=[h for h in candidates if h != router.host],
                wan_interface=getattr(router, "wan_interface", None) or "ether1",
                lan_bridge=getattr(router, "lan_bridge", None) or "bridgeLocal",
            )
            log(
                f"  repair attempt {attempt}: ok={recover.get('ok')} "
                f"host={recover.get('host') or recover.get('working_host') or '-'}"
            )
            if recover.get("ok") and recover.get("host"):
                try:
                    router.host = recover["host"]
                    router.save(update_fields=["host", "updated_at"])
                except Exception:
                    pass

        if attempt < loops and settle > 0:
            sleep(settle)

    return outcome


def run_cpe_connectivity_loop(
    customer,
    *,
    loops: int = 3,
    settle: float = 2.0,
    deep: bool = False,
    repair: bool = False,
    sleep_fn: Callable[[float], None] | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> LoopOutcome:
    """Retry CPE session/API checks; optionally run prepare_customer_cpe_access on repair."""
    loops = max(1, int(loops))
    settle = max(0.0, float(settle))
    sleep = sleep_fn or time.sleep
    log = log_fn or (lambda _msg: None)

    outcome = LoopOutcome(target="cpe", customer=customer, passed=False)
    customer_id = customer.pk

    for attempt in range(1, loops + 1):
        customer = (
            Customer.objects.select_related("router", "organization")
            .filter(pk=customer_id)
            .first()
        )
        if customer is None:
            break

        want_mgmt = bool(deep or repair)
        evaluation = evaluate_cpe_connectivity(customer, deep=want_mgmt)
        if evaluation.get("skipped"):
            passed = bool(evaluation.get("ok"))
        elif want_mgmt:
            # Remote access SLA: must prove API/management, not just PPPoE up.
            passed = bool(evaluation.get("ok") and evaluation.get("cpe_ok"))
        else:
            # Shallow: session presence only (does not claim Open client router works).
            passed = bool(evaluation.get("ok") and evaluation.get("session_active"))
        outcome.attempts.append(
            LoopAttempt(
                attempt=attempt,
                ok=bool(passed),
                reachable=bool((evaluation.get("details") or {}).get("nas", {}).get("probe_online")),
                api_ok=bool(evaluation.get("nas_ok")),
                session_active=bool(evaluation.get("session_active")),
                cpe_ok=bool(evaluation.get("cpe_ok")),
                error=evaluation.get("error") or "",
                hint=evaluation.get("hint") or "",
                details=evaluation.get("details") or {},
            )
        )
        outcome.last_evaluation = evaluation
        log(
            f"  attempt {attempt}/{loops}: nas_ok={evaluation.get('nas_ok')} "
            f"session_active={evaluation.get('session_active')} "
            f"cpe_ok={evaluation.get('cpe_ok')} "
            f"mgmt={evaluation.get('management_ok')}"
        )

        if passed:
            outcome.passed = True
            break

        if repair and attempt < loops and customer.router and evaluation.get("session_active"):
            from core.mikrotik_connect import prepare_customer_cpe_access

            router = customer.router
            host = (router.api_host or router.host or "").strip()
            prep = prepare_customer_cpe_access(
                host,
                router.username,
                router.password or "",
                pppoe_username=customer.pppoe_username,
                customer=customer,
                cpe_username=getattr(customer, "cpe_username", "") or "",
                cpe_password=getattr(customer, "cpe_password", "") or "",
                pppoe_password=getattr(customer, "pppoe_password", "") or "",
                auto_enable=True,
            )
            log(f"  cpe repair attempt {attempt}: prepared={prep.get('prepared')} auth_ok={prep.get('auth_ok')}")

        if attempt < loops and settle > 0:
            sleep(settle)

    return outcome


def routers_for_connectivity_check(
    *,
    organization_id: int = 0,
    router_id: int = 0,
) -> list:
    from core.models import MikroTikRouter

    qs = MikroTikRouter.objects.filter(
        account_status=MikroTikRouter.AccountStatus.ACTIVE,
    ).exclude(host="")
    if router_id:
        qs = qs.filter(pk=router_id)
    elif organization_id:
        qs = qs.filter(organization_id=organization_id)
    return list(qs.order_by("organization_id", "id"))


def pppoe_customers_for_connectivity(
    *,
    organization_id: int = 0,
    customer_id: int = 0,
    router_id: int = 0,
) -> list[Customer]:
    qs = Customer.objects.filter(
        service_type=Customer.ServiceType.PPPOE,
    ).exclude(pppoe_username="").select_related("router", "organization")
    if customer_id:
        qs = qs.filter(pk=customer_id)
    elif router_id:
        qs = qs.filter(router_id=router_id)
    elif organization_id:
        qs = qs.filter(organization_id=organization_id)
    return list(qs.order_by("organization_id", "id"))


def format_connectivity_summary(outcomes: list[LoopOutcome]) -> str:
    passed = sum(1 for o in outcomes if o.passed)
    failed = len(outcomes) - passed
    nas = sum(1 for o in outcomes if o.target == "nas")
    cpe = sum(1 for o in outcomes if o.target == "cpe")
    return f"Done. passed={passed} failed={failed} nas_checks={nas} cpe_checks={cpe}"


# Layered health probe — isolates Offline / Limited / Auth failed / Connected.
_LAYER_PORTS = (8728, 8291, 80, 8080)


def _tcp_open(host: str, port: int, timeout: float) -> tuple[bool, str]:
    import socket

    from core.mikrotik_connect import dial_host

    try:
        with socket.create_connection((dial_host(host), port), timeout=timeout):
            return True, ""
    except TimeoutError:
        return False, f"{port}: timed out"
    except OSError as exc:
        return False, f"{port}: {exc}"


def evaluate_layered_health(router, *, timeout: float = 2.0) -> dict:
    """
    Probe ping, API :8728, Winbox :8291, HTTP :80/:8080, then API login.

    Maps to the same status/score labels as the workspace \"Why it dropped\" panel
    so operators can see *which layer* failed instead of only the final label.
    """
    from core.mikrotik_connect import _icmp_ping, sweep_log_text, test_mikrotik_api_login
    from core.mikrotik_status_samples import (
        is_credential_login_failure,
        status_reason,
        status_score,
    )

    host = (getattr(router, "api_host", None) or getattr(router, "host", None) or "").strip()
    username = (getattr(router, "username", None) or "").strip()
    password = getattr(router, "password", None) or ""

    layers: dict = {
        "ping": False,
        "tcp_8728": False,
        "tcp_8291": False,
        "tcp_80": False,
        "tcp_8080": False,
        "api_auth": None,
    }
    layer_errors: dict[str, str] = {}
    details: dict = {
        "router_id": getattr(router, "pk", None),
        "router_name": getattr(router, "name", "") or host,
        "host": host,
        "username": username,
        "layers": layers,
        "layer_errors": layer_errors,
    }

    if not host:
        return {
            "ok": False,
            "status": "disconnected",
            "score": 0,
            "failing_layer": "host",
            "error": "Router host is missing.",
            "hint": "Set host or WireGuard tunnel address on the router detail page.",
            "reason": status_reason("disconnected", "Router host is missing."),
            "details": details,
        }

    layers["ping"] = bool(_icmp_ping(host, timeout=timeout))
    if not layers["ping"]:
        layer_errors["ping"] = "no ICMP reply"

    for port in _LAYER_PORTS:
        ok, err = _tcp_open(host, port, timeout)
        key = f"tcp_{port}"
        layers[key] = ok
        if not ok and err:
            layer_errors[key] = err

    if layers["tcp_8728"]:
        if not username:
            layers["api_auth"] = False
            layer_errors["api_auth"] = "API username missing"
            status = "auth_failed"
            failing = "api_auth"
            error = "Router API username is missing."
            hint = "Set the API username on the router detail page."
        else:
            login = test_mikrotik_api_login(
                host,
                username,
                password,
                timeout=timeout,
                include_wifi=False,
            )
            layers["api_auth"] = bool(login.get("ok"))
            if login.get("ok"):
                details["identity"] = (login.get("identity") or login.get("board") or "").strip()
                details["serial_number"] = (login.get("serial_number") or "").strip()
                status = "connected"
                failing = ""
                error = ""
                hint = ""
            elif is_credential_login_failure(login.get("error")):
                layer_errors["api_auth"] = sweep_log_text(
                    login.get("error") or "API login failed."
                )
                status = "auth_failed"
                failing = "api_auth"
                error = layer_errors["api_auth"]
                hint = "Update saved API username/password, then MikroTik → Reconnect."
            else:
                # :8728 accepted briefly then dial/login timed out — not a password issue.
                layers["api_auth"] = False
                layer_errors["api_auth"] = sweep_log_text(
                    login.get("error") or "API login timed out."
                )
                status = "reachable"
                failing = "api_auth"
                error = layer_errors["api_auth"]
                hint = (
                    "API port flickered or timed out during login. "
                    "Check WireGuard/tunnel stability and firewall, then retry."
                )
    elif layers["tcp_8291"] or layers["tcp_80"] or layers["tcp_8080"]:
        status = "reachable"
        failing = "tcp_8728"
        error = f"{host}: HTTP/Winbox open but RouterOS API (8728) is closed."
        hint = (
            "Enable IP → Services → api on port 8728 with Allowed From empty, "
            "or re-paste the ISPCENTRIC tunnel script."
        )
        layer_errors.setdefault("tcp_8728", "API port closed")
    elif layers["ping"]:
        status = "limited"
        failing = "tcp_8728"
        error = (
            f"{host}: answers ping only — API port 8728 is closed. "
            "Enable IP → Services → api (Allowed From empty) or re-paste the "
            "ISPCENTRIC tunnel script."
        )
        hint = (
            "Firewall or IP services blocking 8728/80 — open API from the tunnel "
            "subnet, or re-paste the ISPCENTRIC tunnel script."
        )
        layer_errors.setdefault("tcp_8728", "API port closed")
    else:
        status = "disconnected"
        failing = "ping"
        port_errs = [
            layer_errors.get(f"tcp_{p}") for p in _LAYER_PORTS if layer_errors.get(f"tcp_{p}")
        ]
        error = sweep_log_text(
            "; ".join(e for e in port_errs if e) or f"{host}: unreachable"
        )
        hint = _tunnel_unreachable_hint(router)

    return {
        "ok": status == "connected",
        "status": status,
        "score": status_score(status),
        "failing_layer": failing,
        "error": error,
        "hint": hint,
        "reason": status_reason(status, error),
        "details": details,
    }


@dataclass
class LayeredLoopOutcome:
    router: object | None = None
    passed: bool = False
    attempts: list[dict] = field(default_factory=list)
    last_evaluation: dict = field(default_factory=dict)
    layer_pass_rates: dict = field(default_factory=dict)
    status_counts: dict = field(default_factory=dict)
    dominant_failure: str = ""
    flaky: bool = False


def run_layered_health_loop(
    router,
    *,
    loops: int = 5,
    settle: float = 2.0,
    timeout: float = 2.0,
    sleep_fn: Callable[[float], None] | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> LayeredLoopOutcome:
    """
    Repeat layered probes to catch flaky tunnel / API / auth drops.

    Aggregates per-layer pass rates so a 1-in-5 Offline spike is visible
    instead of a single snapshot.
    """
    loops = max(1, int(loops))
    settle = max(0.0, float(settle))
    sleep = sleep_fn or time.sleep
    log = log_fn or (lambda _msg: None)

    outcome = LayeredLoopOutcome(router=router, passed=False)
    layer_ok_counts: dict[str, int] = {
        "ping": 0,
        "tcp_8728": 0,
        "tcp_8291": 0,
        "tcp_80": 0,
        "tcp_8080": 0,
        "api_auth": 0,
    }
    status_counts: dict[str, int] = {}

    for attempt in range(1, loops + 1):
        evaluation = evaluate_layered_health(router, timeout=timeout)
        layers = (evaluation.get("details") or {}).get("layers") or {}
        status = (evaluation.get("status") or "disconnected").strip().lower()
        status_counts[status] = status_counts.get(status, 0) + 1
        for key in layer_ok_counts:
            if layers.get(key) is True:
                layer_ok_counts[key] += 1

        row = {
            "attempt": attempt,
            "ok": bool(evaluation.get("ok")),
            "status": status,
            "score": int(evaluation.get("score") or 0),
            "failing_layer": evaluation.get("failing_layer") or "",
            "error": evaluation.get("error") or "",
            "hint": evaluation.get("hint") or "",
            "layers": dict(layers),
        }
        outcome.attempts.append(row)
        outcome.last_evaluation = evaluation
        log(
            f"  attempt {attempt}/{loops}: status={status} score={row['score']}% "
            f"ping={layers.get('ping')} api={layers.get('tcp_8728')} "
            f"http={layers.get('tcp_80')} auth={layers.get('api_auth')} "
            f"fail={row['failing_layer'] or '-'}"
        )

        if evaluation.get("ok"):
            outcome.passed = True

        if attempt < loops and settle > 0:
            sleep(settle)

    rates = {
        key: round((count / loops) * 100.0, 1) for key, count in layer_ok_counts.items()
    }
    outcome.layer_pass_rates = rates
    outcome.status_counts = status_counts
    # Flaky when more than one distinct status appeared, or Connected < 100%.
    outcome.flaky = len(status_counts) > 1 or (
        status_counts.get("connected", 0) not in (0, loops)
    )

    if outcome.passed and not outcome.flaky:
        outcome.dominant_failure = ""
    else:
        # Prefer the worst failing status seen across the loop.
        priority = (
            "disconnected",
            "wrong_host",
            "auth_failed",
            "limited",
            "reachable",
            "connected",
        )
        for key in priority:
            if status_counts.get(key):
                outcome.dominant_failure = key
                break

    return outcome


def format_layered_loop_summary(outcome: LayeredLoopOutcome) -> str:
    name = getattr(outcome.router, "name", None) or "?"
    rates = outcome.layer_pass_rates or {}
    counts = outcome.status_counts or {}
    status_bits = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    return (
        f"{name}: passed={outcome.passed} flaky={outcome.flaky} "
        f"dominant={outcome.dominant_failure or 'none'} "
        f"statuses[{status_bits}] "
        f"ping={rates.get('ping', 0)}% api8728={rates.get('tcp_8728', 0)}% "
        f"http80={rates.get('tcp_80', 0)}% auth={rates.get('api_auth', 0)}%"
    )


# Layered CPE remote-access probe — matches Open client router path.
_CPE_FAILURE_PRIORITY = (
    "nas_down",
    "not_eligible",
    "offline",
    "wan_mgmt_blocked",
    "firewall_blocked",
    "bad_credentials",
    "proxy_failed",
    "web_ok_api_failed",
    "ok",
)


def evaluate_layered_cpe_access(
    customer,
    *,
    timeout: float = 8.0,
    try_api: bool = True,
    auto_enable: bool = True,
) -> dict:
    """
    Layered remote CPE access check used by Open client router:

    NAS API → session/IP → NAS→CPE ping → web ports via proxy → optional API login.

    failure_class values:
      nas_down | not_eligible | offline | wan_mgmt_blocked | firewall_blocked |
      bad_credentials | proxy_failed | web_ok_api_failed | ok
    """
    from core.mikrotik_connect import (
        customer_cpe_access_eligible,
        prepare_customer_cpe_access,
        probe_customer_cpe_web,
        sweep_log_text,
    )

    router = getattr(customer, "router", None)
    layers = {
        "nas_ok": False,
        "session_active": False,
        "ping_ok": False,
        "web_ok": False,
        "api_ok": False,
    }
    details: dict = {
        "customer_id": getattr(customer, "pk", None),
        "account_number": getattr(customer, "account_number", "") or "",
        "layers": layers,
        "web_port": None,
        "cpe_host": "",
        "steps": [],
    }

    if not customer_cpe_access_eligible(customer):
        return {
            "ok": False,
            "skipped": True,
            "failure_class": "not_eligible",
            "failing_layer": "eligible",
            "error": "Client is not eligible for remote CPE access.",
            "hint": (
                "PPPoE needs a username + assigned NAS; static needs CPE IP or MAC. "
                "Hotspot accounts have no client router."
            ),
            "details": details,
        }

    if not router:
        return {
            "ok": False,
            "skipped": False,
            "failure_class": "nas_down",
            "failing_layer": "nas",
            "error": "No MikroTik NAS assigned.",
            "hint": "Assign a router on the client detail page.",
            "details": details,
        }

    nas = evaluate_nas_connectivity(router, timeout=min(timeout, 3.0))
    details["nas"] = nas.get("details") or {}
    layers["nas_ok"] = bool(nas.get("api_ok"))
    if not layers["nas_ok"]:
        return {
            "ok": False,
            "skipped": False,
            "failure_class": "nas_down",
            "failing_layer": "nas",
            "error": nas.get("error") or "NAS unreachable.",
            "hint": nas.get("hint") or "",
            "details": details,
        }

    nas_host = (router.api_host or router.host or "").strip()
    probe = probe_customer_cpe_web(
        nas_host,
        router.username,
        router.password or "",
        customer=customer,
        cpe_username=getattr(customer, "cpe_username", "") or "",
        cpe_password=getattr(customer, "cpe_password", "") or "",
        pppoe_password=getattr(customer, "pppoe_password", "") or "",
        timeout=timeout,
        auto_enable_www=bool(auto_enable and try_api),
    )
    details["probe"] = {
        "ok": probe.get("ok"),
        "port": probe.get("port"),
        "ping_ok": probe.get("ping_ok"),
        "api_ok": probe.get("api_ok"),
        "www_enabled": probe.get("www_enabled"),
        "steps": probe.get("steps") or [],
        "error": probe.get("error") or "",
        "hint": probe.get("hint") or "",
    }
    details["steps"] = list(probe.get("steps") or [])
    details["cpe_host"] = (probe.get("cpe_host") or "").strip()
    details["web_port"] = probe.get("port")
    layers["session_active"] = bool(probe.get("session_active"))
    layers["ping_ok"] = bool(probe.get("ping_ok"))
    layers["web_ok"] = bool(probe.get("ok") and probe.get("port"))

    if not layers["session_active"]:
        return {
            "ok": False,
            "skipped": False,
            "failure_class": "offline",
            "failing_layer": "session",
            "error": sweep_log_text(
                probe.get("error") or probe.get("hint") or "Client router is offline."
            ),
            "hint": (
                probe.get("hint")
                or "Power on the client router and wait for PPPoE/DHCP to come up."
            ),
            "details": details,
        }

    if layers["web_ok"]:
        if not try_api:
            return {
                "ok": True,
                "skipped": False,
                "failure_class": "ok",
                "failing_layer": "",
                "error": "",
                "hint": "",
                "details": details,
            }

        # probe_customer_cpe_web(auto_enable_www=True) already ran prepare when
        # ports were closed — reuse that outcome instead of a second NAS walk.
        if probe.get("api_ok"):
            layers["api_ok"] = True
            return {
                "ok": True,
                "skipped": False,
                "failure_class": "ok",
                "failing_layer": "",
                "error": "",
                "hint": "",
                "details": details,
            }

        prep: dict = {}
        if probe.get("prep_attempted"):
            prep = {
                "ok": False,
                "auth_ok": False,
                "firewall_blocked": "firewall" in (probe.get("error") or "").lower(),
                "proxy_used": True,
                "steps": list(probe.get("steps") or []),
                "error": probe.get("error") or "CPE API login failed.",
            }
            details["cpe_prep"] = {
                "ok": False,
                "auth_ok": False,
                "firewall_blocked": bool(prep.get("firewall_blocked")),
                "proxy_used": True,
                "steps": prep.get("steps") or [],
                "error": prep.get("error") or "",
                "reused_probe": True,
            }
        else:
            prep = prepare_customer_cpe_access(
                nas_host,
                router.username,
                router.password or "",
                customer=customer,
                cpe_username=getattr(customer, "cpe_username", "") or "",
                cpe_password=getattr(customer, "cpe_password", "") or "",
                pppoe_password=getattr(customer, "pppoe_password", "") or "",
                timeout=timeout,
                auto_enable=auto_enable,
            )
            details["cpe_prep"] = {
                "ok": prep.get("ok"),
                "auth_ok": prep.get("auth_ok"),
                "firewall_blocked": bool(prep.get("firewall_blocked")),
                "proxy_used": prep.get("proxy_used"),
                "steps": prep.get("steps") or [],
                "error": prep.get("error") or "",
            }
            details["steps"].extend(prep.get("steps") or [])
            layers["api_ok"] = bool(prep.get("ok") and prep.get("auth_ok"))
            layers["ping_ok"] = layers["ping_ok"] or bool(prep.get("reachable"))

            if layers["api_ok"]:
                return {
                    "ok": True,
                    "skipped": False,
                    "failure_class": "ok",
                    "failing_layer": "",
                    "error": "",
                    "hint": "",
                    "details": details,
                }

        # Web works — Open client router can still succeed even if API login fails.
        failure = "web_ok_api_failed"
        hint = (
            "WebFig is reachable — Open client router should work. "
            "API login failed; save the correct CPE admin password for Wi‑Fi/API tools."
        )
        if prep.get("firewall_blocked"):
            failure = "firewall_blocked"
            hint = (
                "CPE firewall blocks API. Paste the unlock script from the client "
                "detail page via LAN Winbox."
            )
        err = (prep.get("error") or "").lower()
        if "password" in err or "login" in err or "invalid user" in err:
            failure = "bad_credentials"
            hint = "Update the client router admin password on the client detail page."

        return {
            "ok": True,  # remote web access works
            "skipped": False,
            "failure_class": failure,
            "failing_layer": "api",
            "error": sweep_log_text(prep.get("error") or "CPE API login failed."),
            "hint": hint,
            "details": details,
        }

    # Session up but no web port — classify ping vs firewall vs WAN mgmt.
    if layers["ping_ok"]:
        failure = "wan_mgmt_blocked"
        hint = (
            "ISP can ping the CPE but admin web ports are closed. On consumer routers "
            "enable Remote/WAN Web Management toward the ISP gateway. On MikroTik CPE "
            "paste the unlock script from the client detail page."
        )
        failing = "web"
    else:
        failure = "proxy_failed"
        hint = (
            probe.get("hint")
            or "NAS cannot reach the CPE management ports. Check PPPoE path and CPE firewall."
        )
        failing = "ping"
        if "firewall" in (probe.get("error") or "").lower():
            failure = "firewall_blocked"
            failing = "firewall"

    return {
        "ok": False,
        "skipped": False,
        "failure_class": failure,
        "failing_layer": failing,
        "error": sweep_log_text(
            probe.get("error")
            or "Client router management ports are not reachable from the ISP MikroTik."
        ),
        "hint": hint,
        "details": details,
    }


@dataclass
class CpeAccessLoopOutcome:
    customer: Customer | None = None
    passed: bool = False
    attempts: list[dict] = field(default_factory=list)
    last_evaluation: dict = field(default_factory=dict)
    layer_pass_rates: dict = field(default_factory=dict)
    failure_counts: dict = field(default_factory=dict)
    dominant_failure: str = ""
    flaky: bool = False


def run_layered_cpe_access_loop(
    customer,
    *,
    loops: int = 3,
    settle: float = 2.0,
    timeout: float = 8.0,
    try_api: bool = True,
    auto_enable: bool = True,
    sleep_fn: Callable[[float], None] | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> CpeAccessLoopOutcome:
    """Repeat layered CPE remote-access probes; aggregate flakiness per layer."""
    loops = max(1, int(loops))
    settle = max(0.0, float(settle))
    sleep = sleep_fn or time.sleep
    log = log_fn or (lambda _msg: None)

    outcome = CpeAccessLoopOutcome(customer=customer, passed=False)
    customer_id = customer.pk
    layer_ok_counts = {
        "nas_ok": 0,
        "session_active": 0,
        "ping_ok": 0,
        "web_ok": 0,
        "api_ok": 0,
    }
    failure_counts: dict[str, int] = {}

    for attempt in range(1, loops + 1):
        customer = (
            Customer.objects.select_related("router", "organization")
            .filter(pk=customer_id)
            .first()
        )
        if customer is None:
            break

        evaluation = evaluate_layered_cpe_access(
            customer,
            timeout=timeout,
            try_api=try_api,
            auto_enable=auto_enable,
        )
        layers = (evaluation.get("details") or {}).get("layers") or {}
        failure = (evaluation.get("failure_class") or "unknown").strip().lower()
        failure_counts[failure] = failure_counts.get(failure, 0) + 1
        for key in layer_ok_counts:
            if layers.get(key):
                layer_ok_counts[key] += 1

        # Pass when Open client router can work (web reachable).
        passed = bool(evaluation.get("ok") and not evaluation.get("skipped"))

        row = {
            "attempt": attempt,
            "ok": passed,
            "failure_class": failure,
            "failing_layer": evaluation.get("failing_layer") or "",
            "error": evaluation.get("error") or "",
            "hint": evaluation.get("hint") or "",
            "layers": dict(layers),
            "cpe_host": (evaluation.get("details") or {}).get("cpe_host") or "",
            "web_port": (evaluation.get("details") or {}).get("web_port"),
        }
        outcome.attempts.append(row)
        outcome.last_evaluation = evaluation
        log(
            f"  attempt {attempt}/{loops}: fail={failure} "
            f"nas={layers.get('nas_ok')} session={layers.get('session_active')} "
            f"ping={layers.get('ping_ok')} web={layers.get('web_ok')} "
            f"api={layers.get('api_ok')} host={row['cpe_host'] or '-'} "
            f"port={row['web_port'] or '-'}"
        )

        if passed:
            outcome.passed = True

        if attempt < loops and settle > 0:
            sleep(settle)

    rates = {
        key: round((count / loops) * 100.0, 1) for key, count in layer_ok_counts.items()
    }
    outcome.layer_pass_rates = rates
    outcome.failure_counts = failure_counts
    outcome.flaky = len(failure_counts) > 1
    for key in _CPE_FAILURE_PRIORITY:
        if failure_counts.get(key):
            outcome.dominant_failure = key
            break
    if outcome.passed and not outcome.flaky and outcome.dominant_failure in {
        "ok",
        "web_ok_api_failed",
        "bad_credentials",
    }:
        if outcome.dominant_failure == "ok":
            outcome.dominant_failure = ""

    return outcome


def format_cpe_access_loop_summary(outcome: CpeAccessLoopOutcome) -> str:
    customer = outcome.customer
    label = getattr(customer, "account_number", None) or getattr(customer, "pk", "?")
    rates = outcome.layer_pass_rates or {}
    fails = outcome.failure_counts or {}
    fail_bits = " ".join(f"{k}={v}" for k, v in sorted(fails.items()))
    return (
        f"{label}: passed={outcome.passed} flaky={outcome.flaky} "
        f"dominant={outcome.dominant_failure or 'none'} "
        f"failures[{fail_bits}] "
        f"nas={rates.get('nas_ok', 0)}% session={rates.get('session_active', 0)}% "
        f"ping={rates.get('ping_ok', 0)}% web={rates.get('web_ok', 0)}% "
        f"api={rates.get('api_ok', 0)}%"
    )
