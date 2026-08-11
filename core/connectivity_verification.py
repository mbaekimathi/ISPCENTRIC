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
    from core.wireguard import configured, server_on_tunnel

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
    return (
        "Tunnel router unreachable — paste the WireGuard script on the MikroTik, "
        "add the peer on the VPS wg0, and restart WireGuard."
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
        return {
            "ok": True,
            "skipped": False,
            "nas_ok": True,
            "session_active": True,
            "cpe_ok": True,
            "error": "",
            "hint": "",
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
            "error": "",
            "hint": "",
            "details": details,
        }

    return {
        "ok": False,
        "skipped": False,
        "nas_ok": True,
        "session_active": True,
        "cpe_ok": False,
        "error": sweep_log_text(prep.get("error") or "CPE API login failed."),
        "hint": (
            "Check CPE admin password on the client detail page or enable API "
            "on the client router."
        ),
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

        evaluation = evaluate_cpe_connectivity(customer, deep=deep or repair)
        passed = bool(
            evaluation.get("ok")
            and (
                evaluation.get("skipped")
                or evaluation.get("cpe_ok")
                or evaluation.get("session_active")
            )
        )
        outcome.attempts.append(
            LoopAttempt(
                attempt=attempt,
                ok=bool(evaluation.get("ok")),
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
            f"cpe_ok={evaluation.get('cpe_ok')}"
        )

        if passed and evaluation.get("ok"):
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
