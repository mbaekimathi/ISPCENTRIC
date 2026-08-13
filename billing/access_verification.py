"""
Shared correction-loop logic for PPPoE and Hotspot account access.

Used by management commands and tests to verify billing policy matches NAS state.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, TextIO

from billing.models import Customer
from billing.services import (
    customer_can_surf_via_hotspot,
    customer_can_surf_via_pppoe,
    customer_receives_internet,
)


def billing_allows_surf(customer) -> bool:
    """Whether this account should be surfing right now."""
    service_type = getattr(customer, "service_type", "")
    if service_type == Customer.ServiceType.HOTSPOT:
        return customer_can_surf_via_hotspot(customer)
    if service_type == Customer.ServiceType.PPPOE:
        return customer_can_surf_via_pppoe(customer)
    return customer_receives_internet(customer)


def evaluate_nas_policy(
    customer,
    sync_result: dict | None = None,
    *,
    dry_run: bool = False,
) -> dict:
    """
    Compare billing policy to NAS-side expectations.

    Returns dict with billing_ok, policy_match, details, sync_result.
    """
    billing_ok = billing_allows_surf(customer)
    service_type = getattr(customer, "service_type", "")
    details: dict = {"service_type": service_type, "billing_ok": billing_ok}

    if dry_run or sync_result is None:
        if service_type == Customer.ServiceType.HOTSPOT:
            from core.mikrotik_connect import _hotspot_customer_access_fields

            _mac, disabled, limit_uptime, _comment = _hotspot_customer_access_fields(
                customer
            )
            nas_ok = (not disabled) == billing_ok
            details.update(
                {
                    "hotspot_disabled": disabled,
                    "hotspot_limit_uptime": limit_uptime,
                }
            )
        else:
            nas_ok = True
            details["dry_run_pppoe"] = True
        return {
            "billing_ok": billing_ok,
            "policy_match": nas_ok,
            "details": details,
            "sync_result": sync_result or {},
        }

    if service_type == Customer.ServiceType.HOTSPOT:
        from core.mikrotik_connect import _hotspot_customer_access_fields

        _mac, disabled, limit_uptime, _comment = _hotspot_customer_access_fields(
            customer
        )
        details.update(
            {
                "hotspot_disabled": disabled,
                "hotspot_limit_uptime": limit_uptime,
                "sync_ok": sync_result.get("ok"),
            }
        )
        if billing_ok:
            policy_match = (
                not disabled
                and bool(limit_uptime)
                and bool(sync_result.get("ok"))
                and bool((sync_result.get("provision") or {}).get("ok"))
            )
        else:
            policy_match = disabled and (
                bool(sync_result.get("ok"))
                or bool((sync_result.get("provision") or {}).get("skipped"))
            )
        return {
            "billing_ok": billing_ok,
            "policy_match": policy_match,
            "details": details,
            "sync_result": sync_result,
        }

    from core.mikrotik_connect import (
        PPPOE_BLOCKED_PROFILE_NAME,
        cpe_renew_clear_is_pending,
    )
    from billing.services import customer_pppoe_secret_disabled

    provision = sync_result.get("provision") or {}
    portal = sync_result.get("portal") or {}
    profile = (provision.get("profile") or "").strip()
    details.update(
        {
            "sync_ok": sync_result.get("ok"),
            "sync_allowed": sync_result.get("allowed"),
            "profile": profile,
            "secret_disabled": provision.get("disabled"),
            "cpe_renew_pending": bool(sync_result.get("cpe_renew_clear_pending")),
        }
    )

    if billing_ok:
        nas_ready = bool(
            sync_result.get("allowed")
            and provision.get("ok")
            and not provision.get("disabled")
            and profile != PPPOE_BLOCKED_PROFILE_NAME
        )
        cpe_pending = bool(
            sync_result.get("cpe_renew_clear_pending")
            or (
                portal.get("skipped")
                and not portal.get("ok")
                and cpe_renew_clear_is_pending(customer)
            )
        )
        if cpe_pending and portal.get("skipped"):
            # NAS restore is done; CPE Wi-Fi popup clears when the CPE redials.
            policy_match = nas_ready
            details["cpe_clear_pending"] = True
        else:
            policy_match = nas_ready and not cpe_pending
    else:
        if customer_pppoe_secret_disabled(customer):
            policy_match = bool(
                not sync_result.get("allowed")
                and provision.get("ok")
                and sync_result.get("ok")
                and provision.get("disabled")
            )
        else:
            policy_match = bool(
                not sync_result.get("allowed")
                and provision.get("ok")
                and profile == PPPOE_BLOCKED_PROFILE_NAME
                and sync_result.get("ok")
            )
    return {
        "billing_ok": billing_ok,
        "policy_match": policy_match,
        "details": details,
        "sync_result": sync_result,
    }


@dataclass
class LoopAttempt:
    attempt: int
    billing_ok: bool
    policy_match: bool
    details: dict = field(default_factory=dict)
    sync_result: dict = field(default_factory=dict)


@dataclass
class LoopOutcome:
    customer: Customer
    passed: bool
    attempts: list[LoopAttempt] = field(default_factory=list)
    last_evaluation: dict = field(default_factory=dict)

    @property
    def account_number(self) -> str:
        return getattr(self.customer, "account_number", "") or ""


def run_access_correction_loop(
    customer,
    *,
    loops: int = 3,
    settle: float = 1.5,
    dry_run: bool = False,
    sleep_fn: Callable[[float], None] | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> LoopOutcome:
    """
    Sync (or dry-run) until NAS state matches billing for one customer.

    Unpaid Hotspot MACs get an extra block_hotspot_mac_until_paid retry when
    the first sync pass does not match policy.
    """
    from core.mikrotik_connect import (
        block_hotspot_mac_until_paid,
        sync_customer_subscription_access,
    )

    loops = max(1, int(loops))
    settle = max(0.0, float(settle))
    sleep = sleep_fn or time.sleep
    log = log_fn or (lambda _msg: None)

    outcome = LoopOutcome(customer=customer, passed=False)
    customer_id = customer.pk

    for attempt in range(1, loops + 1):
        customer = (
            Customer.objects.select_related("plan", "organization", "router")
            .filter(pk=customer_id)
            .first()
        )
        if customer is None:
            break

        billing_ok = billing_allows_surf(customer)

        if dry_run:
            evaluation = evaluate_nas_policy(customer, dry_run=True)
            sync_result = evaluation.get("sync_result") or {}
        else:
            sync_result = sync_customer_subscription_access(
                customer,
                provision=True,
                reauthenticate=True,
            )
            customer.refresh_from_db()
            evaluation = evaluate_nas_policy(customer, sync_result)

            if (
                not evaluation["policy_match"]
                and customer.service_type == Customer.ServiceType.HOTSPOT
                and not billing_ok
                and customer.hotspot_mac
            ):
                block_hotspot_mac_until_paid(
                    customer.organization,
                    customer.hotspot_mac,
                    customer=customer,
                    router=customer.router,
                )
                sync_result = sync_customer_subscription_access(
                    customer,
                    provision=True,
                    reauthenticate=True,
                )
                customer.refresh_from_db()
                evaluation = evaluate_nas_policy(customer, sync_result)

        outcome.attempts.append(
            LoopAttempt(
                attempt=attempt,
                billing_ok=billing_ok,
                policy_match=bool(evaluation.get("policy_match")),
                details=evaluation.get("details") or {},
                sync_result=sync_result if isinstance(sync_result, dict) else {},
            )
        )
        outcome.last_evaluation = evaluation

        log(
            f"  attempt {attempt}/{loops}: billing_ok={billing_ok} "
            f"policy_match={evaluation.get('policy_match')} "
            f"details={evaluation.get('details')}"
        )

        if evaluation.get("policy_match"):
            outcome.passed = True
            break

        if attempt < loops and settle > 0 and not dry_run:
            sleep(settle)

    return outcome


def customers_for_access_verification(
    *,
    organization_id: int = 0,
    customer_id: int = 0,
    service: str = "all",
    dynamic_only: bool = False,
) -> list[Customer]:
    """Query PPPoE / Hotspot customers eligible for access loop checks."""
    from django.db.models import Q

    from billing.services import organization_uses_dynamic_access

    qs = Customer.objects.filter(
        Q(service_type=Customer.ServiceType.PPPOE) & ~Q(pppoe_username="")
        | Q(service_type=Customer.ServiceType.HOTSPOT)
        & (~Q(hotspot_mac="") | Q(devices__isnull=False))
    ).select_related("plan", "organization", "router").distinct()

    if customer_id:
        qs = qs.filter(pk=customer_id)
    elif organization_id:
        qs = qs.filter(organization_id=organization_id)

    service = (service or "all").strip().lower()
    if service == "pppoe":
        qs = qs.filter(service_type=Customer.ServiceType.PPPOE)
    elif service == "hotspot":
        qs = qs.filter(service_type=Customer.ServiceType.HOTSPOT)

    customers = list(qs.order_by("organization_id", "service_type", "id"))
    if dynamic_only and not customer_id:
        customers = [
            c
            for c in customers
            if c.organization and organization_uses_dynamic_access(c.organization)
        ]
    return customers


def format_loop_summary(outcomes: list[LoopOutcome]) -> str:
    passed = sum(1 for o in outcomes if o.passed)
    failed = len(outcomes) - passed
    pppoe = sum(
        1
        for o in outcomes
        if o.customer.service_type == Customer.ServiceType.PPPOE
    )
    hotspot = sum(
        1
        for o in outcomes
        if o.customer.service_type == Customer.ServiceType.HOTSPOT
    )
    return (
        f"Done. passed={passed} failed={failed} "
        f"pppoe={pppoe} hotspot={hotspot}"
    )
