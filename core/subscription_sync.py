"""Push subscription access to MikroTik without blocking callers longer than one NAS restore."""

from __future__ import annotations

import threading
import time
from typing import Any


def nas_access_ready(result: dict[str, Any] | None) -> bool:
    """True when the ISP NAS can let this customer surf (CPE popup may still lag)."""
    if not result or not result.get("allowed"):
        return False
    if result.get("ok"):
        return True
    provision = result.get("provision")
    if isinstance(provision, dict) and provision.get("ok") and not provision.get("skipped"):
        return True
    return False


def enqueue_customer_subscription_sync(
    customer_pk: int,
    provision: bool,
    *,
    wait_first: bool = False,
    quick: bool = False,
    reauthenticate: bool = True,
) -> dict[str, Any] | None:
    """
    Sync package access to the NAS.

    ``wait_first=True`` runs one restore on this thread (cash recharge, voucher
    redeem, pause/resume) so surfing can start immediately. ``quick=True`` skips
    extra CPE retries on that first pass; a short background follow-up finishes
    the CPE renew clear after the CPE redials.
    """
    from billing.models import Customer
    from core.mikrotik_connect import (
        cpe_renew_clear_is_pending,
        sync_customer_subscription_access,
    )

    result: dict[str, Any] | None = None

    def _run_once(cust, *, quick_pass: bool) -> dict[str, Any]:
        return sync_customer_subscription_access(
            cust,
            provision=provision,
            reauthenticate=reauthenticate,
            quick=quick_pass,
        )

    def _bg_sync(*, delay_first: float = 0.0) -> None:
        from django.db import connection

        try:
            if delay_first:
                time.sleep(delay_first)
            cust = Customer.objects.select_related(
                "plan", "router", "organization"
            ).get(pk=customer_pk)
            delays = (0.8, 1.5, 3.0)
            for attempt, delay in enumerate(delays, start=1):
                sync_result = sync_customer_subscription_access(
                    cust,
                    provision=provision,
                    reauthenticate=reauthenticate,
                    quick=False,
                )
                # Restore path: keep retrying while CPE renew clear is pending.
                if sync_result.get("allowed"):
                    if sync_result.get("ok") and not sync_result.get(
                        "cpe_renew_clear_pending"
                    ):
                        break
                    if not cpe_renew_clear_is_pending(cust) and sync_result.get("ok"):
                        break
                else:
                    # Pause / expiry block: retry when NAS or CPE portal still failed.
                    portal = sync_result.get("portal") or {}
                    if sync_result.get("ok") and (
                        portal.get("ok") or portal.get("skipped")
                    ):
                        break
                if attempt < len(delays):
                    time.sleep(delay)
                cust = Customer.objects.select_related(
                    "plan", "router", "organization"
                ).get(pk=customer_pk)
        except Exception:
            pass
        finally:
            connection.close()

    if wait_first:
        try:
            cust = Customer.objects.select_related(
                "plan", "router", "organization"
            ).get(pk=customer_pk)
            result = _run_once(cust, quick_pass=quick)
            if nas_access_ready(result):
                pending_cpe = bool(
                    result.get("cpe_renew_clear_pending")
                    or cpe_renew_clear_is_pending(cust)
                )
                if pending_cpe:
                    threading.Thread(
                        target=_bg_sync,
                        kwargs={"delay_first": 0.7},
                        daemon=True,
                    ).start()
                ready = dict(result)
                ready["ok"] = True
                return ready
        except Exception:
            result = result or {"ok": False, "allowed": False}

    threading.Thread(target=_bg_sync, daemon=True).start()
    return result
