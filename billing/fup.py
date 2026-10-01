"""Fair Usage Policy (FUP) helpers for package data caps."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from django.db.models import F
from django.utils import timezone

logger = logging.getLogger(__name__)

_GB = Decimal(1024) ** 3


def plan_fup_enabled(plan) -> bool:
    if plan is None or not getattr(plan, "fup_enabled", False):
        return False
    try:
        limit = Decimal(str(getattr(plan, "fup_data_limit_gb", 0) or 0))
    except Exception:
        return False
    return limit > 0 and int(getattr(plan, "fup_period_value", 0) or 0) >= 1


def plan_fup_limit_bytes(plan) -> int:
    if not plan_fup_enabled(plan):
        return 0
    try:
        gb = Decimal(str(getattr(plan, "fup_data_limit_gb", 0) or 0))
    except Exception:
        return 0
    if gb <= 0:
        return 0
    return int(gb * _GB)


def customer_fup_usage_snapshot(customer, plan=None) -> dict[str, Any]:
    """
    Read-only FUP usage for dashboards (no MikroTik sync, no DB writes).

    Returns percentage of the package data cap used in the current FUP window.
    """
    plan = plan or getattr(customer, "plan", None)
    empty = {
        "enabled": False,
        "percent": 0.0,
        "bytes_used": 0,
        "bytes_limit": 0,
        "restricted": False,
        "action": "",
        "limit_label": "",
        "period_label": "",
        "status_label": "",
    }
    if not plan_fup_enabled(plan):
        return empty

    limit = plan_fup_limit_bytes(plan)
    period = fup_period_timedelta(plan)
    window_start = _as_aware(getattr(customer, "fup_window_start", None))
    now = _now()
    used = int(getattr(customer, "fup_bytes_used", 0) or 0)
    restricted = bool(getattr(customer, "fup_restricted", False))

    # Expired windows display as a fresh period until enforcement resets them.
    if window_start and period and window_start + period <= now:
        used = 0
        restricted = False

    percent = 0.0
    if limit > 0:
        percent = round(min(100.0, (float(used) / float(limit)) * 100.0), 1)
        if used >= limit:
            percent = 100.0
            restricted = True

    action = (getattr(plan, "fup_action", "") or "").strip().lower()
    try:
        limit_gb = Decimal(str(getattr(plan, "fup_data_limit_gb", 0) or 0))
        if limit_gb == limit_gb.to_integral_value():
            limit_label = f"{int(limit_gb)} GB"
        else:
            limit_label = f"{format(limit_gb.normalize(), 'f').rstrip('0').rstrip('.')} GB"
    except Exception:
        limit_label = getattr(plan, "fup_display_label", "") or ""

    value = int(getattr(plan, "fup_period_value", 1) or 1)
    unit = (getattr(plan, "fup_period_unit", "") or "months").strip().lower()
    unit_labels = {
        "hours": ("hour", "hours"),
        "days": ("day", "days"),
        "weeks": ("week", "weeks"),
        "months": ("month", "months"),
        "years": ("year", "years"),
    }
    singular, plural = unit_labels.get(unit, ("period", "periods"))
    period_label = singular if value == 1 else f"{value} {plural}"

    if restricted:
        status_label = "Disconnected" if action == "disconnect" else "Throttled"
    elif percent >= 90:
        status_label = "Near limit"
    elif percent >= 70:
        status_label = "High"
    elif percent > 0:
        status_label = "OK"
    else:
        status_label = "Unused"

    return {
        "enabled": True,
        "percent": percent,
        "bytes_used": used,
        "bytes_limit": limit,
        "restricted": restricted,
        "action": action,
        "limit_label": limit_label,
        "period_label": period_label,
        "status_label": status_label,
    }


def organization_fup_attention_clients(
    organization,
    *,
    min_percent: float = 80.0,
    limit: int = 40,
) -> dict[str, Any]:
    """
    Clients on FUP packages who are at or above ``min_percent`` of their data cap.

    Used on the workspace dashboard to surface 80–100% FUP usage.
    """
    from billing.models import Customer

    empty = {
        "ok": True,
        "clients": [],
        "count": 0,
        "at_limit": 0,
        "near_limit": 0,
        "min_percent": float(min_percent),
    }
    if not organization:
        return empty

    qs = (
        Customer.objects.filter(
            organization=organization,
            plan__fup_enabled=True,
            plan__fup_data_limit_gb__gt=0,
        )
        .exclude(service_type=Customer.ServiceType.STATIC)
        .select_related("plan", "router")
        .only(
            "id",
            "full_name",
            "account_number",
            "phone",
            "service_type",
            "status",
            "fup_window_start",
            "fup_bytes_used",
            "fup_restricted",
            "plan_id",
            "router_id",
            "plan__name",
            "plan__fup_enabled",
            "plan__fup_data_limit_gb",
            "plan__fup_period_value",
            "plan__fup_period_unit",
            "plan__fup_action",
            "plan__fup_throttle_download_mbps",
            "plan__fup_throttle_upload_mbps",
            "router__name",
        )
        .order_by("full_name", "account_number")
    )

    rows: list[dict[str, Any]] = []
    for customer in qs.iterator(chunk_size=200):
        snap = customer_fup_usage_snapshot(customer, getattr(customer, "plan", None))
        if not snap.get("enabled"):
            continue
        percent = float(snap.get("percent") or 0)
        if percent < float(min_percent):
            continue
        plan = getattr(customer, "plan", None)
        rows.append(
            {
                "id": customer.pk,
                "customer_id": customer.pk,
                "full_name": customer.full_name,
                "account_number": customer.account_number,
                "phone": customer.phone or "",
                "service_type": customer.service_type,
                "service_type_label": customer.get_service_type_display(),
                "plan_name": getattr(plan, "name", "") or "",
                "router_name": (
                    customer.router.name if getattr(customer, "router_id", None) else ""
                ),
                "fup_percent": percent,
                "fup_bytes_used": int(snap.get("bytes_used") or 0),
                "fup_bytes_limit": int(snap.get("bytes_limit") or 0),
                "fup_restricted": bool(snap.get("restricted")),
                "fup_action": snap.get("action") or "",
                "fup_limit_label": snap.get("limit_label") or "",
                "fup_period_label": snap.get("period_label") or "",
                "fup_status_label": snap.get("status_label") or "",
            }
        )

    rows.sort(
        key=lambda row: (
            -float(row.get("fup_percent") or 0),
            -int(row.get("fup_bytes_used") or 0),
            (row.get("full_name") or "").casefold(),
        )
    )
    capped = rows[: max(1, min(int(limit or 40), 200))]
    at_limit = sum(1 for row in capped if row.get("fup_restricted") or float(row.get("fup_percent") or 0) >= 100)
    near_limit = max(0, len(capped) - at_limit)
    return {
        "ok": True,
        "clients": capped,
        "count": len(capped),
        "at_limit": at_limit,
        "near_limit": near_limit,
        "min_percent": float(min_percent),
    }


def fup_period_timedelta(plan) -> timedelta | None:
    if plan is None:
        return None
    value = int(getattr(plan, "fup_period_value", 0) or 0)
    if value < 1:
        return None
    unit = (getattr(plan, "fup_period_unit", "") or "").strip().lower()
    if unit == "hours":
        return timedelta(hours=value)
    if unit == "days":
        return timedelta(days=value)
    if unit == "weeks":
        return timedelta(weeks=value)
    if unit == "months":
        return timedelta(days=30 * value)
    if unit == "years":
        return timedelta(days=365 * value)
    return None


def _as_aware(stamp) -> datetime | None:
    if stamp is None:
        return None
    if timezone.is_naive(stamp):
        return timezone.make_aware(stamp, timezone.get_current_timezone())
    return timezone.localtime(stamp)


def _now() -> datetime:
    return timezone.localtime()


def reset_customer_fup_window(customer, *, at=None, save: bool = True) -> list[str]:
    """Start (or restart) the FUP window and clear any restriction."""
    stamp = _as_aware(at) or _now()
    customer.fup_window_start = stamp
    customer.fup_bytes_used = 0
    customer.fup_restricted = False
    customer.fup_restricted_at = None
    fields = [
        "fup_window_start",
        "fup_bytes_used",
        "fup_restricted",
        "fup_restricted_at",
    ]
    if save and getattr(customer, "pk", None):
        customer.save(update_fields=fields)
    return fields


def ensure_fup_window(customer, plan=None, *, now: datetime | None = None) -> bool:
    """
    Ensure the customer has a current FUP window.

    Returns True when the window was created or advanced (restriction cleared).
    """
    plan = plan or getattr(customer, "plan", None)
    if not plan_fup_enabled(plan):
        return False

    stamp = _as_aware(now) or _now()
    period = fup_period_timedelta(plan)
    if period is None:
        return False

    window_start = _as_aware(getattr(customer, "fup_window_start", None))
    if window_start is None:
        seed = (
            _as_aware(getattr(customer, "usage_tracking_since", None))
            or _as_aware(getattr(customer, "package_start", None))
            or stamp
        )
        reset_customer_fup_window(customer, at=seed, save=True)
        return True

    advanced = False
    # Advance through any fully elapsed windows (e.g. after long offline).
    while window_start + period <= stamp:
        window_start = window_start + period
        advanced = True
    if advanced:
        reset_customer_fup_window(customer, at=window_start, save=True)
    return advanced


def customer_fup_blocks_internet(customer, plan=None) -> bool:
    """True when FUP disconnect should block surfing until the window resets."""
    plan = plan or getattr(customer, "plan", None)
    if not plan_fup_enabled(plan):
        return False
    if (getattr(plan, "fup_action", "") or "").strip().lower() != "disconnect":
        return False
    ensure_fup_window(customer, plan)
    return bool(getattr(customer, "fup_restricted", False))


def customer_fup_throttle_speeds(customer, plan=None) -> tuple[int, int] | None:
    """
    Return (upload_mbps, download_mbps) when FUP throttle is active, else None.
    """
    plan = plan or getattr(customer, "plan", None)
    if not plan_fup_enabled(plan):
        return None
    if (getattr(plan, "fup_action", "") or "").strip().lower() != "throttle":
        return None
    ensure_fup_window(customer, plan)
    if not getattr(customer, "fup_restricted", False):
        return None
    upload = int(getattr(plan, "fup_throttle_upload_mbps", 0) or 0)
    download = int(getattr(plan, "fup_throttle_download_mbps", 0) or 0)
    if upload < 1 and download < 1:
        return 1, 1
    if upload < 1:
        upload = download
    if download < 1:
        download = upload
    # Never exceed the package's normal speeds.
    plan_up = int(getattr(plan, "upload_speed_mbps", 0) or 0)
    plan_down = int(
        getattr(plan, "download_speed_mbps", 0) or getattr(plan, "speed_mbps", 0) or 0
    )
    if plan_up >= 1:
        upload = min(upload, plan_up)
    if plan_down >= 1:
        download = min(download, plan_down)
    return max(1, upload), max(1, download)


def _compute_bytes_used_since(customer, since: datetime) -> int:
    """Sum positive session byte deltas from usage samples since ``since``."""
    from billing.models import CustomerUsageSample
    from billing.usage_samples import _bytes_delta

    since = _as_aware(since)
    if since is None or not getattr(customer, "pk", None):
        return 0

    rows = (
        CustomerUsageSample.objects.filter(
            customer_id=customer.pk,
            sampled_at__gte=since,
        )
        .order_by("sampled_at")
        .values("sampled_at", "session_active", "bytes_in", "bytes_out")
    )
    previous_total: int | None = None
    total = 0
    for row in rows:
        bi = int(row["bytes_in"] or 0)
        bo = int(row["bytes_out"] or 0)
        session_total = bi + bo
        active = bool(row["session_active"])
        if not active and session_total == 0:
            continue
        delta = _bytes_delta(previous_total, session_total)
        previous_total = session_total
        total += delta
    return int(total)


def refresh_customer_fup_usage(customer, plan=None, *, save: bool = True) -> int:
    """Recompute ``fup_bytes_used`` from samples in the current window."""
    plan = plan or getattr(customer, "plan", None)
    if not plan_fup_enabled(plan):
        return int(getattr(customer, "fup_bytes_used", 0) or 0)
    ensure_fup_window(customer, plan)
    window_start = _as_aware(getattr(customer, "fup_window_start", None))
    if window_start is None:
        return 0
    used = _compute_bytes_used_since(customer, window_start)
    customer.fup_bytes_used = used
    if save and getattr(customer, "pk", None):
        customer.save(update_fields=["fup_bytes_used"])
    return used


def apply_fup_byte_delta(customer, delta_bytes: int, plan=None) -> dict[str, Any]:
    """
    Add a traffic delta to the current FUP window and enforce the limit.

    Returns a status dict; ``changed`` is True when restriction state flipped.
    """
    from billing.models import Customer

    plan = plan or getattr(customer, "plan", None)
    if not plan_fup_enabled(plan) or not getattr(customer, "pk", None):
        return {"ok": True, "skipped": True, "changed": False}

    ensure_fup_window(customer, plan)
    delta = max(0, int(delta_bytes or 0))
    if delta > 0:
        Customer.objects.filter(pk=customer.pk).update(
            fup_bytes_used=F("fup_bytes_used") + delta
        )
        customer.fup_bytes_used = int(getattr(customer, "fup_bytes_used", 0) or 0) + delta

    return evaluate_customer_fup(customer, plan=plan, recompute_usage=False)


def evaluate_customer_fup(
    customer,
    plan=None,
    *,
    recompute_usage: bool = False,
    sync_access: bool = True,
) -> dict[str, Any]:
    """
    Apply or clear FUP restriction for ``customer``.

    When ``sync_access`` is True and the restriction state changes, push the
    new profile/rate-limit to the NAS in a background thread.
    """
    plan = plan or getattr(customer, "plan", None)
    if not plan_fup_enabled(plan):
        changed = False
        if getattr(customer, "fup_restricted", False) or getattr(
            customer, "fup_bytes_used", 0
        ):
            reset_customer_fup_window(customer, save=True)
            changed = True
        return {
            "ok": True,
            "enabled": False,
            "restricted": False,
            "changed": changed,
            "action": "",
        }

    ensure_fup_window(customer, plan)
    if recompute_usage:
        refresh_customer_fup_usage(customer, plan, save=True)

    limit = plan_fup_limit_bytes(plan)
    used = int(getattr(customer, "fup_bytes_used", 0) or 0)
    should_restrict = limit > 0 and used >= limit
    was_restricted = bool(getattr(customer, "fup_restricted", False))
    action = (getattr(plan, "fup_action", "") or "").strip().lower()
    changed = False
    update_fields: list[str] = []

    if should_restrict and not was_restricted:
        customer.fup_restricted = True
        customer.fup_restricted_at = _now()
        update_fields.extend(["fup_restricted", "fup_restricted_at"])
        changed = True
    elif not should_restrict and was_restricted:
        customer.fup_restricted = False
        customer.fup_restricted_at = None
        update_fields.extend(["fup_restricted", "fup_restricted_at"])
        changed = True

    if update_fields and getattr(customer, "pk", None):
        customer.save(update_fields=update_fields)

    if changed and should_restrict and not was_restricted:
        try:
            from accounts.communications import maybe_notify_fup_limit_reached

            maybe_notify_fup_limit_reached(
                customer,
                plan=plan,
                action=action,
                bytes_used=used,
                bytes_limit=limit,
            )
        except Exception:
            logger.exception(
                "FUP limit notification failed for customer_id=%s",
                getattr(customer, "pk", None),
            )

    if changed and sync_access:
        _schedule_fup_access_sync(customer)

    return {
        "ok": True,
        "enabled": True,
        "restricted": bool(customer.fup_restricted),
        "changed": changed,
        "action": action,
        "bytes_used": used,
        "bytes_limit": limit,
    }


def _schedule_fup_access_sync(customer) -> None:
    """Push updated FUP speeds / disconnect state to MikroTik off-request."""
    customer_id = getattr(customer, "pk", None)
    if not customer_id:
        return

    def _bg(pk: int = int(customer_id)) -> None:
        from django.db import connection

        try:
            from billing.models import Customer
            from core.mikrotik_connect import sync_customer_subscription_access

            row = (
                Customer.objects.filter(pk=pk)
                .select_related("organization", "router", "plan")
                .first()
            )
            if row is None:
                return
            sync_customer_subscription_access(
                row, provision=True, reauthenticate=True
            )
        except Exception:
            logger.exception("FUP access sync failed for customer_id=%s", pk)
        finally:
            connection.close()

    import threading

    threading.Thread(target=_bg, daemon=True).start()
