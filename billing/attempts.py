"""Hotspot captive connection / payment attempt analytics."""

from __future__ import annotations

import logging
from datetime import timedelta

from django.core.cache import cache
from django.db.models import Count, Q
from django.utils import timezone

logger = logging.getLogger(__name__)

EVENT_PORTAL_HIT = "portal_hit"
EVENT_PAYMENT_STARTED = "payment_started"
EVENT_PAYMENT_SUCCESS = "payment_success"
EVENT_PAYMENT_FAILED = "payment_failed"
EVENT_PAYMENT_CANCELLED = "payment_cancelled"
EVENT_AUTHORIZED = "authorized"
EVENT_PAID_NOT_SURFING = "paid_not_surfing"

EVENT_LABELS = {
    EVENT_PORTAL_HIT: "Portal visit",
    EVENT_PAYMENT_STARTED: "Payment attempted",
    EVENT_PAYMENT_SUCCESS: "Payment successful",
    EVENT_PAYMENT_FAILED: "Payment failed",
    EVENT_PAYMENT_CANCELLED: "Payment cancelled",
    EVENT_AUTHORIZED: "Connected (surfing)",
    EVENT_PAID_NOT_SURFING: "Paid but not surfing",
}

FILTER_FAILED = "failed"
FILTER_PAID_NOT_SURFING = "paid_not_surfing"
FILTER_SURFING = "surfing"
FILTER_PORTAL = "portal"

FILTER_CHOICES = (
    (FILTER_FAILED, "Failed attempts"),
    (FILTER_PAID_NOT_SURFING, "Paid, not surfing"),
    (FILTER_SURFING, "Paid & surfing"),
    (FILTER_PORTAL, "Portal visits"),
)
FILTER_KEYS = {key for key, _label in FILTER_CHOICES}
DEFAULT_FILTER = FILTER_FAILED


def record_hotspot_attempt(
    *,
    organization,
    event: str,
    mac: str = "",
    phone: str = "",
    customer=None,
    plan=None,
    stk=None,
    stk_id=None,
    router=None,
    detail: dict | None = None,
    debounce_seconds: int = 0,
) -> object | None:
    """
    Persist a Hotspot funnel event for analytics.

    ``debounce_seconds`` skips duplicate portal hits for the same org+MAC.
    """
    from billing.devices import normalize_device_mac
    from billing.models import HotspotConnectionAttempt

    if organization is None or not getattr(organization, "pk", None):
        return None
    event = (event or "").strip().lower()
    if event not in EVENT_LABELS:
        logger.warning("Unknown Hotspot attempt event=%s", event)
        return None

    mac = normalize_device_mac(mac or "")
    if debounce_seconds > 0 and mac:
        cache_key = f"hotspot_attempt:{organization.pk}:{mac}:{event}"
        if cache.get(cache_key):
            return None
        cache.set(cache_key, 1, timeout=int(debounce_seconds))

    stk_ref = stk
    if stk_ref is None and stk_id:
        from billing.models import StkPushRequest

        stk_ref = StkPushRequest.objects.filter(pk=stk_id).first()

    try:
        return HotspotConnectionAttempt.objects.create(
            organization_id=organization.pk,
            customer_id=getattr(customer, "pk", None),
            plan_id=getattr(plan, "pk", None) or getattr(stk_ref, "plan_id", None),
            stk_request_id=getattr(stk_ref, "pk", None),
            router_id=getattr(router, "pk", None),
            mac=mac,
            phone=(phone or getattr(stk_ref, "phone", "") or "")[:20],
            event=event,
            detail=detail or {},
        )
    except Exception:
        logger.exception(
            "Failed to record Hotspot attempt org=%s event=%s mac=%s",
            getattr(organization, "pk", None),
            event,
            mac,
        )
        return None


def _attempt_identity_key(*, mac: str = "", phone: str = "", customer_id=None) -> tuple:
    mac_key = (mac or "").strip().upper()
    phone_key = (phone or "").strip()
    if mac_key:
        return ("mac", mac_key)
    if phone_key:
        return ("phone", phone_key)
    if customer_id:
        return ("customer", int(customer_id))
    return ("anon", "")


def _aggregate_attempt_rows(events, *, count_events=None) -> list[dict]:
    """
    Collapse attempt events into one row per device/phone.

    ``count_events`` limits which events increase the attempt counter; when
    omitted every event increments the count.
    """
    buckets: dict[tuple, dict] = {}
    count_set = set(count_events) if count_events is not None else None

    for row in events:
        key = _attempt_identity_key(
            mac=getattr(row, "mac", "") or "",
            phone=getattr(row, "phone", "") or "",
            customer_id=getattr(row, "customer_id", None),
        )
        bucket = buckets.get(key)
        created_at = getattr(row, "created_at", None)
        if bucket is None:
            bucket = {
                "mac": (getattr(row, "mac", "") or "").strip(),
                "phone": (getattr(row, "phone", "") or "").strip(),
                "customer_id": getattr(row, "customer_id", None),
                "customer": getattr(row, "customer", None),
                "plan": getattr(row, "plan", None),
                "plan_name": getattr(getattr(row, "plan", None), "name", "") or "",
                "event": getattr(row, "event", "") or "",
                "event_label": "",
                "attempt_count": 0,
                "last_at": created_at,
                "first_at": created_at,
            }
            display = getattr(row, "get_event_display", None)
            bucket["event_label"] = display() if callable(display) else EVENT_LABELS.get(
                bucket["event"], bucket["event"] or "—"
            )
            buckets[key] = bucket
        else:
            if created_at and (bucket["last_at"] is None or created_at > bucket["last_at"]):
                bucket["last_at"] = created_at
                bucket["event"] = getattr(row, "event", "") or bucket["event"]
                display = getattr(row, "get_event_display", None)
                bucket["event_label"] = (
                    display()
                    if callable(display)
                    else EVENT_LABELS.get(bucket["event"], bucket["event"] or "—")
                )
                if getattr(row, "plan", None) is not None:
                    bucket["plan"] = row.plan
                    bucket["plan_name"] = getattr(row.plan, "name", "") or bucket["plan_name"]
                if getattr(row, "customer_id", None):
                    bucket["customer_id"] = row.customer_id
                    bucket["customer"] = getattr(row, "customer", bucket["customer"])
                if (getattr(row, "mac", "") or "").strip() and not bucket["mac"]:
                    bucket["mac"] = row.mac.strip()
                if (getattr(row, "phone", "") or "").strip() and not bucket["phone"]:
                    bucket["phone"] = row.phone.strip()
            if created_at and (bucket["first_at"] is None or created_at < bucket["first_at"]):
                bucket["first_at"] = created_at

        event_name = getattr(row, "event", "") or ""
        if count_set is None or event_name in count_set:
            bucket["attempt_count"] += 1

    rows = list(buckets.values())
    rows.sort(
        key=lambda item: (
            item.get("last_at") is not None,
            item.get("last_at"),
            item.get("attempt_count") or 0,
        ),
        reverse=True,
    )
    return rows


def attempt_summary_for_org(org, *, days: int = 7, view: str = DEFAULT_FILTER) -> dict:
    """Aggregate funnel counters and filtered device rows for Attempted connections."""
    from billing.models import HotspotConnectionAttempt, StkPushRequest

    days = max(1, min(int(days or 7), 90))
    view = (view or DEFAULT_FILTER).strip().lower()
    if view not in FILTER_KEYS:
        view = DEFAULT_FILTER

    since = timezone.now() - timedelta(days=days)
    base = HotspotConnectionAttempt.objects.filter(
        organization_id=org.pk,
        created_at__gte=since,
    )
    counts = {
        row["event"]: row["n"]
        for row in base.values("event").annotate(n=Count("id"))
    }

    portal_macs = (
        base.filter(event=EVENT_PORTAL_HIT)
        .exclude(mac="")
        .values("mac")
        .distinct()
        .count()
    )
    payment_attempts = counts.get(EVENT_PAYMENT_STARTED, 0)
    payment_success = counts.get(EVENT_PAYMENT_SUCCESS, 0)
    payment_failed = counts.get(EVENT_PAYMENT_FAILED, 0) + counts.get(
        EVENT_PAYMENT_CANCELLED, 0
    )
    authorized = counts.get(EVENT_AUTHORIZED, 0)
    paid_not_surfing = counts.get(EVENT_PAID_NOT_SURFING, 0)

    authorized_stk_ids = set(
        base.filter(
            event=EVENT_AUTHORIZED, stk_request_id__isnull=False
        ).values_list("stk_request_id", flat=True)
    )
    paid_not_surfing_stks = list(
        StkPushRequest.objects.filter(
            organization_id=org.pk,
            purpose=StkPushRequest.Purpose.SUBSCRIPTION,
            status=StkPushRequest.Status.SUCCESS,
            subscription_applied=True,
            completed_at__gte=since,
            customer__service_type="hotspot",
        )
        .exclude(pk__in=authorized_stk_ids)
        .select_related("customer", "plan")
        .order_by("-completed_at")[:200]
    )
    if paid_not_surfing == 0:
        paid_not_surfing = len(paid_not_surfing_stks)

    related = base.select_related("customer", "plan", "stk_request")

    if view == FILTER_FAILED:
        failed_events = list(
            related.filter(
                event__in=(EVENT_PAYMENT_FAILED, EVENT_PAYMENT_CANCELLED, EVENT_PAYMENT_STARTED)
            ).order_by("-created_at")[:500]
        )
        # Keep identities that actually failed/cancelled; count all starts+fails.
        failed_identities = {
            _attempt_identity_key(
                mac=row.mac or "",
                phone=row.phone or "",
                customer_id=row.customer_id,
            )
            for row in failed_events
            if row.event in (EVENT_PAYMENT_FAILED, EVENT_PAYMENT_CANCELLED)
        }
        scoped = [
            row
            for row in failed_events
            if _attempt_identity_key(
                mac=row.mac or "",
                phone=row.phone or "",
                customer_id=row.customer_id,
            )
            in failed_identities
        ]
        rows = _aggregate_attempt_rows(
            scoped,
            count_events={
                EVENT_PAYMENT_STARTED,
                EVENT_PAYMENT_FAILED,
                EVENT_PAYMENT_CANCELLED,
            },
        )
        # Prefer last status as failed/cancelled when available.
        for item in rows:
            if item.get("event") == EVENT_PAYMENT_STARTED:
                item["event_label"] = "Payment attempted (failed)"
    elif view == FILTER_PAID_NOT_SURFING:
        paid_events = list(
            related.filter(event=EVENT_PAID_NOT_SURFING).order_by("-created_at")[:300]
        )
        if paid_events:
            rows = _aggregate_attempt_rows(paid_events)
        else:
            # Fall back to successful STKs that never got an authorized event.
            from types import SimpleNamespace

            synthetic = [
                SimpleNamespace(
                    mac=getattr(getattr(stk, "customer", None), "hotspot_mac", "") or "",
                    phone=(
                        getattr(stk, "phone", "")
                        or getattr(getattr(stk, "customer", None), "phone", "")
                        or ""
                    ),
                    customer_id=getattr(stk, "customer_id", None),
                    customer=getattr(stk, "customer", None),
                    plan=getattr(stk, "plan", None),
                    event=EVENT_PAID_NOT_SURFING,
                    created_at=getattr(stk, "completed_at", None)
                    or getattr(stk, "created_at", None),
                    get_event_display=lambda: EVENT_LABELS[EVENT_PAID_NOT_SURFING],
                )
                for stk in paid_not_surfing_stks
            ]
            rows = _aggregate_attempt_rows(synthetic)
    elif view == FILTER_SURFING:
        surfing_events = list(
            related.filter(event=EVENT_AUTHORIZED).order_by("-created_at")[:300]
        )
        rows = _aggregate_attempt_rows(surfing_events)
    else:  # FILTER_PORTAL
        portal_events = list(
            related.filter(event=EVENT_PORTAL_HIT).order_by("-created_at")[:500]
        )
        rows = _aggregate_attempt_rows(portal_events)

    filter_counts = {
        FILTER_FAILED: payment_failed,
        FILTER_PAID_NOT_SURFING: paid_not_surfing,
        FILTER_SURFING: authorized,
        FILTER_PORTAL: counts.get(EVENT_PORTAL_HIT, 0),
    }
    filter_tabs = [
        {"key": key, "label": label, "count": filter_counts.get(key, 0)}
        for key, label in FILTER_CHOICES
    ]

    return {
        "days": days,
        "since": since,
        "view": view,
        "portal_hits": counts.get(EVENT_PORTAL_HIT, 0),
        "unique_devices": portal_macs,
        "payment_attempts": payment_attempts,
        "payment_success": payment_success,
        "payment_failed": payment_failed,
        "authorized": authorized,
        "paid_not_surfing": paid_not_surfing,
        "rows": rows[:120],
        "row_count": len(rows),
        "filter_counts": filter_counts,
        "filter_tabs": filter_tabs,
        "event_labels": EVENT_LABELS,
        "filter_choices": FILTER_CHOICES,
    }


def unpaid_hotspot_shells_q():
    """Q matching never-paid Hotspot STK shells (exclude from My clients)."""
    from django.db.models import Exists, OuterRef

    from billing.models import Payment, StkPushRequest

    has_payment = Payment.objects.filter(invoice__customer_id=OuterRef("pk"))
    has_applied = StkPushRequest.objects.filter(
        customer_id=OuterRef("pk"),
        status=StkPushRequest.Status.SUCCESS,
        subscription_applied=True,
    )
    return (
        Q(service_type="hotspot")
        & Q(package_start__isnull=True)
        & Q(package_end__isnull=True)
        & ~Exists(has_payment)
        & ~Exists(has_applied)
    )
