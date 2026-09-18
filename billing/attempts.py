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


def attempt_summary_for_org(org, *, days: int = 7) -> dict:
    """Aggregate funnel counters for the Attempted connections page."""
    from billing.models import HotspotConnectionAttempt, StkPushRequest

    days = max(1, min(int(days or 7), 90))
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

    if paid_not_surfing == 0:
        authorized_stk_ids = set(
            base.filter(
                event=EVENT_AUTHORIZED, stk_request_id__isnull=False
            ).values_list("stk_request_id", flat=True)
        )
        paid_not_surfing = (
            StkPushRequest.objects.filter(
                organization_id=org.pk,
                purpose=StkPushRequest.Purpose.SUBSCRIPTION,
                status=StkPushRequest.Status.SUCCESS,
                subscription_applied=True,
                completed_at__gte=since,
                customer__service_type="hotspot",
            )
            .exclude(pk__in=authorized_stk_ids)
            .count()
        )

    recent = list(
        base.select_related("customer", "plan", "stk_request")
        .order_by("-created_at")[:80]
    )

    return {
        "days": days,
        "since": since,
        "portal_hits": counts.get(EVENT_PORTAL_HIT, 0),
        "unique_devices": portal_macs,
        "payment_attempts": payment_attempts,
        "payment_success": payment_success,
        "payment_failed": payment_failed,
        "authorized": authorized,
        "paid_not_surfing": paid_not_surfing,
        "recent": recent,
        "event_labels": EVENT_LABELS,
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
