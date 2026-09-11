"""Billing helpers shared by views and forms."""

from __future__ import annotations

import secrets
from calendar import monthrange
from datetime import date, datetime, time, timedelta
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional

from django.core import signing
from django.db.models import Q
from django.utils import timezone

from billing.models import BillingPlan, Customer

RENEW_TOKEN_SALT = "ispcentric-subscription-renew"
# Long grace so SMS/bookmark renew links keep working; still bounds leaked URLs.
RENEW_TOKEN_MAX_AGE_SECONDS = 90 * 24 * 60 * 60


def plans_for_router(
    organization,
    router=None,
    *,
    active_only=True,
    service_type: str | None = None,
):
    """Plans for an org, optionally limited to a MikroTik and/or service type.

    Empty plan.routers means the package is available on every router.
    """
    from django.db.models import Count

    qs = BillingPlan.objects.filter(organization=organization)
    if active_only:
        qs = qs.filter(is_active=True)
    if service_type:
        qs = qs.filter(service_type=service_type)
    if router is None:
        return qs.order_by("price", "name")
    router_id = getattr(router, "pk", router)
    if not router_id:
        return qs.order_by("price", "name")
    return (
        qs.annotate(_router_links=Count("routers"))
        .filter(Q(_router_links=0) | Q(routers=router_id))
        .distinct()
        .order_by("price", "name")
    )


def plan_uses_clock_time(plan_or_duration) -> bool:
    """True for hour-based packages (time-of-day windows)."""
    if plan_or_duration is None:
        return False
    if hasattr(plan_or_duration, "uses_clock_time"):
        return bool(plan_or_duration.uses_clock_time)
    if hasattr(plan_or_duration, "duration_parts"):
        _, unit = plan_or_duration.duration_parts()
        return unit == BillingPlan.DurationUnit.HOURS
    duration = str(getattr(plan_or_duration, "duration", plan_or_duration) or "").strip().lower()
    if duration in BillingPlan.CLOCK_TIME_DURATIONS:
        return True
    if duration == BillingPlan.DurationUnit.HOURS:
        return True
    parts = BillingPlan.LEGACY_DURATION_TO_PARTS.get(duration)
    return bool(parts and parts[1] == BillingPlan.DurationUnit.HOURS)


def generate_customer_account_number(organization, *, prefix: str = "CLT") -> str:
    """Create a unique account number for a customer in this organization."""
    org_id = getattr(organization, "pk", None) or 0
    for _ in range(40):
        candidate = f"{prefix}-{org_id:04d}-{secrets.token_hex(3).upper()}"
        if not Customer.objects.filter(account_number=candidate).exists():
            return candidate
    raise RuntimeError("Could not generate a unique account number.")


def generate_sales_ticket_number(organization=None) -> str:
    """Create a unique sales ticket number like PPP-A1B2."""
    for _ in range(80):
        candidate = f"PPP-{secrets.token_hex(2).upper()}"
        if not Customer.objects.filter(sales_ticket_number=candidate).exists():
            return candidate
    raise RuntimeError("Could not generate a unique sales ticket number.")


def generate_account_number_from_phone(phone: str, *, organization=None) -> str:
    """
    Build a unique account number from the client's phone digits.

    Prefers a normalized Kenyan MSISDN (2547… / 2541…) when the input looks
    like a local mobile number; otherwise uses the raw digits. Falls back to a
    random PPP-prefixed code if the phone has no usable digits.
    """
    msisdn = normalize_kenya_msisdn(phone)
    digits = msisdn or "".join(ch for ch in str(phone or "") if ch.isdigit())
    if not digits:
        return generate_customer_account_number(organization, prefix="PPP")

    base = digits[:40]
    if not Customer.objects.filter(account_number=base).exists():
        return base

    for index in range(2, 100):
        suffix = f"-{index}"
        candidate = f"{base[: 40 - len(suffix)]}{suffix}"
        if not Customer.objects.filter(account_number=candidate).exists():
            return candidate

    return generate_customer_account_number(organization, prefix="PPP")


def _as_local_datetime(value) -> datetime | None:
    """Normalize date/datetime values to an aware local datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if timezone.is_naive(value):
            return timezone.make_aware(value, timezone.get_current_timezone())
        return timezone.localtime(value)
    if isinstance(value, date):
        return timezone.make_aware(
            datetime.combine(value, time.min),
            timezone.get_current_timezone(),
        )
    return None


def _plan_is_hourly(customer) -> bool:
    """Legacy name — true for any clock-time duration (hourly / 6 hours)."""
    plan = getattr(customer, "plan", None)
    return plan_uses_clock_time(plan)


def subscription_access_deadline(customer) -> datetime | None:
    """
    Instant when prepaid access must stop (exclusive).

    Clock-time packages (hourly / 6 hours) end at ``package_end`` exactly.
    Daily / weekly / monthly (and other calendar packages) keep the end
    calendar day inclusive and disconnect at local **00:00** the following
    morning — never at the clock time the package was purchased.
    """
    end = _as_local_datetime(getattr(customer, "package_end", None))
    if end is None:
        return None
    if _plan_is_hourly(customer):
        return end
    end_day = timezone.localtime(end).date()
    next_midnight = datetime.combine(end_day + timedelta(days=1), time.min)
    return timezone.make_aware(next_midnight, timezone.get_current_timezone())


def customer_subscription_window_active(customer, *, now: datetime | None = None) -> bool:
    """True when the client still has remaining prepaid time (stackable renewal)."""
    stamp = now or timezone.localtime()
    if timezone.is_naive(stamp):
        stamp = timezone.make_aware(stamp, timezone.get_current_timezone())
    else:
        stamp = timezone.localtime(stamp)
    active_until = subscription_access_deadline(customer) or _as_local_datetime(
        getattr(customer, "package_end", None)
    )
    return active_until is not None and active_until > stamp


def notify_client_payment_success(
    *,
    organization,
    customer,
    context: dict | None = None,
    stacked: bool = False,
    subject: str = "Payment successful",
) -> None:
    """Send payment_received and optional subscription_extended immediately."""
    from accounts.communications import notify_org_event

    pay_ctx = dict(context or {})
    notify_org_event(
        "payment_received",
        organization=organization,
        client=customer,
        context=pay_ctx,
        subject=subject,
    )
    if stacked:
        notify_org_event(
            "subscription_extended",
            organization=organization,
            client=customer,
            context=pay_ctx,
            subject="Subscription extended",
        )


def notify_client_internet_reconnected(
    *,
    organization,
    customer,
    context: dict | None = None,
) -> None:
    """Send internet_reconnected after access is restored post-payment."""
    from accounts.communications import notify_org_event

    notify_org_event(
        "internet_reconnected",
        organization=organization,
        client=customer,
        context=dict(context or {}),
        subject="Internet reconnection successful",
    )


def customers_near_access_deadline(
    *,
    past_seconds: float = 90,
    future_seconds: float = 45,
    now: datetime | None = None,
):
    """
    Active prepaid customers whose access deadline is imminent or just passed.

    Used by the expiry-watch loop so Hotspot/PPPoE are blocked near the real
    cut-off instead of waiting for the next full subscription sweep.
    """
    from billing.models import Customer

    stamp = now or timezone.now()
    if timezone.is_naive(stamp):
        stamp = timezone.make_aware(stamp, timezone.get_current_timezone())
    qs = (
        Customer.objects.filter(
            status=Customer.Status.ACTIVE,
            service_type__in={
                Customer.ServiceType.PPPOE,
                Customer.ServiceType.HOTSPOT,
            },
        )
        .exclude(package_end=None)
        .filter(
            Q(service_type=Customer.ServiceType.PPPOE, pppoe_username__gt="")
            | Q(service_type=Customer.ServiceType.HOTSPOT, hotspot_mac__gt="")
        )
        .select_related("plan", "organization", "router")
        .order_by("id")
    )
    for customer in qs.iterator(chunk_size=200):
        deadline = subscription_access_deadline(customer)
        if deadline is None:
            continue
        delta = (deadline - stamp).total_seconds()
        if -float(past_seconds) <= delta <= float(future_seconds):
            yield customer


def subscription_period_allows(customer, *, today: date | None = None) -> bool:
    """
    Whether now/today falls inside the customer's package_start–package_end window.

    Missing dates mean no period is configured yet → allow access (legacy clients).
    Hourly / 6-hour packages compare against the current time.
    Other packages include the end calendar day and cut off at local 00:00 after it.
    """
    start = _as_local_datetime(getattr(customer, "package_start", None))
    end = _as_local_datetime(getattr(customer, "package_end", None))
    if start is None and end is None:
        return True

    if _plan_is_hourly(customer):
        now = timezone.localtime()
        if start is not None and now < start:
            return False
        if end is not None and now >= end:
            return False
        return True

    # Date-only callers (reports / admin filters) keep end-day-inclusive semantics.
    if today is not None:
        start_day = timezone.localtime(start).date() if start else None
        end_day = timezone.localtime(end).date() if end else None
        if start_day is not None and today < start_day:
            return False
        if end_day is not None and today > end_day:
            return False
        return True

    now = timezone.localtime()
    if start is not None:
        start_day = timezone.localtime(start).date()
        day_start = timezone.make_aware(
            datetime.combine(start_day, time.min),
            timezone.get_current_timezone(),
        )
        if now < day_start:
            return False
    deadline = subscription_access_deadline(customer)
    if deadline is not None and now >= deadline:
        return False
    return True


def customer_subscription_expired(customer, *, today: date | None = None) -> bool:
    """True when a package end is set and access has passed its cut-off."""
    end = _as_local_datetime(getattr(customer, "package_end", None))
    if end is None:
        return False
    if today is not None and not _plan_is_hourly(customer):
        return today > timezone.localtime(end).date()
    deadline = subscription_access_deadline(customer)
    if deadline is None:
        return False
    return timezone.localtime() >= deadline


def subscription_period_progress(customer, *, now: datetime | None = None) -> dict | None:
    """
    Progress through the current package window.

    Returns None when start/end are missing or invalid.
    ``ratio`` is elapsed / total (may exceed 1.0 after expiry).
    Calendar packages measure against the midnight cut-off, not the purchase clock.
    """
    start = _as_local_datetime(getattr(customer, "package_start", None))
    end = _as_local_datetime(getattr(customer, "package_end", None))
    if start is None or end is None:
        return None
    deadline = subscription_access_deadline(customer) or end
    if deadline <= start:
        return None
    now = now or timezone.localtime()
    if timezone.is_naive(now):
        now = timezone.make_aware(now, timezone.get_current_timezone())
    else:
        now = timezone.localtime(now)
    total = (deadline - start).total_seconds()
    if total <= 0:
        return None
    elapsed = (now - start).total_seconds()
    ratio = elapsed / total
    expired = customer_subscription_expired(customer)
    return {
        "ratio": ratio,
        "percent": int(min(100, max(0, round(ratio * 100)))),
        "expired": expired,
        "at_three_quarters": ratio >= 0.75,
        "needs_attention": expired or ratio >= 0.75,
        "package_start": start,
        "package_end": end,
        "access_deadline": deadline,
    }


def customers_needing_renewal_attention(organization):
    """
    Customers whose package has expired, or who have used ≥ ¾ of the period.

    Returns a list of dicts: ``customer``, ``progress``, ``attention``
    (``expired`` or ``three_quarters``), sorted expired first then by progress.
    """
    if not organization:
        return []
    from datetime import timedelta

    from django.db.models import Q
    from django.db.models.expressions import RawSQL

    now = timezone.localtime()
    # Narrow the scan before Python progress checks:
    # - package_end already past (with +1 day buffer for calendar midnight cut-off)
    # - or MySQL says ≥ 75% of the package window has elapsed
    past_three_quarters = RawSQL(
        "(CASE WHEN package_start IS NULL OR package_end IS NULL OR "
        "TIMESTAMPDIFF(SECOND, package_start, package_end) <= 0 THEN 0 "
        "WHEN TIMESTAMPDIFF(SECOND, package_start, %s) * 4 >= "
        "TIMESTAMPDIFF(SECOND, package_start, package_end) * 3 THEN 1 "
        "ELSE 0 END)",
        (now,),
    )
    qs = (
        Customer.objects.filter(organization=organization)
        .filter(package_end__isnull=False)
        .annotate(_past_three_quarters=past_three_quarters)
        .filter(
            Q(package_end__lt=now + timedelta(days=1)) | Q(_past_three_quarters=1)
        )
        .select_related("plan")
        .order_by("package_end", "full_name")
    )
    rows = []
    for customer in qs.iterator(chunk_size=200):
        expired = customer_subscription_expired(customer)
        progress = subscription_period_progress(customer, now=now)
        if expired:
            rows.append(
                {
                    "customer": customer,
                    "progress": progress,
                    "attention": "expired",
                    "sort_ratio": (progress or {}).get("ratio", 2.0),
                }
            )
            continue
        if progress and progress["at_three_quarters"]:
            rows.append(
                {
                    "customer": customer,
                    "progress": progress,
                    "attention": "three_quarters",
                    "sort_ratio": progress["ratio"],
                }
            )
    rows.sort(
        key=lambda row: (
            0 if row["attention"] == "expired" else 1,
            -row["sort_ratio"],
            (row["customer"].full_name or "").lower(),
        )
    )
    return rows


def customer_package_is_paused(customer) -> bool:
    """True when the package clock is frozen and surfing should stay blocked."""
    return getattr(customer, "package_paused_at", None) is not None


def package_remaining_seconds(customer, *, now: datetime | None = None) -> int | None:
    """
    Seconds left in the current package window.

    While paused, the clock freezes at ``package_paused_at`` so remaining time
    does not shrink until the package is resumed.
    """
    deadline = subscription_access_deadline(customer)
    if deadline is None:
        return None
    now = now or timezone.localtime()
    if timezone.is_naive(now):
        now = timezone.make_aware(now, timezone.get_current_timezone())
    else:
        now = timezone.localtime(now)
    paused_at = _as_local_datetime(getattr(customer, "package_paused_at", None))
    reference = paused_at if paused_at is not None else now
    return int((deadline - reference).total_seconds())


def pause_customer_package(customer, *, now: datetime | None = None):
    """
    Freeze the package clock and block surfing until resume.

    Remaining time is preserved: on resume, ``package_end`` is extended by the
    pause duration so the client continues with what they had left.
    """
    if customer_package_is_paused(customer):
        raise ValueError("This package is already paused.")
    if getattr(customer, "package_end", None) is None:
        raise ValueError("Set a package period before pausing.")
    if customer_subscription_expired(customer):
        raise ValueError("Cannot pause an expired package.")
    now = now or timezone.localtime()
    if timezone.is_naive(now):
        now = timezone.make_aware(now, timezone.get_current_timezone())
    else:
        now = timezone.localtime(now)
    start = _as_local_datetime(getattr(customer, "package_start", None))
    if start is not None and now < start:
        raise ValueError("Cannot pause a package that has not started yet.")
    customer.package_paused_at = now
    customer.save(update_fields=["package_paused_at"])
    try:
        from core.mikrotik_connect import invalidate_captive_redirect_cache_for_customer

        invalidate_captive_redirect_cache_for_customer(customer)
    except Exception:
        pass
    from accounts.communications import notify_org_event

    notify_org_event(
        "package_pause_resume",
        organization=getattr(customer, "organization", None),
        client=customer,
        context={"status": "paused"},
        subject="Package paused",
    )
    notify_org_event(
        "account_status",
        organization=getattr(customer, "organization", None),
        client=customer,
        context={"status": "suspended", "status_label": "Internet suspended"},
        subject="Internet suspended",
    )
    return customer


def resume_customer_package(customer, *, now: datetime | None = None):
    """
    Unfreeze the package clock and restore surfing for the remaining period.

    Extends ``package_end`` by how long the package was paused so the client
    continues from the time they had left when paused.
    """
    paused_at = _as_local_datetime(getattr(customer, "package_paused_at", None))
    if paused_at is None:
        raise ValueError("This package is not paused.")
    now = now or timezone.localtime()
    if timezone.is_naive(now):
        now = timezone.make_aware(now, timezone.get_current_timezone())
    else:
        now = timezone.localtime(now)
    pause_duration = now - paused_at
    if pause_duration.total_seconds() < 0:
        pause_duration = timedelta(0)
    update_fields = ["package_paused_at"]
    end = _as_local_datetime(getattr(customer, "package_end", None))
    if end is not None and pause_duration.total_seconds() > 0:
        customer.package_end = end + pause_duration
        update_fields.append("package_end")
    customer.package_paused_at = None
    customer.save(update_fields=update_fields)
    try:
        from core.mikrotik_connect import invalidate_captive_redirect_cache_for_customer

        invalidate_captive_redirect_cache_for_customer(customer)
    except Exception:
        pass
    from accounts.communications import notify_org_event

    notify_org_event(
        "package_pause_resume",
        organization=getattr(customer, "organization", None),
        client=customer,
        context={"status": "resumed"},
        subject="Package resumed",
    )
    notify_org_event(
        "account_status",
        organization=getattr(customer, "organization", None),
        client=customer,
        context={"status": "active", "status_label": "Internet reactivated"},
        subject="Internet reactivated",
    )
    return customer


def clear_customer_package_pause(customer, *, save: bool = True) -> bool:
    """Clear a frozen package clock (e.g. after assigning a fresh period)."""
    if not customer_package_is_paused(customer):
        return False
    customer.package_paused_at = None
    if save:
        customer.save(update_fields=["package_paused_at"])
    return True


def end_customer_subscription(customer, *, now: datetime | None = None):
    """
    Immediately end the prepaid window and cut surfing.

    Remaining time is forfeited (unlike pause). Hotspot unused vouchers are
    invalidated so devices cannot reconnect until the next recharge.
    """
    if getattr(customer, "package_start", None) is None and getattr(
        customer, "package_end", None
    ) is None:
        raise ValueError("This client has no package period to end.")
    if customer_subscription_expired(customer) and not customer_package_is_paused(customer):
        raise ValueError("This subscription has already ended.")

    now = now or timezone.localtime()
    if timezone.is_naive(now):
        now = timezone.make_aware(now, timezone.get_current_timezone())
    else:
        now = timezone.localtime(now)

    clear_customer_package_pause(customer, save=False)
    plan = getattr(customer, "plan", None)
    if plan_uses_clock_time(plan):
        customer.package_end = now
    else:
        # Calendar packages stay live through the end calendar day. Set end to
        # yesterday so today is already past the inclusive window.
        yesterday = now.date() - timedelta(days=1)
        customer.package_end = timezone.make_aware(
            datetime.combine(yesterday, time.min),
            timezone.get_current_timezone(),
        )
    customer.save(update_fields=["package_end", "package_paused_at"])

    try:
        from billing.vouchers import invalidate_unused_customer_vouchers

        invalidate_unused_customer_vouchers(customer)
    except Exception:  # noqa: BLE001 — ending must not fail on voucher cleanup
        pass
    return customer


def organization_uses_dynamic_access(organization) -> bool:
    """
    Dual-path access: home CPE dials PPPoE during the subscription window;
    phones and other devices pay for ISP Hotspot only after a successful purchase.
    """
    if not organization:
        return False
    return bool(
        getattr(organization, "pppoe_compulsory", False)
        and getattr(organization, "hotspot_enabled", False)
    )


def customer_can_surf_via_hotspot(
    customer, organization=None, *, today: date | None = None
) -> bool:
    """
    Hotspot surfing is allowed only for HOTSPOT customers with an active,
    paid package window (set after voucher redeem or cash recharge).
    """
    if getattr(customer, "service_type", None) != Customer.ServiceType.HOTSPOT:
        return False
    return customer_receives_internet(customer, organization, today=today)


def customer_can_surf_via_pppoe(
    customer, organization=None, *, today: date | None = None
) -> bool:
    """
    PPPoE surfing is allowed only for PPPOE customers inside the subscription
    period. Payment alone does not extend access until the package is applied.
    """
    if getattr(customer, "service_type", None) != Customer.ServiceType.PPPOE:
        return False
    org = organization or getattr(customer, "organization", None)
    if org and getattr(org, "pppoe_compulsory", False):
        if not (customer.pppoe_username or "").strip():
            return False
    return customer_receives_internet(customer, organization, today=today)


def customer_receives_internet(customer, organization=None, *, today: date | None = None) -> bool:
    """
    Whether this customer is eligible for internet under org + subscription policy.

    Blocks when:
    - customer status is not active
    - package is paused (clock frozen; remaining time preserved)
    - today/now is outside package_start / package_end (when set)
    - Hotspot or PPPoE customer has no purchased period at all
    - PPPoE is compulsory and a non-Hotspot customer is not a registered PPPoE user

    Prefer ``customer_can_surf_via_hotspot`` / ``customer_can_surf_via_pppoe`` when
    enforcing the dynamic dual-path model (PPPoE compulsory + Hotspot fallback).
    """
    org = organization or getattr(customer, "organization", None)
    if getattr(customer, "status", None) != Customer.Status.ACTIVE:
        return False
    if customer_package_is_paused(customer):
        return False
    if customer.service_type in {
        Customer.ServiceType.HOTSPOT,
        Customer.ServiceType.PPPOE,
    }:
        # Both access paths are prepaid. Customer rows are often created at
        # register/captive time before money arrives — missing dates must not
        # grant free surfing. A purchased window is required.
        if getattr(customer, "package_end", None) is None:
            return False
        if not subscription_period_allows(customer, today=today):
            return False
        if customer.service_type == Customer.ServiceType.HOTSPOT:
            # Hotspot login is itself the controlled access method.
            return True
        if not org or not getattr(org, "pppoe_compulsory", False):
            return True
        return bool((customer.pppoe_username or "").strip())
    if not subscription_period_allows(customer, today=today):
        return False
    if not org or not getattr(org, "pppoe_compulsory", False):
        return True
    return (
        customer.service_type == Customer.ServiceType.PPPOE
        and bool((customer.pppoe_username or "").strip())
    )


def customer_portal_access_context(customer, *, preview: str = "") -> dict:
    """
    Captive portal copy when a subscriber is paused, expired, or can renew.

    Paused packages must not offer payment — staff must resume the subscription.

    ``preview`` is for staff theme preview only (``paused`` / ``renew`` / ``demo``)
    and does not change billing state.
    """
    preview = (preview or "").strip().lower()
    if preview == "paused":
        remaining_label = ""
        if customer:
            remaining = package_remaining_seconds(customer)
            if remaining is not None and remaining > 0:
                hours, rem = divmod(remaining, 3600)
                minutes, _ = divmod(rem, 60)
                if hours:
                    remaining_label = f"{hours}h {minutes}m left when resumed"
                elif minutes:
                    remaining_label = f"{minutes} minutes left when resumed"
                else:
                    remaining_label = "Less than a minute left when resumed"
        if not remaining_label:
            remaining_label = "1 day 6 hours left when resumed"
        return {
            "subscription_paused": True,
            "subscription_expired": False,
            "access_banner_title": "Internet paused",
            "access_banner_message": (
                "Your provider paused this subscription. Internet stays off "
                "until they resume your package."
                + (f" {remaining_label}." if remaining_label else "")
            ),
            "show_renew_payment": False,
        }
    if preview in {"renew", "demo"}:
        return {
            "subscription_paused": False,
            "subscription_expired": True,
            "access_banner_title": "Subscription ended",
            "access_banner_message": (
                "Choose a package below and pay with M-Pesa to restore internet."
            ),
            "show_renew_payment": True,
        }

    paused = bool(customer and customer_package_is_paused(customer))
    expired = bool(customer and customer_subscription_expired(customer))
    receives = bool(customer and customer_receives_internet(customer))

    ctx = {
        "subscription_paused": paused,
        "subscription_expired": expired,
        "access_banner_title": "",
        "access_banner_message": "",
        "show_renew_payment": True,
    }
    if paused:
        remaining_label = ""
        if customer:
            remaining = package_remaining_seconds(customer)
            if remaining is not None and remaining > 0:
                hours, rem = divmod(remaining, 3600)
                minutes, _ = divmod(rem, 60)
                if hours:
                    remaining_label = f"{hours}h {minutes}m left when resumed"
                elif minutes:
                    remaining_label = f"{minutes} minutes left when resumed"
                else:
                    remaining_label = "Less than a minute left when resumed"
        ctx.update(
            {
                "access_banner_title": "Internet paused",
                "access_banner_message": (
                    "Your provider paused this subscription. Internet stays off "
                    "until they resume your package."
                    + (f" {remaining_label}." if remaining_label else "")
                ),
                "show_renew_payment": False,
            }
        )
    elif customer and (expired or not receives):
        ctx.update(
            {
                "access_banner_title": "Subscription ended",
                "access_banner_message": (
                    "Choose a package below and pay with M-Pesa to restore internet."
                ),
                "show_renew_payment": True,
            }
        )
    return ctx


def customer_pppoe_secret_disabled(customer, *, today: date | None = None) -> bool:
    """
    Whether the NAS /ppp/secret should be disabled.

    Suspended → disable secret (cannot dial).
    Inactive / expired / unpaid → keep secret enabled so the CPE can dial,
    but provision onto the blocked PPP profile so surfing is denied at the NAS.
    """
    if getattr(customer, "status", None) == Customer.Status.SUSPENDED:
        return True
    return False


def make_renew_token(customer) -> str:
    """Signed token for the public renew / captive portal page."""
    pk = getattr(customer, "pk", None)
    if not pk:
        raise ValueError("Customer must be saved before creating a renew token.")
    return signing.dumps({"cid": int(pk)}, salt=RENEW_TOKEN_SALT)


def resolve_customer_from_renew_token(token: str) -> Customer | None:
    """Load a customer from a renew token, or None if invalid/expired."""
    try:
        payload = signing.loads(
            token,
            salt=RENEW_TOKEN_SALT,
            max_age=RENEW_TOKEN_MAX_AGE_SECONDS,
        )
    except signing.BadSignature:
        return None
    customer_id = payload.get("cid") if isinstance(payload, dict) else None
    if not customer_id:
        return None
    return (
        Customer.objects.select_related("plan", "organization", "router")
        .filter(pk=customer_id)
        .first()
    )


def _add_months(start: date, months: int) -> date:
    """Add calendar months, clamping the day to the target month's last day."""
    month_index = start.month - 1 + months
    year = start.year + month_index // 12
    month = month_index % 12 + 1
    day = min(start.day, monthrange(year, month)[1])
    return date(year, month, day)


def normalize_kenya_msisdn(phone: str) -> str:
    """Normalize a Kenyan phone number to 2547… / 2541… digits for Daraja."""
    digits = "".join(ch for ch in str(phone or "") if ch.isdigit())
    if digits.startswith("254") and len(digits) >= 12:
        return digits[:12]
    if digits.startswith("0") and len(digits) >= 10:
        return f"254{digits[1:10]}"
    if len(digits) == 9 and digits[0] in {"7", "1"}:
        return f"254{digits}"
    return digits


def format_customer_phone_display(phone: str) -> str:
    """Prefer 07xxxxxxxx / 01xxxxxxxx for stored and displayed customer phones."""
    raw = (phone or "").strip()
    msisdn = normalize_kenya_msisdn(raw)
    if msisdn.startswith("254") and len(msisdn) == 12:
        return f"0{msisdn[3:]}"
    return raw


def normalize_customer_phone_key(phone: str) -> str:
    """Canonical phone key for duplicate detection within an organization."""
    raw = (phone or "").strip()
    if not raw:
        return ""
    msisdn = normalize_kenya_msisdn(raw)
    if msisdn.startswith("254") and len(msisdn) == 12:
        return msisdn
    return "".join(ch for ch in raw if ch.isdigit())


def find_customer_by_phone(organization, phone: str, *, exclude_pk=None):
    """Return the first customer in this org whose phone normalizes to the same key."""
    key = normalize_customer_phone_key(phone)
    if not key or organization is None:
        return None
    org_id = getattr(organization, "pk", organization)
    qs = Customer.objects.filter(organization_id=org_id).exclude(phone="").order_by("id")
    if exclude_pk:
        qs = qs.exclude(pk=exclude_pk)
    for row in qs.iterator():
        if normalize_customer_phone_key(row.phone) == key:
            return row
    return None


def customer_phone_is_taken(organization, phone: str, *, exclude_pk=None) -> bool:
    return find_customer_by_phone(organization, phone, exclude_pk=exclude_pk) is not None


PHONE_ALREADY_REGISTERED = (
    "That phone number is already registered to another account."
)


def _resolve_duration_parts(
    plan: BillingPlan | None = None,
    *,
    duration: str | None = None,
    duration_value: int | None = None,
    duration_unit: str | None = None,
) -> tuple[int, str]:
    """Normalize plan / legacy key / explicit parts into (value, unit)."""
    if duration_value is not None and duration_unit:
        value = int(duration_value)
        unit = str(duration_unit).strip().lower()
        if value >= 1 and unit in {choice.value for choice in BillingPlan.DurationUnit}:
            return value, unit
    if plan is not None and hasattr(plan, "duration_parts"):
        return plan.duration_parts()
    duration_key = str(duration or getattr(plan, "duration", None) or "").strip().lower()
    parts = BillingPlan.LEGACY_DURATION_TO_PARTS.get(duration_key)
    if parts:
        return parts
    raise ValueError("Unsupported package duration.")


def plan_billing_unit_seconds(plan, *, reference: datetime | date | None = None) -> float:
    """Length of one billed plan unit in seconds (for proration)."""
    if plan is None:
        raise ValueError("Select a package.")
    value, unit = _resolve_duration_parts(plan)
    if unit == BillingPlan.DurationUnit.HOURS:
        return float(value * 3600)
    if unit == BillingPlan.DurationUnit.DAYS:
        return float(value * 86400)
    if unit == BillingPlan.DurationUnit.WEEKS:
        return float(value * 7 * 86400)
    ref = reference or timezone.localtime()
    if isinstance(ref, datetime):
        ref_day = timezone.localtime(ref).date() if timezone.is_aware(ref) else ref.date()
    else:
        ref_day = ref
    if unit == BillingPlan.DurationUnit.MONTHS:
        month_count = value
    elif unit == BillingPlan.DurationUnit.YEARS:
        month_count = value * 12
    else:
        raise ValueError("Unsupported package duration for partial recharge.")
    total = 0
    cursor = ref_day
    for _ in range(max(int(month_count), 1)):
        days = monthrange(cursor.year, cursor.month)[1]
        total += days
        cursor = _add_months(cursor.replace(day=1), 1)
    return float(total * 86400)


def partial_recharge_window(
    from_date: date,
    to_date: date,
    plan,
) -> tuple[datetime, datetime]:
    """
    Build package_start / package_end for a partial recharge date range.

    Both dates are inclusive calendar days. Clock-time packages use an exclusive
    end at local midnight after ``to_date``. Calendar packages store ``to_date``
    as package_end (end day stays inclusive via subscription_access_deadline).
    """
    if from_date is None or to_date is None:
        raise ValueError("Select both the from and to dates.")
    if to_date < from_date:
        raise ValueError("The to date must be on or after the from date.")
    tz = timezone.get_current_timezone()
    start = timezone.make_aware(datetime.combine(from_date, time.min), tz)
    if plan_uses_clock_time(plan):
        end = timezone.make_aware(
            datetime.combine(to_date + timedelta(days=1), time.min),
            tz,
        )
    else:
        end = timezone.make_aware(datetime.combine(to_date, time.min), tz)
    return start, end


def partial_recharge_billed_seconds(start: datetime, end: datetime, plan) -> float:
    """Seconds used to prorate amount for a partial window."""
    start_dt = _as_local_datetime(start)
    end_dt = _as_local_datetime(end)
    if start_dt is None or end_dt is None:
        raise ValueError("Invalid partial recharge window.")
    if plan_uses_clock_time(plan):
        seconds = (end_dt - start_dt).total_seconds()
    else:
        end_day = timezone.localtime(end_dt).date()
        deadline = timezone.make_aware(
            datetime.combine(end_day + timedelta(days=1), time.min),
            timezone.get_current_timezone(),
        )
        seconds = (deadline - start_dt).total_seconds()
    if seconds <= 0:
        raise ValueError("Partial recharge period must be greater than zero.")
    return seconds


def compute_partial_recharge_amount(plan, start: datetime, end: datetime) -> Decimal:
    """Prorate plan price across the selected partial window."""
    if plan is None:
        raise ValueError("Select a package.")
    try:
        price = Decimal(plan.price)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Package price is invalid.") from exc
    if price < 0:
        raise ValueError("Package price must not be negative.")
    seconds = partial_recharge_billed_seconds(start, end, plan)
    unit = plan_billing_unit_seconds(plan, reference=start)
    if unit <= 0:
        raise ValueError("Could not determine the package billing unit.")
    units = Decimal(str(seconds)) / Decimal(str(unit))
    amount = (price * units).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if amount <= 0:
        # Tiny windows on cheap hourly plans still record a minimum charge.
        amount = Decimal("0.01")
    return amount


def compute_partial_to_date_from_amount(
    plan,
    from_date: date,
    amount,
) -> date:
    """
    Derive the inclusive end date from cash received at the package rate.

    Inverse of day-based proration: amount ≈ price × (days × 86400 / unit).
    Days are rounded half-up, with a minimum of one inclusive day.
    """
    if from_date is None:
        raise ValueError("Select the start date.")
    if plan is None:
        raise ValueError("Select a package.")
    try:
        price = Decimal(plan.price)
        amount = Decimal(amount)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Enter a valid amount.") from exc
    if amount <= 0:
        raise ValueError("Amount must be greater than zero.")
    if price <= 0:
        raise ValueError("Package price must be greater than zero.")

    start = timezone.make_aware(
        datetime.combine(from_date, time.min),
        timezone.get_current_timezone(),
    )
    unit = plan_billing_unit_seconds(plan, reference=start)
    if unit <= 0:
        raise ValueError("Could not determine the package billing unit.")

    days_exact = (amount / price) * (Decimal(str(unit)) / Decimal("86400"))
    inclusive_days = int(days_exact.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    if inclusive_days < 1:
        inclusive_days = 1
    return from_date + timedelta(days=inclusive_days - 1)


def apply_subscription_period(customer, *, plan=None, start=None, end=None):
    """Set an explicit prepaid surfing window (partial recharge)."""
    plan = plan or getattr(customer, "plan", None)
    if plan is None:
        raise ValueError("Customer has no billing plan to renew.")
    start_dt = _as_local_datetime(start)
    end_dt = _as_local_datetime(end)
    if start_dt is None or end_dt is None:
        raise ValueError("Partial recharge requires both from and to dates.")
    if end_dt <= start_dt and plan_uses_clock_time(plan):
        raise ValueError("The to date must be after the from date.")
    if timezone.localtime(end_dt).date() < timezone.localtime(start_dt).date():
        raise ValueError("The to date must be on or after the from date.")
    customer.package_start = start_dt
    customer.package_end = end_dt
    customer.usage_tracking_since = start_dt
    update_fields = ["package_start", "package_end", "usage_tracking_since"]
    if clear_customer_package_pause(customer, save=False):
        update_fields.append("package_paused_at")
    customer.save(update_fields=update_fields)
    return customer


def apply_cash_recharge_period(customer, *, plan=None, start=None, end=None):
    """
    Apply a cash-recharge surfing window without forfeiting remaining paid time.

    If the client is still inside an active prepaid window, the purchased
    duration is stacked onto the current access deadline and ``package_start``
    is left alone. Only expired / missing packages get the absolute start–end
    range from the form.
    """
    plan = plan or getattr(customer, "plan", None)
    if plan is None:
        raise ValueError("Customer has no billing plan to renew.")
    start_dt = _as_local_datetime(start)
    end_dt = _as_local_datetime(end)
    if start_dt is None or end_dt is None:
        raise ValueError("Partial recharge requires both from and to dates.")

    purchased_seconds = partial_recharge_billed_seconds(start_dt, end_dt, plan)
    now = timezone.localtime()
    active_until = subscription_access_deadline(customer)
    if active_until is None or active_until <= now:
        return apply_subscription_period(
            customer, plan=plan, start=start_dt, end=end_dt
        )

    current_start = _as_local_datetime(getattr(customer, "package_start", None))
    access_start = (
        current_start if current_start is not None and current_start <= now else now
    )
    new_deadline = active_until + timedelta(seconds=purchased_seconds)
    if plan_uses_clock_time(plan):
        package_end = new_deadline
    else:
        # Calendar packages store the inclusive end day; access stops at the
        # following local midnight (subscription_access_deadline).
        end_day = timezone.localtime(new_deadline - timedelta(microseconds=1)).date()
        package_end = timezone.make_aware(
            datetime.combine(end_day, time.min),
            timezone.get_current_timezone(),
        )

    customer.package_start = access_start
    customer.package_end = package_end
    update_fields = ["package_start", "package_end"]
    if clear_customer_package_pause(customer, save=False):
        update_fields.append("package_paused_at")
    customer.save(update_fields=update_fields)
    return customer


def apply_subscription_renewal(customer, *, plan=None):
    """
    Extend the customer's package period after a successful payment.

    If the current period is still active, stack the new period onto package_end.
    If expired / missing, start a fresh period from now.
    """
    plan = plan or getattr(customer, "plan", None)
    if plan is None:
        raise ValueError("Customer has no billing plan to renew.")
    now = timezone.localtime()
    current_start = _as_local_datetime(getattr(customer, "package_start", None))
    current_end = _as_local_datetime(getattr(customer, "package_end", None))
    # Calendar packages stay active until local midnight after the end day —
    # do not treat an afternoon package_end clock time as already expired.
    active_until = subscription_access_deadline(customer) or current_end
    fresh_start = True
    if active_until is not None and active_until > now:
        # Stack the purchased duration onto the current expiry, but preserve
        # the start of the active access window. Moving package_start to the
        # old expiry makes a customer who pays twice appear ineligible until
        # the first package ends.
        calculation_start = current_end or active_until
        access_start = current_start if current_start and current_start <= now else now
        fresh_start = False
    else:
        calculation_start = now
        access_start = now
    end = compute_package_end(calculation_start, plan)
    if end is None:
        raise ValueError("Could not compute the new package end from the plan duration.")
    customer.package_start = access_start
    customer.package_end = end
    update_fields = ["package_start", "package_end"]
    # Fresh renewals restart data-used tracking; stacked renewals keep the
    # current package window's counter so mid-period top-ups stay continuous.
    if fresh_start or getattr(customer, "usage_tracking_since", None) is None:
        customer.usage_tracking_since = access_start
        update_fields.append("usage_tracking_since")
    if clear_customer_package_pause(customer, save=False):
        update_fields.append("package_paused_at")
    customer.save(update_fields=update_fields)
    return customer


def reset_customer_usage_tracking(customer, *, at=None):
    """
    Restart data-used tracking from ``at`` (default: now).

    Keeps historical usage samples; charts/totals simply ignore traffic before
    the new baseline so operators can monitor the current package window.
    """
    stamp = _as_local_datetime(at) or timezone.localtime()
    customer.usage_tracking_since = stamp
    customer.save(update_fields=["usage_tracking_since"])
    return customer


def set_customer_package_renewed(customer, *, renewed_at, plan=None):
    """
    Record when the client's package was renewed and restart usage tracking.

    Sets ``package_start`` to the renewal moment, recomputes ``package_end``
    from the plan duration when a plan is available, and aligns
    ``usage_tracking_since`` so data-used totals match that package window.
    """
    plan = plan or getattr(customer, "plan", None)
    start_dt = _as_local_datetime(renewed_at)
    if start_dt is None:
        raise ValueError("Choose a valid package renewal date.")
    customer.package_start = start_dt
    update_fields = ["package_start", "usage_tracking_since"]
    if plan is not None:
        end = compute_package_end(start_dt, plan)
        if end is None:
            raise ValueError("Could not compute the package end from the plan duration.")
        customer.package_end = end
        update_fields.append("package_end")
    customer.usage_tracking_since = start_dt
    if clear_customer_package_pause(customer, save=False):
        update_fields.append("package_paused_at")
    customer.save(update_fields=update_fields)
    return customer


def payment_mpesa_reference(payment) -> str:
    """Prefer the real M-Pesa receipt over Safaricom CheckoutRequestID placeholders."""
    checkout_ids: set[str] = set()
    for stk in payment.stk_push_requests.all():
        receipt = (stk.mpesa_receipt or "").strip()
        if receipt:
            return receipt
        # Recover from raw_callback when the model field was never copied.
        raw = stk.raw_callback if isinstance(stk.raw_callback, dict) else {}
        if raw:
            from billing.stk import extract_mpesa_receipt_from_raw

            buried = extract_mpesa_receipt_from_raw(raw)
            if buried:
                return buried
        checkout_id = (stk.checkout_request_id or "").strip()
        if checkout_id:
            checkout_ids.add(checkout_id)
    ref = (payment.reference or "").strip()
    if not ref:
        return ""
    # Checkout IDs look like ws_CO_… and are not the SMS receipt number.
    if ref in checkout_ids or ref.startswith("ws_CO_"):
        return ""
    return ref


def heal_payment_mpesa_reference(payment) -> str:
    """
    Resolve the display M-Pesa receipt and persist it onto payment.reference
    when a real receipt is known on a linked STK row.

    Works for payments collected via Company Payment Gateway or an ISP's own
    Payment Gateway — credential source does not affect receipt persistence.
    """
    display_ref = payment_mpesa_reference(payment)
    if not display_ref:
        return ""
    current = (payment.reference or "").strip()
    linked_checkouts = {
        (stk.checkout_request_id or "").strip()
        for stk in payment.stk_push_requests.all()
        if (stk.checkout_request_id or "").strip()
    }
    if (
        not current
        or current in linked_checkouts
        or current.startswith("ws_CO_")
    ) and current != display_ref:
        payment.reference = display_ref[:100]
        payment.save(update_fields=["reference"])
    # Keep STK.mpesa_receipt in sync when recovery came from raw_callback only.
    for stk in payment.stk_push_requests.all():
        if (stk.mpesa_receipt or "").strip() == display_ref:
            continue
        from billing.stk import ensure_stk_payment_receipt

        ensure_stk_payment_receipt(stk, receipt=display_ref)
        break
    return display_ref


def heal_payment_mpesa_phone(payment) -> str:
    """
    Resolve the M-Pesa payer phone and persist it onto payment.phone.

    Prefers Payment.phone, then linked STK.phone / callback PhoneNumber.
    Works for Company Payment Gateway and ISP-owned gateways alike.
    """
    from billing.stk import resolve_stk_mpesa_phone

    current = format_customer_phone_display(getattr(payment, "phone", "") or "").strip()
    if current:
        return current[:30]

    found = ""
    for stk in payment.stk_push_requests.all():
        found = resolve_stk_mpesa_phone(stk)
        if found:
            break
    if not found:
        return ""

    display = format_customer_phone_display(found)[:30]
    if display and (payment.phone or "").strip() != display:
        payment.phone = display
        payment.save(update_fields=["phone"])
    return display


def create_renewal_invoice_and_payment(
    *,
    customer,
    organization,
    amount,
    reference: str = "",
    phone: str = "",
    recorded_by=None,
    notes: str = "M-Pesa STK Push subscription renewal",
    invoice_prefix: str = "REN",
    method: str | None = None,
):
    """Create a paid invoice + payment row for a successful renewal payment."""
    from billing.models import Invoice, Payment

    payment_method = method or Payment.Method.MPESA
    now = timezone.localtime()
    stamp = now.strftime("%Y%m%d%H%M%S")
    invoice_number = f"{invoice_prefix}-{organization.pk}-{stamp}-{secrets.token_hex(2).upper()}"
    while Invoice.objects.filter(invoice_number=invoice_number).exists():
        invoice_number = f"{invoice_prefix}-{organization.pk}-{stamp}-{secrets.token_hex(2).upper()}"
    invoice = Invoice.objects.create(
        organization=organization,
        customer=customer,
        invoice_number=invoice_number,
        amount=amount,
        status=Invoice.Status.PAID,
        due_date=now.date(),
        issued_at=now,
        paid_at=now,
        notes=notes,
    )
    paid_phone = format_customer_phone_display(phone or "")[:30]
    payment = Payment.objects.create(
        organization=organization,
        invoice=invoice,
        amount=amount,
        method=payment_method,
        reference=(reference or "")[:100],
        phone=paid_phone,
        received_at=now,
        recorded_by=recorded_by,
    )
    return invoice, payment


def customer_needs_nas_provision(customer) -> bool:
    """Whether recharge / pause / resume should push MikroTik immediately."""
    mac = (getattr(customer, "hotspot_mac", None) or "").strip()
    if mac:
        return True
    username = (getattr(customer, "pppoe_username", None) or "").strip()
    # Username alone is enough: provision_customer_pppoe can resolve an org NAS
    # when router_id is missing.
    return bool(username)


def recharge_customer_cash(
    *,
    customer,
    organization,
    plan,
    amount,
    reference: str = "",
    recorded_by=None,
    notes: str = "Cash subscription recharge",
    period_start=None,
    period_end=None,
):
    """
    Record a cash payment and immediately extend the customer's prepaid package.

    Hotspot: also issues fresh access vouchers and expects the caller to kick
    MikroTik sessions so devices autoconnect or redeem a voucher to start fresh.
    PPPoE: activates access right away (no vouchers).

    When ``period_start`` and ``period_end`` are provided, that range is the
    purchased duration. Active clients keep remaining paid time (duration is
    stacked onto the current access deadline). Expired clients get the absolute
    window. Omitting both dates stacks one full plan unit (offer-aware).
    """
    from django.db import transaction

    from billing.models import BillingPlan, Payment
    from billing.vouchers import create_vouchers_for_cash_recharge, format_voucher_code

    if plan is None:
        raise ValueError("Select a package to recharge.")
    try:
        amount = Decimal(amount).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception as exc:  # noqa: BLE001 — invalid Decimal input
        raise ValueError("Enter a valid recharge amount.") from exc
    if amount <= 0:
        raise ValueError("Recharge amount must be greater than zero.")

    partial = period_start is not None or period_end is not None
    if partial and (period_start is None or period_end is None):
        raise ValueError("Partial recharge requires both from and to dates.")

    vouchers = []
    stacked = customer_subscription_window_active(customer)
    with transaction.atomic():
        update_fields: list[str] = []
        if customer.plan_id != plan.pk:
            customer.plan = plan
            update_fields.append("plan")
        if customer.status != Customer.Status.ACTIVE:
            customer.status = Customer.Status.ACTIVE
            update_fields.append("status")
        if update_fields:
            customer.save(update_fields=update_fields)

        note_text = notes or "Cash subscription recharge"
        if partial and not notes:
            note_text = "Cash partial subscription recharge"

        invoice, payment = create_renewal_invoice_and_payment(
            customer=customer,
            organization=organization,
            amount=amount,
            reference=reference,
            recorded_by=recorded_by,
            notes=note_text,
            invoice_prefix="CASH",
            method=Payment.Method.CASH,
        )
        if partial:
            apply_cash_recharge_period(
                customer,
                plan=plan,
                start=period_start,
                end=period_end,
            )
        else:
            from billing.package_offers import apply_paid_subscription_with_offer

            apply_paid_subscription_with_offer(customer, plan=plan)
        customer.refresh_from_db()

        is_hotspot = (
            getattr(customer, "service_type", "") == Customer.ServiceType.HOTSPOT
            or getattr(plan, "service_type", "") == BillingPlan.ServiceType.HOTSPOT
        )
        if is_hotspot:
            vouchers = create_vouchers_for_cash_recharge(
                organization=organization,
                customer=customer,
                plan=plan,
                payment=payment,
            )

    voucher_codes = [format_voucher_code(row.code) for row in vouchers]
    pay_ctx = {
        "amount": str(amount),
        "invoice_number": invoice.invoice_number if invoice else "",
        "package_name": getattr(plan, "name", "") or "",
        "reference": (reference or "")[:100],
        "package_end": (
            customer.package_end.isoformat() if customer.package_end else ""
        ),
    }
    notify_client_payment_success(
        organization=organization,
        customer=customer,
        context=pay_ctx,
        stacked=stacked,
    )
    from accounts.communications import notify_org_event

    notify_org_event(
        "invoice_receipt",
        organization=organization,
        client=customer,
        context=pay_ctx,
        subject="Invoice / receipt",
    )
    # PPPoE cash recharge restores access immediately (no voucher gate).
    if not vouchers:
        notify_client_internet_reconnected(
            organization=organization,
            customer=customer,
            context=pay_ctx,
        )
    return {
        "customer": customer,
        "invoice": invoice,
        "payment": payment,
        "partial": partial,
        "vouchers": vouchers,
        "voucher_codes": voucher_codes,
        "kick_sessions": bool(vouchers),
        "stacked": stacked,
    }


def resolve_lead_allocation_plan(organization, customer=None):
    """Pick a billing package linked to this lead (or cheapest for the ISP)."""
    from billing.models import BillingPlan

    if customer is not None and customer.plan_id:
        return customer.plan
    return (
        BillingPlan.objects.filter(organization=organization, is_active=True)
        .order_by("price", "name")
        .first()
    )


def resolve_lead_allocation_technician_options(
    *,
    organization,
    request_technician: bool,
    technician_mode: str = "",
    technician_id=None,
) -> dict:
    """
    Validate Accept-lead technician options.

    - No specific technician selected → queued (open for any tech)
    - Specific technician selected → assigned + assignee
    """
    from accounts.models import Employee

    mode = (technician_mode or "").strip().lower()
    # Without a concrete assignee, keep the ticket open for technicians.
    if not request_technician or mode in {"", "open", "none"}:
        return {
            "ok": True,
            "request_technician": bool(request_technician),
            "mode": "open",
            "technician": None,
            "status": Customer.Status.QUEUED,
        }

    if mode != "assigned":
        return {
            "ok": False,
            "error": "Choose Open or select a technician.",
        }

    try:
        tech_pk = int(technician_id)
    except (TypeError, ValueError):
        return {"ok": False, "error": "Select a technician employee."}

    technician = (
        Employee.objects.select_related("user")
        .filter(
            pk=tech_pk,
            role=Employee.Role.TECHNICIAN,
            status=Employee.Status.ACTIVE,
        )
        .filter(Q(organization=organization) | Q(organization__isnull=True))
        .first()
    )
    if technician is None:
        # Allow any active technician in the system when none are org-linked.
        technician = (
            Employee.objects.select_related("user")
            .filter(
                pk=tech_pk,
                role=Employee.Role.TECHNICIAN,
                status=Employee.Status.ACTIVE,
            )
            .first()
        )
    if technician is None:
        return {
            "ok": False,
            "error": "Choose an active technician from your organization.",
        }
    return {
        "ok": True,
        "request_technician": True,
        "mode": "assigned",
        "technician": technician,
        "status": Customer.Status.ASSIGNED,
    }


def resolve_lead_allocation_fee(
    *, organization=None, customer=None, commission=None
) -> dict:
    """
    Price a lead-allocation STK from IT Support → Sales commission settings.

    - per_ticket → fixed KES amount (rate_value)
    - per_ticket_package → rate_value % of the lead's package price
    """
    from accounts.models import Employee, RoleCommission

    if commission is None:
        commission = RoleCommission.for_role(Employee.Role.SALES)
    if not commission.enabled:
        return {
            "ok": False,
            "error": (
                "Sales commission is disabled. "
                "Enable it under IT Support → Commissions → Sales."
            ),
            "commission": commission,
        }

    rate = Decimal(commission.rate_value or 0)
    plan = customer.plan if customer is not None and customer.plan_id else None
    if plan is None and organization is not None:
        plan = resolve_lead_allocation_plan(organization, customer)

    if commission.rate_type == RoleCommission.RateType.PER_TICKET:
        amount = rate.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        if amount <= 0:
            return {
                "ok": False,
                "error": (
                    "Set a per-ticket sales commission greater than zero "
                    "in IT Support → Commissions → Sales."
                ),
                "commission": commission,
            }
        return {
            "ok": True,
            "amount": amount,
            "plan": plan,
            "commission": commission,
            "amount_display": f"KES {amount}",
        }

    if commission.rate_type == RoleCommission.RateType.PER_TICKET_PACKAGE:
        if plan is None:
            return {
                "ok": False,
                "error": (
                    "Sales commission is % of package, but this lead has no package. "
                    "Assign a package on the ticket or switch to per-ticket commission."
                ),
                "commission": commission,
            }
        package_price = Decimal(plan.price or 0)
        if package_price <= 0:
            return {
                "ok": False,
                "error": "Lead package price must be greater than zero.",
                "commission": commission,
                "plan": plan,
            }
        amount = (package_price * rate / Decimal("100")).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        if amount <= 0:
            return {
                "ok": False,
                "error": (
                    "Computed sales commission is zero. "
                    "Check the package % in IT Support → Commissions → Sales."
                ),
                "commission": commission,
                "plan": plan,
            }
        return {
            "ok": True,
            "amount": amount,
            "plan": plan,
            "commission": commission,
            "amount_display": f"KES {amount}",
            "package_price": package_price,
            "percent": rate,
        }

    return {
        "ok": False,
        "error": (
            "Configure a sales ticket commission module "
            "in IT Support → Commissions → Sales."
        ),
        "commission": commission,
    }


def compute_package_end(
    start: date | datetime | None,
    plan: BillingPlan | None = None,
    *,
    duration: str | None = None,
    duration_value: int | None = None,
    duration_unit: str | None = None,
) -> Optional[datetime]:
    """
    Derive package end from a start moment and billing plan duration.

    Supports legacy duration keys and customizable value + unit periods
    (hours, days, weeks, months, years).
    """
    if start is None:
        return None
    start_dt = _as_local_datetime(start)
    if start_dt is None:
        return None
    try:
        value, unit = _resolve_duration_parts(
            plan,
            duration=duration,
            duration_value=duration_value,
            duration_unit=duration_unit,
        )
    except ValueError:
        return None
    if unit == BillingPlan.DurationUnit.HOURS:
        return start_dt + timedelta(hours=value)
    if unit == BillingPlan.DurationUnit.DAYS:
        return start_dt + timedelta(days=value)
    if unit == BillingPlan.DurationUnit.WEEKS:
        return start_dt + timedelta(weeks=value)
    local_start = timezone.localtime(start_dt)
    if unit == BillingPlan.DurationUnit.MONTHS:
        end_day = _add_months(local_start.date(), value)
        return timezone.make_aware(
            datetime.combine(end_day, local_start.time()),
            timezone.get_current_timezone(),
        )
    if unit == BillingPlan.DurationUnit.YEARS:
        end_day = _add_months(local_start.date(), value * 12)
        return timezone.make_aware(
            datetime.combine(end_day, local_start.time()),
            timezone.get_current_timezone(),
        )
    return None
