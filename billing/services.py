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
    """True for hourly / 6-hour packages (time-of-day windows)."""
    if plan_or_duration is None:
        return False
    duration = getattr(plan_or_duration, "duration", plan_or_duration) or ""
    return str(duration).strip().lower() in BillingPlan.CLOCK_TIME_DURATIONS


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
    now = timezone.localtime()
    qs = (
        Customer.objects.filter(organization=organization)
        .filter(package_end__isnull=False)
        .select_related("plan")
        .order_by("package_end", "full_name")
    )
    rows = []
    for customer in qs:
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
    return customer


def clear_customer_package_pause(customer, *, save: bool = True) -> bool:
    """Clear a frozen package clock (e.g. after assigning a fresh period)."""
    if not customer_package_is_paused(customer):
        return False
    customer.package_paused_at = None
    if save:
        customer.save(update_fields=["package_paused_at"])
    return True


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


def customer_pppoe_secret_disabled(customer, *, today: date | None = None) -> bool:
    """
    Whether the NAS /ppp/secret should be disabled.

    Account suspend/inactive → disable secret (cannot dial).
    Expired package alone → keep secret enabled but use the blocked PPP profile
    (see provision_customer_pppoe) so surfing stops at the NAS.
    """
    if getattr(customer, "status", None) != Customer.Status.ACTIVE:
        return True
    return False


def make_renew_token(customer) -> str:
    """Signed token for the public renew / captive portal page."""
    pk = getattr(customer, "pk", None)
    if not pk:
        raise ValueError("Customer must be saved before creating a renew token.")
    return signing.dumps({"cid": int(pk)}, salt=RENEW_TOKEN_SALT)


def resolve_customer_from_renew_token(token: str) -> Customer | None:
    """Load a customer from a renew token, or None if invalid."""
    try:
        payload = signing.loads(token, salt=RENEW_TOKEN_SALT, max_age=None)
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
    if active_until is not None and active_until > now:
        # Stack the purchased duration onto the current expiry, but preserve
        # the start of the active access window. Moving package_start to the
        # old expiry makes a customer who pays twice appear ineligible until
        # the first package ends.
        calculation_start = current_end or active_until
        access_start = current_start if current_start and current_start <= now else now
    else:
        calculation_start = now
        access_start = now
    end = compute_package_end(calculation_start, plan)
    if end is None:
        raise ValueError("Could not compute the new package end from the plan duration.")
    customer.package_start = access_start
    customer.package_end = end
    update_fields = ["package_start", "package_end"]
    if clear_customer_package_pause(customer, save=False):
        update_fields.append("package_paused_at")
    customer.save(update_fields=update_fields)
    return customer


def create_renewal_invoice_and_payment(
    *,
    customer,
    organization,
    amount,
    reference: str = "",
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
    payment = Payment.objects.create(
        organization=organization,
        invoice=invoice,
        amount=amount,
        method=payment_method,
        reference=(reference or "")[:100],
        received_at=now,
        recorded_by=recorded_by,
    )
    return invoice, payment


def recharge_customer_cash(
    *,
    customer,
    organization,
    plan,
    amount,
    reference: str = "",
    recorded_by=None,
    notes: str = "Cash subscription recharge",
):
    """
    Record a cash payment and immediately extend the customer's prepaid package.

    Unlike M-Pesa STK (which issues a voucher), staff cash recharges activate
    access right away and sync to the router afterward.
    """
    from django.db import transaction

    from billing.models import Payment

    if plan is None:
        raise ValueError("Select a package to recharge.")
    try:
        amount = Decimal(amount).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception as exc:  # noqa: BLE001 — invalid Decimal input
        raise ValueError("Enter a valid recharge amount.") from exc
    if amount <= 0:
        raise ValueError("Recharge amount must be greater than zero.")

    with transaction.atomic():
        update_fields: list[str] = []
        if customer.plan_id != plan.pk:
            customer.plan = plan
            update_fields.append("plan")
        if customer.status in {
            Customer.Status.SUSPENDED,
            Customer.Status.INACTIVE,
        }:
            customer.status = Customer.Status.ACTIVE
            update_fields.append("status")
        if update_fields:
            customer.save(update_fields=update_fields)

        invoice, payment = create_renewal_invoice_and_payment(
            customer=customer,
            organization=organization,
            amount=amount,
            reference=reference,
            recorded_by=recorded_by,
            notes=notes or "Cash subscription recharge",
            invoice_prefix="CASH",
            method=Payment.Method.CASH,
        )
        apply_subscription_renewal(customer, plan=plan)
        customer.refresh_from_db()

    return {
        "customer": customer,
        "invoice": invoice,
        "payment": payment,
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

    - No specific technician selected → allocated_open (open for any tech)
    - Specific technician selected → allocated_closed + assignee
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
            "status": Customer.Status.ALLOCATED_OPEN,
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
        "status": Customer.Status.ALLOCATED_CLOSED,
    }


def resolve_lead_allocation_fee(*, organization=None, customer=None) -> dict:
    """
    Price a lead-allocation STK from IT Support → Sales commission settings.

    - per_ticket → fixed KES amount (rate_value)
    - per_ticket_package → rate_value % of the lead's package price
    """
    from accounts.models import Employee, RoleCommission

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
) -> Optional[datetime]:
    """
    Derive package end from a start moment and billing plan duration.

    hourly       → start + 1 hour
    six_hours    → start + 6 hours
    daily        → start + 1 day
    weekly       → start + 7 days
    monthly      → start + 1 calendar month
    quarterly    → start + 3 calendar months
    semi_annual  → start + 6 calendar months
    yearly       → start + 1 calendar year
    """
    if start is None:
        return None
    start_dt = _as_local_datetime(start)
    if start_dt is None:
        return None
    duration_key = (duration or getattr(plan, "duration", None) or "").strip().lower()
    if not duration_key:
        return None
    if duration_key == BillingPlan.Duration.HOURLY:
        return start_dt + timedelta(hours=1)
    if duration_key == BillingPlan.Duration.SIX_HOURS:
        return start_dt + timedelta(hours=6)
    if duration_key == BillingPlan.Duration.DAILY:
        return start_dt + timedelta(days=1)
    if duration_key == BillingPlan.Duration.WEEKLY:
        return start_dt + timedelta(days=7)
    if duration_key == BillingPlan.Duration.MONTHLY:
        end_day = _add_months(timezone.localtime(start_dt).date(), 1)
        return timezone.make_aware(
            datetime.combine(end_day, timezone.localtime(start_dt).time()),
            timezone.get_current_timezone(),
        )
    if duration_key == BillingPlan.Duration.QUARTERLY:
        end_day = _add_months(timezone.localtime(start_dt).date(), 3)
        return timezone.make_aware(
            datetime.combine(end_day, timezone.localtime(start_dt).time()),
            timezone.get_current_timezone(),
        )
    if duration_key == BillingPlan.Duration.SEMI_ANNUAL:
        end_day = _add_months(timezone.localtime(start_dt).date(), 6)
        return timezone.make_aware(
            datetime.combine(end_day, timezone.localtime(start_dt).time()),
            timezone.get_current_timezone(),
        )
    if duration_key == BillingPlan.Duration.YEARLY:
        end_day = _add_months(timezone.localtime(start_dt).date(), 12)
        return timezone.make_aware(
            datetime.combine(end_day, timezone.localtime(start_dt).time()),
            timezone.get_current_timezone(),
        )
    return None
