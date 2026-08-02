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


def plans_for_router(organization, router=None, *, active_only=True):
    """Plans for an org, optionally limited to a MikroTik.

    Empty plan.routers means the package is available on every router.
    """
    from django.db.models import Count

    qs = BillingPlan.objects.filter(organization=organization)
    if active_only:
        qs = qs.filter(is_active=True)
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
    plan = getattr(customer, "plan", None)
    return bool(plan and getattr(plan, "duration", "") == BillingPlan.Duration.HOURLY)


def subscription_period_allows(customer, *, today: date | None = None) -> bool:
    """
    Whether now/today falls inside the customer's package_start–package_end window.

    Missing dates mean no period is configured yet → allow access (legacy clients).
    Hourly packages compare against the current time.
    Other packages compare against the local calendar date (end day inclusive).
    """
    start = _as_local_datetime(getattr(customer, "package_start", None))
    end = _as_local_datetime(getattr(customer, "package_end", None))
    if start is None and end is None:
        return True

    if _plan_is_hourly(customer):
        now = timezone.localtime()
        if start is not None and now < start:
            return False
        if end is not None and now > end:
            return False
        return True

    today = today or timezone.localdate()
    start_day = timezone.localtime(start).date() if start else None
    end_day = timezone.localtime(end).date() if end else None
    if start_day is not None and today < start_day:
        return False
    if end_day is not None and today > end_day:
        return False
    return True


def customer_subscription_expired(customer, *, today: date | None = None) -> bool:
    """True when a package end is set and the current moment/day is after it."""
    end = _as_local_datetime(getattr(customer, "package_end", None))
    if end is None:
        return False
    if _plan_is_hourly(customer):
        return timezone.localtime() > end
    today = today or timezone.localdate()
    return today > timezone.localtime(end).date()


def subscription_period_progress(customer, *, now: datetime | None = None) -> dict | None:
    """
    Progress through the current package window.

    Returns None when start/end are missing or invalid.
    ``ratio`` is elapsed / total (may exceed 1.0 after expiry).
    """
    start = _as_local_datetime(getattr(customer, "package_start", None))
    end = _as_local_datetime(getattr(customer, "package_end", None))
    if start is None or end is None or end <= start:
        return None
    now = now or timezone.localtime()
    if timezone.is_naive(now):
        now = timezone.make_aware(now, timezone.get_current_timezone())
    else:
        now = timezone.localtime(now)
    total = (end - start).total_seconds()
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


def customer_receives_internet(customer, organization=None, *, today: date | None = None) -> bool:
    """
    Whether this customer is eligible for internet under org + subscription policy.

    Blocks when:
    - customer status is not active
    - today/now is outside package_start / package_end (when set)
    - Hotspot or PPPoE customer has no purchased period at all
    - PPPoE is compulsory and a non-Hotspot customer is not a registered PPPoE user
    """
    org = organization or getattr(customer, "organization", None)
    if getattr(customer, "status", None) != Customer.Status.ACTIVE:
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
    if current_end is not None and current_end > now:
        # Stack the purchased duration onto the current expiry, but preserve
        # the start of the active access window. Moving package_start to the
        # old expiry makes a customer who pays twice appear ineligible until
        # the first package ends.
        calculation_start = current_end
        access_start = current_start if current_start and current_start <= now else now
    else:
        calculation_start = now
        access_start = now
    end = compute_package_end(calculation_start, plan)
    if end is None:
        raise ValueError("Could not compute the new package end from the plan duration.")
    customer.package_start = access_start
    customer.package_end = end
    customer.save(update_fields=["package_start", "package_end"])
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
):
    """Create a paid invoice + M-Pesa payment row for a successful STK payment."""
    from billing.models import Invoice, Payment

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
        method=Payment.Method.MPESA,
        reference=(reference or "")[:100],
        received_at=now,
        recorded_by=recorded_by,
    )
    return invoice, payment


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

    hourly  → start + 1 hour
    daily   → start + 1 day
    weekly  → start + 7 days
    monthly → start + 1 calendar month
    yearly  → start + 1 calendar year
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
    if duration_key == BillingPlan.Duration.YEARLY:
        end_day = _add_months(timezone.localtime(start_dt).date(), 12)
        return timezone.make_aware(
            datetime.combine(end_day, timezone.localtime(start_dt).time()),
            timezone.get_current_timezone(),
        )
    return None
