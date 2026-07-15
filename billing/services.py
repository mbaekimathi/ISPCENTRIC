"""Billing helpers shared by views and forms."""

from __future__ import annotations

import calendar
import secrets
from datetime import date, datetime, timedelta
from decimal import Decimal

from django.utils import timezone

from billing.models import BillingPlan, Customer, Invoice


def generate_customer_account_number(organization, *, prefix: str = "CLT") -> str:
    """Create a unique account number for a customer in this organization."""
    org_id = getattr(organization, "pk", None) or 0
    for _ in range(40):
        candidate = f"{prefix}-{org_id:04d}-{secrets.token_hex(3).upper()}"
        if not Customer.objects.filter(account_number=candidate).exists():
            return candidate
    raise RuntimeError("Could not generate a unique account number.")


def generate_invoice_number(organization, *, prefix: str = "INV") -> str:
    """Create a unique invoice number for an organization."""
    org_id = getattr(organization, "pk", None) or 0
    for _ in range(40):
        candidate = f"{prefix}-{org_id:04d}-{secrets.token_hex(3).upper()}"
        if not Invoice.objects.filter(invoice_number=candidate).exists():
            return candidate
    raise RuntimeError("Could not generate a unique invoice number.")


def customer_receives_internet(customer, organization=None) -> bool:
    """
    Whether this customer is eligible for internet under org policy.

    When PPPoE compulsory check is on, only active PPPoE-registered clients qualify.
    """
    org = organization or getattr(customer, "organization", None)
    if customer.status != Customer.Status.ACTIVE:
        return False
    if not org or not getattr(org, "pppoe_compulsory", False):
        return True
    return (
        customer.service_type == Customer.ServiceType.PPPOE
        and bool((customer.pppoe_username or "").strip())
    )


def _add_calendar_months(start: date, months: int) -> date:
    """Advance a date by whole calendar months, clamping the day if needed."""
    month_index = start.month - 1 + months
    year = start.year + month_index // 12
    month = month_index % 12 + 1
    day = min(start.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def calculate_service_end(
    start: date,
    duration: str | None = None,
    *,
    plan: BillingPlan | None = None,
) -> date:
    """
    Auto-calculate the surfing end date from a start date and plan duration.

    Duration comes from the plan when provided; otherwise from `duration`,
    defaulting to monthly.
    """
    if not isinstance(start, date):
        raise TypeError("start must be a date")

    period = (duration or "").strip().lower()
    if plan is not None and not period:
        period = (getattr(plan, "duration", None) or "").strip().lower()
    if not period:
        period = BillingPlan.Duration.MONTHLY

    if period == BillingPlan.Duration.HOURLY:
        return start
    if period == BillingPlan.Duration.DAILY:
        return start + timedelta(days=1)
    if period == BillingPlan.Duration.WEEKLY:
        return start + timedelta(days=7)
    if period == BillingPlan.Duration.YEARLY:
        return _add_calendar_months(start, 12)
    # monthly (default)
    return _add_calendar_months(start, 1)


def service_days_remaining(until: date | None, *, today: date | None = None) -> int:
    """Inclusive paid days left through `until` (0 if expired or missing)."""
    if until is None:
        return 0
    today = today or date.today()
    if until < today:
        return 0
    return (until - today).days + 1


def service_end_from_remaining_days(start: date, remaining_days: int) -> date:
    """Build an end date for an inclusive remaining-day count starting at `start`."""
    if remaining_days <= 0:
        return start
    return start + timedelta(days=remaining_days - 1)


def _as_date(value) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return timezone.localdate(value) if timezone.is_aware(value) else value.date()
    if isinstance(value, date):
        return value
    return None


def _cycle_payment_label(invoice: Invoice | None, *, today: date) -> tuple[str, str]:
    """Return (code, display) for a cycle's payment state."""
    if invoice is None:
        return "unpaid", "Unpaid"
    status = invoice.status
    if status == Invoice.Status.PAID:
        return "paid", "Paid"
    if status == Invoice.Status.CANCELLED:
        return "cancelled", "Cancelled"
    if status == Invoice.Status.OVERDUE or (
        status == Invoice.Status.PENDING and invoice.due_date < today
    ):
        return "overdue", "Overdue"
    if status == Invoice.Status.DRAFT:
        return "draft", "Draft"
    return "unpaid", "Unpaid"


def ensure_period_invoice(
    customer,
    *,
    period_start: date,
    period_end: date,
    organization=None,
) -> Invoice | None:
    """
    Create (or reuse) an invoice for one surfing/billing period.

    Skips creation when the plan has no amount and no prior invoice exists.
    """
    org = organization or getattr(customer, "organization", None)
    if not org:
        return None

    existing = (
        Invoice.objects.filter(
            customer=customer,
            organization=org,
            period_start=period_start,
            period_end=period_end,
        )
        .exclude(status=Invoice.Status.CANCELLED)
        .order_by("-issued_at")
        .first()
    )
    if existing:
        return existing

    plan = getattr(customer, "plan", None)
    amount = getattr(plan, "price", None)
    if amount is None:
        amount = Decimal("0.00")

    return Invoice.objects.create(
        organization=org,
        customer=customer,
        invoice_number=generate_invoice_number(org),
        amount=amount,
        status=Invoice.Status.PENDING,
        due_date=period_end,
        period_start=period_start,
        period_end=period_end,
        notes=f"Billing cycle {period_start.isoformat()} → {period_end.isoformat()}",
    )


def build_customer_billing_cycles(
    customer,
    *,
    today: date | None = None,
    organization=None,
) -> list[dict]:
    """
    Build every billing cycle since registration through the current period.

    Each row includes paid/unpaid status (from matching invoices) and whether it
    is the client's current surfing cycle.
    """
    today = today or timezone.localdate()
    org = organization or getattr(customer, "organization", None)
    plan = getattr(customer, "plan", None)
    duration = getattr(plan, "duration", None) or BillingPlan.Duration.MONTHLY
    plan_amount = getattr(plan, "price", None)

    created = _as_date(getattr(customer, "created_at", None)) or today
    service_start = _as_date(getattr(customer, "service_start", None))
    service_until = _as_date(getattr(customer, "service_until", None))

    invoices = list(
        Invoice.objects.filter(customer=customer, organization=org)
        .exclude(status=Invoice.Status.CANCELLED)
        .prefetch_related("payments")
        .order_by("period_start", "issued_at")
        if org
        else []
    )

    windows: list[tuple[date, date]] = []
    seen: set[tuple[date, date]] = set()

    def add_window(start: date | None, end: date | None) -> None:
        if not start or not end or end < start:
            return
        key = (start, end)
        if key in seen:
            return
        seen.add(key)
        windows.append(key)

    # Expected cycles from registration through today (inclusive).
    cursor = created
    safety = 0
    while cursor <= today and safety < 400:
        end = calculate_service_end(cursor, duration, plan=plan)
        if end < cursor:
            end = cursor
        add_window(cursor, end)
        nxt = end if end > cursor else cursor + timedelta(days=1)
        if nxt <= cursor:
            nxt = cursor + timedelta(days=1)
        cursor = nxt
        safety += 1

    # Always include the live surfing period and any invoice-backed periods.
    add_window(service_start, service_until)
    for inv in invoices:
        add_window(_as_date(inv.period_start), _as_date(inv.period_end))

    windows.sort(key=lambda item: (item[0], item[1]))

    def match_invoice(start: date, end: date) -> Invoice | None:
        for inv in invoices:
            p_start = _as_date(inv.period_start)
            p_end = _as_date(inv.period_end)
            if p_start and p_end and p_start == start and p_end == end:
                return inv
        for inv in invoices:
            p_start = _as_date(inv.period_start)
            p_end = _as_date(inv.period_end)
            if p_start and p_end and p_start <= end and p_end >= start:
                return inv
        for inv in invoices:
            issued = _as_date(inv.issued_at)
            due = _as_date(inv.due_date)
            if issued and start <= issued <= end:
                return inv
            if due and start <= due <= end:
                return inv
        return None

    cycles: list[dict] = []
    for index, (start, end) in enumerate(windows, start=1):
        invoice = match_invoice(start, end)
        pay_code, pay_label = _cycle_payment_label(invoice, today=today)
        is_current = bool(
            (service_start and service_until and start == service_start and end == service_until)
            or (start <= today <= end and customer.status == Customer.Status.ACTIVE)
        )
        if (
            is_current is False
            and service_start
            and service_until
            and start <= today <= end
            and customer.status == Customer.Status.PAUSED
        ):
            # Paused clients still show the frozen window as current when it matches.
            is_current = start == service_start and end == service_until

        amount = invoice.amount if invoice is not None else plan_amount
        cycles.append(
            {
                "index": index,
                "start": start,
                "end": end,
                "amount": amount,
                "payment_code": pay_code,
                "payment_label": pay_label,
                "is_current": is_current,
                "is_paid": pay_code == "paid",
                "invoice": invoice,
                "invoice_number": invoice.invoice_number if invoice else "",
                "due_date": invoice.due_date if invoice else end,
                "plan_name": getattr(plan, "name", "") or "",
                "duration_label": (
                    plan.get_duration_display() if plan is not None else "Monthly"
                ),
            }
        )

    # Prefer exactly one current marker: live service window first, else today's window.
    current_idxs = [i for i, row in enumerate(cycles) if row["is_current"]]
    if len(current_idxs) > 1:
        preferred = None
        if service_start and service_until:
            for i in current_idxs:
                if cycles[i]["start"] == service_start and cycles[i]["end"] == service_until:
                    preferred = i
                    break
        if preferred is None:
            preferred = current_idxs[-1]
        for i in current_idxs:
            cycles[i]["is_current"] = i == preferred

    return cycles
