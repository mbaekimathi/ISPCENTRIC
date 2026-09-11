"""Operational audit rows for payments, subscription periods, and PPPoE registration."""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP

from django.db.models import Q

from billing.models import Customer, Payment
from billing.services import (
    _as_local_datetime,
    compute_package_end,
    plan_billing_unit_seconds,
    plan_uses_clock_time,
)


def _user_label(user) -> str:
    if user is None:
        return ""
    return (user.get_full_name() or "").strip() or (user.username or "")


def _employee_label(employee) -> str:
    if employee is None:
        return ""
    user = getattr(employee, "user", None)
    name = _user_label(user)
    if name:
        return name
    return str(employee)


def format_duration_span(seconds: float | int | None) -> str:
    """Human-readable absolute duration (e.g. '3d 4h', '45m')."""
    if seconds is None:
        return "—"
    total = abs(int(round(float(seconds))))
    if total <= 0:
        return "0m"
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes and (not days or not hours):
        parts.append(f"{minutes}m")
    elif not parts and minutes:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append("0m")
    return " ".join(parts)


def format_signed_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "—"
    value = float(seconds)
    if abs(value) < 1:
        return "0m"
    sign = "+" if value > 0 else "−"
    return f"{sign}{format_duration_span(value)}"


def _money(value) -> Decimal:
    try:
        return Decimal(value or 0).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        return Decimal("0.00")


def _period_tolerance_seconds(plan) -> float:
    if plan_uses_clock_time(plan):
        return 120.0  # 2 minutes for clock packages
    return 86400.0  # 1 calendar day


def build_payment_recharge_audits(organization, *, limit: int = 200) -> list[dict]:
    """Payments with package-vs-edited amount and estimated duration deltas."""
    if organization is None:
        return []

    payments = (
        Payment.objects.filter(organization=organization)
        .select_related(
            "invoice",
            "invoice__customer",
            "invoice__customer__plan",
            "recorded_by",
        )
        .order_by("-received_at")[:limit]
    )

    rows: list[dict] = []
    for pay in payments:
        invoice = pay.invoice
        customer = getattr(invoice, "customer", None) if invoice else None
        plan = getattr(customer, "plan", None) if customer else None
        plan_price = _money(getattr(plan, "price", 0) if plan else 0)
        paid = _money(pay.amount)
        amount_delta = paid - plan_price
        is_edited = bool(plan) and abs(amount_delta) > Decimal("0.01")

        duration_delta_seconds = None
        purchased_label = "—"
        package_duration_label = plan.get_duration_display() if plan else "—"
        if plan and plan_price > 0:
            try:
                unit_seconds = float(plan_billing_unit_seconds(plan))
            except ValueError:
                unit_seconds = 0.0
            if unit_seconds > 0:
                ratio = float(paid / plan_price)
                purchased_seconds = ratio * unit_seconds
                duration_delta_seconds = purchased_seconds - unit_seconds
                purchased_label = format_duration_span(purchased_seconds)
                if abs(duration_delta_seconds) >= _period_tolerance_seconds(plan):
                    is_edited = True

        notes = (getattr(invoice, "notes", None) or "").strip().lower()
        if "partial" in notes:
            is_edited = True

        rows.append(
            {
                "payment_id": pay.pk,
                "received_at": pay.received_at,
                "customer_id": getattr(customer, "pk", None),
                "customer_name": getattr(customer, "full_name", None) or "—",
                "account_number": getattr(customer, "account_number", None) or "—",
                "pppoe_username": getattr(customer, "pppoe_username", None) or "",
                "plan_name": getattr(plan, "name", None) or "—",
                "plan_price": plan_price,
                "amount": paid,
                "amount_delta": amount_delta,
                "method": pay.get_method_display(),
                "method_key": pay.method,
                "reference": (pay.reference or "").strip(),
                "recharged_by": _user_label(pay.recorded_by) or "Client / self-pay",
                "is_edited": is_edited,
                "package_fit": "Edited" if is_edited else "Per package",
                "package_duration": package_duration_label,
                "purchased_duration": purchased_label,
                "duration_delta_seconds": duration_delta_seconds,
                "duration_delta_label": (
                    format_signed_duration(duration_delta_seconds)
                    if duration_delta_seconds is not None and is_edited
                    else "—"
                ),
                "amount_delta_label": (
                    f"{'+' if amount_delta > 0 else ''}{amount_delta}"
                    if is_edited
                    else "—"
                ),
                "notes": (getattr(invoice, "notes", None) or "").strip(),
            }
        )
    return rows


def build_subscription_period_audits(organization, *, limit: int = 500) -> list[dict]:
    """Clients whose current window matches one plan unit vs edited/stacked."""
    if organization is None:
        return []

    customers = (
        Customer.objects.filter(organization=organization)
        .filter(package_start__isnull=False, package_end__isnull=False, plan__isnull=False)
        .select_related("plan", "registered_by")
        .order_by("full_name")[:limit]
    )

    rows: list[dict] = []
    for customer in customers:
        plan = customer.plan
        start = _as_local_datetime(customer.package_start)
        end = _as_local_datetime(customer.package_end)
        if start is None or end is None or plan is None:
            continue
        expected_end = compute_package_end(start, plan)
        if expected_end is None:
            continue
        expected_end = _as_local_datetime(expected_end) or expected_end
        actual_seconds = (end - start).total_seconds()
        expected_seconds = (expected_end - start).total_seconds()
        delta_seconds = actual_seconds - expected_seconds
        tolerance = _period_tolerance_seconds(plan)
        is_edited = abs(delta_seconds) > tolerance

        rows.append(
            {
                "customer_id": customer.pk,
                "customer_name": customer.full_name,
                "account_number": customer.account_number or "—",
                "pppoe_username": customer.pppoe_username or "",
                "service_type": customer.get_service_type_display(),
                "plan_name": plan.name,
                "plan_duration": plan.get_duration_display(),
                "package_start": start,
                "package_end": end,
                "expected_end": expected_end,
                "actual_duration": format_duration_span(actual_seconds),
                "expected_duration": format_duration_span(expected_seconds),
                "is_edited": is_edited,
                "package_fit": (
                    "Edited (outside single period)" if is_edited else "Per package"
                ),
                "outside_by": (
                    format_signed_duration(delta_seconds) if is_edited else "—"
                ),
                "outside_seconds": delta_seconds if is_edited else 0,
            }
        )

    # Edited first, then name.
    rows.sort(key=lambda row: (not row["is_edited"], row["customer_name"].lower()))
    return rows


def build_pppoe_registration_audits(organization, *, limit: int = 500) -> list[dict]:
    """Registered PPPoE clients and the staff who took part."""
    if organization is None:
        return []

    customers = (
        Customer.objects.filter(
            organization=organization,
            service_type=Customer.ServiceType.PPPOE,
        )
        .filter(Q(pppoe_username__gt="") | Q(account_number__gt=""))
        .select_related("registered_by", "assigned_technician", "assigned_technician__user", "plan")
        .order_by("-created_at")[:limit]
    )

    rows: list[dict] = []
    for customer in customers:
        registered_by = _user_label(customer.registered_by) or "—"
        technician = _employee_label(customer.assigned_technician) or "—"
        participants = []
        if registered_by != "—":
            participants.append(f"Registered by {registered_by}")
        if technician != "—":
            participants.append(f"Technician {technician}")
        rows.append(
            {
                "customer_id": customer.pk,
                "customer_name": customer.full_name,
                "account_number": customer.account_number or "—",
                "pppoe_username": customer.pppoe_username or "—",
                "phone": customer.phone or "—",
                "plan_name": getattr(customer.plan, "name", None) or "—",
                "status": customer.get_status_display(),
                "registered_by": registered_by,
                "technician": technician,
                "participants": ", ".join(participants) if participants else "—",
                "created_at": customer.created_at,
            }
        )
    return rows


def build_audits_summary(organization) -> dict:
    payments = build_payment_recharge_audits(organization, limit=500)
    periods = build_subscription_period_audits(organization, limit=1000)
    registrations = build_pppoe_registration_audits(organization, limit=1000)
    return {
        "payment_count": len(payments),
        "payment_edited_count": sum(1 for row in payments if row["is_edited"]),
        "period_count": len(periods),
        "period_edited_count": sum(1 for row in periods if row["is_edited"]),
        "period_standard_count": sum(1 for row in periods if not row["is_edited"]),
        "registration_count": len(registrations),
        "payments": payments,
        "periods": periods,
        "registrations": registrations,
    }
