"""Hotspot pay modes: this device (fixed package) vs other devices (hourly quote)."""

from __future__ import annotations

from datetime import timedelta
from decimal import ROUND_HALF_UP, Decimal

from django.utils import timezone

PAY_MODE_THIS_DEVICE = "this_device"
PAY_MODE_OTHER_DEVICES = "other_devices"

MAX_OTHER_DEVICE_HOURS = 168
MAX_OTHER_DEVICE_COUNT = 50
MIN_OTHER_DEVICE_HOURS = 1
MIN_OTHER_DEVICE_COUNT = 1
MIN_STK_AMOUNT = Decimal("1")


def other_devices_base_price(plan) -> Decimal:
    """Standard base fee before hourly top-up."""
    if plan is None:
        return Decimal("0")
    custom = getattr(plan, "hotspot_other_base_price", None)
    if custom is not None and custom != "":
        return Decimal(custom).quantize(Decimal("0.01"))
    return Decimal(getattr(plan, "price", 0) or 0).quantize(Decimal("0.01"))


def hourly_rate_per_device(plan) -> Decimal:
    if plan is None:
        return Decimal("0")
    return Decimal(getattr(plan, "hotspot_hourly_rate_per_device", 0) or 0).quantize(
        Decimal("0.01")
    )


def plan_supports_other_devices(plan) -> bool:
    from billing.models import BillingPlan

    if plan is None:
        return False
    if getattr(plan, "service_type", "") != BillingPlan.ServiceType.HOTSPOT:
        return False
    if not getattr(plan, "hotspot_other_devices_enabled", True):
        return False
    return hourly_rate_per_device(plan) > 0


def calculate_other_devices_total(plan, *, device_count: int, hours: int) -> Decimal:
    base = other_devices_base_price(plan)
    rate = hourly_rate_per_device(plan)
    devices = max(0, int(device_count or 0))
    hrs = max(0, int(hours or 0))
    total = base + (rate * Decimal(devices) * Decimal(hrs))
    return total.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def quote_other_devices_purchase(plan, *, device_count: int, hours: int) -> dict:
    """Validate inputs and return a server-side quote for STK."""
    if not plan_supports_other_devices(plan):
        return {
            "ok": False,
            "error": "This package does not support paying for other devices.",
        }
    try:
        devices = int(device_count)
        hrs = int(hours)
    except (TypeError, ValueError):
        return {"ok": False, "error": "Enter valid device and hour counts."}

    if devices < MIN_OTHER_DEVICE_COUNT or devices > MAX_OTHER_DEVICE_COUNT:
        return {
            "ok": False,
            "error": f"Choose between {MIN_OTHER_DEVICE_COUNT} and {MAX_OTHER_DEVICE_COUNT} devices.",
        }
    if hrs < MIN_OTHER_DEVICE_HOURS or hrs > MAX_OTHER_DEVICE_HOURS:
        return {
            "ok": False,
            "error": f"Choose between {MIN_OTHER_DEVICE_HOURS} and {MAX_OTHER_DEVICE_HOURS} hours.",
        }

    base = other_devices_base_price(plan)
    rate = hourly_rate_per_device(plan)
    top_up = (rate * Decimal(devices) * Decimal(hrs)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    # Match M-Pesa STK integer rounding so the quoted total equals the charge.
    total = (base + top_up).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    if total < MIN_STK_AMOUNT:
        return {
            "ok": False,
            "error": f"Total must be at least KES {MIN_STK_AMOUNT:.0f}.",
        }

    return {
        "ok": True,
        "device_count": devices,
        "hours": hrs,
        "base_price": str(base),
        "hourly_rate": str(rate),
        "top_up": str(top_up),
        "total": str(total),
        "voucher_count": devices,
        "package_hours": hrs,
    }


def stk_pay_mode(stk) -> str:
    raw = getattr(stk, "raw_callback", None)
    if not isinstance(raw, dict):
        return PAY_MODE_THIS_DEVICE
    mode = (raw.get("pay_mode") or PAY_MODE_THIS_DEVICE).strip().lower()
    if mode == PAY_MODE_OTHER_DEVICES:
        return PAY_MODE_OTHER_DEVICES
    return PAY_MODE_THIS_DEVICE


def stk_other_devices_meta(stk) -> dict:
    raw = getattr(stk, "raw_callback", None)
    if not isinstance(raw, dict):
        return {}
    if stk_pay_mode(stk) != PAY_MODE_OTHER_DEVICES:
        return {}
    try:
        device_count = int(raw.get("device_count") or raw.get("voucher_count") or 0)
    except (TypeError, ValueError):
        device_count = 0
    try:
        hours = int(raw.get("package_hours") or raw.get("hours") or 0)
    except (TypeError, ValueError):
        hours = 0
    return {
        "device_count": device_count,
        "hours": hours,
        "voucher_count": device_count,
        "package_hours": hours,
    }


def apply_hotspot_other_devices_period(customer, *, plan, hours: int) -> None:
    """
    Apply or stack a clock-time surfing window from an hourly multi-device purchase.
    """
    from billing.services import (
        clear_customer_package_pause,
        subscription_access_deadline,
    )

    hours = max(MIN_OTHER_DEVICE_HOURS, int(hours or 0))
    now = timezone.localtime()
    delta = timedelta(hours=hours)
    active_until = subscription_access_deadline(customer)
    current_start = getattr(customer, "package_start", None)
    if active_until is not None and active_until > now:
        new_end = active_until + delta
        access_start = current_start if current_start and current_start <= now else now
    else:
        access_start = now
        new_end = now + delta

    customer.package_start = access_start
    customer.package_end = new_end
    update_fields = ["package_start", "package_end"]
    if clear_customer_package_pause(customer, save=False):
        update_fields.append("package_paused_at")
    if getattr(customer, "usage_tracking_since", None) is None or active_until is None or active_until <= now:
        customer.usage_tracking_since = access_start
        update_fields.append("usage_tracking_since")
    customer.save(update_fields=update_fields)
