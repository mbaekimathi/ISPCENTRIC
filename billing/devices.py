"""Hotspot device registry: MACs on a Customer, capped by plan.max_devices."""

from __future__ import annotations

from django.db import IntegrityError, transaction
from django.utils import timezone

MAX_DEVICES_HARD_CAP = 50
UNLIMITED_DEVICES = 0


def plan_max_devices(plan) -> int:
    """Return the device cap for a plan. 0 means unlimited."""
    if plan is None:
        return 1
    try:
        n = int(getattr(plan, "max_devices", 0) or 0)
    except (TypeError, ValueError):
        n = 0
    if n <= 0:
        return UNLIMITED_DEVICES
    return min(n, MAX_DEVICES_HARD_CAP)


def plan_devices_unlimited(plan) -> bool:
    return plan is not None and plan_max_devices(plan) == UNLIMITED_DEVICES


def customer_max_devices(customer) -> int:
    return plan_max_devices(getattr(customer, "plan", None))


def customer_devices_unlimited(customer) -> bool:
    return plan_devices_unlimited(getattr(customer, "plan", None))


def normalize_device_mac(mac: str) -> str:
    """Uppercase AA:BB:CC:DD:EE:FF."""
    mac = (mac or "").strip().upper().replace("-", ":")
    compact = mac.replace(":", "")
    if len(compact) == 12 and all(ch in "0123456789ABCDEF" for ch in compact):
        return ":".join(compact[i : i + 2] for i in range(0, 12, 2))
    return mac


def hotspot_macs_for_customer(customer) -> list[str]:
    """Primary MAC first, then extra CustomerDevice rows."""
    if customer is None:
        return []
    seen: list[str] = []
    seen_set: set[str] = set()

    def _add(raw: str) -> None:
        mac = normalize_device_mac(raw)
        if not mac or mac in seen_set:
            return
        seen_set.add(mac)
        seen.append(mac)

    _add(getattr(customer, "hotspot_mac", "") or "")
    prefetched = getattr(customer, "_prefetched_objects_cache", {})
    if "devices" in prefetched:
        rows = prefetched["devices"]
    else:
        try:
            rows = list(customer.devices.all())
        except Exception:
            rows = []
    for row in rows:
        _add(getattr(row, "mac", "") or "")
    return seen


def customer_owns_hotspot_mac(customer, mac: str) -> bool:
    mac = normalize_device_mac(mac)
    if not mac or customer is None:
        return False
    return mac in {m.upper() for m in hotspot_macs_for_customer(customer)}


def find_hotspot_customer_for_mac(org, mac: str, *, active_only: bool = True):
    """Look up a Hotspot customer by MAC via CustomerDevice, then hotspot_mac."""
    from billing.models import Customer, CustomerDevice

    mac = normalize_device_mac(mac)
    if not mac or org is None:
        return None
    org_id = getattr(org, "pk", org)
    qs = (
        CustomerDevice.objects.filter(organization_id=org_id, mac__iexact=mac)
        .select_related("customer", "customer__plan", "customer__organization", "customer__router")
        .order_by("id")
    )
    device = qs.first()
    if device is not None and device.customer is not None:
        customer = device.customer
        if customer.service_type != Customer.ServiceType.HOTSPOT:
            return None
        if active_only and customer.status != Customer.Status.ACTIVE:
            return None
        return customer
    qs = Customer.objects.filter(
        organization_id=org_id,
        service_type=Customer.ServiceType.HOTSPOT,
        hotspot_mac__iexact=mac,
    ).select_related("plan", "organization", "router")
    if active_only:
        qs = qs.filter(status=Customer.Status.ACTIVE)
    return qs.order_by("id").first()


def find_hotspot_customer_by_phone(org, phone: str, *, active_only: bool = False):
    from billing.models import Customer
    from billing.services import normalize_customer_phone_key

    key = normalize_customer_phone_key(phone)
    if not key or org is None:
        return None
    org_id = getattr(org, "pk", org)
    qs = Customer.objects.filter(
        organization_id=org_id,
        service_type=Customer.ServiceType.HOTSPOT,
        phone_normalized=key,
    ).select_related("plan", "organization", "router")
    if active_only:
        qs = qs.filter(status=Customer.Status.ACTIVE)
    return qs.order_by("id").first()


def ensure_customer_device(customer, mac: str):
    """Create the device row if missing. Does not enforce max_devices."""
    from billing.models import CustomerDevice

    mac = normalize_device_mac(mac)
    if not mac or customer is None or not getattr(customer, "pk", None):
        return None
    org_id = getattr(customer, "organization_id", None)
    if not org_id:
        return None
    now = timezone.now()
    try:
        device, created = CustomerDevice.objects.get_or_create(
            organization_id=org_id,
            mac=mac,
            defaults={
                "customer_id": customer.pk,
                "last_seen_at": now,
            },
        )
    except IntegrityError:
        return CustomerDevice.objects.filter(organization_id=org_id, mac=mac).first()
    if device.customer_id != customer.pk:
        return device
    if not created:
        CustomerDevice.objects.filter(pk=device.pk).update(last_seen_at=now)
        device.last_seen_at = now
    return device


def _ensure_primary_mac(customer, mac: str) -> None:
    mac = normalize_device_mac(mac)
    if not mac or customer is None:
        return
    if (getattr(customer, "hotspot_mac", None) or "").strip():
        return
    customer.hotspot_mac = mac
    customer.save(update_fields=["hotspot_mac"])


def attach_hotspot_device(customer, mac: str, *, enforce_cap: bool = True) -> dict:
    """
    Link MAC to customer if under plan.max_devices.

    Returns ``{"ok": True, "created": bool, "device": ...}`` or
    ``{"ok": False, "error": str, "at_cap": bool}``.
    """
    from billing.models import Customer, CustomerDevice

    mac = normalize_device_mac(mac)
    if not mac:
        return {"ok": False, "error": "Could not identify this device."}
    if customer is None:
        return {"ok": False, "error": "No customer account."}

    existing = CustomerDevice.objects.filter(
        organization_id=customer.organization_id, mac=mac
    ).first()
    if existing is not None:
        if existing.customer_id != customer.pk:
            return {
                "ok": False,
                "error": "This device is already linked to another account.",
            }
        CustomerDevice.objects.filter(pk=existing.pk).update(last_seen_at=timezone.now())
        _ensure_primary_mac(customer, mac)
        return {"ok": True, "created": False, "device": existing}

    other = (
        Customer.objects.filter(
            organization_id=customer.organization_id,
            hotspot_mac__iexact=mac,
        )
        .exclude(pk=customer.pk)
        .first()
    )
    if other is not None:
        return {
            "ok": False,
            "error": "This device is already linked to another account.",
        }

    current = hotspot_macs_for_customer(customer)
    if mac not in current and enforce_cap:
        cap = customer_max_devices(customer)
        if cap > 0 and len(current) >= cap:
            label = "1 device" if cap == 1 else f"{cap} devices"
            return {
                "ok": False,
                "at_cap": True,
                "max_devices": cap,
                "error": (
                    f"This package allows {label}. "
                    "Remove a device or choose a package with a higher device limit."
                ),
            }

    device = ensure_customer_device(customer, mac)
    if device is None:
        return {"ok": False, "error": "Could not link this device."}
    if device.customer_id != customer.pk:
        return {
            "ok": False,
            "error": "This device is already linked to another account.",
        }
    _ensure_primary_mac(customer, mac)
    return {"ok": True, "created": True, "device": device}


def maybe_set_customer_phone(customer, phone: str) -> None:
    """Store phone on a Hotspot customer when empty and unique."""
    from billing.models import Customer
    from billing.services import normalize_customer_phone_key

    phone = (phone or "").strip()
    key = normalize_customer_phone_key(phone)
    if not key or customer is None:
        return
    if normalize_customer_phone_key(customer.phone):
        return
    clash = (
        Customer.objects.filter(
            organization_id=customer.organization_id,
            phone_normalized=key,
        )
        .exclude(pk=customer.pk)
        .exists()
    )
    if clash:
        return
    customer.phone = phone
    customer.save(update_fields=["phone", "phone_normalized"])


def _locked_hotspot_customer_for_mac(org, mac: str):
    from billing.models import Customer, CustomerDevice

    mac = normalize_device_mac(mac)
    org_id = getattr(org, "pk", org)
    device = (
        CustomerDevice.objects.select_for_update()
        .filter(organization_id=org_id, mac=mac)
        .select_related(
            "customer", "customer__plan", "customer__organization", "customer__router"
        )
        .first()
    )
    if device is not None:
        return device.customer
    return (
        Customer.objects.select_for_update()
        .filter(
            organization_id=org_id,
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac__iexact=mac,
        )
        .select_related("plan", "organization", "router")
        .order_by("id")
        .first()
    )


def resolve_or_create_hotspot_customer(
    org,
    *,
    mac: str,
    phone: str = "",
    plan=None,
    router=None,
) -> dict:
    """
    Find or create the Hotspot Customer for this captive device.

    Identity: MAC first, then phone (family account). New MACs attach up to
    ``plan.max_devices``. An extra device on an already-paid account does not
    need a new payment.
    """
    from billing.models import Customer
    from billing.services import (
        customer_can_surf_via_hotspot,
        normalize_customer_phone_key,
    )

    mac = normalize_device_mac(mac)
    if not mac:
        return {
            "ok": False,
            "error": "Could not identify this device. Rejoin the Hotspot and try again.",
            "status": 400,
        }

    phone = (phone or "").strip()
    router_id = getattr(router, "pk", None)

    with transaction.atomic():
        existing = _locked_hotspot_customer_for_mac(org, mac)
        if existing is not None:
            if existing.status != Customer.Status.ACTIVE:
                return {
                    "ok": False,
                    "error": (
                        "This device account is suspended. Contact your internet "
                        "provider before making a payment."
                    ),
                    "status": 403,
                }
            maybe_set_customer_phone(existing, phone)
            if router is not None and existing.router_id != router_id:
                existing.router = router
                existing.save(update_fields=["router"])
            if plan is not None and existing.plan_id is None:
                existing.plan = plan
                existing.save(update_fields=["plan"])
            attach_hotspot_device(existing, mac, enforce_cap=False)
            return {
                "ok": True,
                "customer": existing,
                "created": False,
                "attached": False,
                "already_paid": customer_can_surf_via_hotspot(existing),
            }

        by_phone = find_hotspot_customer_by_phone(org, phone) if phone else None
        if by_phone is not None:
            by_phone = (
                Customer.objects.select_for_update()
                .select_related("plan", "organization", "router")
                .filter(pk=by_phone.pk)
                .first()
            )
            if by_phone.status != Customer.Status.ACTIVE:
                return {
                    "ok": False,
                    "error": (
                        "This account is suspended. Contact your internet "
                        "provider before making a payment."
                    ),
                    "status": 403,
                }
            if plan is not None and by_phone.plan_id is None:
                by_phone.plan = plan
                by_phone.save(update_fields=["plan"])
            attach = attach_hotspot_device(by_phone, mac, enforce_cap=True)
            if not attach.get("ok"):
                return {
                    "ok": False,
                    "error": attach.get("error") or "Could not add this device.",
                    "status": 400,
                    "at_cap": bool(attach.get("at_cap")),
                }
            if router is not None and by_phone.router_id != router_id:
                by_phone.router = router
                by_phone.save(update_fields=["router"])
            return {
                "ok": True,
                "customer": by_phone,
                "created": False,
                "attached": True,
                "already_paid": customer_can_surf_via_hotspot(by_phone),
            }

        account_number = f"HOT-{org.pk}-{mac.replace(':', '')}"[:40]
        phone_to_store = phone
        key = normalize_customer_phone_key(phone) if phone else ""
        if key and Customer.objects.filter(
            organization=org, phone_normalized=key
        ).exists():
            phone_to_store = ""
        try:
            customer = Customer.objects.create(
                organization=org,
                full_name=f"Hotspot device {mac[-5:]}",
                phone=phone_to_store,
                account_number=account_number,
                service_type=Customer.ServiceType.HOTSPOT,
                hotspot_mac=mac,
                status=Customer.Status.ACTIVE,
                plan=plan,
                router=router,
            )
        except IntegrityError:
            again = _locked_hotspot_customer_for_mac(org, mac)
            if again is None and phone:
                again = find_hotspot_customer_by_phone(org, phone)
            if again is None:
                raise
            attach = attach_hotspot_device(again, mac, enforce_cap=True)
            if not attach.get("ok"):
                return {
                    "ok": False,
                    "error": attach.get("error") or "Could not add this device.",
                    "status": 400,
                    "at_cap": bool(attach.get("at_cap")),
                }
            return {
                "ok": True,
                "customer": again,
                "created": False,
                "attached": True,
                "already_paid": customer_can_surf_via_hotspot(again),
            }
        attach_hotspot_device(customer, mac, enforce_cap=False)
        return {
            "ok": True,
            "customer": customer,
            "created": True,
            "attached": True,
            "already_paid": False,
        }
