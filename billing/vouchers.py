"""Access vouchers: create on payment, one per Hotspot device, burn when used."""

from __future__ import annotations

import logging
import secrets
import string
import threading
from typing import Iterable

from django.db import IntegrityError, transaction
from django.utils import timezone

from billing.models import AccessVoucher, Customer, StkPushRequest
from billing.package_offers import apply_paid_subscription_with_offer

logger = logging.getLogger(__name__)

# Skip O/I so the letter is not mistaken for 0/1 on a phone.
_CODE_LETTERS = "".join(ch for ch in string.ascii_uppercase if ch not in "OI")
_CODE_DIGITS = string.digits


def normalize_voucher_code(raw: str) -> str:
    """Uppercase alphanumeric only (strips spaces and dashes)."""
    return "".join(ch for ch in (raw or "").upper() if ch.isalnum())


def format_voucher_code(code: str) -> str:
    """Display new codes as 4827-K; keep legacy 8-char as XXXX-XXXX."""
    compact = normalize_voucher_code(code)
    if len(compact) == 5 and compact[:4].isdigit() and compact[4].isalpha():
        return f"{compact[:4]}-{compact[4]}"
    if len(compact) == 8:
        return f"{compact[:4]}-{compact[4:]}"
    return compact


def _generate_code() -> str:
    """Four digits plus one letter, e.g. 4827K."""
    digits = "".join(secrets.choice(_CODE_DIGITS) for _ in range(4))
    letter = secrets.choice(_CODE_LETTERS)
    return f"{digits}{letter}"


def voucher_count_for_plan(plan) -> int:
    """How many one-time vouchers a successful payment should issue."""
    from billing.devices import MAX_DEVICES_HARD_CAP
    from billing.models import BillingPlan

    if plan is None:
        return 1
    if getattr(plan, "service_type", "") != BillingPlan.ServiceType.HOTSPOT:
        return 1
    try:
        n = int(getattr(plan, "max_devices", 0) or 0)
    except (TypeError, ValueError):
        n = 0
    if n <= 0:
        # Unlimited Hotspot: one voucher unlocks the paid account.
        return 1
    return min(max(n, 1), MAX_DEVICES_HARD_CAP)


def customer_unused_voucher_count(customer) -> int:
    if customer is None or not getattr(customer, "pk", None):
        return 0
    return AccessVoucher.objects.filter(
        customer_id=customer.pk,
        status=AccessVoucher.Status.VALID,
    ).count()


def _create_one_voucher(
    *,
    organization,
    customer,
    plan,
    stk=None,
    payment=None,
    subscription_applied: bool = False,
) -> AccessVoucher:
    last_error = None
    for _ in range(12):
        code = _generate_code()
        try:
            with transaction.atomic():
                return AccessVoucher.objects.create(
                    organization=organization,
                    customer=customer,
                    plan=plan,
                    stk_request=stk,
                    payment=payment,
                    subscription_applied=bool(subscription_applied),
                    code=code,
                    status=AccessVoucher.Status.VALID,
                )
        except IntegrityError as exc:
            last_error = exc
    raise RuntimeError("Could not allocate a unique voucher code.") from last_error


def create_vouchers_for_stk(stk: StkPushRequest) -> list[AccessVoucher]:
    """
    Create VALID voucher(s) for a successful subscription payment.

    Hotspot: one voucher per package device (max_devices). PPPoE: one voucher.
    Idempotent: existing rows for this STK are reused; extras are filled up to the count.
    """
    existing = list(
        AccessVoucher.objects.filter(stk_request=stk).order_by("id")
    )
    customer = stk.customer
    plan = stk.plan or (customer.plan if customer else None)
    if customer is None or plan is None:
        if existing:
            return existing
        raise ValueError("Voucher requires a customer and plan.")

    needed = voucher_count_for_plan(plan)
    if len(existing) >= needed:
        return existing[:needed]

    created = list(existing)
    while len(created) < needed:
        created.append(
            _create_one_voucher(
                organization=stk.organization,
                customer=customer,
                plan=plan,
                stk=stk,
                payment=getattr(stk, "payment", None),
                subscription_applied=bool(getattr(stk, "subscription_applied", False)),
            )
        )
    return created


def invalidate_unused_customer_vouchers(customer, *, keep_ids: Iterable[int] | None = None) -> int:
    """Burn leftover VALID vouchers so a fresh recharge batch is the only redeemable set."""
    if customer is None or not getattr(customer, "pk", None):
        return 0
    keep = {int(pk) for pk in (keep_ids or []) if pk}
    now = timezone.now()
    updated = 0
    qs = AccessVoucher.objects.filter(
        customer_id=customer.pk,
        status=AccessVoucher.Status.VALID,
    )
    if keep:
        qs = qs.exclude(pk__in=keep)
    for voucher in qs:
        voucher.status = AccessVoucher.Status.INVALID
        voucher.invalidated_at = now
        voucher.save(update_fields=["status", "invalidated_at"])
        updated += 1
    return updated


def create_vouchers_for_cash_recharge(
    *,
    organization,
    customer,
    plan,
    payment=None,
) -> list[AccessVoucher]:
    """
    Issue a fresh Hotspot voucher batch after staff cash recharge.

    Marks older unused vouchers invalid, then creates one code per device slot.
    Package is already extended by the recharge, so vouchers are marked applied.
    """
    if customer is None or plan is None:
        raise ValueError("Voucher requires a customer and plan.")
    needed = voucher_count_for_plan(plan)
    invalidate_unused_customer_vouchers(customer)
    created: list[AccessVoucher] = []
    for _ in range(needed):
        created.append(
            _create_one_voucher(
                organization=organization,
                customer=customer,
                plan=plan,
                payment=payment,
                subscription_applied=True,
            )
        )
    return created


def vouchers_for_batch(voucher: AccessVoucher | None) -> list[AccessVoucher]:
    """Sibling vouchers from the same STK or cash payment."""
    if voucher is None:
        return []
    if voucher.stk_request_id:
        return list(
            AccessVoucher.objects.filter(stk_request_id=voucher.stk_request_id).order_by(
                "id"
            )
        )
    if voucher.payment_id:
        return list(
            AccessVoucher.objects.filter(payment_id=voucher.payment_id).order_by("id")
        )
    return [voucher]


def create_voucher_for_stk(stk: StkPushRequest) -> AccessVoucher:
    """
    Create VALID voucher(s) and return the primary redeemable code.

    Idempotent. Prefer a still-valid voucher when some of the batch were already used.
    """
    vouchers = create_vouchers_for_stk(stk)
    if not vouchers:
        raise RuntimeError("Could not allocate a voucher code.")
    for voucher in vouchers:
        if voucher.status == AccessVoucher.Status.VALID:
            return voucher
    return vouchers[0]


def voucher_payload(
    voucher: AccessVoucher | None,
    *,
    all_vouchers: list[AccessVoucher] | None = None,
) -> dict:
    """Pay-page fields: only still-valid (unused) voucher codes."""
    if voucher is None and not all_vouchers:
        return {}
    if all_vouchers is None and voucher is not None:
        all_vouchers = vouchers_for_batch(voucher)
    elif all_vouchers is None:
        all_vouchers = [voucher] if voucher else []
    valid = [row for row in all_vouchers if row.status == AccessVoucher.Status.VALID]
    codes = [format_voucher_code(row.code) for row in valid]
    primary = valid[0] if valid else None
    return {
        "voucher_id": primary.pk if primary else None,
        "voucher_code": codes[0] if codes else "",
        "voucher_codes": codes,
        "voucher_count": len(all_vouchers),
        "voucher_valid_count": len(valid),
        "voucher_status": (
            primary.status if primary is not None else AccessVoucher.Status.INVALID
        ),
        "voucher_redeemable": bool(primary and primary.is_redeemable),
    }


def _mark_voucher_used(voucher: AccessVoucher, *, mac: str = "") -> AccessVoucher:
    """Burn a voucher so it can never activate another device."""
    from billing.devices import normalize_device_mac

    now = timezone.now()
    voucher.status = AccessVoucher.Status.INVALID
    voucher.redeemed_at = voucher.redeemed_at or now
    voucher.invalidated_at = now
    if mac:
        voucher.redeemed_mac = normalize_device_mac(mac)[:17]
    voucher.save(update_fields=["status", "redeemed_at", "invalidated_at", "redeemed_mac"])
    return voucher


@transaction.atomic
def redeem_access_voucher(
    *,
    organization,
    code: str,
    customer: Customer | None = None,
    mac: str = "",
    provision: bool = True,
    wait_first: bool = True,
    quick: bool = True,
) -> dict:
    """
    Redeem a VALID voucher once: link the device, apply the paid package, authorize.

    Device attach runs before package renewal so a failed link (at-cap / MAC clash)
    leaves the voucher VALID with no subscription extension. Marks the voucher
    INVALID (used) only after a successful path. ``provision=False`` skips MikroTik.
    """
    compact = normalize_voucher_code(code)
    if len(compact) < 5:
        return {"ok": False, "error": "Enter a valid voucher code."}

    voucher = (
        AccessVoucher.objects.select_for_update()
        .select_related("customer", "customer__plan", "customer__router", "plan", "stk_request")
        .filter(organization=organization, code=compact)
        .first()
    )
    if voucher is None:
        return {"ok": False, "error": "Voucher not found."}

    if voucher.status in (AccessVoucher.Status.EXPIRED, AccessVoucher.Status.INVALID):
        return {
            "ok": False,
            "error": "This voucher was already used and is no longer valid.",
            "voucher_status": voucher.status,
        }
    if voucher.status != AccessVoucher.Status.VALID:
        return {"ok": False, "error": "This voucher cannot be used."}

    target = customer or voucher.customer
    if target is None:
        return {"ok": False, "error": "No customer is linked to this voucher."}
    if target.organization_id != organization.pk:
        return {"ok": False, "error": "Voucher not found."}
    if customer is not None and customer.pk != voucher.customer_id:
        from billing.services import customer_can_surf_via_hotspot

        stray = (
            getattr(customer, "service_type", "") == Customer.ServiceType.HOTSPOT
            and not customer_can_surf_via_hotspot(customer)
            and not AccessVoucher.objects.filter(
                customer=customer, status=AccessVoucher.Status.VALID
            ).exists()
        )
        if not stray:
            return {
                "ok": False,
                "error": "This voucher belongs to a different account.",
            }
        target = voucher.customer

    paid_plan = voucher.plan or target.plan
    if paid_plan is not None and target.plan_id != paid_plan.pk:
        target.plan = paid_plan
        target.save(update_fields=["plan"])

    # Link the device before applying the package so a failed attach
    # (at cap / MAC clash) cannot leave a renewal committed for retry.
    if mac:
        from billing.devices import (
            attach_hotspot_device,
            normalize_device_mac,
            reassign_unpaid_hotspot_mac,
        )

        mac = normalize_device_mac(mac)
        moved = reassign_unpaid_hotspot_mac(target, mac)
        if not moved.get("ok"):
            attach = attach_hotspot_device(target, mac, enforce_cap=True)
            if not attach.get("ok"):
                return {
                    "ok": False,
                    "error": attach.get("error") or "Could not link this device.",
                    "at_cap": bool(attach.get("at_cap")),
                }

    stk = voucher.stk_request
    # Cash recharge / auto-connect may already have applied this payment.
    already_applied = bool(voucher.subscription_applied) or (
        stk is not None and bool(stk.subscription_applied)
    )
    if not already_applied:
        try:
            apply_paid_subscription_with_offer(target, plan=paid_plan)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        voucher.subscription_applied = True
        voucher.save(update_fields=["subscription_applied"])
        if voucher.payment_id:
            AccessVoucher.objects.filter(payment_id=voucher.payment_id).update(
                subscription_applied=True
            )
        elif stk is not None:
            AccessVoucher.objects.filter(stk_request=stk).update(
                subscription_applied=True
            )

    _mark_voucher_used(voucher, mac=mac)

    if stk is not None and not stk.subscription_applied:
        stk.subscription_applied = True
        stk.save(update_fields=["subscription_applied"])
        AccessVoucher.objects.filter(stk_request=stk).update(subscription_applied=True)

    nas = {"ok": False, "allowed": False}
    if provision:
        try:
            from core.subscription_sync import enqueue_customer_subscription_sync

            nas = (
                enqueue_customer_subscription_sync(
                    target.pk,
                    True,
                    wait_first=wait_first,
                    quick=quick,
                    reauthenticate=False,
                )
                or nas
            )
        except Exception:  # noqa: BLE001 — package already applied
            logger.exception(
                "Voucher %s redeemed for customer %s but MikroTik sync failed",
                voucher.code,
                target.pk,
            )

    target.refresh_from_db()
    from core.subscription_sync import nas_access_ready

    authorized = nas_access_ready(nas) if nas else False
    siblings = vouchers_for_batch(voucher)
    return {
        "ok": True,
        "activated": True,
        "customer_id": target.pk,
        "account_number": target.account_number,
        "package_start": target.package_start.isoformat() if target.package_start else "",
        "package_end": target.package_end.isoformat() if target.package_end else "",
        "authorized": authorized,
        "offline": bool(nas.get("offline")),
        "authorization_error": (
            ""
            if authorized
            else (nas.get("message") or "Package activated; router authorize retry needed.")
        ),
        "can_retry_authorize": not authorized,
        "stk_id": stk.pk if stk else None,
        **voucher_payload(voucher, all_vouchers=siblings),
        "voucher_status": AccessVoucher.Status.INVALID,
        "voucher_redeemable": False,
    }


def activate_paid_subscription_stk(
    stk: StkPushRequest,
    *,
    mac: str = "",
    wait_first: bool = False,
    quick: bool = True,
    background: bool = False,
) -> dict:
    """
    Apply the paid package and push MikroTik for the customer who just paid.

    The voucher stays VALID until NAS authorize succeeds, so the pay page can
    fall back to manual entry if auto-connect does not start surfing.
    ``background=True`` returns immediately (Daraja callback must not wait on NAS).
    """
    if stk.purpose != StkPushRequest.Purpose.SUBSCRIPTION:
        return {"ok": False, "skipped": True, "reason": "not_subscription"}
    if stk.status != StkPushRequest.Status.SUCCESS:
        return {"ok": False, "skipped": True, "reason": "not_success"}

    if background:
        stk_id = stk.pk
        mac_value = (mac or "").strip()

        def _run(pk: int = stk_id, mac_hint: str = mac_value) -> None:
            from django.db import connection

            try:
                request = StkPushRequest.objects.select_related(
                    "customer",
                    "customer__plan",
                    "customer__router",
                    "organization",
                ).get(pk=pk)
                activate_paid_subscription_stk(
                    request,
                    mac=mac_hint,
                    wait_first=False,
                    quick=True,
                    background=False,
                )
            except Exception:  # noqa: BLE001
                logger.exception("Background STK activate failed for stk=%s", pk)
            finally:
                connection.close()

        threading.Thread(
            target=_run, daemon=True, name=f"stk-activate-{stk.pk}"
        ).start()
        return {"ok": True, "queued": True}

    customer = stk.customer
    if customer is None:
        return {"ok": False, "error": "No customer on this payment."}

    device_mac = (mac or getattr(customer, "hotspot_mac", None) or "").strip()
    try:
        vouchers = create_vouchers_for_stk(stk)
    except Exception:  # noqa: BLE001
        logger.exception("Could not create voucher while activating STK %s", stk.pk)
        return {"ok": False, "error": "Could not create voucher."}
    voucher = next(
        (row for row in vouchers if row.status == AccessVoucher.Status.VALID),
        vouchers[0] if vouchers else None,
    )
    if voucher is None:
        return {"ok": False, "error": "Could not create voucher."}

    if not stk.subscription_applied:
        paid_plan = voucher.plan or customer.plan
        if paid_plan is not None and customer.plan_id != paid_plan.pk:
            customer.plan = paid_plan
            customer.save(update_fields=["plan"])
        try:
            apply_paid_subscription_with_offer(customer, plan=paid_plan)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        stk.subscription_applied = True
        stk.save(update_fields=["subscription_applied"])
        AccessVoucher.objects.filter(stk_request=stk).update(subscription_applied=True)
        if device_mac:
            from billing.devices import attach_hotspot_device, normalize_device_mac

            attach_hotspot_device(
                customer, normalize_device_mac(device_mac), enforce_cap=True
            )
        customer.refresh_from_db()

    nas = {"ok": False, "allowed": False}
    try:
        from core.subscription_sync import enqueue_customer_subscription_sync

        nas = (
            enqueue_customer_subscription_sync(
                customer.pk,
                True,
                wait_first=wait_first,
                quick=quick,
                reauthenticate=False,
            )
            or nas
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "STK %s package applied but MikroTik sync failed for customer %s",
            stk.pk,
            customer.pk,
        )
    from core.subscription_sync import nas_access_ready

    authorized = nas_access_ready(nas)
    if authorized and voucher is not None and voucher.status == AccessVoucher.Status.VALID:
        # Consume only this device’s voucher; sibling device codes stay valid.
        _mark_voucher_used(voucher, mac=device_mac)
    siblings = list(AccessVoucher.objects.filter(stk_request=stk).order_by("id"))
    voucher.refresh_from_db()
    return {
        "ok": True,
        "activated": True,
        "already_applied": True,
        "authorized": authorized,
        "offline": bool(nas.get("offline")),
        "authorization_error": (
            ""
            if authorized
            else (nas.get("message") or "Package activated; router authorize retry needed.")
        ),
        "can_retry_authorize": not authorized,
        "stk_id": stk.pk,
        **voucher_payload(voucher, all_vouchers=siblings),
    }


def _apply_package_while_burning(voucher: AccessVoucher) -> None:
    customer = voucher.customer
    paid_plan = voucher.plan or getattr(customer, "plan", None)
    stk = voucher.stk_request
    if customer is None:
        return
    if voucher.subscription_applied or (stk is not None and stk.subscription_applied):
        return
    try:
        if paid_plan is not None and customer.plan_id != paid_plan.pk:
            customer.plan = paid_plan
            customer.save(update_fields=["plan"])
        apply_paid_subscription_with_offer(customer, plan=paid_plan)
        voucher.subscription_applied = True
        voucher.save(update_fields=["subscription_applied"])
        if voucher.payment_id:
            AccessVoucher.objects.filter(payment_id=voucher.payment_id).update(
                subscription_applied=True
            )
        if stk is not None and not stk.subscription_applied:
            stk.subscription_applied = True
            stk.save(update_fields=["subscription_applied"])
            AccessVoucher.objects.filter(stk_request=stk).update(
                subscription_applied=True
            )
    except Exception:  # noqa: BLE001
        logger.exception(
            "Failed applying package while invalidating voucher %s",
            voucher.code,
        )


def invalidate_unused_vouchers_for_expired_customers(
    customers: Iterable[Customer],
) -> int:
    """
    Burn leftover VALID device vouchers once the paid period has ended.

    Extra phones must not reconnect after the package clock runs out.
    Already-used (INVALID) rows stay as history.
    """
    from billing.services import (
        customer_can_surf_via_hotspot,
        customer_receives_internet,
    )

    rows = [c for c in customers if getattr(c, "pk", None)]
    if not rows:
        return 0

    now = timezone.now()
    updated = 0
    with transaction.atomic():
        for customer in rows:
            service = getattr(customer, "service_type", "")
            if service == Customer.ServiceType.HOTSPOT:
                if customer_can_surf_via_hotspot(customer):
                    continue
            elif customer_receives_internet(customer):
                continue
            qs = AccessVoucher.objects.select_for_update().filter(
                customer_id=customer.pk,
                status=AccessVoucher.Status.VALID,
            )
            for voucher in qs:
                voucher.status = AccessVoucher.Status.INVALID
                voucher.invalidated_at = now
                voucher.save(update_fields=["status", "invalidated_at"])
                updated += 1
    return updated


def invalidate_vouchers_for_surfing_customers(customers: Iterable[Customer]) -> int:
    """
    Burn vouchers once the client is surfing.

    Hotspot: only the voucher for a device that is actually online. Unused
    sibling device vouchers stay VALID so other phones can still connect.
    PPPoE: burn the single line voucher.

    - VALID → INVALID: also apply the paid package so money is not lost
    - EXPIRED → INVALID: session confirmed in use after redeem
    """
    from billing.devices import hotspot_macs_for_customer, normalize_device_mac

    rows = [c for c in customers if getattr(c, "pk", None)]
    if not rows:
        return 0

    now = timezone.now()
    updated = 0
    with transaction.atomic():
        for customer in rows:
            qs = list(
                AccessVoucher.objects.select_for_update()
                .select_related("customer", "plan", "stk_request")
                .filter(
                    customer_id=customer.pk,
                    status__in=[AccessVoucher.Status.VALID, AccessVoucher.Status.EXPIRED],
                )
                .order_by("id")
            )
            if not qs:
                continue
            expired = [v for v in qs if v.status == AccessVoucher.Status.EXPIRED]
            valid = [v for v in qs if v.status == AccessVoucher.Status.VALID]

            for voucher in expired:
                _apply_package_while_burning(voucher)
                voucher.status = AccessVoucher.Status.INVALID
                voucher.invalidated_at = now
                voucher.save(update_fields=["status", "invalidated_at"])
                updated += 1

            if not valid:
                continue

            if getattr(customer, "service_type", "") != Customer.ServiceType.HOTSPOT:
                for voucher in valid:
                    _apply_package_while_burning(voucher)
                    _mark_voucher_used(voucher)
                    updated += 1
                continue

            used_macs = {
                normalize_device_mac(mac)
                for mac in AccessVoucher.objects.filter(
                    customer_id=customer.pk,
                    status=AccessVoucher.Status.INVALID,
                )
                .exclude(redeemed_mac="")
                .values_list("redeemed_mac", flat=True)
            }
            surfing_macs = hotspot_macs_for_customer(customer) or [
                normalize_device_mac(getattr(customer, "hotspot_mac", "") or "")
            ]
            for mac in surfing_macs:
                if not mac or mac in used_macs or not valid:
                    continue
                voucher = valid.pop(0)
                _apply_package_while_burning(voucher)
                _mark_voucher_used(voucher, mac=mac)
                used_macs.add(mac)
                updated += 1
    return updated


def attach_voucher_to_stk_status(payload: dict, stk: StkPushRequest) -> dict:
    """Add voucher fields to payment-status JSON when a voucher exists."""
    vouchers = list(AccessVoucher.objects.filter(stk_request=stk).order_by("id"))
    if not vouchers and stk.status == StkPushRequest.Status.SUCCESS:
        try:
            vouchers = create_vouchers_for_stk(stk)
        except Exception:  # noqa: BLE001
            logger.exception("Could not create voucher for STK %s", stk.pk)
            vouchers = []
    voucher = next(
        (row for row in vouchers if row.status == AccessVoucher.Status.VALID),
        vouchers[0] if vouchers else None,
    )
    payload.update(voucher_payload(voucher, all_vouchers=vouchers))
    voucher_valid = any(row.status == AccessVoucher.Status.VALID for row in vouchers)
    payload["voucher_fallback"] = bool(
        voucher_valid and payload.get("subscription_applied") and not payload.get("authorized")
    )
    if voucher_valid and not payload.get("subscription_applied"):
        payload["needs_voucher"] = True
        if "authorized" not in payload:
            payload["authorized"] = False
    else:
        payload["needs_voucher"] = False
    return payload


def voucher_pay_url_for_customer(customer, request=None) -> str:
    """Canonical pay page where this client's voucher can be redeemed."""
    from django.urls import reverse

    from core.hotspot_portal import public_absolute_url

    if customer is None:
        return ""
    org = getattr(customer, "organization", None)
    if org is None or not getattr(org, "join_code", None):
        return ""
    if getattr(customer, "service_type", "") == Customer.ServiceType.HOTSPOT:
        path = reverse("core:hotspot_pay", kwargs={"join_code": org.join_code})
        return public_absolute_url(path, request) if request is not None else path
    from core.mikrotik_connect import _pppoe_pay_portal_url

    url = _pppoe_pay_portal_url(org, customer=customer)
    if url and str(url).startswith("http"):
        return url
    path = reverse("core:pppoe_pay", kwargs={"join_code": org.join_code})
    return public_absolute_url(path, request) if request is not None else path


def build_voucher_share(voucher: AccessVoucher, *, request=None, pay_url: str = "") -> dict:
    """
    Share text + WhatsApp / SMS / email links for staff to send a voucher to the client.
    """
    from urllib.parse import quote

    from billing.services import normalize_kenya_msisdn

    code = format_voucher_code(voucher.code)
    org_name = getattr(voucher.organization, "name", "") or "ISPCENTRIC"
    plan_name = getattr(voucher.plan, "name", "") or "your package"
    customer = voucher.customer
    pay = (pay_url or "").strip() or voucher_pay_url_for_customer(customer, request)
    share_text = (
        f"{org_name}: your internet voucher is {code}. "
        f"Open the pay page and enter this code once to activate {plan_name}. "
        f"A used voucher cannot be reused."
    )
    if pay:
        share_text = f"{share_text}\n{pay}"

    phone = ""
    if customer is not None:
        try:
            phone = normalize_kenya_msisdn(customer.phone or "")
        except Exception:
            phone = "".join(ch for ch in (customer.phone or "") if ch.isdigit())

    encoded = quote(share_text)
    whatsapp_client_url = (
        f"https://wa.me/{phone}?text={encoded}" if phone else ""
    )
    whatsapp_share_url = f"https://wa.me/?text={encoded}"
    sms_url = (
        f"sms:{phone}?&body={encoded}" if phone else f"sms:?&body={encoded}"
    )
    email_url = (
        "mailto:"
        + quote((getattr(customer, "email", "") or "").strip())
        + "?subject="
        + quote(f"{org_name} internet voucher")
        + "&body="
        + encoded
    )
    return {
        "code_display": code,
        "share_text": share_text,
        "pay_url": pay,
        "whatsapp_client_url": whatsapp_client_url,
        "whatsapp_share_url": whatsapp_share_url,
        "sms_url": sms_url,
        "email_url": email_url,
        "phone": phone,
        "can_share": voucher.status == AccessVoucher.Status.VALID,
    }


def vouchers_for_customer_billing(customer, *, request=None) -> list[dict]:
    """Serialize customer vouchers for the client billing page."""
    if customer is None:
        return []
    pay_url = voucher_pay_url_for_customer(customer, request)
    rows = (
        AccessVoucher.objects.filter(customer=customer)
        .select_related("plan", "organization", "customer", "stk_request")
        .order_by("-created_at")[:50]
    )
    payload = []
    for voucher in rows:
        share = build_voucher_share(voucher, request=request, pay_url=pay_url)
        payload.append(
            {
                "voucher": voucher,
                "code_display": share["code_display"],
                "status": voucher.status,
                "status_label": voucher.get_status_display(),
                "plan_name": getattr(voucher.plan, "name", "") or "—",
                "created_at": voucher.created_at,
                "redeemed_at": voucher.redeemed_at,
                "invalidated_at": voucher.invalidated_at,
                "mpesa_receipt": (
                    getattr(voucher.stk_request, "mpesa_receipt", "") or ""
                    if voucher.stk_request_id
                    else ""
                ),
                "share": share,
            }
        )
    return payload
