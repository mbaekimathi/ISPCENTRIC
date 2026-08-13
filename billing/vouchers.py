"""Access vouchers: create on payment, redeem once, burn on surfing."""

from __future__ import annotations

import logging
import secrets
import string
import threading
from typing import Iterable

from django.db import IntegrityError, transaction
from django.utils import timezone

from billing.models import AccessVoucher, Customer, StkPushRequest
from billing.services import apply_subscription_renewal

logger = logging.getLogger(__name__)

_CODE_ALPHABET = string.ascii_uppercase + string.digits
# Skip ambiguous characters for phone entry.
_CODE_ALPHABET = "".join(ch for ch in _CODE_ALPHABET if ch not in "01OI")


def normalize_voucher_code(raw: str) -> str:
    """Uppercase alphanumeric only (strips spaces and dashes)."""
    return "".join(ch for ch in (raw or "").upper() if ch.isalnum())


def format_voucher_code(code: str) -> str:
    """Display as XXXX-XXXX when 8 chars."""
    compact = normalize_voucher_code(code)
    if len(compact) == 8:
        return f"{compact[:4]}-{compact[4:]}"
    return compact


def _generate_code() -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(8))


def create_voucher_for_stk(stk: StkPushRequest) -> AccessVoucher:
    """
    Create a VALID voucher for a successful subscription payment.

    Idempotent: returns the existing voucher when one is already linked to this STK.
    """
    from django.core.exceptions import ObjectDoesNotExist

    try:
        existing = stk.access_voucher
    except (ObjectDoesNotExist, AttributeError):
        existing = None
    if existing is not None:
        return existing
    linked = AccessVoucher.objects.filter(stk_request=stk).first()
    if linked is not None:
        return linked

    customer = stk.customer
    plan = stk.plan or (customer.plan if customer else None)
    if customer is None or plan is None:
        raise ValueError("Voucher requires a customer and plan.")

    last_error = None
    for _ in range(12):
        code = _generate_code()
        try:
            with transaction.atomic():
                return AccessVoucher.objects.create(
                    organization=stk.organization,
                    customer=customer,
                    plan=plan,
                    stk_request=stk,
                    code=code,
                    status=AccessVoucher.Status.VALID,
                )
        except IntegrityError as exc:
            last_error = exc
            # Race on OneToOne: another worker created it first.
            again = AccessVoucher.objects.filter(stk_request=stk).first()
            if again is not None:
                return again
    raise RuntimeError("Could not allocate a unique voucher code.") from last_error


def voucher_payload(voucher: AccessVoucher | None) -> dict:
    if voucher is None:
        return {}
    return {
        "voucher_id": voucher.pk,
        "voucher_code": format_voucher_code(voucher.code),
        "voucher_status": voucher.status,
        "voucher_redeemable": voucher.is_redeemable,
    }


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
    Redeem a VALID voucher once: apply the paid package and authorize the router.

    Marks the voucher EXPIRED (used). Returns provision details for the pay page.
    ``provision=False`` applies the package only (no MikroTik call).
    """
    compact = normalize_voucher_code(code)
    if len(compact) < 6:
        return {"ok": False, "error": "Enter a valid voucher code."}

    voucher = (
        AccessVoucher.objects.select_for_update()
        .select_related("customer", "customer__plan", "customer__router", "plan", "stk_request")
        .filter(organization=organization, code=compact)
        .first()
    )
    if voucher is None:
        return {"ok": False, "error": "Voucher not found."}

    if voucher.status == AccessVoucher.Status.EXPIRED:
        return {"ok": False, "error": "This voucher was already used.", "voucher_status": "expired"}
    if voucher.status == AccessVoucher.Status.INVALID:
        return {
            "ok": False,
            "error": "This voucher is no longer valid (internet session already started).",
            "voucher_status": "invalid",
        }
    if voucher.status != AccessVoucher.Status.VALID:
        return {"ok": False, "error": "This voucher cannot be used."}

    target = customer or voucher.customer
    if target is None:
        return {"ok": False, "error": "No customer is linked to this voucher."}
    if target.organization_id != organization.pk:
        return {"ok": False, "error": "Voucher not found."}
    if customer is not None and customer.pk != voucher.customer_id:
        return {
            "ok": False,
            "error": "This voucher belongs to a different account.",
        }

    paid_plan = voucher.plan or target.plan
    if paid_plan is not None and target.plan_id != paid_plan.pk:
        target.plan = paid_plan
        target.save(update_fields=["plan"])

    stk = voucher.stk_request
    # Auto-connect may already have applied this payment; don't double-extend.
    if stk is None or not stk.subscription_applied:
        try:
            apply_subscription_renewal(target, plan=paid_plan)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}

    voucher.status = AccessVoucher.Status.EXPIRED
    voucher.redeemed_at = timezone.now()
    if mac:
        from billing.devices import attach_hotspot_device, normalize_device_mac

        mac = normalize_device_mac(mac)
        voucher.redeemed_mac = mac[:17]
        attach_hotspot_device(target, mac, enforce_cap=True)
    voucher.save(update_fields=["status", "redeemed_at", "redeemed_mac"])

    if stk is not None and not stk.subscription_applied:
        stk.subscription_applied = True
        stk.save(update_fields=["subscription_applied"])

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
    return {
        "ok": True,
        "activated": True,
        "voucher_status": AccessVoucher.Status.EXPIRED,
        "voucher_code": format_voucher_code(voucher.code),
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
        **voucher_payload(voucher),
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
    voucher = AccessVoucher.objects.filter(stk_request=stk).first()
    if voucher is None:
        try:
            voucher = create_voucher_for_stk(stk)
        except Exception:  # noqa: BLE001
            logger.exception("Could not create voucher while activating STK %s", stk.pk)
            return {"ok": False, "error": "Could not create voucher."}

    if not stk.subscription_applied:
        paid_plan = voucher.plan or customer.plan
        if paid_plan is not None and customer.plan_id != paid_plan.pk:
            customer.plan = paid_plan
            customer.save(update_fields=["plan"])
        try:
            apply_subscription_renewal(customer, plan=paid_plan)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        stk.subscription_applied = True
        stk.save(update_fields=["subscription_applied"])
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
        voucher.status = AccessVoucher.Status.EXPIRED
        voucher.redeemed_at = timezone.now()
        if device_mac:
            from billing.devices import normalize_device_mac

            voucher.redeemed_mac = normalize_device_mac(device_mac)[:17]
            voucher.save(update_fields=["status", "redeemed_at", "redeemed_mac"])
        else:
            voucher.save(update_fields=["status", "redeemed_at"])
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
        "voucher_code": format_voucher_code(voucher.code) if voucher else "",
        "voucher_status": voucher.status if voucher else "",
        "voucher_redeemable": bool(
            voucher is not None and voucher.status == AccessVoucher.Status.VALID
        ),
    }


def invalidate_vouchers_for_surfing_customers(customers: Iterable[Customer]) -> int:
    """
    Burn vouchers once the client is surfing.

    - VALID → INVALID: also apply the paid package so money is not lost
    - EXPIRED → INVALID: session confirmed in use after redeem
    """
    customer_ids = [c.pk for c in customers if getattr(c, "pk", None)]
    if not customer_ids:
        return 0

    now = timezone.now()
    updated = 0
    with transaction.atomic():
        qs = (
            AccessVoucher.objects.select_for_update()
            .select_related("customer", "plan", "stk_request")
            .filter(
                customer_id__in=customer_ids,
                status__in=[AccessVoucher.Status.VALID, AccessVoucher.Status.EXPIRED],
            )
        )
        for voucher in qs:
            if voucher.status == AccessVoucher.Status.VALID:
                customer = voucher.customer
                paid_plan = voucher.plan or getattr(customer, "plan", None)
                stk = voucher.stk_request
                if customer is not None and (
                    stk is None or not stk.subscription_applied
                ):
                    try:
                        if paid_plan is not None and customer.plan_id != paid_plan.pk:
                            customer.plan = paid_plan
                            customer.save(update_fields=["plan"])
                        apply_subscription_renewal(customer, plan=paid_plan)
                        if stk is not None and not stk.subscription_applied:
                            stk.subscription_applied = True
                            stk.save(update_fields=["subscription_applied"])
                    except Exception:  # noqa: BLE001
                        logger.exception(
                            "Failed applying package while invalidating voucher %s",
                            voucher.code,
                        )
            voucher.status = AccessVoucher.Status.INVALID
            voucher.invalidated_at = now
            voucher.save(update_fields=["status", "invalidated_at"])
            updated += 1
    return updated


def attach_voucher_to_stk_status(payload: dict, stk: StkPushRequest) -> dict:
    """Add voucher fields to payment-status JSON when a voucher exists."""
    voucher = AccessVoucher.objects.filter(stk_request=stk).first()
    if voucher is None and stk.status == StkPushRequest.Status.SUCCESS:
        try:
            voucher = create_voucher_for_stk(stk)
        except Exception:  # noqa: BLE001
            logger.exception("Could not create voucher for STK %s", stk.pk)
            voucher = None
    payload.update(voucher_payload(voucher))
    voucher_valid = bool(
        voucher is not None and voucher.status == AccessVoucher.Status.VALID
    )
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
        f"Open the pay page and enter this code to activate {plan_name}."
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
