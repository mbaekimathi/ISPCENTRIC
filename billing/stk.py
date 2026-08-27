"""M-Pesa STK Push initiation and fulfillment for subscription renewals."""

from __future__ import annotations

import json
import logging
from decimal import Decimal

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from accounts.models import ClientSettings, PaymentGateway
from accounts.mpesa_daraja import initiate_stk_push, query_stk_push
from billing.models import Customer, Invoice, StkPushRequest
from billing.services import (
    create_renewal_invoice_and_payment,
    normalize_kenya_msisdn,
    resolve_lead_allocation_fee,
    resolve_lead_allocation_technician_options,
)

logger = logging.getLogger(__name__)

# Captive pay pages poll ~1s for UX, but Safaricom STK Query is slow (up to
# 25s). Only one Daraja query per STK every few seconds; intervening polls
# return local pending so the queue does not pile up behind Safaricom.
STK_QUERY_MIN_INTERVAL_SECONDS = 3

# Keys that must survive Daraja callback/query overwrites of raw_callback.
_STK_RAW_PRESERVE_KEYS = (
    "lead_allocation_options",
    "environment",
    "initiate",
)


def _merge_stk_raw_callback(existing, incoming) -> dict:
    """Merge callback/query payload onto stored STK raw data without dropping options."""
    base = existing if isinstance(existing, dict) else {}
    update = incoming if isinstance(incoming, dict) else {}
    preserved = {key: base[key] for key in _STK_RAW_PRESERVE_KEYS if key in base}
    return {**preserved, **update}


def _callback_metadata_map(items) -> dict:
    out = {}
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("Name") or item.get("name")
        if not name:
            continue
        value = item.get("Value")
        if value is None:
            value = item.get("value")
        out[str(name)] = value
    return out


def resolve_stk_callback_url(
    creds: dict,
    request=None,
    *,
    environment: str | None = None,
) -> str:
    env = (
        environment
        or creds.get("environment")
        or PaymentGateway.Environment.SANDBOX
    ).strip().lower()

    url = (creds.get("callback_url") or "").strip()
    if url:
        url = PaymentGateway.normalize_callback_url(url)
    else:
        url = PaymentGateway.normalize_callback_url(
            PaymentGateway.default_callback_url(env, request)
        )
    if not url and request is not None:
        url = request.build_absolute_uri(PaymentGateway.STK_CALLBACK_PATH)

    # Production Daraja requires a public HTTPS callback (not localhost).
    # Local confirmation still works via STK Query polling.
    if env == PaymentGateway.Environment.PRODUCTION and _is_local_http_callback(url):
        try:
            from core.hotspot_portal import public_base_url

            public = (public_base_url() or "").strip().rstrip("/")
        except Exception:
            from django.conf import settings

            public = (getattr(settings, "PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
        if public.startswith("https://"):
            return f"{public}{PaymentGateway.STK_CALLBACK_PATH}"
        return f"https://ispcentric.local{PaymentGateway.STK_CALLBACK_PATH}"

    return url or f"{PaymentGateway.sandbox_base_url(request)}{PaymentGateway.STK_CALLBACK_PATH}"


def _is_local_http_callback(url: str) -> bool:
    raw = (url or "").strip().lower()
    return raw.startswith("http://localhost") or raw.startswith("http://127.0.0.1")


def _is_invalid_access_token_error(result: dict) -> bool:
    err = f"{result.get('error') or ''} {json.dumps(result.get('data') or {})}".lower()
    return "invalid access token" in err or "404.001.03" in err


def start_subscription_stk_payment(
    *,
    organization,
    customer: Customer,
    phone: str,
    plan=None,
    user=None,
    request=None,
) -> dict:
    """Validate and initiate STK Push for a customer's plan price."""
    if customer.organization_id != organization.pk:
        return {"ok": False, "error": "Customer does not belong to this organization."}
    plan = plan or customer.plan
    if plan is None:
        return {"ok": False, "error": "Assign a billing package before collecting payment."}
    if plan.organization_id != organization.pk or not plan.is_active:
        return {"ok": False, "error": "Choose an active package from this organization."}
    amount = Decimal(plan.price or 0)
    if amount <= 0:
        return {"ok": False, "error": "Package price must be greater than zero."}

    creds = organization.effective_daraja_credentials()
    if not creds.get("enabled"):
        return {"ok": False, "error": "Enable Daraja STK Push in Settings → STK Payment Settings first."}
    if not creds.get("ready"):
        return {
            "ok": False,
            "error": creds.get("message") or "Daraja STK Push is not ready yet.",
        }

    msisdn = normalize_kenya_msisdn(phone or customer.phone)
    if not (msisdn.startswith("254") and len(msisdn) == 12):
        return {
            "ok": False,
            "error": "Enter a valid Kenyan mobile number (e.g. 07xxxxxxxx).",
        }

    account_ref = PaymentGateway.account_reference_for_client(customer) or customer.account_number
    environment = (
        creds.get("environment") or PaymentGateway.Environment.SANDBOX
    ).strip().lower()

    stk = StkPushRequest.objects.create(
        organization=organization,
        customer=customer,
        plan=plan,
        amount=amount,
        phone=msisdn,
        account_reference=account_ref[:64],
        initiated_by=user if getattr(user, "is_authenticated", False) else None,
        status=StkPushRequest.Status.PENDING,
    )

    def _send(env: str) -> dict:
        return initiate_stk_push(
            consumer_key=creds["consumer_key"],
            consumer_secret=creds["consumer_secret"],
            passkey=creds["passkey"],
            shortcode=creds["shortcode"],
            payment_type=creds.get("payment_type") or "",
            amount=amount,
            phone=msisdn,
            account_reference=account_ref,
            callback_url=resolve_stk_callback_url(
                creds, request=request, environment=env
            ),
            environment=env,
            description="Subscription",
        )

    result = _send(environment)
    used_env = environment
    # Common misconfig: production Daraja keys saved while gateway env is sandbox.
    if (
        not result.get("ok")
        and environment == PaymentGateway.Environment.SANDBOX
        and _is_invalid_access_token_error(result)
    ):
        retry = _send(PaymentGateway.Environment.PRODUCTION)
        if retry.get("ok"):
            result = retry
            used_env = PaymentGateway.Environment.PRODUCTION
            logger.warning(
                "STK Push sandbox rejected credentials (Invalid Access Token); "
                "succeeded against production API for org=%s stk=%s",
                organization.pk,
                stk.pk,
            )
        else:
            result = retry

    if not result.get("ok"):
        error = result.get("error") or "STK Push failed."
        if _is_invalid_access_token_error(result):
            error = (
                "Daraja rejected the access token for STK Push. "
                "In IT Support → Payment Gateway, set Environment to match your "
                "consumer key/secret (Production vs Sandbox), and ensure "
                "Lipa Na M-Pesa Online is enabled on the Daraja app."
            )
        stk.status = StkPushRequest.Status.FAILED
        stk.result_desc = error[:255]
        stk.completed_at = timezone.now()
        stk.raw_callback = {"initiate_error": result, "environment": used_env}
        stk.save(
            update_fields=["status", "result_desc", "completed_at", "raw_callback"]
        )
        return {"ok": False, "error": error, "stk_id": stk.pk}

    stk.merchant_request_id = (result.get("merchant_request_id") or "")[:64]
    stk.checkout_request_id = (result.get("checkout_request_id") or "")[:64]
    stk.result_desc = (result.get("customer_message") or "STK Push sent.")[:255]
    stk.raw_callback = {"initiate": result.get("data") or {}, "environment": used_env}
    stk.save(
        update_fields=[
            "merchant_request_id",
            "checkout_request_id",
            "result_desc",
            "raw_callback",
        ]
    )
    return {
        "ok": True,
        "stk_id": stk.pk,
        "checkout_request_id": stk.checkout_request_id,
        "message": (
            result.get("customer_message")
            or f"STK Push sent to {msisdn}. Ask the client to enter their M-Pesa PIN."
        ),
        "amount": str(amount),
        "phone": msisdn,
        "customer_name": customer.full_name,
        "account_number": customer.account_number,
        "plan_name": plan.name,
        "environment": used_env,
        "shortcode": creds.get("shortcode") or "",
    }


def start_lead_allocation_stk_payment(
    *,
    organization,
    customer: Customer,
    phone: str,
    user=None,
    request=None,
    request_technician: bool = False,
    technician_mode: str = "",
    technician_id=None,
) -> dict:
    """Initiate STK Push so an ISP can pay to allocate an open sales lead."""
    if customer.status != Customer.Status.NEW or customer.organization_id is not None:
        return {"ok": False, "error": "This lead is no longer available to accept."}

    tech_opts = resolve_lead_allocation_technician_options(
        organization=organization,
        request_technician=request_technician,
        technician_mode=technician_mode,
        technician_id=technician_id,
    )
    if not tech_opts.get("ok"):
        return {"ok": False, "error": tech_opts.get("error") or "Invalid technician options."}

    fee = resolve_lead_allocation_fee(organization=organization, customer=customer)
    if not fee.get("ok"):
        return {"ok": False, "error": fee.get("error") or "Sales commission is not configured."}
    amount = Decimal(fee["amount"])
    plan = fee.get("plan")
    technician = tech_opts.get("technician")

    creds = organization.effective_daraja_credentials()
    if not creds.get("enabled"):
        return {"ok": False, "error": "Enable Daraja STK Push in Settings → STK Payment Settings first."}
    if not creds.get("ready"):
        return {
            "ok": False,
            "error": creds.get("message") or "Daraja STK Push is not ready yet.",
        }

    msisdn = normalize_kenya_msisdn(phone or organization.phone or customer.phone)
    if not (msisdn.startswith("254") and len(msisdn) == 12):
        return {
            "ok": False,
            "error": "Enter a valid Kenyan mobile number (e.g. 07xxxxxxxx).",
        }

    ticket = (customer.sales_ticket_number or customer.account_number or f"C{customer.pk}")[:64]
    account_ref = f"LEAD-{ticket}"[:64]
    environment = (
        creds.get("environment") or PaymentGateway.Environment.SANDBOX
    ).strip().lower()

    allocation_options = {
        "request_technician": bool(tech_opts.get("request_technician")),
        "mode": tech_opts.get("mode") or "none",
        "technician_id": technician.pk if technician is not None else None,
        "status": tech_opts.get("status"),
    }

    stk = StkPushRequest.objects.create(
        organization=organization,
        customer=customer,
        plan=plan,
        purpose=StkPushRequest.Purpose.LEAD_ALLOCATION,
        amount=amount,
        phone=msisdn,
        account_reference=account_ref,
        initiated_by=user if getattr(user, "is_authenticated", False) else None,
        status=StkPushRequest.Status.PENDING,
        raw_callback={"lead_allocation_options": allocation_options},
    )

    def _send(env: str) -> dict:
        return initiate_stk_push(
            consumer_key=creds["consumer_key"],
            consumer_secret=creds["consumer_secret"],
            passkey=creds["passkey"],
            shortcode=creds["shortcode"],
            payment_type=creds.get("payment_type") or "",
            amount=amount,
            phone=msisdn,
            account_reference=account_ref,
            callback_url=resolve_stk_callback_url(
                creds, request=request, environment=env
            ),
            environment=env,
            description="Lead allocation",
        )

    result = _send(environment)
    used_env = environment
    if (
        not result.get("ok")
        and environment == PaymentGateway.Environment.SANDBOX
        and _is_invalid_access_token_error(result)
    ):
        retry = _send(PaymentGateway.Environment.PRODUCTION)
        if retry.get("ok"):
            result = retry
            used_env = PaymentGateway.Environment.PRODUCTION
            logger.warning(
                "Lead STK sandbox rejected credentials; production OK org=%s stk=%s",
                organization.pk,
                stk.pk,
            )
        else:
            result = retry

    if not result.get("ok"):
        error = result.get("error") or "STK Push failed."
        if _is_invalid_access_token_error(result):
            error = (
                "Daraja rejected the access token for STK Push. "
                "In IT Support → Payment Gateway, set Environment to match your "
                "consumer key/secret (Production vs Sandbox)."
            )
        stk.status = StkPushRequest.Status.FAILED
        stk.result_desc = error[:255]
        stk.completed_at = timezone.now()
        stk.raw_callback = {"initiate_error": result, "environment": used_env}
        stk.save(
            update_fields=["status", "result_desc", "completed_at", "raw_callback"]
        )
        return {"ok": False, "error": error, "stk_id": stk.pk}

    stk.merchant_request_id = (result.get("merchant_request_id") or "")[:64]
    stk.checkout_request_id = (result.get("checkout_request_id") or "")[:64]
    stk.result_desc = (result.get("customer_message") or "STK Push sent.")[:255]
    raw = stk.raw_callback if isinstance(stk.raw_callback, dict) else {}
    stk.raw_callback = {
        **raw,
        "initiate": result.get("data") or {},
        "environment": used_env,
        "lead_allocation_options": allocation_options,
    }
    stk.save(
        update_fields=[
            "merchant_request_id",
            "checkout_request_id",
            "result_desc",
            "raw_callback",
        ]
    )
    return {
        "ok": True,
        "stk_id": stk.pk,
        "checkout_request_id": stk.checkout_request_id,
        "message": (
            result.get("customer_message")
            or f"STK Push sent to {msisdn}. Enter the M-Pesa PIN to allocate this lead."
        ),
        "amount": str(amount),
        "phone": msisdn,
        "customer_name": customer.full_name,
        "account_number": customer.account_number,
        "ticket_number": customer.sales_ticket_number or "",
        "plan_name": plan.name if plan is not None else "",
        "purpose": StkPushRequest.Purpose.LEAD_ALLOCATION,
        "allocation_status": allocation_options.get("status"),
        "request_technician": allocation_options.get("request_technician"),
        "technician_mode": allocation_options.get("mode"),
        "environment": used_env,
        "shortcode": creds.get("shortcode") or "",
    }


def _platform_daraja_credentials() -> dict:
    """Company Payment Gateway only — used for platform fees, never ISP Daraja fields."""
    return PaymentGateway.get_solo().as_stk_credentials()


def start_mikrotik_onboarding_stk_payment(
    *,
    organization,
    phone: str,
    label: str = "",
    user=None,
    request=None,
) -> dict:
    """Initiate STK Push for the platform MikroTik onboarding fee."""
    settings_obj = ClientSettings.get_solo()
    if not settings_obj.onboarding_fee_ready:
        return {
            "ok": False,
            "error": "MikroTik onboarding fee is not enabled or amount is not set.",
            "payment_required": False,
        }

    amount = Decimal(settings_obj.onboarding_fee_amount)
    creds = _platform_daraja_credentials()
    if not creds.get("enabled"):
        return {
            "ok": False,
            "error": "Activate STK Push under IT Support → Payment Gateway first.",
        }
    if not creds.get("ready"):
        return {
            "ok": False,
            "error": creds.get("message") or "Payment Gateway is not ready yet.",
        }

    org_phone = getattr(organization, "phone", "") or ""
    user_phone = ""
    if user is not None:
        user_phone = getattr(user, "phone", "") or ""
    msisdn = normalize_kenya_msisdn(phone or org_phone or user_phone)
    if not (msisdn.startswith("254") and len(msisdn) == 12):
        return {
            "ok": False,
            "error": "Enter a valid Kenyan mobile number (e.g. 07xxxxxxxx).",
            "payment_required": True,
            "amount": str(amount),
        }

    site_label = (label or "").strip() or "MikroTik"
    account_ref = f"MK-{organization.pk}-{msisdn[-4:]}"[:64]
    environment = (
        creds.get("environment") or PaymentGateway.Environment.SANDBOX
    ).strip().lower()

    stk = StkPushRequest.objects.create(
        organization=organization,
        customer=None,
        plan=None,
        purpose=StkPushRequest.Purpose.MIKROTIK_ONBOARDING,
        amount=amount,
        phone=msisdn,
        account_reference=account_ref,
        initiated_by=user if getattr(user, "is_authenticated", False) else None,
        status=StkPushRequest.Status.PENDING,
        raw_callback={
            "mikrotik_onboarding": {
                "label": site_label,
                "user_id": getattr(user, "pk", None),
                "script_used": False,
            }
        },
    )

    def _send(env: str) -> dict:
        return initiate_stk_push(
            consumer_key=creds["consumer_key"],
            consumer_secret=creds["consumer_secret"],
            passkey=creds["passkey"],
            shortcode=creds["shortcode"],
            payment_type=creds.get("payment_type") or "",
            amount=amount,
            phone=msisdn,
            account_reference=account_ref,
            callback_url=resolve_stk_callback_url(
                creds, request=request, environment=env
            ),
            environment=env,
            description="MikroTik onboarding",
        )

    result = _send(environment)
    used_env = environment
    if (
        not result.get("ok")
        and environment == PaymentGateway.Environment.SANDBOX
        and _is_invalid_access_token_error(result)
    ):
        retry = _send(PaymentGateway.Environment.PRODUCTION)
        if retry.get("ok"):
            result = retry
            used_env = PaymentGateway.Environment.PRODUCTION
            logger.info(
                "Onboarding STK sandbox rejected credentials; production OK org=%s stk=%s",
                organization.pk,
                stk.pk,
            )

    if not result.get("ok"):
        error = result.get("error") or "Could not start STK Push."
        stk.status = StkPushRequest.Status.FAILED
        stk.result_desc = error[:255]
        stk.completed_at = timezone.now()
        stk.raw_callback = {
            "initiate_error": result,
            "environment": used_env,
            "mikrotik_onboarding": {
                "label": site_label,
                "user_id": getattr(user, "pk", None),
                "script_used": False,
            },
        }
        stk.save(
            update_fields=["status", "result_desc", "completed_at", "raw_callback"]
        )
        return {"ok": False, "error": error, "stk_id": stk.pk}

    stk.merchant_request_id = (result.get("merchant_request_id") or "")[:64]
    stk.checkout_request_id = (result.get("checkout_request_id") or "")[:64]
    stk.result_desc = (result.get("customer_message") or "STK Push sent.")[:255]
    raw = stk.raw_callback if isinstance(stk.raw_callback, dict) else {}
    stk.raw_callback = {
        **raw,
        "initiate": result.get("data") or {},
        "environment": used_env,
    }
    stk.save(
        update_fields=[
            "merchant_request_id",
            "checkout_request_id",
            "result_desc",
            "raw_callback",
        ]
    )
    return {
        "ok": True,
        "stk_id": stk.pk,
        "checkout_request_id": stk.checkout_request_id,
        "payment_required": True,
        "message": (
            result.get("customer_message")
            or f"STK Push sent to {msisdn}. Enter the M-Pesa PIN to unlock the script."
        ),
        "amount": str(amount),
        "phone": msisdn,
        "purpose": StkPushRequest.Purpose.MIKROTIK_ONBOARDING,
        "environment": used_env,
        "shortcode": creds.get("shortcode") or "",
    }


def _fulfill_mikrotik_onboarding_stk(stk: StkPushRequest) -> dict:
    """Mark onboarding fee paid so the tunnel script can be generated."""
    stk.status = StkPushRequest.Status.SUCCESS
    stk.subscription_applied = True
    stk.completed_at = timezone.now()
    stk.save(
        update_fields=[
            "status",
            "result_code",
            "result_desc",
            "mpesa_receipt",
            "raw_callback",
            "subscription_applied",
            "completed_at",
        ]
    )
    return {
        "ok": True,
        "stk_id": stk.pk,
        "purpose": StkPushRequest.Purpose.MIKROTIK_ONBOARDING,
        "onboarding_paid": True,
        "mpesa_receipt": stk.mpesa_receipt,
        "amount": str(stk.amount),
    }


def consume_mikrotik_onboarding_payment(
    *,
    organization,
    user,
    stk_id: int,
    label: str = "",
    mark_used: bool = True,
) -> dict:
    """Validate a paid onboarding STK and optionally mark it used for script generation."""
    try:
        stk = StkPushRequest.objects.get(pk=stk_id)
    except StkPushRequest.DoesNotExist:
        return {"ok": False, "error": "Payment was not found. Pay again to continue."}

    if stk.organization_id != getattr(organization, "pk", None):
        return {"ok": False, "error": "This payment does not belong to your organization."}
    if stk.purpose != StkPushRequest.Purpose.MIKROTIK_ONBOARDING:
        return {"ok": False, "error": "This payment is not an onboarding fee."}
    if stk.status != StkPushRequest.Status.SUCCESS or not stk.subscription_applied:
        return {
            "ok": False,
            "error": "Complete the M-Pesa prompt before generating the script.",
            "stk_id": stk.pk,
            "status": stk.status,
        }

    raw = stk.raw_callback if isinstance(stk.raw_callback, dict) else {}
    meta = raw.get("mikrotik_onboarding") if isinstance(raw.get("mikrotik_onboarding"), dict) else {}
    if meta.get("script_used"):
        return {
            "ok": False,
            "error": "This payment was already used to generate a script. Pay again for another site.",
            "stk_id": stk.pk,
        }
    paid_user_id = meta.get("user_id")
    if paid_user_id and getattr(user, "pk", None) and paid_user_id != user.pk:
        return {"ok": False, "error": "This onboarding payment belongs to another user."}

    if mark_used:
        meta = {
            **meta,
            "script_used": True,
            "script_label": (label or meta.get("label") or "").strip(),
            "script_used_at": timezone.now().isoformat(),
        }
        raw = {**raw, "mikrotik_onboarding": meta}
        stk.raw_callback = raw
        stk.save(update_fields=["raw_callback"])
    return {"ok": True, "stk_id": stk.pk, "amount": str(stk.amount)}


def _persist_stk_receipt_fields(
    stk: StkPushRequest,
    *,
    raw: dict | None,
    result_desc: str,
    result_code: int,
    receipt: str,
) -> dict:
    """Idempotent receipt/status updates after fulfillment already applied."""
    update_fields: list[str] = []
    if raw is not None:
        update_fields.append("raw_callback")
    if result_desc:
        update_fields.append("result_desc")
    if result_code is not None:
        update_fields.append("result_code")
    if receipt:
        update_fields.append("mpesa_receipt")
    if update_fields:
        stk.save(update_fields=list(dict.fromkeys(update_fields)))
    if receipt and stk.payment_id:
        payment = stk.payment
        current_ref = (payment.reference or "").strip()
        if not current_ref or current_ref == (stk.checkout_request_id or "").strip():
            payment.reference = receipt[:100]
            payment.save(update_fields=["reference"])
    return {
        "ok": True,
        "already_applied": True,
        "stk_id": stk.pk,
        "package_start": getattr(stk.customer, "package_start", None) if stk.customer_id else None,
        "package_end": getattr(stk.customer, "package_end", None) if stk.customer_id else None,
        "mpesa_receipt": stk.mpesa_receipt,
        "purpose": stk.purpose,
        "customer_status": getattr(stk.customer, "status", None) if stk.customer_id else None,
    }


def _fulfill_lead_allocation_stk(stk: StkPushRequest) -> dict:
    """Assign the lead to the paying ISP and mark it allocated."""
    from accounts.models import Employee

    customer = Customer.objects.select_for_update().select_related("plan").get(
        pk=stk.customer_id
    )
    if (
        customer.status in Customer.ALLOCATED_STATUSES
        and customer.organization_id == stk.organization_id
    ):
        pass
    elif customer.status != Customer.Status.NEW or customer.organization_id is not None:
        stk.status = StkPushRequest.Status.FAILED
        stk.result_desc = "Lead was taken by another ISP before payment completed."[:255]
        stk.completed_at = timezone.now()
        stk.save(
            update_fields=[
                "status",
                "result_code",
                "result_desc",
                "mpesa_receipt",
                "raw_callback",
                "completed_at",
            ]
        )
        return {
            "ok": False,
            "error": stk.result_desc,
            "stk_id": stk.pk,
        }

    raw = stk.raw_callback if isinstance(stk.raw_callback, dict) else {}
    options = raw.get("lead_allocation_options") or {}
    target_status = options.get("status") or Customer.Status.ALLOCATED_OPEN
    if target_status not in {
        Customer.Status.ALLOCATED_OPEN,
        Customer.Status.ALLOCATED_CLOSED,
        Customer.Status.ALLOCATED,
    }:
        target_status = Customer.Status.ALLOCATED_OPEN

    technician = None
    tech_id = options.get("technician_id")
    if tech_id and target_status == Customer.Status.ALLOCATED_CLOSED:
        technician = (
            Employee.objects.filter(
                pk=tech_id,
                role=Employee.Role.TECHNICIAN,
                status=Employee.Status.ACTIVE,
            )
            .filter(Q(organization_id=stk.organization_id) | Q(organization__isnull=True))
            .first()
        )
        if technician is None:
            technician = Employee.objects.filter(
                pk=tech_id,
                role=Employee.Role.TECHNICIAN,
                status=Employee.Status.ACTIVE,
            ).first()

    # Closed assignment requires a concrete technician; otherwise keep open pool.
    if target_status == Customer.Status.ALLOCATED_CLOSED and technician is None:
        target_status = Customer.Status.ALLOCATED_OPEN

    paid_plan = stk.plan or customer.plan
    update_fields = ["organization", "status", "assigned_technician"]
    customer.organization = stk.organization
    customer.status = target_status
    customer.assigned_technician = technician
    if paid_plan is not None and customer.plan_id != paid_plan.pk:
        customer.plan = paid_plan
        update_fields.append("plan")
    customer.save(update_fields=update_fields)

    invoice = stk.invoice
    payment = stk.payment
    if invoice is None or payment is None:
        invoice, payment = create_renewal_invoice_and_payment(
            customer=customer,
            organization=stk.organization,
            amount=stk.amount,
            reference=stk.mpesa_receipt or stk.checkout_request_id,
            recorded_by=stk.initiated_by,
            notes="M-Pesa STK Push lead allocation",
            invoice_prefix="LEAD",
        )
        stk.invoice = invoice
        stk.payment = payment

    stk.status = StkPushRequest.Status.SUCCESS
    stk.subscription_applied = True
    stk.completed_at = timezone.now()
    stk.save(
        update_fields=[
            "status",
            "result_code",
            "result_desc",
            "mpesa_receipt",
            "raw_callback",
            "invoice",
            "payment",
            "subscription_applied",
            "completed_at",
        ]
    )
    return {
        "ok": True,
        "already_applied": False,
        "stk_id": stk.pk,
        "purpose": StkPushRequest.Purpose.LEAD_ALLOCATION,
        "customer_status": customer.status,
        "customer_phone": customer.phone or "",
        "assigned_technician_id": technician.pk if technician else None,
        "mpesa_receipt": stk.mpesa_receipt,
        "invoice_number": invoice.invoice_number if invoice else "",
        "package_start": customer.package_start,
        "package_end": customer.package_end,
    }


@transaction.atomic
def reverse_lead_allocation(
    *,
    organization,
    customer: Customer,
    user=None,
    reason: str = "",
) -> dict:
    """
    Reverse an allocated lead payment record and return the ticket to the open pool.
    Status flips to NEW immediately; M-Pesa refund must be handled out-of-band.
    """
    reason = (reason or "").strip()
    if not reason:
        return {"ok": False, "error": "Enter a reason for this reversal."}
    if len(reason) > 255:
        reason = reason[:255]

    if (
        customer.status not in Customer.ALLOCATED_STATUSES
        or customer.organization_id != organization.pk
    ):
        return {"ok": False, "error": "Only tickets allocated to your ISP can be reversed."}

    stk = (
        StkPushRequest.objects.select_for_update()
        .filter(
            organization=organization,
            customer=customer,
            purpose=StkPushRequest.Purpose.LEAD_ALLOCATION,
            status=StkPushRequest.Status.SUCCESS,
            subscription_applied=True,
        )
        .select_related("payment", "invoice")
        .order_by("-completed_at", "-pk")
        .first()
    )

    if stk is not None:
        payment = stk.payment
        raw_existing = stk.raw_callback if isinstance(stk.raw_callback, dict) else {}
        if raw_existing.get("lead_allocation_reversed"):
            return {"ok": False, "error": "This allocation was already reversed."}

        if payment is not None:
            note = (payment.invoice.notes if payment.invoice_id else "") or ""
            if "[LEAD ALLOCATION REVERSED]" in note:
                return {"ok": False, "error": "This allocation was already reversed."}
            if payment.invoice_id:
                inv = payment.invoice
                inv.notes = (
                    f"{(inv.notes or '').strip()} "
                    f"[LEAD ALLOCATION REVERSED] Reason: {reason}"
                ).strip()
                inv.status = Invoice.Status.CANCELLED
                inv.save(update_fields=["notes", "status"])
            payment.reference = (
                f"REV-{(payment.reference or stk.mpesa_receipt or str(stk.pk))}"[:100]
            )
            payment.save(update_fields=["reference"])

        raw = stk.raw_callback if isinstance(stk.raw_callback, dict) else {}
        raw = {
            **raw,
            "lead_allocation_reversed": True,
            "reversed_at": timezone.now().isoformat(),
            "reversal_reason": reason,
        }
        if user is not None and getattr(user, "pk", None):
            raw["reversed_by"] = user.pk
        stk.raw_callback = raw
        stk.result_desc = f"Reversed: {reason}"[:255]
        stk.save(update_fields=["raw_callback", "result_desc"])

    customer.organization = None
    customer.status = Customer.Status.NEW
    customer.assigned_technician = None
    customer.save(update_fields=["organization", "status", "assigned_technician"])
    return {
        "ok": True,
        "customer_id": customer.pk,
        "ticket_number": customer.sales_ticket_number or customer.account_number,
        "status": customer.status,
        "reason": reason,
        "message": (
            "Allocation reversed. Ticket is New again. "
            "Process the M-Pesa refund separately if needed."
        ),
    }


@transaction.atomic
def fulfill_successful_stk(
    stk: StkPushRequest,
    *,
    result_code: int = 0,
    result_desc: str = "",
    mpesa_receipt: str = "",
    raw: dict | None = None,
) -> dict:
    """Mark STK success and apply purpose-specific fulfillment (idempotent)."""
    stk = StkPushRequest.objects.select_for_update().select_related(
        "customer", "customer__plan", "plan", "organization", "payment"
    ).get(pk=stk.pk)

    if raw is not None:
        stk.raw_callback = _merge_stk_raw_callback(stk.raw_callback, raw)
    stk.result_code = result_code
    if result_desc:
        stk.result_desc = result_desc[:255]
    receipt = (mpesa_receipt or "").strip()
    if receipt:
        stk.mpesa_receipt = receipt[:64]

    if stk.status == StkPushRequest.Status.SUCCESS and stk.subscription_applied:
        return _persist_stk_receipt_fields(
            stk,
            raw=stk.raw_callback if raw is not None else None,
            result_desc=result_desc,
            result_code=result_code,
            receipt=receipt,
        )

    if stk.purpose == StkPushRequest.Purpose.LEAD_ALLOCATION:
        return _fulfill_lead_allocation_stk(stk)

    if stk.purpose == StkPushRequest.Purpose.MIKROTIK_ONBOARDING:
        return _fulfill_mikrotik_onboarding_stk(stk)

    customer = stk.customer
    if customer is None:
        stk.status = StkPushRequest.Status.FAILED
        stk.result_desc = "Missing customer for subscription STK."[:255]
        stk.completed_at = timezone.now()
        stk.save(
            update_fields=[
                "status",
                "result_code",
                "result_desc",
                "mpesa_receipt",
                "raw_callback",
                "completed_at",
            ]
        )
        return {"ok": False, "error": stk.result_desc, "stk_id": stk.pk}

    from billing.vouchers import create_vouchers_for_stk, voucher_payload

    # Already paid: persist receipt updates, return the voucher(s).
    # Pay-page / callback auto-redeem applies the package; fulfill itself does not.
    if stk.status == StkPushRequest.Status.SUCCESS:
        persisted = _persist_stk_receipt_fields(
            stk,
            raw=stk.raw_callback if raw is not None else None,
            result_desc=result_desc,
            result_code=result_code,
            receipt=receipt,
        )
        vouchers = create_vouchers_for_stk(stk)
        voucher = next(
            (row for row in vouchers if row.status == row.Status.VALID),
            vouchers[0] if vouchers else None,
        )
        persisted["already_applied"] = bool(stk.subscription_applied)
        persisted["needs_voucher"] = bool(
            voucher is not None and voucher.status == voucher.Status.VALID
        )
        persisted["authorized"] = False
        persisted["just_provisioned"] = False
        persisted["provision_ok"] = False
        persisted["provision_allowed"] = False
        persisted.update(voucher_payload(voucher, all_vouchers=vouchers))
        return persisted

    paid_plan = stk.plan or customer.plan
    if paid_plan is not None and customer.plan_id != paid_plan.pk:
        customer.plan = paid_plan
        customer.save(update_fields=["plan"])

    invoice = stk.invoice
    payment = stk.payment
    if invoice is None or payment is None:
        invoice, payment = create_renewal_invoice_and_payment(
            customer=customer,
            organization=stk.organization,
            amount=stk.amount,
            reference=stk.mpesa_receipt or stk.checkout_request_id,
            recorded_by=stk.initiated_by,
        )
        stk.invoice = invoice
        stk.payment = payment

    # Payment is recorded; package + MikroTik activate only after voucher redeem.
    stk.status = StkPushRequest.Status.SUCCESS
    stk.subscription_applied = False
    stk.completed_at = timezone.now()
    stk.save(
        update_fields=[
            "status",
            "result_code",
            "result_desc",
            "mpesa_receipt",
            "raw_callback",
            "invoice",
            "payment",
            "subscription_applied",
            "completed_at",
        ]
    )

    vouchers = create_vouchers_for_stk(stk)
    voucher = next(
        (row for row in vouchers if row.status == row.Status.VALID),
        vouchers[0] if vouchers else None,
    )

    return {
        "ok": True,
        "already_applied": False,
        "stk_id": stk.pk,
        "package_start": customer.package_start,
        "package_end": customer.package_end,
        "mpesa_receipt": stk.mpesa_receipt,
        "invoice_number": invoice.invoice_number if invoice else "",
        "provision_ok": False,
        "provision_allowed": False,
        "provision_offline": False,
        "provision_message": "",
        "just_provisioned": False,
        "needs_voucher": True,
        "authorized": False,
        **voucher_payload(voucher, all_vouchers=vouchers),
    }


def mark_stk_failed(
    stk: StkPushRequest,
    *,
    result_code=None,
    result_desc: str = "",
    cancelled: bool = False,
    raw: dict | None = None,
) -> StkPushRequest:
    if stk.status == StkPushRequest.Status.SUCCESS:
        return stk
    stk.status = (
        StkPushRequest.Status.CANCELLED if cancelled else StkPushRequest.Status.FAILED
    )
    if result_code is not None:
        try:
            stk.result_code = int(result_code)
        except (TypeError, ValueError):
            pass
    if result_desc:
        stk.result_desc = result_desc[:255]
    if raw is not None:
        stk.raw_callback = _merge_stk_raw_callback(stk.raw_callback, raw)
    stk.completed_at = timezone.now()
    stk.save(
        update_fields=[
            "status",
            "result_code",
            "result_desc",
            "raw_callback",
            "completed_at",
        ]
    )
    return stk


def process_stk_callback_payload(payload: dict) -> dict:
    """Handle Daraja STK callback body and fulfill or fail the matching request."""
    body = payload.get("Body") if isinstance(payload, dict) else None
    callback = body.get("stkCallback") if isinstance(body, dict) else None
    if not isinstance(callback, dict):
        return {"ok": False, "error": "Unrecognized callback payload."}

    checkout_id = (callback.get("CheckoutRequestID") or "").strip()
    merchant_id = (callback.get("MerchantRequestID") or "").strip()
    try:
        result_code = int(callback.get("ResultCode"))
    except (TypeError, ValueError):
        result_code = None
    result_desc = (callback.get("ResultDesc") or "").strip()

    stk = None
    if checkout_id:
        stk = (
            StkPushRequest.objects.select_related("customer", "organization", "customer__plan")
            .filter(checkout_request_id=checkout_id)
            .first()
        )
    if stk is None and merchant_id:
        stk = (
            StkPushRequest.objects.select_related("customer", "organization", "customer__plan")
            .filter(merchant_request_id=merchant_id)
            .order_by("-created_at")
            .first()
        )
    if stk is None:
        return {"ok": False, "error": "No matching STK request found.", "checkout_request_id": checkout_id}

    if result_code == 0:
        metadata = {}
        callback_metadata = callback.get("CallbackMetadata") or {}
        if isinstance(callback_metadata, dict):
            metadata = _callback_metadata_map(callback_metadata.get("Item"))
        receipt = str(
            metadata.get("MpesaReceiptNumber")
            or metadata.get("MpesaReceiptNo")
            or ""
        ).strip()
        result = fulfill_successful_stk(
            stk,
            result_code=0,
            result_desc=result_desc or "The service request is processed successfully.",
            mpesa_receipt=receipt,
            raw=payload,
        )
        if result.get("ok"):
            stk.refresh_from_db()
            if stk.purpose == StkPushRequest.Purpose.SUBSCRIPTION:
                from billing.vouchers import activate_paid_subscription_stk

                # Do not block Daraja's HTTP ack on MikroTik — apply in the background.
                activate_paid_subscription_stk(stk, background=True)
        return result

    cancelled = result_code == 1032
    mark_stk_failed(
        stk,
        result_code=result_code,
        result_desc=result_desc or ("Cancelled by user." if cancelled else "Payment failed."),
        cancelled=cancelled,
        raw=payload,
    )
    return {
        "ok": True,
        "failed": True,
        "cancelled": cancelled,
        "stk_id": stk.pk,
        "result_code": result_code,
        "result_desc": result_desc,
    }


# Daraja STK result codes, phrased for the paying customer rather than an
# operator. Safaricom's own ResultDesc is the fallback for anything unlisted.
STK_FAILURE_REASONS = {
    1: "Your M-Pesa balance is too low for this package.",
    17: "M-Pesa declined the request. Please try again in a moment.",
    26: "M-Pesa is busy right now. Please try again in a moment.",
    1001: (
        "You have another M-Pesa transaction in progress. "
        "Finish or cancel it, then try again."
    ),
    1019: "The payment request expired before it was confirmed.",
    1025: "M-Pesa could not process the request. Please try again.",
    1032: "You cancelled the M-Pesa prompt.",
    1037: (
        "The M-Pesa prompt did not reach your phone. "
        "Check that the number is correct and your phone has signal."
    ),
    2001: "The M-Pesa PIN entered was incorrect.",
    9999: "M-Pesa could not complete the request. Please try again.",
}

# Daraja acknowledges an initiation with wording like "Success. Request accepted
# for processing", which reads as though payment already went through.
_ACCEPTANCE_PHRASES = (
    "request accepted for processing",
    "success. request accepted",
    "stk push sent",
)

PENDING_MESSAGE = "Waiting for you to enter your M-Pesa PIN…"

# An unanswered STK prompt lapses on the handset well before this, but the
# request is never marked failed on a timeout — only Daraja can tell us the
# customer did not pay, and a late callback must still be able to activate.
STK_PROMPT_DEADLINE_SECONDS = 150


def stk_failure_reason(result_code, result_desc: str = "") -> str:
    """Customer-facing explanation for a failed or cancelled STK attempt."""
    try:
        code = int(result_code)
    except (TypeError, ValueError):
        code = None
    mapped = STK_FAILURE_REASONS.get(code)
    if mapped:
        return mapped
    desc = (result_desc or "").strip()
    return desc or "The payment was not completed."


def _still_pending(base: dict, stk: StkPushRequest, *, result_desc: str = "") -> dict:
    """Fill in the pending half of a status payload, flagging a lapsed prompt."""
    base["pending"] = True
    base["success"] = False
    base["result_desc"] = stk_pending_message(result_desc)
    elapsed = (
        (timezone.now() - stk.created_at).total_seconds() if stk.created_at else 0
    )
    if elapsed > STK_PROMPT_DEADLINE_SECONDS:
        base["expired"] = True
        base["can_retry"] = True
        base["reason"] = (
            "The M-Pesa prompt has not been confirmed yet. "
            "If it never reached your phone, you can try again."
        )
    return base


def stk_pending_message(result_desc: str = "") -> str:
    """Keep Daraja's 'request accepted' wording from looking like a success."""
    desc = (result_desc or "").strip()
    if not desc:
        return PENDING_MESSAGE
    lowered = desc.lower()
    if any(phrase in lowered for phrase in _ACCEPTANCE_PHRASES):
        return PENDING_MESSAGE
    return desc


def _apply_paid_subscription_to_status(
    payload: dict,
    stk: StkPushRequest,
    *,
    wait_for_nas: bool = False,
) -> dict:
    """Redeem the paying customer's voucher and optionally wait for NAS authorize."""
    if (
        stk.purpose != StkPushRequest.Purpose.SUBSCRIPTION
        or stk.status != StkPushRequest.Status.SUCCESS
    ):
        return payload
    from billing.vouchers import activate_paid_subscription_stk, attach_voucher_to_stk_status

    # Dashboard polls must not start a new NAS sync every 2s. Captive pay pages
    # (wait_for_nas) still push MikroTik on this request so surfing can start.
    activation = {}
    if not stk.subscription_applied or wait_for_nas:
        activation = activate_paid_subscription_stk(
            stk,
            wait_first=wait_for_nas,
            quick=True,
        )
    stk.refresh_from_db()
    customer = stk.customer
    if customer is not None:
        customer.refresh_from_db()
        payload["customer_name"] = customer.full_name
        payload["account_number"] = customer.account_number
        payload["package_start"] = (
            customer.package_start.isoformat() if customer.package_start else ""
        )
        payload["package_end"] = (
            customer.package_end.isoformat() if customer.package_end else ""
        )
    payload["subscription_applied"] = stk.subscription_applied
    if activation.get("queued"):
        payload["authorized"] = False
        payload["can_retry_authorize"] = True
    elif activation.get("ok"):
        payload["authorized"] = bool(activation.get("authorized"))
        payload["offline"] = bool(activation.get("offline"))
        payload["authorization_error"] = activation.get("authorization_error") or ""
        payload["can_retry_authorize"] = not payload["authorized"]
    payload["surfing"] = bool(payload.get("authorized"))
    attach_voucher_to_stk_status(payload, stk)
    if payload.get("subscription_applied"):
        payload["needs_voucher"] = False
    return payload


def refresh_stk_status(stk: StkPushRequest, *, wait_for_nas: bool = False) -> dict:
    """
    Return current STK status; if still pending, query Daraja (needed when
    localhost callbacks cannot be reached).

    ``wait_for_nas=True`` (captive pay pages) applies the package and waits for
    one quick MikroTik restore so the device can surf on this response.
    """
    stk.refresh_from_db()
    customer = stk.customer
    base = {
        "ok": True,
        "stk_id": stk.pk,
        "status": stk.status,
        "result_desc": stk.result_desc,
        "mpesa_receipt": stk.mpesa_receipt,
        "amount": str(stk.amount),
        "phone": stk.phone,
        "customer_name": customer.full_name if customer is not None else "",
        "account_number": customer.account_number if customer is not None else "",
        "package_start": (
            customer.package_start.isoformat()
            if customer is not None and customer.package_start
            else ""
        ),
        "package_end": (
            customer.package_end.isoformat()
            if customer is not None and customer.package_end
            else ""
        ),
        "subscription_applied": stk.subscription_applied,
        "purpose": stk.purpose,
        "onboarding_paid": bool(
            stk.purpose == StkPushRequest.Purpose.MIKROTIK_ONBOARDING
            and stk.status == StkPushRequest.Status.SUCCESS
            and stk.subscription_applied
        ),
    }
    if stk.status != StkPushRequest.Status.PENDING:
        base["pending"] = False
        base["success"] = stk.status == StkPushRequest.Status.SUCCESS
        if not base["success"]:
            base["reason"] = stk_failure_reason(stk.result_code, stk.result_desc)
            base["cancelled"] = stk.status == StkPushRequest.Status.CANCELLED
            base["can_retry"] = True
        elif stk.purpose == StkPushRequest.Purpose.SUBSCRIPTION:
            _apply_paid_subscription_to_status(base, stk, wait_for_nas=wait_for_nas)
        return base

    if not stk.checkout_request_id:
        return _still_pending(base, stk, result_desc=stk.result_desc)

    org = stk.organization
    creds = org.effective_daraja_credentials()
    if not creds.get("ready"):
        return _still_pending(base, stk)

    # Skip Safaricom if another poll already queried this STK recently.
    # Callbacks still flip status in DB — those polls take the SUCCESS branch
    # above and never reach here.
    try:
        from django.core.cache import cache

        query_lock = f"stk:daraja-query:{stk.pk}"
        if not cache.add(query_lock, 1, STK_QUERY_MIN_INTERVAL_SECONDS):
            return _still_pending(base, stk, result_desc=stk.result_desc)
    except Exception:
        pass

    stored = stk.raw_callback if isinstance(stk.raw_callback, dict) else {}
    query_env = (
        stored.get("environment")
        or creds.get("environment")
        or PaymentGateway.Environment.SANDBOX
    )

    query = query_stk_push(
        consumer_key=creds["consumer_key"],
        consumer_secret=creds["consumer_secret"],
        passkey=creds["passkey"],
        shortcode=creds["shortcode"],
        checkout_request_id=stk.checkout_request_id,
        environment=query_env,
    )
    if (
        query.get("pending") is False
        and not query.get("success")
        and _is_invalid_access_token_error(query)
        and str(query_env).lower() == PaymentGateway.Environment.SANDBOX
    ):
        query = query_stk_push(
            consumer_key=creds["consumer_key"],
            consumer_secret=creds["consumer_secret"],
            passkey=creds["passkey"],
            shortcode=creds["shortcode"],
            checkout_request_id=stk.checkout_request_id,
            environment=PaymentGateway.Environment.PRODUCTION,
        )
    if query.get("pending"):
        return _still_pending(
            base, stk, result_desc=query.get("result_desc") or stk.result_desc
        )

    if query.get("success"):
        receipt = ""
        data = query.get("data") or {}
        # Query response often lacks receipt; keep blank unless present
        receipt = str(
            data.get("MpesaReceiptNumber")
            or data.get("mpesa_receipt")
            or ""
        ).strip()
        fulfill = fulfill_successful_stk(
            stk,
            result_code=int(query.get("result_code") or 0),
            result_desc=query.get("result_desc") or "Payment confirmed.",
            mpesa_receipt=receipt or stk.mpesa_receipt,
            raw={"query": data},
        )
        stk.refresh_from_db()
        customer.refresh_from_db()
        applied = bool(fulfill.get("ok"))
        payload = {
            "ok": applied,
            "pending": False,
            "success": applied,
            "stk_id": stk.pk,
            "status": stk.status,
            "result_desc": stk.result_desc,
            "mpesa_receipt": stk.mpesa_receipt,
            "amount": str(stk.amount),
            "phone": stk.phone,
            "customer_name": customer.full_name,
            "account_number": customer.account_number,
            "package_start": customer.package_start.isoformat() if customer.package_start else "",
            "package_end": customer.package_end.isoformat() if customer.package_end else "",
            "subscription_applied": stk.subscription_applied,
            "error": fulfill.get("error") or "",
        }
        if applied and fulfill.get("just_provisioned"):
            # Hand authorization through so payment-status views do not open a
            # second MikroTik session in the same request.
            payload["just_provisioned"] = True
            payload["authorized"] = bool(
                fulfill.get("provision_ok") and fulfill.get("provision_allowed")
            )
            if not payload["authorized"]:
                payload["authorization_error"] = (
                    fulfill.get("provision_message")
                    or "Payment succeeded, but router authorization failed."
                )
                payload["can_retry"] = False
                payload["can_retry_authorize"] = True
                payload["offline"] = bool(fulfill.get("provision_offline"))
        if applied and stk.purpose == StkPushRequest.Purpose.SUBSCRIPTION:
            _apply_paid_subscription_to_status(
                payload, stk, wait_for_nas=wait_for_nas
            )
        if not applied:
            # M-Pesa took the money but the subscription could not be applied.
            # Retrying the charge would double-bill, so send them to support.
            payload["reason"] = (
                fulfill.get("error")
                or "Payment was received but the package could not be activated."
            )
            payload["can_retry"] = False
        return payload

    mark_stk_failed(
        stk,
        result_code=query.get("result_code"),
        result_desc=query.get("result_desc") or "Payment was not completed.",
        cancelled=bool(query.get("cancelled")),
        raw={"query": query.get("data") or {}},
    )
    stk.refresh_from_db()
    return {
        "ok": True,
        "pending": False,
        "success": False,
        "cancelled": bool(query.get("cancelled")),
        "reason": stk_failure_reason(stk.result_code, stk.result_desc),
        "can_retry": True,
        "stk_id": stk.pk,
        "status": stk.status,
        "result_desc": stk.result_desc,
        "mpesa_receipt": stk.mpesa_receipt,
        "amount": str(stk.amount),
        "phone": stk.phone,
        "customer_name": customer.full_name,
        "account_number": customer.account_number,
        "package_start": customer.package_start.isoformat() if customer.package_start else "",
        "package_end": customer.package_end.isoformat() if customer.package_end else "",
        "subscription_applied": stk.subscription_applied,
    }
