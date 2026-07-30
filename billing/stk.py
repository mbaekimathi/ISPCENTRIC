"""M-Pesa STK Push initiation and fulfillment for subscription renewals."""

from __future__ import annotations

import json
import logging
from decimal import Decimal

from django.db import transaction
from django.utils import timezone

from accounts.models import PaymentGateway
from accounts.mpesa_daraja import initiate_stk_push, query_stk_push
from billing.models import Customer, StkPushRequest
from billing.services import (
    apply_subscription_renewal,
    create_renewal_invoice_and_payment,
    normalize_kenya_msisdn,
)

logger = logging.getLogger(__name__)


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
            PaymentGateway.default_callback_url(env)
        )
    if not url and request is not None:
        url = request.build_absolute_uri(PaymentGateway.STK_CALLBACK_PATH)

    # Production Daraja requires a public HTTPS callback (not localhost).
    # Local confirmation still works via STK Query polling.
    if env == PaymentGateway.Environment.PRODUCTION and _is_local_http_callback(url):
        from django.conf import settings

        public = (getattr(settings, "PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
        if public.startswith("https://"):
            return f"{public}{PaymentGateway.STK_CALLBACK_PATH}"
        return f"https://ispcentric.local{PaymentGateway.STK_CALLBACK_PATH}"

    return url or f"{PaymentGateway.sandbox_base_url()}{PaymentGateway.STK_CALLBACK_PATH}"


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
    user=None,
    request=None,
) -> dict:
    """Validate and initiate STK Push for a customer's plan price."""
    if customer.organization_id != organization.pk:
        return {"ok": False, "error": "Customer does not belong to this organization."}
    plan = customer.plan
    if plan is None:
        return {"ok": False, "error": "Assign a billing package before collecting payment."}
    amount = Decimal(plan.price or 0)
    if amount <= 0:
        return {"ok": False, "error": "Package price must be greater than zero."}

    creds = organization.effective_daraja_credentials()
    if not creds.get("enabled"):
        return {"ok": False, "error": "Enable Daraja STK Push on My Account first."}
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


@transaction.atomic
def fulfill_successful_stk(
    stk: StkPushRequest,
    *,
    result_code: int = 0,
    result_desc: str = "",
    mpesa_receipt: str = "",
    raw: dict | None = None,
) -> dict:
    """Mark STK success, renew subscription, and record invoice/payment (idempotent)."""
    stk = StkPushRequest.objects.select_for_update().select_related(
        "customer", "customer__plan", "organization"
    ).get(pk=stk.pk)

    if raw:
        stk.raw_callback = raw
    stk.result_code = result_code
    if result_desc:
        stk.result_desc = result_desc[:255]
    if mpesa_receipt:
        stk.mpesa_receipt = mpesa_receipt[:64]

    if stk.status == StkPushRequest.Status.SUCCESS and stk.subscription_applied:
        return {
            "ok": True,
            "already_applied": True,
            "stk_id": stk.pk,
            "package_start": stk.customer.package_start,
            "package_end": stk.customer.package_end,
            "mpesa_receipt": stk.mpesa_receipt,
        }

    customer = stk.customer
    try:
        apply_subscription_renewal(customer, plan=customer.plan)
    except ValueError as exc:
        stk.status = StkPushRequest.Status.FAILED
        stk.result_desc = str(exc)[:255]
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
        return {"ok": False, "error": str(exc), "stk_id": stk.pk}

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

    try:
        from core.mikrotik_connect import sync_customer_subscription_access

        # Do not expire the captive client's host entry while this function is
        # running inside its payment-status request. That network reset can
        # sever the JSON response before the browser learns payment succeeded.
        # The loaded welcome page performs the final reauthentication instead.
        sync_customer_subscription_access(
            customer,
            provision=True,
            reauthenticate=False,
        )
    except Exception:  # noqa: BLE001 — payment already succeeded
        logger.exception(
            "Subscription renewed for customer %s but MikroTik sync failed",
            customer.pk,
        )

    return {
        "ok": True,
        "already_applied": False,
        "stk_id": stk.pk,
        "package_start": customer.package_start,
        "package_end": customer.package_end,
        "mpesa_receipt": stk.mpesa_receipt,
        "invoice_number": invoice.invoice_number if invoice else "",
    }


def mark_stk_failed(
    stk: StkPushRequest,
    *,
    result_code=None,
    result_desc: str = "",
    cancelled: bool = False,
    raw: dict | None = None,
) -> StkPushRequest:
    if stk.status == StkPushRequest.Status.SUCCESS and stk.subscription_applied:
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
    if raw:
        stk.raw_callback = raw
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
        return fulfill_successful_stk(
            stk,
            result_code=0,
            result_desc=result_desc or "The service request is processed successfully.",
            mpesa_receipt=receipt,
            raw=payload,
        )

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


def refresh_stk_status(stk: StkPushRequest) -> dict:
    """
    Return current STK status; if still pending, query Daraja (needed when
    localhost callbacks cannot be reached).
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
        "customer_name": customer.full_name,
        "account_number": customer.account_number,
        "package_start": customer.package_start.isoformat() if customer.package_start else "",
        "package_end": customer.package_end.isoformat() if customer.package_end else "",
        "subscription_applied": stk.subscription_applied,
    }
    if stk.status != StkPushRequest.Status.PENDING:
        base["pending"] = False
        base["success"] = stk.status == StkPushRequest.Status.SUCCESS
        if not base["success"]:
            base["reason"] = stk_failure_reason(stk.result_code, stk.result_desc)
            base["cancelled"] = stk.status == StkPushRequest.Status.CANCELLED
            base["can_retry"] = True
        return base

    if not stk.checkout_request_id:
        return _still_pending(base, stk, result_desc=stk.result_desc)

    org = stk.organization
    creds = org.effective_daraja_credentials()
    if not creds.get("ready"):
        return _still_pending(base, stk)

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
