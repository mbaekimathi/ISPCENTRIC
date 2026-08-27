"""Safaricom Daraja STK Push configuration checks and API helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from decimal import Decimal, ROUND_HALF_UP
from typing import Any
from urllib.parse import urlparse

from django.core.cache import cache
from django.utils import timezone

from accounts.models import PaymentGateway

SANDBOX_OAUTH_URL = (
    "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
)
PRODUCTION_OAUTH_URL = (
    "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
)
SANDBOX_STK_URL = (
    "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
)
PRODUCTION_STK_URL = "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
SANDBOX_STK_QUERY_URL = (
    "https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query"
)
PRODUCTION_STK_QUERY_URL = (
    "https://api.safaricom.co.ke/mpesa/stkpushquery/v1/query"
)
OAUTH_TIMEOUT_SECONDS = 12
STK_TIMEOUT_SECONDS = 25
_TOKEN_CACHE_PREFIX = "daraja_oauth:"
_TOKEN_SAFETY_SECONDS = 60
# Safaricom's edge (especially sandbox) intermittently drops TLS handshakes;
# retries turn those blips into a normal response instead of a failed payment.
CONNECT_RETRIES = 4
RETRY_BACKOFF_SECONDS = 0.75
# Safaricom's published sandbox test shortcode. Any other shortcode must use
# the production API host — sandbox.safaricom.co.ke will reject / time out.
SANDBOX_TEST_SHORTCODE = "174379"


def resolve_daraja_api_environment(shortcode: str = "", environment: str = "") -> str:
    """
    Pick the Daraja API host environment from shortcode + configured env.

    Non-sandbox shortcodes cannot use sandbox.safaricom.co.ke. Misconfigured
    gateways that leave Environment=Sandbox with a live Paybill/Till cause
    SSL timeouts / UNEXPECTED_EOF against the sandbox edge.
    """
    env = (environment or "").strip().lower() or PaymentGateway.Environment.SANDBOX
    code = (shortcode or "").strip()
    if code and code != SANDBOX_TEST_SHORTCODE:
        return PaymentGateway.Environment.PRODUCTION
    if env == PaymentGateway.Environment.PRODUCTION:
        return PaymentGateway.Environment.PRODUCTION
    return PaymentGateway.Environment.SANDBOX


def _is_local_http_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "http" and host in {"localhost", "127.0.0.1"}


def _oauth_url(environment: str) -> str:
    if (environment or "").strip().lower() == PaymentGateway.Environment.PRODUCTION:
        return PRODUCTION_OAUTH_URL
    return SANDBOX_OAUTH_URL


def _stk_url(environment: str) -> str:
    if (environment or "").strip().lower() == PaymentGateway.Environment.PRODUCTION:
        return PRODUCTION_STK_URL
    return SANDBOX_STK_URL


def _stk_query_url(environment: str) -> str:
    if (environment or "").strip().lower() == PaymentGateway.Environment.PRODUCTION:
        return PRODUCTION_STK_QUERY_URL
    return SANDBOX_STK_QUERY_URL


def _is_transient_connect_error(exc: BaseException) -> bool:
    """True when the request almost certainly never reached Safaricom."""
    reason = getattr(exc, "reason", exc)
    if isinstance(
        reason,
        (
            ssl.SSLEOFError,
            ssl.SSLZeroReturnError,
            ConnectionResetError,
            ConnectionRefusedError,
            ConnectionAbortedError,
            socket.gaierror,
        ),
    ):
        return True
    if isinstance(reason, ssl.SSLError):
        # Handshake-stage TLS failures (e.g. UNEXPECTED_EOF_WHILE_READING).
        return "handshake" in str(reason).lower() or "eof" in str(reason).lower()
    if isinstance(reason, (TimeoutError, socket.timeout)):
        # Connect-stage timeouts only; callers decide whether this is retry-safe.
        return True
    return False


def _network_error_message(exc: BaseException) -> str:
    reason = getattr(exc, "reason", exc)
    if isinstance(reason, ssl.SSLError):
        return (
            "Could not complete a secure connection to Safaricom Daraja "
            f"({reason}). This is usually a temporary network issue — try again."
        )
    return f"Could not reach Daraja ({reason})."


def _https_opener() -> urllib.request.OpenerDirector:
    """Fresh opener per attempt so a dead TLS session is not reused."""
    context = ssl.create_default_context()
    # Prefer TLS 1.2+; Safaricom production speaks TLS 1.2.
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    https = urllib.request.HTTPSHandler(context=context)
    return urllib.request.build_opener(https)


def _json_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    timeout: int = OAUTH_TIMEOUT_SECONDS,
    retry_on_timeout: bool = True,
) -> dict[str, Any]:
    """
    Call Daraja and normalize the response.

    Transient TLS/connection failures are retried because they happen before the
    request reaches Safaricom. `retry_on_timeout` must be False for requests that
    charge a customer (STK Push), where a timeout may mean the prompt was already
    delivered and retrying could double-charge.
    """
    body = None
    req_headers = {"Accept": "application/json", "Connection": "close"}
    if headers:
        req_headers.update(headers)
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=req_headers, method=method)

    last_error = "Could not reach Daraja."
    for attempt in range(CONNECT_RETRIES + 1):
        try:
            opener = _https_opener()
            with opener.open(request, timeout=timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
                data = json.loads(raw or "{}")
                return {
                    "ok": 200 <= response.status < 300,
                    "http_status": response.status,
                    "data": data if isinstance(data, dict) else {"raw": data},
                    "error": "",
                }
        except urllib.error.HTTPError as exc:
            detail = ""
            data: dict[str, Any] = {}
            try:
                raw = exc.read().decode("utf-8", errors="replace")
                parsed = json.loads(raw or "{}")
                if isinstance(parsed, dict):
                    data = parsed
                    detail = (
                        parsed.get("errorMessage")
                        or parsed.get("error_description")
                        or parsed.get("error")
                        or parsed.get("ResponseDescription")
                        or ""
                    )
            except Exception:
                detail = ""
            return {
                "ok": False,
                "http_status": exc.code,
                "data": data,
                "error": detail or f"HTTP {exc.code}",
            }
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
            is_timeout = isinstance(
                getattr(exc, "reason", exc), (TimeoutError, socket.timeout)
            )
            if is_timeout:
                last_error = "Daraja request timed out."
            else:
                last_error = _network_error_message(exc)
            retryable = _is_transient_connect_error(exc) and (
                retry_on_timeout or not is_timeout
            )
            if retryable and attempt < CONNECT_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))
                continue
            return {
                "ok": False,
                "http_status": None,
                "data": {},
                "error": last_error,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "ok": False,
                "http_status": None,
                "data": {},
                "error": str(exc),
            }

    return {"ok": False, "http_status": None, "data": {}, "error": last_error}


def _token_cache_key(consumer_key: str, environment: str) -> str:
    digest = hashlib.sha256(
        f"{consumer_key}|{(environment or '').strip().lower()}".encode()
    ).hexdigest()[:32]
    return f"{_TOKEN_CACHE_PREFIX}{digest}"


def invalidate_access_token_cache(*, consumer_key: str, environment: str) -> None:
    """Drop a cached Daraja token after Safaricom rejects it."""
    cache.delete(_token_cache_key(consumer_key, environment))


def _looks_like_invalid_access_token(error: str = "", data: dict | None = None) -> bool:
    blob = f"{error or ''} {json.dumps(data or {})}".lower()
    return "invalid access token" in blob or "404.001.03" in blob


def get_access_token(*, consumer_key: str, consumer_secret: str, environment: str) -> dict[str, Any]:
    """Request a Daraja OAuth access token (cached until shortly before expiry)."""
    cache_key = _token_cache_key(consumer_key, environment)
    cached = cache.get(cache_key)
    if cached:
        return {
            "ok": True,
            "access_token": cached,
            "expires_in": None,
            "error": "",
            "cached": True,
        }

    token_url = _oauth_url(environment)
    credentials = base64.b64encode(
        f"{consumer_key}:{consumer_secret}".encode("utf-8")
    ).decode("ascii")
    result = _json_request(
        token_url,
        headers={"Authorization": f"Basic {credentials}"},
        timeout=OAUTH_TIMEOUT_SECONDS,
    )
    data = result.get("data") or {}
    token = (data.get("access_token") or "").strip()
    if result.get("ok") and token:
        try:
            expires = int(data.get("expires_in") or 3599)
        except (TypeError, ValueError):
            expires = 3599
        cache.set(cache_key, token, timeout=max(30, expires - _TOKEN_SAFETY_SECONDS))
        return {
            "ok": True,
            "access_token": token,
            "expires_in": data.get("expires_in"),
            "error": "",
        }
    return {
        "ok": False,
        "access_token": "",
        "expires_in": None,
        "error": result.get("error") or "Daraja did not return an access token.",
    }


def _stk_password(shortcode: str, passkey: str, timestamp: str) -> str:
    raw = f"{shortcode}{passkey}{timestamp}".encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _amount_int(amount) -> int:
    value = Decimal(str(amount)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return int(value)


def initiate_stk_push(
    *,
    consumer_key: str,
    consumer_secret: str,
    passkey: str,
    shortcode: str,
    payment_type: str,
    amount,
    phone: str,
    account_reference: str,
    callback_url: str,
    environment: str,
    description: str = "Subscription renewal",
) -> dict[str, Any]:
    """Send Lipa Na M-Pesa Online (STK Push) request."""
    token_result = get_access_token(
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        environment=environment,
    )
    if not token_result.get("ok"):
        return {
            "ok": False,
            "error": token_result.get("error") or "Could not authenticate with Daraja.",
            "data": {},
        }

    timestamp = timezone.localtime().strftime("%Y%m%d%H%M%S")
    msisdn = "".join(ch for ch in str(phone or "") if ch.isdigit())
    shortcode_s = str(shortcode or "").strip()
    transaction_type = (
        "CustomerBuyGoodsOnline"
        if (payment_type or "").strip().lower() == PaymentGateway.PaymentType.TILL
        else "CustomerPayBillOnline"
    )
    payload = {
        "BusinessShortCode": shortcode_s,
        "Password": _stk_password(shortcode_s, passkey, timestamp),
        "Timestamp": timestamp,
        "TransactionType": transaction_type,
        "Amount": _amount_int(amount),
        "PartyA": msisdn,
        "PartyB": shortcode_s,
        "PhoneNumber": msisdn,
        "CallBackURL": str(callback_url).strip(),
        "AccountReference": (account_reference or "ISPCENTRIC")[:12],
        "TransactionDesc": (description or "Subscription renewal")[:13],
    }
    if not (msisdn.startswith("254") and len(msisdn) == 12):
        return {
            "ok": False,
            "error": "PhoneNumber must be a Kenyan MSISDN like 2547xxxxxxxx.",
            "data": {"PhoneNumber": msisdn},
        }
    result = _json_request(
        _stk_url(environment),
        method="POST",
        headers={"Authorization": f"Bearer {token_result['access_token']}"},
        payload=payload,
        timeout=STK_TIMEOUT_SECONDS,
        # A timeout may mean the prompt already reached the customer's phone.
        retry_on_timeout=False,
    )
    data = result.get("data") or {}
    checkout_id = (data.get("CheckoutRequestID") or "").strip()
    response_code = str(data.get("ResponseCode") or "")
    if result.get("ok") and checkout_id and response_code in {"0", "00"}:
        return {
            "ok": True,
            "error": "",
            "merchant_request_id": (data.get("MerchantRequestID") or "").strip(),
            "checkout_request_id": checkout_id,
            "customer_message": (data.get("CustomerMessage") or "").strip(),
            "phone": msisdn,
            "shortcode": shortcode_s,
            "environment": (environment or "").strip().lower(),
            "data": data,
        }
    error = (
        data.get("errorMessage")
        or data.get("ResponseDescription")
        or result.get("error")
        or "STK Push request failed."
    )
    if _looks_like_invalid_access_token(error, data):
        invalidate_access_token_cache(
            consumer_key=consumer_key, environment=environment
        )
    return {
        "ok": False,
        "error": error,
        "merchant_request_id": (data.get("MerchantRequestID") or "").strip(),
        "checkout_request_id": checkout_id,
        "customer_message": (data.get("CustomerMessage") or "").strip(),
        "phone": msisdn,
        "shortcode": shortcode_s,
        "environment": (environment or "").strip().lower(),
        "data": data,
    }


# Daraja reuses the ResultCode field for "not finished yet" states. Treating one
# of these as a terminal failure tells a customer who is still holding their
# phone that payment failed, and a retry would charge them twice.
STK_IN_PROGRESS_RESULT_CODES = {4999}
_IN_PROGRESS_ERROR_CODES = {"500.001.1001"}
_IN_PROGRESS_PHRASES = (
    "still under processing",
    "being processed",
    "is in progress",
)


def _is_stk_in_progress(code_int, desc: str, data: dict) -> bool:
    """True when Daraja is saying "ask again later" rather than "this failed"."""
    if code_int in STK_IN_PROGRESS_RESULT_CODES:
        return True
    error_code = str(data.get("errorCode") or data.get("ErrorCode") or "").strip()
    if error_code in _IN_PROGRESS_ERROR_CODES:
        return True
    lowered = (desc or "").strip().lower()
    return any(phrase in lowered for phrase in _IN_PROGRESS_PHRASES)


def query_stk_push(
    *,
    consumer_key: str,
    consumer_secret: str,
    passkey: str,
    shortcode: str,
    checkout_request_id: str,
    environment: str,
) -> dict[str, Any]:
    """Query the status of a previously initiated STK Push."""
    token_result = get_access_token(
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        environment=environment,
    )
    if not token_result.get("ok"):
        return {
            "ok": False,
            "pending": True,
            "error": token_result.get("error") or "Could not authenticate with Daraja.",
            "data": {},
        }

    timestamp = timezone.localtime().strftime("%Y%m%d%H%M%S")
    payload = {
        "BusinessShortCode": str(shortcode).strip(),
        "Password": _stk_password(str(shortcode).strip(), passkey, timestamp),
        "Timestamp": timestamp,
        "CheckoutRequestID": str(checkout_request_id).strip(),
    }
    result = _json_request(
        _stk_query_url(environment),
        method="POST",
        headers={"Authorization": f"Bearer {token_result['access_token']}"},
        payload=payload,
        timeout=STK_TIMEOUT_SECONDS,
    )
    data = result.get("data") or {}
    token_error = (
        result.get("error")
        or data.get("errorMessage")
        or data.get("error_description")
        or ""
    )
    if _looks_like_invalid_access_token(token_error, data):
        invalidate_access_token_cache(
            consumer_key=consumer_key, environment=environment
        )
        return {
            "ok": False,
            "pending": False,
            "success": False,
            "result_code": None,
            "result_desc": token_error or "Invalid Access Token",
            "data": data,
            "error": token_error or "Invalid Access Token",
        }
    result_code = data.get("ResultCode")
    if result_code is None:
        result_code = data.get("resultCode")
    try:
        code_int = int(result_code) if result_code is not None and str(result_code) != "" else None
    except (TypeError, ValueError):
        code_int = None
    desc = (
        data.get("ResultDesc")
        or data.get("resultDesc")
        or data.get("ResponseDescription")
        or result.get("error")
        or ""
    )
    # 0 = success; 1032 = cancelled by user; other codes = failed / still processing
    if code_int == 0:
        return {
            "ok": True,
            "pending": False,
            "success": True,
            "result_code": code_int,
            "result_desc": desc,
            "data": data,
            "error": "",
        }
    if code_int is None or str(data.get("ResponseCode") or "") not in {"0", "00", ""}:
        # Still waiting / ambiguous — keep polling
        response_code = str(data.get("ResponseCode") or "")
        if response_code in {"0", "00"} and code_int is None:
            return {
                "ok": True,
                "pending": True,
                "success": False,
                "result_code": None,
                "result_desc": desc or "Waiting for customer confirmation.",
                "data": data,
                "error": "",
            }
        if not result.get("ok") and not data:
            return {
                "ok": False,
                "pending": True,
                "success": False,
                "result_code": None,
                "result_desc": desc,
                "data": data,
                "error": result.get("error") or desc,
            }
    if _is_stk_in_progress(code_int, desc, data):
        return {
            "ok": True,
            "pending": True,
            "success": False,
            "result_code": code_int,
            "result_desc": desc or "Waiting for customer confirmation.",
            "data": data,
            "error": "",
        }
    if code_int == 1032:
        return {
            "ok": True,
            "pending": False,
            "success": False,
            "cancelled": True,
            "result_code": code_int,
            "result_desc": desc or "Request cancelled by user.",
            "data": data,
            "error": "",
        }
    if code_int is not None:
        return {
            "ok": True,
            "pending": False,
            "success": False,
            "cancelled": False,
            "result_code": code_int,
            "result_desc": desc or "Payment was not completed.",
            "data": data,
            "error": "",
        }
    return {
        "ok": True,
        "pending": True,
        "success": False,
        "result_code": None,
        "result_desc": desc or "Waiting for customer confirmation.",
        "data": data,
        "error": "",
    }


def _request_access_token(
    *, consumer_key: str, consumer_secret: str, environment: str
) -> dict[str, Any]:
    """Live-check Daraja app credentials via OAuth client_credentials."""
    result = get_access_token(
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        environment=environment,
    )
    if result.get("ok"):
        expires = result.get("expires_in")
        detail = "Daraja accepted the consumer key and secret."
        if expires:
            detail = f"{detail} Token expires in {expires}s."
        return {
            "ok": True,
            "status": "ok",
            "message": detail,
            "http_status": 200,
        }
    return {
        "ok": False,
        "status": "invalid",
        "message": result.get("error") or "Consumer key or secret was rejected by Daraja.",
        "http_status": None,
    }


def normalize_gateway_values(raw: dict[str, Any] | None = None, gateway=None) -> dict[str, Any]:
    """Merge draft form values over a saved PaymentGateway instance."""
    source = gateway or PaymentGateway.get_solo()
    values = {
        "enabled": bool(getattr(source, "enabled", False)),
        "environment": (getattr(source, "environment", "") or PaymentGateway.Environment.SANDBOX),
        "payment_type": (getattr(source, "payment_type", "") or "").strip(),
        "shortcode": (getattr(source, "shortcode", "") or "").strip(),
        "consumer_key": (getattr(source, "consumer_key", "") or "").strip(),
        "consumer_secret": (getattr(source, "consumer_secret", "") or "").strip(),
        "passkey": (getattr(source, "passkey", "") or "").strip(),
        "callback_url": (getattr(source, "callback_url", "") or "").strip(),
    }
    if raw:
        if "enabled" in raw:
            enabled_raw = raw.get("enabled")
            if isinstance(enabled_raw, bool):
                values["enabled"] = enabled_raw
            else:
                values["enabled"] = str(enabled_raw).lower() in {
                    "1",
                    "true",
                    "on",
                    "yes",
                }
        for key in (
            "environment",
            "payment_type",
            "shortcode",
            "consumer_key",
            "consumer_secret",
            "passkey",
            "callback_url",
        ):
            if key in raw and raw.get(key) is not None:
                values[key] = str(raw.get(key) or "").strip()
    values["environment"] = resolve_daraja_api_environment(
        values.get("shortcode") or "",
        values.get("environment") or "",
    )
    if (
        values["environment"] == PaymentGateway.Environment.SANDBOX
        and not values["callback_url"]
    ):
        values["callback_url"] = PaymentGateway.default_callback_url(
            PaymentGateway.Environment.SANDBOX
        )
    return values


def check_stk_configuration(values: dict[str, Any], *, live: bool = True) -> dict[str, Any]:
    """
    Validate STK Push setup.

    When live=True, also requests an OAuth token from Safaricom Daraja.
    """
    checks: list[dict[str, Any]] = []
    enabled = bool(values.get("enabled"))
    environment = resolve_daraja_api_environment(
        values.get("shortcode") or "",
        values.get("environment") or "",
    )
    payment_type = (values.get("payment_type") or "").strip()
    shortcode = (values.get("shortcode") or "").strip()
    consumer_key = (values.get("consumer_key") or "").strip()
    consumer_secret = (values.get("consumer_secret") or "").strip()
    passkey = (values.get("passkey") or "").strip()
    callback_url = (values.get("callback_url") or "").strip()

    if not enabled:
        checks.append(
            {
                "key": "enabled",
                "ok": False,
                "label": "STK Push",
                "message": "Inactive — activate STK Push to use Daraja.",
            }
        )
        return {
            "ok": False,
            "configured": False,
            "status": "inactive",
            "summary": "STK Push is inactive.",
            "environment": environment or PaymentGateway.Environment.SANDBOX,
            "checks": checks,
            "checked_live": False,
        }

    checks.append(
        {
            "key": "enabled",
            "ok": True,
            "label": "STK Push",
            "message": "Activated",
        }
    )

    missing = []
    if not payment_type:
        missing.append("payment type")
    if not shortcode:
        missing.append("shortcode")
    if not consumer_key:
        missing.append("consumer key")
    if not consumer_secret:
        missing.append("consumer secret")
    if not passkey:
        missing.append("passkey")
    if not callback_url:
        missing.append("callback URL")

    fields_ok = not missing
    checks.append(
        {
            "key": "fields",
            "ok": fields_ok,
            "label": "Required fields",
            "message": (
                "All required credentials are filled."
                if fields_ok
                else f"Missing: {', '.join(missing)}."
            ),
        }
    )

    shortcode_ok = bool(shortcode) and shortcode.isdigit()
    checks.append(
        {
            "key": "shortcode",
            "ok": shortcode_ok,
            "label": "Business shortcode",
            "message": (
                f"Shortcode {shortcode} looks valid."
                if shortcode_ok
                else "Shortcode must be digits only."
            ),
        }
    )

    callback_ok = False
    callback_message = "Callback URL is required."
    if callback_url:
        if environment == PaymentGateway.Environment.PRODUCTION:
            if callback_url.startswith("https://") and not _is_local_http_url(callback_url):
                callback_ok = True
                callback_message = "Production callback uses HTTPS."
            elif _is_local_http_url(callback_url):
                # Local development: Daraja cannot reach localhost, but STK Query
                # polling still confirms payments. Do not block the OAuth check.
                callback_ok = True
                callback_message = (
                    "Localhost callback cannot receive Safaricom posts in production. "
                    "STK Query polling will confirm payments on this PC."
                )
            else:
                callback_ok = False
                callback_message = (
                    "Production requires a public HTTPS callback (not localhost)."
                )
        else:
            callback_ok = callback_url.startswith("https://") or _is_local_http_url(
                callback_url
            )
            callback_message = (
                "Sandbox callback accepted (local or hosted)."
                if callback_ok
                else "Sandbox callback must be https://… (hosted) or http://localhost… (local)."
            )
    checks.append(
        {
            "key": "callback",
            "ok": callback_ok,
            "label": "Callback URL",
            "message": callback_message,
        }
    )

    local_ok = fields_ok and shortcode_ok and callback_ok
    live_result = None
    if live and fields_ok and shortcode_ok and consumer_key and consumer_secret:
        live_result = _request_access_token(
            consumer_key=consumer_key,
            consumer_secret=consumer_secret,
            environment=environment,
        )
        checks.append(
            {
                "key": "oauth",
                "ok": bool(live_result.get("ok")),
                "label": "Daraja OAuth",
                "message": live_result.get("message") or "OAuth check finished.",
            }
        )
        # Passkey/shortcode cannot be fully verified without sending STK,
        # but confirm they are present once OAuth succeeds.
        if live_result.get("ok"):
            checks.append(
                {
                    "key": "stk_ready",
                    "ok": True,
                    "label": "STK credentials",
                    "message": (
                        "Passkey and shortcode are set. OAuth succeeded — "
                        "configuration looks ready for STK Push."
                    ),
                }
            )
    elif live and local_ok:
        checks.append(
            {
                "key": "oauth",
                "ok": False,
                "label": "Daraja OAuth",
                "message": "Consumer key and secret are required for a live check.",
            }
        )

    configured = local_ok and (not live or bool(live_result and live_result.get("ok")))
    if not enabled:
        status = "inactive"
        summary = "STK Push is inactive."
    elif not local_ok:
        status = "incomplete"
        summary = "Configuration is incomplete."
    elif live and live_result and not live_result.get("ok"):
        status = live_result.get("status") or "invalid"
        summary = live_result.get("message") or "Daraja rejected the credentials."
    elif configured:
        status = "ok"
        summary = "STK Push is well configured."
    else:
        status = "incomplete"
        summary = "Configuration is incomplete."

    return {
        "ok": configured,
        "configured": configured,
        "status": status,
        "summary": summary,
        "environment": environment or PaymentGateway.Environment.SANDBOX,
        "checks": checks,
        "checked_live": bool(live and live_result is not None),
    }
