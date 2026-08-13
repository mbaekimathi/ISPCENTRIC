"""Send SMS, email, and WhatsApp using organization communication credentials."""

from __future__ import annotations

import json
import logging
import re
import smtplib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from email.mime.text import MIMEText
from email.utils import formataddr

from .models import CommunicationSettings, PlatformCommunicationSettings

logger = logging.getLogger(__name__)

# Planned outbound events, derived from live ISPCENTRIC workflows.
# Clients = subscribers of this ISP. ISP account = owner / staff on this workspace.
CLIENT_COMMUNICATION_EVENTS = (
    {
        "key": "client_welcome",
        "title": "Welcome / account created",
        "when": "A PPPoE, Hotspot, or Static client is registered.",
        "includes": "Account number, PPPoE username/password or Hotspot login, and support contacts.",
        "channels": ("sms", "whatsapp", "email"),
    },
    {
        "key": "hotspot_voucher",
        "title": "Hotspot voucher issued",
        "when": "Staff generate or share a Hotspot voucher.",
        "includes": "Voucher code, validity, and speeds.",
        "channels": ("sms", "whatsapp", "email"),
    },
    {
        "key": "lead_installation",
        "title": "Lead & installation updates",
        "when": "A lead is allocated, a technician is assigned, or installation is accepted, declined, or marked not interested.",
        "includes": "Visit window, technician name, and next step.",
        "channels": ("sms", "whatsapp", "email"),
    },
    {
        "key": "stk_prompt",
        "title": "STK Push confirmation",
        "when": "A subscription STK Push is sent to the client's phone.",
        "includes": "Amount, package name, and Paybill/Till reference. Daraja prompts the phone; SMS/WhatsApp can confirm it.",
        "channels": ("sms", "whatsapp"),
    },
    {
        "key": "payment_received",
        "title": "Payment received",
        "when": "Cash recharge or M-Pesa STK succeeds and the package is extended.",
        "includes": "Receipt, amount, package, and new expiry.",
        "channels": ("sms", "whatsapp", "email"),
    },
    {
        "key": "payment_failed",
        "title": "Payment failed or cancelled",
        "when": "STK Push fails, expires, or the client cancels on the phone.",
        "includes": "Reason and how to retry payment.",
        "channels": ("sms", "whatsapp"),
    },
    {
        "key": "renewal_reminder",
        "title": "Package expiring soon",
        "when": "The client has used about three-quarters of the current package window.",
        "includes": "Days or hours left and a renew link / Paybill instructions.",
        "channels": ("sms", "whatsapp", "email"),
    },
    {
        "key": "package_expired",
        "title": "Package expired",
        "when": "The subscription sweep finds the package window has ended and access is blocked.",
        "includes": "Expiry time and how to recharge.",
        "channels": ("sms", "whatsapp", "email"),
    },
    {
        "key": "package_pause_resume",
        "title": "Package paused or resumed",
        "when": "Staff freeze or restart the client's package clock.",
        "includes": "Whether surfing is blocked or restored, and remaining time.",
        "channels": ("sms", "whatsapp"),
    },
    {
        "key": "account_status",
        "title": "Account suspended or reactivated",
        "when": "The client status changes to suspended, inactive, or active.",
        "includes": "New status and who to contact.",
        "channels": ("sms", "whatsapp", "email"),
    },
    {
        "key": "wifi_changed",
        "title": "Wi‑Fi credentials changed",
        "when": "CPE Wi‑Fi SSID or password is updated from the client page.",
        "includes": "New SSID and password.",
        "channels": ("sms", "whatsapp"),
    },
    {
        "key": "invoice_receipt",
        "title": "Invoice or receipt",
        "when": "A renewal invoice or payment receipt is created.",
        "includes": "Invoice number, amount, and period covered.",
        "channels": ("email", "whatsapp"),
    },
)

ISP_COMMUNICATION_EVENTS = (
    {
        "key": "isp_password_reset",
        "title": "Password reset",
        "when": "The ISP owner or staff requests a login reset.",
        "includes": "Reset link. Uses platform email, not this organization's SMS/WhatsApp gateway.",
        "channels": ("email",),
        "recipient": "Owner or staff login email",
    },
    {
        "key": "isp_employee_joined",
        "title": "Employee joined with join code",
        "when": "Someone registers using this company's 6-digit join code.",
        "includes": "Name, role, and join code used.",
        "channels": ("sms", "email", "whatsapp"),
        "recipient": "Organization owner",
    },
    {
        "key": "isp_lead_open",
        "title": "New open lead",
        "when": "Sales captures a new unassigned lead visible to ISPs.",
        "includes": "Lead name, phone, location, and service type.",
        "channels": ("sms", "email"),
        "recipient": "Organization owner / sales",
    },
    {
        "key": "isp_lead_allocated",
        "title": "Lead allocated to this ISP",
        "when": "Lead-allocation STK Push succeeds and the client is assigned to this company.",
        "includes": "Lead details, amount paid, and assigned technician if any.",
        "channels": ("sms", "email", "whatsapp"),
        "recipient": "Organization owner",
    },
    {
        "key": "isp_technician_assigned",
        "title": "Installation assigned to a technician",
        "when": "A lead or client is allocated to a technician on this account.",
        "includes": "Client name, location, and preferred installation date.",
        "channels": ("sms", "whatsapp"),
        "recipient": "Assigned technician",
    },
    {
        "key": "isp_installation_result",
        "title": "Installation accepted or declined",
        "when": "A technician accepts, declines, or completes an installation.",
        "includes": "Outcome and any decline reason.",
        "channels": ("sms", "email"),
        "recipient": "Organization owner",
    },
    {
        "key": "isp_mikrotik_onboarding",
        "title": "MikroTik onboarding fee",
        "when": "Onboarding-fee STK Push succeeds or fails before a tunnel script is generated.",
        "includes": "Router name, amount, and whether the script can be generated.",
        "channels": ("sms", "email", "whatsapp"),
        "recipient": "Organization owner",
    },
    {
        "key": "isp_stk_collection",
        "title": "Client payment collected",
        "when": "A subscriber STK Push succeeds into this ISP's Paybill or Till.",
        "includes": "Client name, account number, amount, and M-Pesa receipt.",
        "channels": ("sms", "email"),
        "recipient": "Organization owner",
    },
    {
        "key": "isp_stk_failed",
        "title": "STK Push failed to send",
        "when": "Daraja credentials are missing or Safaricom rejects the STK request.",
        "includes": "Error from Daraja and which client/lead it was for.",
        "channels": ("email", "sms"),
        "recipient": "Organization owner",
    },
    {
        "key": "isp_referral_active",
        "title": "Referral became active",
        "when": "An ISP you referred onboards their first MikroTik.",
        "includes": "Referred company name and referral status change.",
        "channels": ("sms", "email", "whatsapp"),
        "recipient": "Referring ISP owner",
    },
    {
        "key": "isp_client_registered",
        "title": "New client registered by sales",
        "when": "Sales or staff register a PPPoE/Hotspot/Static client under this ISP.",
        "includes": "Client name, phone, account number, and service type.",
        "channels": ("email", "sms"),
        "recipient": "Organization owner",
    },
)

# ISPCENTRIC platform → ISPs / staff. Separate from each ISP's client credentials.
PLATFORM_TO_ISP_EVENTS = (
    {
        "key": "platform_isp_welcome",
        "title": "New ISP registered",
        "when": "A company creates an ISPCENTRIC account.",
        "includes": "Welcome, join code, and how to onboard a MikroTik.",
        "channels": ("email", "sms", "whatsapp"),
        "recipient": "New ISP owner",
    },
    {
        "key": "platform_isp_status",
        "title": "ISP account activated or suspended",
        "when": "Staff change an organization status to active, registered, or suspended.",
        "includes": "New status and who to contact.",
        "channels": ("email", "sms", "whatsapp"),
        "recipient": "ISP owner",
    },
    {
        "key": "platform_password_reset",
        "title": "Password reset",
        "when": "An ISP owner or staff requests a login reset.",
        "includes": "Reset link. Can use Django EMAIL_* if platform SMTP is off.",
        "channels": ("email",),
        "recipient": "Login email on the account",
    },
    {
        "key": "platform_onboarding_fee",
        "title": "MikroTik onboarding fee",
        "when": "Platform onboarding-fee STK Push succeeds or fails (Company Payment Gateway).",
        "includes": "Amount, router, and whether the tunnel script can be generated.",
        "channels": ("sms", "email", "whatsapp"),
        "recipient": "ISP owner",
    },
    {
        "key": "platform_referral_active",
        "title": "Referral became active",
        "when": "An ISP referred through the platform onboards their first MikroTik.",
        "includes": "Referred company name and referral status.",
        "channels": ("sms", "email", "whatsapp"),
        "recipient": "Referring ISP owner",
    },
    {
        "key": "platform_announcement",
        "title": "Platform announcement",
        "when": "ISPCENTRIC sends a maintenance or product notice to ISPs.",
        "includes": "Announcement body and any action required.",
        "channels": ("email", "sms", "whatsapp"),
        "recipient": "ISP owners",
    },
)

PLATFORM_TO_STAFF_EVENTS = (
    {
        "key": "platform_staff_new_isp",
        "title": "New ISP registered",
        "when": "A company account is created on the platform.",
        "includes": "Company name, owner, and join code.",
        "channels": ("email", "sms"),
        "recipient": "IT Support / Super Admin",
    },
    {
        "key": "platform_staff_onboarding_paid",
        "title": "Onboarding fee collected",
        "when": "A MikroTik onboarding STK Push succeeds on the platform gateway.",
        "includes": "ISP name, amount, and M-Pesa receipt.",
        "channels": ("email", "sms"),
        "recipient": "IT Support",
    },
    {
        "key": "platform_staff_daraja_fail",
        "title": "Platform STK / Daraja failure",
        "when": "Company Payment Gateway credentials fail or Safaricom rejects a platform STK.",
        "includes": "Error from Daraja and which ISP/lead it was for.",
        "channels": ("email", "sms"),
        "recipient": "IT Support",
    },
    {
        "key": "platform_staff_new_lead",
        "title": "New unassigned lead",
        "when": "Sales captures a lead that is not yet allocated to an ISP.",
        "includes": "Lead name, phone, location, and service type.",
        "channels": ("email", "sms"),
        "recipient": "IT Support / Sales admin",
    },
    {
        "key": "platform_staff_employee_joined",
        "title": "Employee joined with join code",
        "when": "Someone registers using an ISP join code.",
        "includes": "Name, role, and company joined.",
        "channels": ("email", "sms"),
        "recipient": "IT Support / HR",
    },
)

_AFRICASTALKING_SMS = "https://api.africastalking.com/version1/messaging"
_AFRICASTALKING_SMS_SANDBOX = "https://api.sandbox.africastalking.com/version1/messaging"
_AFRICASTALKING_API = "https://api.africastalking.com"
_AFRICASTALKING_API_SANDBOX = "https://api.sandbox.africastalking.com"
_AFRICASTALKING_WHATSAPP = "https://chat.africastalking.com/whatsapp/message/send"
_META_GRAPH = "https://graph.facebook.com/v21.0"
_META_WHATSAPP = "https://graph.facebook.com/v21.0/{phone_number_id}/messages"
_TWILIO_API = "https://api.twilio.com/2010-04-01/Accounts/{sid}"
_TWILIO_MESSAGES = "https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"

_SMTP_PROVIDERS = (
    (("gmail.com", "googlemail.com"), "smtp.gmail.com", 587, True, "Gmail"),
    (
        ("outlook.com", "hotmail.com", "live.com", "msn.com", "office365.com"),
        "smtp.office365.com",
        587,
        True,
        "Microsoft 365 / Outlook",
    ),
    (("yahoo.com", "ymail.com"), "smtp.mail.yahoo.com", 587, True, "Yahoo"),
    (("zoho.com", "zoho.eu"), "smtp.zoho.com", 587, True, "Zoho"),
    (("icloud.com", "me.com", "mac.com"), "smtp.mail.me.com", 587, True, "iCloud"),
)


def settings_for(organization) -> CommunicationSettings | None:
    return CommunicationSettings.for_organization(organization)


def platform_settings() -> PlatformCommunicationSettings:
    return PlatformCommunicationSettings.get_solo()


def normalize_msisdn(raw: str, *, default_dial: str = "254") -> str:
    """Return digits with country code, no plus (e.g. 254712345678)."""
    digits = re.sub(r"\D", "", raw or "")
    if not digits:
        return ""
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith("0") and len(digits) >= 10:
        digits = default_dial + digits.lstrip("0")
    return digits


def _plus_msisdn(raw: str) -> str:
    digits = normalize_msisdn(raw)
    return f"+{digits}" if digits else ""


def _http_request(
    url: str,
    *,
    method: str = "POST",
    headers: dict | None = None,
    data=None,
    form: bool = False,
    auth: tuple[str, str] | None = None,
    timeout: int = 20,
) -> dict:
    hdrs = {
        "Accept": "application/json",
        "User-Agent": "ISPCENTRIC/1.0",
    }
    if headers:
        hdrs.update(headers)
    method = (method or "POST").upper()
    if data is not None and method == "GET" and isinstance(data, dict):
        query = urllib.parse.urlencode(data)
        url = f"{url}{'&' if '?' in url else '?'}{query}"
        data = None
    body = None
    if data is not None:
        if form:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
            body = urllib.parse.urlencode(data).encode("utf-8")
        else:
            hdrs.setdefault("Content-Type", "application/json")
            body = json.dumps(data).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    if auth:
        import base64

        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            payload = _maybe_json(raw)
            return {"ok": True, "status": response.status, "body": raw, "data": payload}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return {
            "ok": False,
            "status": exc.code,
            "error": _error_message(raw) or str(exc),
            "body": raw,
        }
    except Exception as exc:
        logger.warning("Communication HTTP error: %s", exc)
        return {"ok": False, "error": str(exc)}


def _maybe_json(raw: str):
    try:
        return json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return None


def _error_message(raw: str) -> str:
    payload = _maybe_json(raw)
    if isinstance(payload, dict):
        error = payload.get("error") or payload.get("message") or payload.get("Message")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("Message") or error)
        if error:
            return str(error)
    text = (raw or "").strip()
    return text[:300] if text else ""


def send_sms(*, organization, to: str, message: str) -> dict:
    """Send an SMS using the organization's configured gateway."""
    comms = settings_for(organization)
    if comms is None:
        return {"ok": False, "error": "No organization communications settings."}
    status = comms.sms_status()
    if not status["ready"]:
        return {"ok": False, "error": status["message"]}
    to_digits = normalize_msisdn(to)
    if not to_digits:
        return {"ok": False, "error": "Enter a valid phone number."}
    body = (message or "").strip()
    if not body:
        return {"ok": False, "error": "Message is empty."}

    provider = comms.sms_provider
    sender = (comms.sms_sender_id or "").strip() or (comms.sms_from_number or "").strip()
    if provider == CommunicationSettings.SmsProvider.AFRICASTALKING:
        username = (comms.sms_username or "").strip()
        url = (
            _AFRICASTALKING_SMS_SANDBOX
            if username.lower() == "sandbox"
            else _AFRICASTALKING_SMS
        )
        payload = {
            "username": username,
            "to": f"+{to_digits}",
            "message": body,
        }
        if sender:
            payload["from"] = sender
        result = _http_request(
            url,
            headers={"apiKey": (comms.sms_api_key or "").strip()},
            data=payload,
            form=True,
        )
        if not result.get("ok"):
            return {"ok": False, "error": result.get("error") or "SMS send failed."}
        return {"ok": True, "provider": provider, "data": result.get("data")}

    if provider == CommunicationSettings.SmsProvider.TWILIO:
        sid = (comms.sms_username or "").strip()
        twilio_data = {
            "To": _plus_msisdn(to_digits),
            "Body": body,
        }
        if sender.upper().startswith("MG"):
            twilio_data["MessagingServiceSid"] = sender
        else:
            twilio_data["From"] = _plus_msisdn(sender) or sender
        result = _http_request(
            _TWILIO_MESSAGES.format(sid=urllib.parse.quote(sid)),
            data=twilio_data,
            form=True,
            auth=(sid, (comms.sms_api_key or "").strip()),
        )
        if not result.get("ok"):
            return {"ok": False, "error": result.get("error") or "SMS send failed."}
        return {"ok": True, "provider": provider, "data": result.get("data")}

    result = _http_request(
        (comms.sms_base_url or "").strip(),
        data={
            "to": f"+{to_digits}",
            "message": body,
            "from": (comms.sms_sender_id or "").strip(),
            "api_key": (comms.sms_api_key or "").strip(),
        },
    )
    if not result.get("ok"):
        return {"ok": False, "error": result.get("error") or "SMS send failed."}
    return {"ok": True, "provider": provider, "data": result.get("data")}


def send_email(*, organization, to: str, subject: str, body: str) -> dict:
    """Send email using the organization's SMTP credentials."""
    comms = settings_for(organization)
    if comms is None:
        return {"ok": False, "error": "No organization communications settings."}
    status = comms.email_status()
    if not status["ready"]:
        return {"ok": False, "error": status["message"]}
    recipient = (to or "").strip()
    if not recipient or "@" not in recipient:
        return {"ok": False, "error": "Enter a valid email address."}
    host = (comms.email_host or "").strip()
    port = int(comms.email_port or 587)
    username = (comms.email_host_user or "").strip()
    password = (comms.email_host_password or "").strip()
    from_email = (comms.email_from_email or "").strip() or username
    from_name = (comms.email_from_name or "").strip()
    message = MIMEText(body or "", "plain", "utf-8")
    message["Subject"] = (subject or "").strip() or "Message"
    message["From"] = formataddr((from_name, from_email)) if from_name else from_email
    message["To"] = recipient
    try:
        context = ssl.create_default_context()
        if port == 465:
            smtp = smtplib.SMTP_SSL(host, port, timeout=20, context=context)
        else:
            smtp = smtplib.SMTP(host, port, timeout=20)
        with smtp:
            if port != 465 and comms.email_use_tls:
                smtp.starttls(context=context)
            smtp.login(username, password)
            smtp.sendmail(from_email, [recipient], message.as_string())
    except Exception as exc:
        logger.warning("SMTP send failed: %s", exc)
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "provider": "smtp"}


def send_whatsapp(*, organization, to: str, message: str) -> dict:
    """Send a WhatsApp text message using the organization's provider."""
    comms = settings_for(organization)
    if comms is None:
        return {"ok": False, "error": "No organization communications settings."}
    status = comms.whatsapp_status()
    if not status["ready"]:
        return {"ok": False, "error": status["message"]}
    to_digits = normalize_msisdn(to)
    if not to_digits:
        return {"ok": False, "error": "Enter a valid phone number."}
    body = (message or "").strip()
    if not body:
        return {"ok": False, "error": "Message is empty."}

    provider = comms.whatsapp_provider
    if provider == CommunicationSettings.WhatsAppProvider.META:
        phone_id = urllib.parse.quote((comms.whatsapp_phone_number_id or "").strip())
        result = _http_request(
            _META_WHATSAPP.format(phone_number_id=phone_id),
            headers={
                "Authorization": f"Bearer {(comms.whatsapp_access_token or '').strip()}",
            },
            data={
                "messaging_product": "whatsapp",
                "to": to_digits,
                "type": "text",
                "text": {"preview_url": False, "body": body},
            },
        )
        if not result.get("ok"):
            return {"ok": False, "error": result.get("error") or "WhatsApp send failed."}
        return {"ok": True, "provider": provider, "data": result.get("data")}

    if provider == CommunicationSettings.WhatsAppProvider.TWILIO:
        sid = (comms.whatsapp_username or "").strip()
        from_number = _plus_msisdn(comms.whatsapp_from_number) or (
            comms.whatsapp_from_number or ""
        ).strip()
        if from_number and not from_number.startswith("whatsapp:"):
            from_number = f"whatsapp:{from_number if from_number.startswith('+') else '+' + normalize_msisdn(from_number)}"
        result = _http_request(
            _TWILIO_MESSAGES.format(sid=urllib.parse.quote(sid)),
            data={
                "To": f"whatsapp:+{to_digits}",
                "From": from_number,
                "Body": body,
            },
            form=True,
            auth=(sid, (comms.whatsapp_api_key or "").strip()),
        )
        if not result.get("ok"):
            return {"ok": False, "error": result.get("error") or "WhatsApp send failed."}
        return {"ok": True, "provider": provider, "data": result.get("data")}

    result = _http_request(
        _AFRICASTALKING_WHATSAPP,
        headers={"apiKey": (comms.whatsapp_api_key or "").strip()},
        data={
            "username": (comms.whatsapp_username or "").strip(),
            "to": f"+{to_digits}",
            "from": _plus_msisdn(comms.whatsapp_from_number)
            or (comms.whatsapp_from_number or "").strip(),
            "message": body,
        },
    )
    if not result.get("ok"):
        return {"ok": False, "error": result.get("error") or "WhatsApp send failed."}
    return {"ok": True, "provider": provider, "data": result.get("data")}


def suggest_smtp(address: str) -> dict | None:
    """Guess SMTP host/port from an email address or domain so any mailbox type works."""
    text = (address or "").strip().lower()
    host = text.split("@")[-1] if "@" in text else text
    host = host.split(":")[0].strip().strip(".")
    if not host or "." not in host:
        return None
    for domains, smtp_host, port, use_tls, label in _SMTP_PROVIDERS:
        if host == smtp_host or host in domains or any(host.endswith(f".{domain}") for domain in domains):
            return {
                "host": smtp_host,
                "port": port,
                "use_tls": use_tls,
                "label": label,
            }
    return None


def _looks_like_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value or "")
    return len(digits) >= 8 and not re.search(r"[A-Za-z]", value or "")


def _sender_item(value, label=None, kind="sender", extra=None) -> dict | None:
    value = str(value or "").strip()
    if not value:
        return None
    item = {
        "value": value,
        "label": (label or value).strip() or value,
        "type": kind,
    }
    if extra:
        item.update(extra)
    return item


def _dedupe_sender_items(items: list) -> list:
    seen = set()
    out = []
    for item in items:
        if not item or not item.get("value"):
            continue
        key = (item.get("type") or "", str(item["value"]).lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _parse_sender_list(payload) -> list:
    items = []
    if payload is None:
        return items
    if isinstance(payload, list):
        for row in payload:
            if isinstance(row, (list, dict)):
                items.extend(_parse_sender_list(row))
            else:
                kind = "phone" if _looks_like_phone(str(row)) else "sender"
                item = _sender_item(row, kind=kind)
                if item:
                    items.append(item)
        return items
    if not isinstance(payload, dict):
        kind = "phone" if _looks_like_phone(str(payload)) else "sender"
        item = _sender_item(payload, kind=kind)
        return [item] if item else []

    for key in (
        "SenderIds",
        "senderIds",
        "sender_ids",
        "Senders",
        "senders",
        "data",
        "results",
        "Numbers",
        "phone_numbers",
        "incoming_phone_numbers",
        "messaging_services",
        "SMSMessageData",
    ):
        if key in payload:
            items.extend(_parse_sender_list(payload[key]))

    phone = payload.get("phone_number") or payload.get("phoneNumber") or payload.get("display_phone_number")
    if phone and not payload.get("id"):
        friendly = payload.get("friendly_name") or payload.get("friendlyName") or ""
        label = f"{friendly} ({phone})" if friendly and friendly != phone else phone
        item = _sender_item(phone, label, "phone")
        if item:
            items.append(item)

    sid = str(payload.get("sid") or "")
    if sid.startswith("MG"):
        name = payload.get("friendly_name") or sid
        item = _sender_item(sid, f"{name} (Messaging Service)", "service")
        if item:
            items.append(item)

    display = payload.get("display_phone_number") or payload.get("displayPhoneNumber")
    meta_id = payload.get("id")
    if meta_id and display:
        verified = payload.get("verified_name") or payload.get("verifiedName") or ""
        label = f"{display}" + (f" · {verified}" if verified else "")
        item = _sender_item(str(meta_id), f"{label} ({meta_id})", "meta_id", extra={"phone": display})
        if item:
            items.append(item)
        phone_item = _sender_item(display, display, "phone")
        if phone_item:
            items.append(phone_item)

    for key in (
        "SenderId",
        "senderId",
        "sender_id",
        "from",
        "From",
        "number",
        "Number",
        "shortcode",
        "ShortCode",
        "shortCode",
    ):
        raw = payload.get(key)
        if raw in (None, "") or isinstance(raw, (dict, list)):
            continue
        kind = "phone" if _looks_like_phone(str(raw)) else "sender"
        item = _sender_item(raw, kind=kind)
        if item:
            items.append(item)
    return items


def _fetch_message(items: list, connected: str) -> str:
    if items:
        return (
            f"{connected} Fetched {len(items)} sender option(s). "
            "Pick one or type any sender ID, shortcode, or phone number."
        )
    return (
        f"{connected} No senders were listed. "
        "You can still type any sender ID, shortcode, or phone number."
    )


def _fetch_africastalking_sms(username: str, api_key: str) -> dict:
    if not username or not api_key:
        return {"ok": False, "items": [], "error": "Enter the Africa's Talking username and API key first."}
    api = _AFRICASTALKING_API_SANDBOX if username.lower() == "sandbox" else _AFRICASTALKING_API
    headers = {"apiKey": api_key}
    user = _http_request(
        f"{api}/version1/user",
        method="GET",
        headers=headers,
        data={"username": username},
    )
    if not user.get("ok"):
        return {
            "ok": False,
            "items": [],
            "error": user.get("error") or "Africa's Talking login failed.",
        }
    items = []
    for path in ("/version1/senderids", "/version1/senderid"):
        result = _http_request(
            f"{api}{path}",
            method="GET",
            headers=headers,
            data={"username": username},
        )
        if result.get("ok"):
            items.extend(_parse_sender_list(result.get("data")))
    items = _dedupe_sender_items(items)
    return {"ok": True, "items": items, "message": _fetch_message(items, "Africa's Talking connected.")}


def _fetch_twilio_numbers(sid: str, token: str) -> dict:
    if not sid or not token:
        return {"ok": False, "items": [], "error": "Enter the Twilio Account SID and Auth Token first."}
    base = _TWILIO_API.format(sid=urllib.parse.quote(sid))
    items = []
    numbers = _http_request(
        f"{base}/IncomingPhoneNumbers.json",
        method="GET",
        auth=(sid, token),
    )
    if not numbers.get("ok"):
        return {
            "ok": False,
            "items": [],
            "error": numbers.get("error") or "Twilio login failed.",
        }
    items.extend(_parse_sender_list(numbers.get("data")))
    services = _http_request(
        f"{base}/Messaging/Services.json",
        method="GET",
        auth=(sid, token),
    )
    if services.get("ok"):
        items.extend(_parse_sender_list(services.get("data")))
    items = _dedupe_sender_items(items)
    return {"ok": True, "items": items, "message": _fetch_message(items, "Twilio connected.")}


def _fetch_custom_sms(base_url: str, api_key: str, username: str = "") -> dict:
    if not base_url:
        return {"ok": False, "items": [], "error": "Enter the custom SMS API URL first."}
    parsed = urllib.parse.urlsplit(base_url)
    list_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, "", "")
    )
    payload = {"action": "list_senders", "api_key": api_key, "username": username}
    result = _http_request(list_url, data=payload)
    if not result.get("ok"):
        result = _http_request(list_url, method="GET", data={"list": "senders", "api_key": api_key})
    items = _dedupe_sender_items(_parse_sender_list(result.get("data"))) if result.get("ok") else []
    if result.get("ok"):
        return {"ok": True, "items": items, "message": _fetch_message(items, "Custom SMS API connected.")}
    return {
        "ok": True,
        "items": [],
        "message": (
            "Custom API did not list senders. Type any sender ID, shortcode, or phone number "
            "your gateway accepts."
        ),
    }


def _fetch_meta_whatsapp(token: str, phone_number_id: str = "") -> dict:
    if not token:
        return {"ok": False, "items": [], "error": "Enter the Meta access token first."}
    items = []
    if phone_number_id:
        result = _http_request(
            f"{_META_GRAPH}/{urllib.parse.quote(phone_number_id)}",
            method="GET",
            data={"fields": "id,display_phone_number,verified_name", "access_token": token},
        )
        if result.get("ok"):
            items.extend(_parse_sender_list(result.get("data")))
    debug = _http_request(
        f"{_META_GRAPH}/debug_token",
        method="GET",
        data={"input_token": token, "access_token": token},
    )
    info = debug.get("data") if isinstance(debug.get("data"), dict) else {}
    if isinstance(info.get("data"), dict):
        info = info["data"]
    waba_ids = []
    for row in info.get("granular_scopes") or []:
        if not isinstance(row, dict):
            continue
        if "whatsapp" in str(row.get("scope") or "").lower():
            waba_ids.extend(row.get("target_ids") or [])
    waba_ids.extend(info.get("target_ids") or [])
    for waba in dict.fromkeys(str(item) for item in waba_ids if item):
        result = _http_request(
            f"{_META_GRAPH}/{urllib.parse.quote(waba)}/phone_numbers",
            method="GET",
            data={"access_token": token},
        )
        if result.get("ok"):
            items.extend(_parse_sender_list(result.get("data")))
    items = _dedupe_sender_items(items)
    if not items and not debug.get("ok"):
        return {"ok": False, "items": [], "error": debug.get("error") or "Meta token check failed."}
    return {"ok": True, "items": items, "message": _fetch_message(items, "WhatsApp Cloud API connected.")}


def fetch_sms_senders(*, provider: str, username: str = "", api_key: str = "", base_url: str = "") -> dict:
    provider = (provider or "").strip()
    if provider == CommunicationSettings.SmsProvider.AFRICASTALKING:
        return _fetch_africastalking_sms(username.strip(), api_key.strip())
    if provider == CommunicationSettings.SmsProvider.TWILIO:
        return _fetch_twilio_numbers(username.strip(), api_key.strip())
    if provider == CommunicationSettings.SmsProvider.CUSTOM:
        return _fetch_custom_sms(base_url.strip(), api_key.strip(), username.strip())
    return {"ok": False, "items": [], "error": "Choose an SMS provider."}


def fetch_whatsapp_senders(
    *,
    provider: str,
    username: str = "",
    api_key: str = "",
    access_token: str = "",
    phone_number_id: str = "",
) -> dict:
    provider = (provider or "").strip()
    if provider == CommunicationSettings.WhatsAppProvider.META:
        return _fetch_meta_whatsapp(access_token.strip(), phone_number_id.strip())
    if provider == CommunicationSettings.WhatsAppProvider.TWILIO:
        return _fetch_twilio_numbers(username.strip(), api_key.strip())
    if provider == CommunicationSettings.WhatsAppProvider.AFRICASTALKING:
        return _fetch_africastalking_sms(username.strip(), api_key.strip())
    return {"ok": False, "items": [], "error": "Choose a WhatsApp provider."}


def fetch_provider_options(payload: dict) -> dict:
    """Fetch sender/SMTP options for the configured provider (any sender type)."""
    channel = str((payload or {}).get("channel") or "").strip().lower()
    if channel == "email":
        suggestion = suggest_smtp(
            payload.get("email_host_user") or payload.get("email_from_email") or payload.get("email_host") or ""
        )
        if not suggestion:
            return {
                "ok": True,
                "channel": "email",
                "smtp": None,
                "message": "No known mailbox provider matched. Enter any SMTP host, port, and password.",
            }
        return {
            "ok": True,
            "channel": "email",
            "smtp": suggestion,
            "message": f"Detected {suggestion['label']}. SMTP host, port, and TLS were filled — save when ready.",
        }
    if channel == "whatsapp":
        result = fetch_whatsapp_senders(
            provider=payload.get("whatsapp_provider") or "",
            username=payload.get("whatsapp_username") or "",
            api_key=payload.get("whatsapp_api_key") or "",
            access_token=payload.get("whatsapp_access_token") or "",
            phone_number_id=payload.get("whatsapp_phone_number_id") or "",
        )
        result["channel"] = "whatsapp"
        return result
    result = fetch_sms_senders(
        provider=payload.get("sms_provider") or "",
        username=payload.get("sms_username") or "",
        api_key=payload.get("sms_api_key") or "",
        base_url=payload.get("sms_base_url") or "",
    )
    result["channel"] = "sms"
    return result
