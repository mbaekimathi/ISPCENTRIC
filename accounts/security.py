"""Auth hardening helpers: password policy, rate limits, registration gates."""

from __future__ import annotations

import logging
import time

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.cache import cache
from django.core.exceptions import ValidationError as DjangoValidationError
from django import forms

logger = logging.getLogger(__name__)


def format_retry_after(seconds: int) -> str:
    """Human-readable wait time for rate-limit messages."""
    seconds = max(1, int(seconds))
    if seconds < 60:
        unit = "second" if seconds == 1 else "seconds"
        return f"{seconds} {unit}"
    minutes = seconds // 60
    rem = seconds % 60
    if minutes < 60:
        m_unit = "minute" if minutes == 1 else "minutes"
        if rem == 0:
            return f"{minutes} {m_unit}"
        s_unit = "second" if rem == 1 else "seconds"
        return f"{minutes} {m_unit} {rem} {s_unit}"
    hours = minutes // 60
    rem_min = minutes % 60
    h_unit = "hour" if hours == 1 else "hours"
    if rem_min == 0:
        return f"{hours} {h_unit}"
    m_unit = "minute" if rem_min == 1 else "minutes"
    return f"{hours} {h_unit} {rem_min} {m_unit}"


def public_pay_rate_limit_message(retry_after: int) -> str:
    return (
        "Too many payment attempts. Try again in "
        f"{format_retry_after(retry_after)}."
    )


class AuthRateLimitExceeded(Exception):
    """Raised when an auth endpoint has too many attempts."""

    def __init__(self, retry_after: int = 900, *, message: str | None = None):
        self.retry_after = max(1, int(retry_after or 1))
        super().__init__(
            message
            or f"Too many attempts. Try again in {format_retry_after(self.retry_after)}."
        )


def client_ip(request) -> str:
    return (getattr(request, "META", {}) or {}).get("REMOTE_ADDR") or "unknown"


def _rate_key(scope: str, ip: str, identifier: str = "") -> str:
    ident = (identifier or "").strip().lower()[:80]
    return f"auth_rl:{scope}:{ip}:{ident}"


def _read_rate_entry(key: str, *, window: int = 900) -> tuple[int, int]:
    """Return (count, remaining_seconds). Expired / missing entries are (0, 0)."""
    try:
        data = cache.get(key) or {}
    except Exception:
        return 0, 0
    now = time.time()
    count = int(data.get("count") or 0)
    expires_at = float(data.get("expires_at") or 0)
    if expires_at > 0:
        remaining = int(expires_at - now)
        if remaining <= 0:
            return 0, 0
        return count, remaining
    # Legacy entries without expires_at: treat full window as remaining.
    if count > 0:
        return count, max(1, int(window))
    return 0, 0


def record_auth_failure(
    scope: str,
    request,
    identifier: str = "",
    *,
    limit: int = 5,
    window: int = 900,
) -> int:
    """Increment failure counter. Returns new count."""
    key = _rate_key(scope, client_ip(request), identifier)
    try:
        now = time.time()
        data = cache.get(key) or {}
        count = int(data.get("count") or 0)
        expires_at = float(data.get("expires_at") or 0)
        if expires_at <= now:
            count = 0
            expires_at = now + window
        elif count <= 0:
            expires_at = now + window
        count += 1
        ttl = max(1, int(expires_at - now))
        cache.set(key, {"count": count, "expires_at": expires_at}, ttl)
        return count
    except Exception:
        # Hosted file-cache permission blips must not turn Pay into HTTP 500.
        logger.exception("auth rate-limit cache write failed for %s", scope)
        return 0


def clear_auth_failures(scope: str, request, identifier: str = "") -> None:
    try:
        cache.delete(_rate_key(scope, client_ip(request), identifier))
    except Exception:
        pass


def is_auth_rate_limited(
    scope: str,
    request,
    identifier: str = "",
    *,
    limit: int = 5,
    window: int = 900,
) -> bool:
    key = _rate_key(scope, client_ip(request), identifier)
    count, _remaining = _read_rate_entry(key, window=window)
    return count >= limit


def auth_rate_limit_retry_after(
    scope: str,
    request,
    identifier: str = "",
    *,
    limit: int = 5,
    window: int = 900,
) -> int:
    """Seconds until the rate limit clears, or 0 if not limited."""
    key = _rate_key(scope, client_ip(request), identifier)
    count, remaining = _read_rate_entry(key, window=window)
    if count < limit:
        return 0
    return max(1, remaining or window)


def assert_auth_allowed(
    scope: str,
    request,
    identifier: str = "",
    *,
    limit: int = 5,
    window: int = 900,
) -> None:
    retry_after = auth_rate_limit_retry_after(
        scope, request, identifier, limit=limit, window=window
    )
    if retry_after:
        raise AuthRateLimitExceeded(retry_after)


def assert_public_pay_allowed(request, join_code: str = "") -> None:
    """Rate-limit public captive STK start endpoints (per IP and per join code)."""
    retry_after = auth_rate_limit_retry_after(
        "stk_start_ip", request, limit=12, window=900
    )
    if join_code:
        code_retry = auth_rate_limit_retry_after(
            "stk_start_code",
            request,
            identifier=join_code,
            limit=20,
            window=900,
        )
        if code_retry:
            retry_after = max(retry_after, code_retry)
    if retry_after:
        raise AuthRateLimitExceeded(
            retry_after,
            message=public_pay_rate_limit_message(retry_after),
        )


def validate_account_password(
    password1: str,
    password2: str,
    *,
    user=None,
    required: bool = False,
) -> str:
    """
    Accept a matching 6-digit numeric password or a longer password that passes
    Django AUTH_PASSWORD_VALIDATORS.

    Blank passwords are allowed when required=False (profile edit leave-unchanged).
    """
    password1 = password1 or ""
    password2 = password2 or ""
    if not password1 and not password2:
        if required:
            raise forms.ValidationError("Enter a password.")
        return ""
    if password1 != password2:
        raise forms.ValidationError("Passwords do not match.")

    digits1 = "".join(ch for ch in password1 if ch.isdigit())
    digits2 = "".join(ch for ch in password2 if ch.isdigit())
    if len(digits1) == 6 and digits1 == digits2:
        return digits1

    try:
        validate_password(password1, user=user)
    except DjangoValidationError as exc:
        raise forms.ValidationError(list(exc.messages)) from exc
    return password1


def normalize_six_digit_login_code(value: str) -> str:
    """Require exactly six numeric digits (shared by ISP owners and staff login codes)."""
    code = "".join(ch for ch in str(value or "") if ch.isdigit())
    if len(code) != 6:
        raise forms.ValidationError("Enter a 6-digit login code.")
    return code


def isp_owner_login_code_taken(code: str, *, exclude_org_id=None) -> bool:
    """True when an ISP client already uses this code in Organization.login_code."""
    from accounts.models import Organization

    qs = Organization.objects.filter(login_code=code)
    if exclude_org_id:
        qs = qs.exclude(pk=exclude_org_id)
    return qs.exists()


def employee_login_code_taken(code: str, *, exclude_employee_id=None) -> bool:
    """True when a staff account already uses this code in Employee.login_code."""
    from accounts.models import Employee

    qs = Employee.objects.filter(login_code=code)
    if exclude_employee_id:
        qs = qs.exclude(pk=exclude_employee_id)
    return qs.exists()


def assert_owner_login_code_available(code: str, *, organization=None):
    """Ensure a 6-digit code is free for Organization.login_code (ISP clients only)."""
    if isp_owner_login_code_taken(
        code, exclude_org_id=getattr(organization, "pk", None)
    ):
        raise forms.ValidationError("That login code is already taken.")


def assert_employee_login_code_available(code: str, *, employee=None):
    """Ensure a 6-digit code is free for Employee.login_code (staff only)."""
    if employee_login_code_taken(
        code, exclude_employee_id=getattr(employee, "pk", None)
    ):
        raise forms.ValidationError("This login code is not available. Choose another.")


def validate_employee_password(
    password1: str,
    password2: str,
    *,
    required: bool = True,
    user=None,
) -> str:
    """Accept a 6-digit numeric password or a longer password for staff accounts."""
    return validate_account_password(
        password1,
        password2,
        user=user,
        required=required,
    )


EMPLOYEE_PASSWORD_LABEL = "Password"
EMPLOYEE_PASSWORD_CONFIRM_LABEL = "Confirm password"
EMPLOYEE_PASSWORD_LOGIN_HELP = (
    "Use your 6-digit code or a longer password (at least 8 characters)."
)
EMPLOYEE_PASSWORD_SET_HELP = (
    "Choose a 6-digit code or a longer password that meets the strength rules."
)


def employee_password_field_attrs(*, placeholder="Password", autocomplete="new-password"):
    """Widget attrs for staff password fields that accept PIN or passphrase."""
    return {
        "placeholder": placeholder,
        "autocomplete": autocomplete,
        "class": "form-control password-input",
    }


# Backward-compatible alias used by older imports/tests.
def validate_flexible_password(
    password1: str,
    password2: str,
    *,
    required: bool = False,
    user=None,
) -> str:
    return validate_account_password(
        password1, password2, user=user, required=required
    )


def owner_registration_open(*, referral_code: str = "") -> bool:
    """Public owner self-signup when Client Settings Register link is on.

    IT Support controls this via Client settings → Register link. An env invite
    key still opens registration. Referral invite links can open register when
    the public Register link is hidden (referrals enabled + code present).
    """
    if getattr(settings, "OWNER_REGISTER_INVITE_KEY", ""):
        return True
    from accounts.models import ClientSettings

    client = ClientSettings.get_solo()
    if client.landing_register_enabled:
        return True
    # Referral invite links can still open register when the public Register link is hidden.
    if client.referral_enabled and (referral_code or "").strip():
        return True
    return False


def owner_invite_required() -> bool:
    return bool(getattr(settings, "OWNER_REGISTER_INVITE_KEY", ""))


GOOGLE_VERIFIED_EMAIL_SESSION_KEY = "google_verified_email"


def google_login_gate_required() -> bool:
    """True when ISP client login must connect Google before code/password."""
    client_id = (getattr(settings, "GOOGLE_OAUTH_CLIENT_ID", "") or "").strip()
    client_secret = (getattr(settings, "GOOGLE_OAUTH_CLIENT_SECRET", "") or "").strip()
    if not (client_id and client_secret):
        return False
    from accounts.models import ClientSettings

    solo = ClientSettings.get_solo()
    return bool(solo.google_login_enabled and solo.google_login_require_email_match)


def google_verified_email_from_request(request) -> str:
    if request is None:
        return ""
    return (request.session.get(GOOGLE_VERIFIED_EMAIL_SESSION_KEY) or "").strip().lower()


def google_wrong_profile_message(
    *,
    connected_email: str = "",
    account_email: str = "",
) -> str:
    """User-facing notice when the connected Google profile does not match the ISP account."""
    return "Wrong Google account"
