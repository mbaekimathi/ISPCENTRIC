"""Auth hardening helpers: password policy, rate limits, registration gates."""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.cache import cache
from django.core.exceptions import ValidationError as DjangoValidationError
from django import forms


class AuthRateLimitExceeded(Exception):
    """Raised when an auth endpoint has too many attempts."""

    def __init__(self, retry_after: int = 900):
        self.retry_after = retry_after
        super().__init__("Too many attempts. Try again later.")


def client_ip(request) -> str:
    return (getattr(request, "META", {}) or {}).get("REMOTE_ADDR") or "unknown"


def _rate_key(scope: str, ip: str, identifier: str = "") -> str:
    ident = (identifier or "").strip().lower()[:80]
    return f"auth_rl:{scope}:{ip}:{ident}"


def is_auth_rate_limited(
    scope: str,
    request,
    identifier: str = "",
    *,
    limit: int = 5,
) -> bool:
    key = _rate_key(scope, client_ip(request), identifier)
    data = cache.get(key) or {"count": 0}
    return int(data.get("count") or 0) >= limit


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
    data = cache.get(key) or {"count": 0}
    count = int(data.get("count") or 0) + 1
    cache.set(key, {"count": count}, window)
    return count


def clear_auth_failures(scope: str, request, identifier: str = "") -> None:
    cache.delete(_rate_key(scope, client_ip(request), identifier))


def assert_auth_allowed(
    scope: str,
    request,
    identifier: str = "",
    *,
    limit: int = 5,
    window: int = 900,
) -> None:
    if is_auth_rate_limited(scope, request, identifier, limit=limit):
        raise AuthRateLimitExceeded(window)


def assert_public_pay_allowed(request, join_code: str = "") -> None:
    """Rate-limit public captive STK start endpoints (per IP and per join code)."""
    assert_auth_allowed("stk_start_ip", request, limit=12, window=900)
    if join_code:
        assert_auth_allowed(
            "stk_start_code",
            request,
            identifier=join_code,
            limit=20,
            window=900,
        )


def validate_account_password(
    password1: str,
    password2: str,
    *,
    user=None,
    required: bool = False,
) -> str:
    """
    Enforce Django AUTH_PASSWORD_VALIDATORS (min length, not numeric-only, etc.).

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
    try:
        validate_password(password1, user=user)
    except DjangoValidationError as exc:
        raise forms.ValidationError(list(exc.messages)) from exc
    return password1


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
