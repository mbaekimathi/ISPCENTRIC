"""Django system checks for hosted / VPS deployment readiness."""

from __future__ import annotations

from django.conf import settings
from django.core.checks import Error, Warning, register


@register()
def check_hosted_wireguard_mismatch(app_configs, **kwargs):
    """Warn when WireGuard is configured but the app is not in hosted mode."""
    from core.wireguard import configured

    if getattr(settings, "HOSTED", False) or not configured():
        return []
    return [
        Warning(
            "WIREGUARD_ENDPOINT is set but DJANGO_HOSTED is false — MikroTik "
            "management will use LAN discovery instead of the tunnel. On a VPS "
            "set DJANGO_HOSTED=true (or deploy under /opt/ispcentric).",
            id="core.W001",
        )
    ]


@register()
def check_hosted_public_base_url(app_configs, **kwargs):
    """Hosted installs need a public portal URL phones and routers can reach."""
    if not getattr(settings, "HOSTED", False):
        return []

    from core.hotspot_portal import public_base_url

    base = (public_base_url() or "").strip()
    if base:
        return []
    return [
        Error(
            "PUBLIC_BASE_URL is missing or unusable on a hosted install. Set it "
            "to your public site origin (e.g. http://isp.example.com) so Hotspot "
            "and PPPoE renew pages work at remote sites.",
            id="core.E001",
        )
    ]


@register()
def check_hosted_wireguard(app_configs, **kwargs):
    """Hosted installs require a complete WireGuard server configuration."""
    if not getattr(settings, "HOSTED", False):
        return []

    from core.wireguard import configured, server_on_tunnel

    errors: list[Error] = []
    warnings: list[Warning] = []

    if not configured():
        errors.append(
            Error(
                "WireGuard is not fully configured. Set WIREGUARD_ENDPOINT and "
                "WIREGUARD_SERVER_PUBLIC_KEY in .env (see .env.production.example).",
                id="core.E002",
            )
        )
        return errors

    if not server_on_tunnel() and not (getattr(settings, "WIREGUARD_SYNC_COMMAND", "") or "").strip():
        warnings.append(
            Warning(
                "This process cannot reach the WireGuard tunnel server address and "
                "WIREGUARD_SYNC_COMMAND is empty. Enable wg-quick@wg0 and set "
                "WIREGUARD_SYNC_COMMAND so MikroTik peers register on onboarding.",
                id="core.W002",
            )
        )

    return errors + warnings


@register()
def check_hosted_production_secrets(app_configs, **kwargs):
    """Production hosted installs should pin encryption and M-Pesa callback IPs."""
    if not getattr(settings, "HOSTED", False) or getattr(settings, "DEBUG", True):
        return []

    warnings: list[Warning] = []
    if not (getattr(settings, "FIELD_ENCRYPTION_KEY", "") or "").strip():
        warnings.append(
            Warning(
                "FIELD_ENCRYPTION_KEY is unset on a production hosted install. "
                "Safest if secrets are already encrypted: set it to a copy of the "
                "current DJANGO_SECRET_KEY (passphrase). Or generate a Fernet key "
                "only when ciphertext is still plaintext — see .env.production.example.",
                id="core.W003",
            )
        )
    if not (getattr(settings, "MPESA_CALLBACK_ALLOWED_IPS", "") or "").strip():
        warnings.append(
            Warning(
                "MPESA_CALLBACK_ALLOWED_IPS is empty on a production hosted install. "
                "Pin Safaricom callback source IPs in .env to reject forged STK posts "
                "(see .env.production.example).",
                id="core.W004",
            )
        )
    return warnings


@register()
def check_mpesa_stk_callback_public(app_configs, **kwargs):
    """Daraja STK callbacks must use a public HTTPS URL Safaricom can POST to."""
    try:
        from accounts.models import PaymentGateway
        from core.hotspot_portal import (
            mpesa_stk_callback_reachability,
            mpesa_stk_callback_url,
        )

        gateway = PaymentGateway.get_solo()
        if not gateway.is_stk_ready():
            return []
        reach = mpesa_stk_callback_reachability()
        url = reach.get("url") or mpesa_stk_callback_url()
        if not url:
            return []
        issues = []
        if not reach.get("ok"):
            issues.append(
                Warning(
                    reach.get("warning")
                    or (
                        "M-Pesa STK callback URL is not reachable from Safaricom. "
                        f"Configure PUBLIC_BASE_URL so {url} is a public HTTPS origin."
                    ),
                    id="core.W005",
                )
            )
        elif getattr(settings, "HOSTED", False) and url.lower().startswith("http://"):
            issues.append(
                Warning(
                    reach.get("warning")
                    or (
                        "M-Pesa STK callback uses HTTP on a hosted install. "
                        "Use HTTPS in PUBLIC_BASE_URL for reliable payment receipts."
                    ),
                    id="core.W006",
                )
            )
        return issues
    except Exception:
        return []
