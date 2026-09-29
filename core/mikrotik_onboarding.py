"""
MikroTik onboarding orchestrator — server-owned session from script → commit.

Views delegate prepare / connect / tunnel verify sync / commit here so host and
credential resolution is not re-derived from conflicting POST fields.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.core import signing
from django.db import transaction
from django.utils import timezone

from core import wireguard
from core.models import MikroTikOnboardingSession, MikroTikRouter, WireGuardReservation

logger = logging.getLogger(__name__)

SESSION_SIGNING_SALT = "mikrotik-onboarding-session-v1"
SESSION_MAX_AGE_SEC = 4 * 3600
LEGACY_STATUS_SALT = "mikrotik-tunnel-status"

_OPEN_SESSION_PHASES = (
    MikroTikOnboardingSession.Phase.PREPARED,
    MikroTikOnboardingSession.Phase.TUNNEL_READY,
    MikroTikOnboardingSession.Phase.AUTHENTICATED,
)


class OnboardingError(Exception):
    """Operator-visible onboarding failure."""

    def __init__(self, message: str, *, field: str = ""):
        super().__init__(message)
        self.message = message
        self.field = field or ""


@dataclass
class CommitResult:
    router: MikroTikRouter
    tunnel: bool


def _session_ttl() -> timedelta:
    hours = int(getattr(settings, "MIKROTIK_ONBOARDING_SESSION_HOURS", 4) or 4)
    return timedelta(hours=max(1, hours))


def issue_session_token(session: MikroTikOnboardingSession) -> str:
    return signing.dumps(
        {
            "sid": session.pk,
            "org_id": session.organization_id,
            "user_id": session.initiated_by_id,
        },
        salt=SESSION_SIGNING_SALT,
        compress=True,
    )


def load_open_session(
    token: str,
    *,
    organization,
    user,
) -> MikroTikOnboardingSession:
    token = (token or "").strip()
    if not token or not organization or not user:
        raise OnboardingError("Onboarding session is missing — Connect again.")
    try:
        payload = signing.loads(
            token,
            salt=SESSION_SIGNING_SALT,
            max_age=SESSION_MAX_AGE_SEC,
        )
    except signing.BadSignature as exc:
        raise OnboardingError("Onboarding session expired — start Connect again.") from exc

    if int(payload.get("org_id") or 0) != int(organization.pk):
        raise OnboardingError("This onboarding session belongs to another workspace.")
    if int(payload.get("user_id") or 0) != int(user.pk):
        raise OnboardingError("This onboarding session belongs to another user.")

    session = (
        MikroTikOnboardingSession.objects.select_related("reservation", "organization")
        .filter(pk=int(payload["sid"]), organization=organization)
        .first()
    )
    if session is None:
        raise OnboardingError("Onboarding session was not found — Connect again.")
    if session.expires_at and session.expires_at < timezone.now():
        raise OnboardingError("Onboarding session expired — Connect again.")
    if not session.is_open:
        raise OnboardingError("This onboarding session is already finished.")
    if session.reservation_id:
        if not WireGuardReservation.objects.filter(pk=session.reservation_id).exists():
            session.phase = MikroTikOnboardingSession.Phase.CANCELLED
            session.save(update_fields=["phase", "updated_at"])
            raise OnboardingError(
                "Tunnel reservation was removed — Generate script again, then Connect."
            )
    return session


def session_for_legacy_status_token(
    token: str,
    *,
    organization,
    user,
) -> MikroTikOnboardingSession | None:
    """Attach tunnel-status polling to a DB session (creates one if needed)."""
    token = (token or "").strip()
    if not token or not organization:
        return None
    try:
        signed = signing.loads(token, salt=LEGACY_STATUS_SALT, max_age=3600)
    except signing.BadSignature:
        return None
    if signed.get("user_id") != user.pk:
        return None
    token_org = signed.get("org_id")
    if token_org and int(token_org) != int(organization.pk):
        return None
    address = (signed.get("address") or "").strip()
    if not address:
        return None

    reservation = wireguard.reservation_for_address(address, organization=organization)
    session = (
        MikroTikOnboardingSession.objects.filter(
            organization=organization,
            initiated_by=user,
            tunnel_address=address,
            phase__in=[
                MikroTikOnboardingSession.Phase.PREPARED,
                MikroTikOnboardingSession.Phase.TUNNEL_READY,
                MikroTikOnboardingSession.Phase.AUTHENTICATED,
            ],
        )
        .order_by("-created_at")
        .first()
    )
    if session is None:
        cancel_open_onboarding_sessions(
            organization=organization,
            tunnel_address=address,
        )
        session = MikroTikOnboardingSession.objects.create(
            organization=organization,
            initiated_by=user,
            reservation=reservation,
            label=(getattr(reservation, "label", None) or "").strip(),
            tunnel_address=address,
            planned_lan=(getattr(reservation, "lan_address", None) or "") or None,
            phase=MikroTikOnboardingSession.Phase.PREPARED,
            expires_at=timezone.now() + _session_ttl(),
        )
    elif reservation and session.reservation_id != reservation.pk:
        session.reservation = reservation
        session.planned_lan = reservation.lan_address or session.planned_lan
        session.save(update_fields=["reservation", "planned_lan", "updated_at"])
    return session


def resolve_session_from_request(
    request,
    *,
    organization,
    user,
) -> MikroTikOnboardingSession | None:
    raw = (
        (request.POST.get("session_token") or "")
        or (request.GET.get("session_token") or "")
        or (request.POST.get("onboarding_session_token") or "")
    ).strip()
    if raw:
        try:
            return load_open_session(raw, organization=organization, user=user)
        except OnboardingError:
            return None
    legacy = (request.POST.get("token") or request.GET.get("token") or "").strip()
    if legacy:
        return session_for_legacy_status_token(
            legacy, organization=organization, user=user
        )
    return None


def cancel_open_onboarding_sessions(
    *,
    organization=None,
    reservation_id: int | None = None,
    tunnel_address: str = "",
    exclude_session_id: int | None = None,
) -> int:
    """Invalidate open DB sessions so old tokens cannot block a fresh onboard."""
    qs = MikroTikOnboardingSession.objects.filter(phase__in=_OPEN_SESSION_PHASES)
    if organization is not None:
        qs = qs.filter(organization=organization)
    if reservation_id:
        qs = qs.filter(reservation_id=reservation_id)
    tunnel = (tunnel_address or "").strip()
    if tunnel:
        qs = qs.filter(tunnel_address=tunnel)
    if exclude_session_id:
        qs = qs.exclude(pk=exclude_session_id)
    if not qs.exists():
        return 0
    count = qs.update(
        phase=MikroTikOnboardingSession.Phase.CANCELLED,
        updated_at=timezone.now(),
    )
    if count:
        logger.info("Cancelled %s open MikroTik onboarding session(s)", count)
    return count


def expire_stale_onboarding_sessions(*, organization=None) -> int:
    """
    Cancel open sessions that timed out or lost their WireGuard reservation row.
    """
    qs = MikroTikOnboardingSession.objects.filter(phase__in=_OPEN_SESSION_PHASES)
    if organization is not None:
        qs = qs.filter(organization=organization)
    now = timezone.now()
    stale_pks: list[int] = []
    live_reservation_ids = set(
        WireGuardReservation.objects.values_list("pk", flat=True)
    )
    for session in qs.only("pk", "expires_at", "reservation_id"):
        if session.expires_at and session.expires_at < now:
            stale_pks.append(session.pk)
            continue
        if session.reservation_id and session.reservation_id not in live_reservation_ids:
            stale_pks.append(session.pk)
    if not stale_pks:
        return 0
    count = MikroTikOnboardingSession.objects.filter(pk__in=stale_pks).update(
        phase=MikroTikOnboardingSession.Phase.CANCELLED,
        updated_at=now,
    )
    if count:
        logger.info("Expired %s stale MikroTik onboarding session(s)", count)
    return count


def cleanup_onboarding_workspace(*, organization) -> dict[str, int]:
    """
    Run before Generate script / tunnel verify — drops dead sessions for this ISP.
    """
    expired = expire_stale_onboarding_sessions(organization=organization)
    return {"sessions_expired": expired}


def create_session_for_reservation(
    reservation: WireGuardReservation,
    *,
    organization,
    user,
    label: str = "",
) -> MikroTikOnboardingSession:
    return MikroTikOnboardingSession.objects.create(
        organization=organization,
        initiated_by=user,
        reservation=reservation,
        label=(label or reservation.label or "").strip(),
        tunnel_address=reservation.address,
        planned_lan=reservation.lan_address or None,
        phase=MikroTikOnboardingSession.Phase.PREPARED,
        expires_at=timezone.now() + _session_ttl(),
    )


def prepare_onboarding_session(
    reservation: WireGuardReservation,
    *,
    organization,
    user,
    label: str = "",
) -> MikroTikOnboardingSession:
    """
    One canonical open session per reservation — old tokens for the same site are cancelled.
    """
    cleanup_onboarding_workspace(organization=organization)
    cancel_open_onboarding_sessions(
        organization=organization,
        reservation_id=reservation.pk,
    )
    cancel_open_onboarding_sessions(
        organization=organization,
        tunnel_address=str(reservation.address or ""),
    )
    return create_session_for_reservation(
        reservation,
        organization=organization,
        user=user,
        label=label,
    )


def create_connect_only_session(
    *,
    organization,
    user,
    label: str = "",
) -> MikroTikOnboardingSession:
    return MikroTikOnboardingSession.objects.create(
        organization=organization,
        initiated_by=user,
        label=(label or "MikroTik").strip(),
        phase=MikroTikOnboardingSession.Phase.PREPARED,
        expires_at=timezone.now() + _session_ttl(),
    )


def sync_session_from_tunnel_payload(
    session: MikroTikOnboardingSession,
    payload: dict[str, Any],
) -> None:
    """Update session after mikrotik_tunnel_status JSON response."""
    if not session or not session.is_open:
        return
    lan = (payload.get("lan_address") or "").strip()
    if lan:
        session.discovered_lan = lan
    if payload.get("ready"):
        if session.phase in {
            MikroTikOnboardingSession.Phase.PREPARED,
            MikroTikOnboardingSession.Phase.TUNNEL_READY,
        }:
            session.phase = MikroTikOnboardingSession.Phase.TUNNEL_READY
        if not session.tunnel_verified_at:
            session.tunnel_verified_at = timezone.now()
    address = (payload.get("address") or session.tunnel_address or "").strip()
    if address and not session.tunnel_address:
        session.tunnel_address = address
    if payload.get("keys_rotated") and session.tunnel_address:
        reservation = wireguard.reservation_for_address(
            session.tunnel_address, organization=session.organization
        )
        if reservation:
            session.reservation = reservation
            session.planned_lan = reservation.lan_address or session.planned_lan
    session.save(
        update_fields=[
            "discovered_lan",
            "phase",
            "tunnel_verified_at",
            "tunnel_address",
            "reservation",
            "planned_lan",
            "updated_at",
        ]
    )


def attach_session_token(payload: dict[str, Any], session: MikroTikOnboardingSession | None) -> None:
    if not session:
        return
    token = issue_session_token(session)
    payload["session_token"] = token
    payload["status_token"] = token


def find_router_by_hardware(
    org,
    *,
    serial_number: str = "",
    software_id: str = "",
    host: str = "",
) -> MikroTikRouter | None:
    if not org:
        return None
    serial = (serial_number or "").strip()
    soft = (software_id or "").strip()
    if serial:
        match = (
            MikroTikRouter.objects.filter(organization=org, serial_number=serial)
            .order_by("id")
            .first()
        )
        if match:
            return match
    if soft:
        match = (
            MikroTikRouter.objects.filter(organization=org, software_id=soft)
            .order_by("id")
            .first()
        )
        if match:
            return match
    host_value = (host or "").strip()
    if host_value:
        return (
            MikroTikRouter.objects.filter(organization=org, host__iexact=host_value)
            .order_by("id")
            .first()
        )
    return None


def apply_hardware_ids(
    router: MikroTikRouter,
    *,
    serial_number: str = "",
    software_id: str = "",
) -> list[str]:
    changed: list[str] = []
    serial = (serial_number or "").strip()
    soft = (software_id or "").strip()
    if serial and serial != (router.serial_number or ""):
        router.serial_number = serial
        changed.append("serial_number")
    if soft and soft != (router.software_id or ""):
        router.software_id = soft
        changed.append("software_id")
    return changed


def record_authentication(
    session: MikroTikOnboardingSession,
    *,
    connect_result: dict[str, Any],
    username: str,
    password: str,
) -> None:
    from core.mikrotik_connect import normalize_mikrotik_host

    management = normalize_mikrotik_host(
        connect_result.get("host") or connect_result.get("suggested_lan_ip") or ""
    )
    dial = normalize_mikrotik_host(connect_result.get("connect_host") or management)
    session.verified_dial_host = dial or None
    session.management_host = management or None
    session.username = (username or "").strip()
    session.password = password or ""
    session.serial_number = (connect_result.get("serial_number") or "").strip()
    session.software_id = (connect_result.get("software_id") or "").strip()
    session.board_name = (connect_result.get("board") or "").strip()
    session.routeros_version = (connect_result.get("version") or "").strip()
    session.lan_ip_applied_at_connect = bool(connect_result.get("lan_ip_applied"))
    tunnel = normalize_mikrotik_host(connect_result.get("tunnel_host") or "")
    if tunnel:
        session.tunnel_address = tunnel or session.tunnel_address
    if dial and not session.discovered_lan:
        session.discovered_lan = dial
    session.phase = MikroTikOnboardingSession.Phase.AUTHENTICATED
    session.authenticated_at = timezone.now()
    session.save()


def authenticate_connect(
    session: MikroTikOnboardingSession,
    *,
    host: str,
    username: str,
    password: str,
    script_lan: str = "",
    tunnel_host: str = "",
    organization,
) -> dict[str, Any]:
    """
    RouterOS API login for Connect — updates session and returns JSON payload.
    """
    from core.mikrotik_connect import (
        _api_session,
        _ensure_hotspot_management_access,
        clear_onboard_connect_auth_cooldown,
        is_onboard_connect_auth_cooling_down,
        is_transient_onboard_host,
        mark_onboard_connect_auth_failure,
        normalize_mikrotik_host,
        on_router_lan,
        pick_local_onboard_connect_host,
        resolve_onboard_management_host,
        suggest_unique_mikrotik_lan_ip,
        change_mikrotik_lan_ip,
        test_mikrotik_api_login,
    )
    from core.mikrotik_discovery import guess_model

    connect_host = normalize_mikrotik_host(host)
    script_lan_norm = normalize_mikrotik_host(script_lan or "")
    tunnel = normalize_mikrotik_host(
        tunnel_host or (session.tunnel_address or "") or ""
    )

    if tunnel:
        peer_gate = wireguard.onboard_tunnel_peer_ready(tunnel, organization=organization)
        if peer_gate.get("required") and not peer_gate.get("ok"):
            if not wireguard._tunnel_host_reachable(tunnel):
                return {
                    "ok": False,
                    "peer_sync_required": True,
                    "error": (
                        peer_gate.get("error")
                        or peer_gate.get("peer_sync_hint")
                        or "WireGuard peer is not registered on the VPS yet."
                    ),
                }

    if on_router_lan():
        connect_host = pick_local_onboard_connect_host(
            tunnel_address=tunnel,
            reservation_label=(getattr(session.reservation, "label", None) or ""),
            planned_lan=script_lan_norm or (session.planned_lan or ""),
            current=connect_host,
        )

    dial_host = connect_host
    org_id = int(getattr(organization, "pk", 0) or 0)
    if org_id and is_onboard_connect_auth_cooling_down(dial_host, org_id):
        return {
            "ok": False,
            "auth_error": True,
            "cooling_down": True,
            "retry_after_sec": 45,
            "error": (
                "Too many failed API logins — wait ~45 seconds, then use the correct "
                "RouterOS username and password (same as Winbox)."
            ),
        }

    from core.mikrotik_connect import _is_wireguard_tunnel_host

    result = test_mikrotik_api_login(dial_host, username, password)
    # On the MikroTik LAN: if tunnel IP is unreachable from this PC, retry LAN.
    if (
        not result.get("ok")
        and on_router_lan()
        and _is_wireguard_tunnel_host(dial_host)
        and not bool(result.get("auth_error"))
    ):
        lan_fallback = pick_local_onboard_connect_host(
            tunnel_address=tunnel,
            reservation_label=(getattr(session.reservation, "label", None) or ""),
            planned_lan=script_lan_norm or (session.planned_lan or ""),
            current="",
        )
        if lan_fallback and lan_fallback != dial_host:
            lan_try = test_mikrotik_api_login(lan_fallback, username, password)
            if lan_try.get("ok"):
                result = lan_try
                dial_host = lan_fallback
                connect_host = lan_fallback
            else:
                result = lan_try
                dial_host = lan_fallback
                connect_host = lan_fallback

    if not result.get("ok"):
        err = result.get("error") or "Connection failed."
        auth_error = bool(result.get("auth_error"))
        if not auth_error:
            low = err.lower()
            auth_error = any(
                token in low
                for token in ("login failed", "invalid user", "password", "authentication")
            )
        # Tunnel IP unreachable: rewrite the generic “paste script” tip — script often already OK.
        if (
            not auth_error
            and _is_wireguard_tunnel_host(dial_host)
            and "could not reach" in err.lower()
        ):
            from core.wireguard import server_on_tunnel

            if not server_on_tunnel():
                from core.mikrotik_connect import hosted_dashboard_url

                dashboard = hosted_dashboard_url() or "the hosted ISPCENTRIC site"
                err = (
                    f"This PC cannot dial tunnel IP {dial_host}:8728 (WireGuard is on the VPS). "
                    f"Open {dashboard}, use Tunnel IP Connect there — or connect with the "
                    "router LAN IP (e.g. 192.168.88.1) while on the same network."
                )
            elif not wireguard._tunnel_host_reachable(dial_host):
                err = (
                    f"Tunnel peer {dial_host} is not answering the billing server yet. "
                    "On the VPS run: manage.py wireguard_peer --sync-server, wait ~30s for "
                    "handshake, confirm Winbox ping to 10.9.0.1 is OK, then Connect again."
                )
            else:
                err = (
                    f"Billing server can ping {dial_host} but TCP 8728 did not open. "
                    "In Winbox: /ip service print where name=api — must be enabled on 8728. "
                    "Then retry Connect with the correct RouterOS password (same as Winbox)."
                )
        if auth_error and org_id:
            mark_onboard_connect_auth_failure(dial_host, org_id)
        payload = {"ok": False, "error": err, "auth_error": auth_error}
        if auth_error:
            payload["retry_after_sec"] = 45
        return payload

    try:
        with _api_session(dial_host, username, password, timeout=8.0) as sock:
            _ensure_hotspot_management_access(
                sock, username=username, password=password
            )
    except Exception:
        pass

    existing = find_router_by_hardware(
        organization,
        serial_number=(result.get("serial_number") or ""),
        software_id=(result.get("software_id") or ""),
        host=result.get("host") or host,
    )
    if existing:
        from django.urls import reverse

        detail_url = reverse("core:mikrotik_detail", args=[existing.pk])
        return {
            "ok": False,
            "already_onboarded": True,
            "error": (
                f'This MikroTik is already onboarded as “{existing.name}”. '
                "Open it from the list or use Reconnect — you cannot register the same device twice."
            ),
            "existing_router_id": existing.pk,
            "existing_router_name": existing.name,
            "existing_router_url": detail_url,
            "serial_number": (result.get("serial_number") or "").strip(),
            "software_id": (result.get("software_id") or "").strip(),
            "host": result.get("host") or host,
        }

    final_host = connect_host or normalize_mikrotik_host(result.get("host") or host)
    lan_ip_applied = False
    lan_message = ""

    if is_transient_onboard_host(connect_host):
        suggested_lan_ip = suggest_unique_mikrotik_lan_ip(
            list(
                MikroTikRouter.objects.filter(organization=organization).values_list(
                    "host", flat=True
                )
            )
        )
        if connect_host != suggested_lan_ip:
            lan_result = change_mikrotik_lan_ip(
                connect_host,
                username,
                password,
                suggested_lan_ip,
                api_hosts=[h for h in (tunnel, connect_host) if h],
            )
            if not lan_result.get("ok"):
                return {
                    "ok": False,
                    "error": lan_result.get("error")
                    or "Could not assign a unique LAN IP on this MikroTik.",
                }
            lan_ip_applied = True
            final_host = resolve_onboard_management_host(
                connect_host=connect_host,
                tunnel_host=tunnel,
                lan_result=lan_result,
                fallback=suggested_lan_ip,
            )
            lan_message = (lan_result.get("message") or "").strip()
    elif tunnel and not on_router_lan():
        final_host = tunnel

    payload = {
        "ok": True,
        "host": final_host,
        "connect_host": connect_host,
        "tunnel_host": tunnel,
        "name": result.get("name") or "",
        "identity": result.get("identity") or "",
        "version": result.get("version") or "",
        "board": result.get("board") or "",
        "serial_number": (result.get("serial_number") or "").strip(),
        "software_id": (result.get("software_id") or "").strip(),
        "model": guess_model(result.get("board") or ""),
        "username": username,
        "wifi_ssid": result.get("wifi_ssid") or "",
        "wifi_password": result.get("wifi_password") or "",
        "wifi_mode": result.get("wifi_mode") or "",
        "already_onboarded": False,
        "requires_ip_change": False,
        "lan_ip_applied": lan_ip_applied,
        "lan_message": lan_message,
        "factory_default_ip": "192.168.88.1",
        "suggested_lan_ip": final_host,
    }
    if org_id:
        clear_onboard_connect_auth_cooldown(dial_host, org_id)
    record_authentication(session, connect_result=payload, username=username, password=password)
    attach_session_token(payload, session)
    return payload


@transaction.atomic
def commit_session(
    session: MikroTikOnboardingSession,
    form,
    *,
    organization,
    request,
) -> CommitResult:
    """
    Save MikroTikRouter from an authenticated onboarding session + metadata form.
    """
    from accounts.communications import dispatch_org_event, dispatch_platform_event
    from core.mikrotik_connect import (
        configure_mikrotik_wifi,
        finalize_onboard_addresses,
        normalize_mikrotik_host,
    )
    from core.mikrotik_jobs import schedule_post_onboard_nas_refresh

    if session.phase != MikroTikOnboardingSession.Phase.AUTHENTICATED:
        raise OnboardingError(
            "Connect to the MikroTik before onboarding — session is not authenticated."
        )
    if not session.management_host and not session.verified_dial_host:
        raise OnboardingError("Onboarding session has no verified router address.")

    serial = (session.serial_number or "").strip()
    soft = (session.software_id or "").strip()
    if not serial and not soft:
        raise OnboardingError(
            "Could not read this MikroTik’s serial number. Connect again with API enabled.",
            field="host",
        )

    existing = find_router_by_hardware(
        organization,
        serial_number=serial,
        software_id=soft,
        host=session.management_host or "",
    )
    if existing:
        raise OnboardingError(
            f'This MikroTik is already onboarded as “{existing.name}”. '
            "Open it from the list or use Reconnect.",
            field="host",
        )

    router = form.save(commit=False)
    router.organization = organization
    router.host = normalize_mikrotik_host(
        session.management_host or session.verified_dial_host or router.host
    )
    router.username = (session.username or router.username or "").strip()
    router.password = session.password or router.password or ""
    apply_hardware_ids(router, serial_number=serial, software_id=soft)

    tunnel_host = normalize_mikrotik_host(session.tunnel_address or "")
    if tunnel_host:
        router.vpn_address = tunnel_host

    wifi_ssid = (router.wifi_ssid or "").strip()
    wifi_password = router.wifi_password or ""
    original_ssid = (request.POST.get("wifi_ssid_original") or "").strip()
    original_password = request.POST.get("wifi_password_original") or ""
    wifi_mode = (request.POST.get("wifi_mode") or "").strip()
    apply_ssid = wifi_ssid != original_ssid
    apply_password = wifi_password != original_password
    wants_wifi = bool(wifi_ssid or wifi_password)
    wifi_changed = apply_ssid or apply_password

    if wants_wifi and wifi_changed:
        if wifi_password and not wifi_ssid:
            raise OnboardingError(
                "Enter a Wi‑Fi name when setting a Wi‑Fi password.",
                field="wifi_ssid",
            )
        if apply_password and wifi_password and len(wifi_password) < 8:
            raise OnboardingError(
                "Wi‑Fi password must be at least 8 characters.",
                field="wifi_password",
            )
        wifi_host = tunnel_host or (
            session.verified_dial_host or session.management_host or router.host
        )
        wifi_result = configure_mikrotik_wifi(
            wifi_host,
            router.username,
            router.password,
            wifi_ssid=wifi_ssid,
            wifi_password=wifi_password,
            wifi_mode=wifi_mode,
            apply_ssid=apply_ssid and bool(wifi_ssid),
            apply_password=apply_password and bool(wifi_password),
        )
        if not wifi_result.get("ok"):
            raise OnboardingError(
                wifi_result.get("error") or "Could not apply Wi‑Fi settings on the router.",
                field="wifi_ssid",
            )

    finalize_onboard_addresses(
        router,
        lan_host=router.host,
        tunnel_host=tunnel_host,
    )
    router.save()
    wireguard.adopt_reservation_for_router(router)

    session.phase = MikroTikOnboardingSession.Phase.COMMITTED
    session.committed_at = timezone.now()
    session.router = router
    session.save(
        update_fields=["phase", "committed_at", "router", "updated_at"]
    )
    cancel_open_onboarding_sessions(
        organization=organization,
        tunnel_address=tunnel_host,
        exclude_session_id=session.pk,
    )
    if session.reservation_id:
        cancel_open_onboarding_sessions(
            organization=organization,
            reservation_id=session.reservation_id,
            exclude_session_id=session.pk,
        )

    try:
        dispatch_platform_event(
            "platform_isp_mikrotik_onboarded",
            organization=organization,
            request=request,
            context={
                "company_name": getattr(organization, "name", "") or "your company",
                "router_name": router.name or "MikroTik",
                "join_code": getattr(organization, "join_code", "") or "",
            },
            subject=f"MikroTik onboarded — {router.name or 'router'}",
        )
    except Exception:
        logger.exception("Failed to dispatch MikroTik onboarded platform notification")
    try:
        dispatch_org_event(
            "isp_mikrotik_onboarded",
            organization=organization,
            request=request,
            context={
                "company_name": getattr(organization, "name", "") or "your company",
                "router_name": router.name or "MikroTik",
                "join_code": getattr(organization, "join_code", "") or "",
            },
            subject=f"MikroTik onboarded — {router.name or 'router'}",
        )
    except Exception:
        logger.exception("Failed to dispatch MikroTik onboarded organization notification")

    if organization and getattr(organization, "referred_by_id", None):
        was_first = (
            MikroTikRouter.objects.filter(organization=organization)
            .exclude(pk=router.pk)
            .count()
            == 0
        )
        if was_first and organization.mark_referral_active():
            referrer = getattr(organization, "referred_by", None)
            if referrer is not None:
                from accounts.communications import notify_org_event, notify_platform_event

                ctx = {
                    "company_name": getattr(organization, "name", "") or "",
                    "referrer_name": getattr(referrer, "name", "") or "",
                }
                notify_org_event(
                    "isp_referral_active",
                    organization=referrer,
                    context=ctx,
                    subject="Referral became active",
                )
                notify_platform_event(
                    "platform_referral_active",
                    organization=organization,
                    context=ctx,
                    subject="Referral became active",
                )

    try:
        from core.hotspot_portal import public_base_url, remember_org_portal_base

        remember_org_portal_base(organization.pk, public_base_url(request))
    except Exception:
        pass

    schedule_post_onboard_nas_refresh(
        router,
        organization_id=organization.pk,
        user_id=getattr(request.user, "pk", None),
        tunnel=bool(tunnel_host),
    )

    return CommitResult(router=router, tunnel=bool(tunnel_host))
