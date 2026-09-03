"""Client (organization owner) workspace helpers and module pages."""

import gzip
import hashlib
import http.client
import json
import logging
import re
import ssl
import threading
import time
import zlib
from functools import wraps
from http.cookies import SimpleCookie
from urllib.parse import urlencode, urlsplit

from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.core.cache import cache
from django.core import signing
from django.core.paginator import Paginator
from django.db.models import Count, Q, Sum
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from accounts.communications import (
    CLIENT_COMMUNICATION_EVENTS,
    ISP_COMMUNICATION_EVENTS,
    fetch_provider_options,
)
from accounts.forms import (
    CommunicationSettingsForm,
    HotspotSettingsForm,
    OrganizationEditForm,
    OwnerProfileForm,
    PppoeSettingsForm,
)
from accounts.models import (
    ClientSettings,
    CommunicationSettings,
    Employee,
    NetworkEquipment,
    Organization,
    PaymentGateway,
)
from accounts.routing import (
    can_access_client_portal,
    can_switch_roles,
    get_client_view_organization,
    home_url_for_user,
    is_viewing_as_client,
)
from billing.forms import (
    CustomerCashRechargeForm,
    CustomerDetailsEditForm,
    PppoeClientRegisterForm,
)
from billing.models import AccessVoucher, BillingPlan, Customer, Invoice, Payment, StkPushRequest
from billing.services import (
    compute_package_end,
    customer_needs_nas_provision,
    customer_package_is_paused,
    customer_portal_access_context,
    customer_receives_internet,
    customer_subscription_expired,
    customers_needing_renewal_attention,
    package_remaining_seconds,
    pause_customer_package,
    plan_uses_clock_time,
    plans_for_router,
    recharge_customer_cash,
    resolve_lead_allocation_fee,
    resume_customer_package,
    subscription_access_deadline,
)
from billing.stk import (
    consume_mikrotik_onboarding_payment,
    refresh_stk_status,
    reverse_lead_allocation,
    start_lead_allocation_stk_payment,
    start_mikrotik_onboarding_stk_payment,
)
from core import wireguard
from core.subscription_sync import enqueue_customer_subscription_sync
from core.forms import (
    MikroTikCleanUplinkForm,
    MikroTikCredentialsForm,
    MikroTikEditDetailsForm,
    MikroTikOnboardForm,
    MikroTikSuspendForm,
    CustomerCpeAccessForm,
    MikroTikWifiSettingsForm,
    MikroTikWifiToggleForm,
)
from core.mikrotik_catalog import mikrotik_model_catalog, mikrotik_model_image
from core.mikrotik_connect import (
    BOND_MODES,
    DEFAULT_BOND_NAME,
    access_customer_cpe_wifi,
    apply_mikrotik_access_changes,
    change_mikrotik_lan_ip,
    is_transient_onboard_host,
    normalize_mikrotik_host,
    resolve_onboard_management_host,
    apply_unified_management_host,
    discover_local_mikrotik_host,
    pick_local_onboard_connect_host,
    finalize_onboard_addresses,
    suggest_unique_mikrotik_lan_ip,
    apply_mikrotik_uplink_bond,
    apply_mikrotik_uplink_failover,
    apply_mikrotik_uplink_balance,
    read_smart_balance_status,
    apply_mikrotik_single_wan,
    switch_mikrotik_single_wan,
    apply_pppoe_enforcement_on_router,
    apply_hotspot_on_router,
    check_mikrotik_reachable,
    clear_mikrotik_uplink_multi,
    customer_cpe_web_proxy,
    customer_cpe_access_eligible,
    customer_cpe_access_mode,
    customer_cpe_proxy_scope,
    dial_host,
    resolve_customer_cpe_target,
    probe_customer_cpe_web,
    probe_mikrotik_for_onboarding,
    login_customer_cpe_web_session,
    CPE_WEB_PORTS,
    mikrotik_probe_timeout,
    PPPOE_LOCAL_ADDRESS as MK_PPPOE_LOCAL_ADDRESS,
    configure_customer_cpe_web_wifi,
    configure_mikrotik_wifi,
    disconnect_hotspot_customer,
    fetch_active_pppoe_usernames,
    fetch_customer_cpe_web_data,
    fetch_customer_cpe_live_usage,
    fetch_customer_hotspot_usage,
    fetch_customer_pppoe_usage,
    fetch_hotspot_client_macs,
    fetch_mikrotik_live_snapshot_for_router,
    find_hotspot_router_for_mac,
    find_pppoe_customer_for_ip,
    list_mikrotik_ports,
    assess_uplink_switch_risk,
    assess_uplink_mode_apply_risk,
    assess_touch_ports_internet,
    assess_bond_members_readiness,
    assess_port_internet_readiness,
    build_uplink_recovery_script,
    check_router_tunnel_management,
    cpe_firewall_unlock_script,
    on_router_lan,
    prepare_customer_cpe_access,
    provision_customer_pppoe,
    provision_static_client_dhcp_lease,
    read_mikrotik_uplink_multi,
    read_client_wan_usage,
    build_wan_traffic_share,
    build_api_enable_terminal_script,
    build_single_wan_recovery_script,
    read_mikrotik_wifi,
    recover_mikrotik_connection,
    reconnect_after_uplink_apply,
    reboot_mikrotik,
    set_mikrotik_clean_uplink,
    set_mikrotik_port_enabled,
    sync_customer_subscription_access,
    test_mikrotik_api_login,
    toggle_mikrotik_port,
    toggle_mikrotik_wifi,
    _api_session,
    _ensure_hotspot_management_access,
    _router_api_host_candidates,
)
from core.mikrotik_jobs import (
    NAS_REFRESH_JOB,
    ensure_nas_refresh_job,
    get_job,
    get_router_jobs,
    schedule_mikrotik_job,
    schedule_nas_refresh,
    schedule_post_onboard_nas_refresh,
    set_job,
)
from core.mikrotik_discovery import annotate_onboarded, discover_mikrotik_devices, guess_model
from core.models import MikroTikRouter, WireGuardReservation
from core.places import resolve_location, search_locations


CLIENT_COMMON_NAV_START = [
    {"key": "workspace", "label": "Dashboard", "url_name": "core:workspace"},
]

CLIENT_COMMON_NAV_END = [
    {"key": "settings", "label": "System settings", "url_name": "core:system_settings"},
    {"key": "logout", "label": "Logout", "action": "logout"},
]

# Page-only sidebar links (shown between Dashboard and System settings).
CLIENT_SIDEBARS = {
    "workspace": {
        "label": "Workspace",
        "items": [
            {"key": "mikrotik", "label": "MikroTik", "url_name": "core:mikrotik"},
            {"key": "clients", "label": "My clients", "url_name": "core:my_clients"},
            {"key": "billing", "label": "Billings", "url_name": "billing:dashboard"},
            {"key": "account", "label": "My account", "url_name": "core:my_account"},
            {"key": "leads", "label": "Leads", "url_name": "core:leads"},
            {"key": "technicians", "label": "Technicians", "url_name": "core:technicians"},
            {"key": "shop", "label": "Shop", "url_name": "core:shop"},
            {"key": "referral", "label": "Referrals", "url_name": "core:referrals"},
        ],
    },
    "mikrotik": {
        "label": "MikroTik",
        "items": [
            {"key": "mikrotik", "label": "All routers", "url_name": "core:mikrotik"},
            {
                "key": "onboard",
                "label": "Connect to a New MikroTik",
                "action": "mikrotik_onboard",
            },
        ],
    },
    "mikrotik_detail": {
        "label": "MikroTik",
        "items": [
            {
                "key": "edit_details",
                "label": "Edit details",
                "action": "open_modal",
                "modal": "mikrotik-edit-modal",
            },
            {
                "key": "wifi_credentials",
                "label": "Wi‑Fi credentials",
                "action": "open_modal",
                "modal": "mikrotik-credentials-modal",
            },
            {
                "key": "toggle_wifi",
                "label": "Activate Wi‑Fi",
                "action": "open_modal",
                "modal": "mikrotik-wifi-modal",
            },
        ],
    },
    "clients": {
        "label": "My clients",
        "items": [
            {
                "key": "register_pppoe",
                "label": "Register PPPoE client",
                "action": "open_modal",
                "modal": "pppoe-register-modal",
            },
            {
                "key": "pending_activation",
                "label": "Pending activation",
                "url_name": "core:my_clients",
                "query": "tab=pppoe&view=pending",
            },
            {
                "key": "general_usage",
                "label": "General usage",
                "url_name": "core:clients_general_usage",
            },
            {
                "key": "clients_pppoe",
                "label": "View PPPoE clients",
                "url_name": "core:my_clients",
                "tab": "pppoe",
            },
            {
                "key": "clients_static",
                "label": "View static clients",
                "url_name": "core:my_clients",
                "tab": "static",
            },
            {
                "key": "clients_hotspot",
                "label": "View hotspot clients",
                "url_name": "core:my_clients",
                "tab": "hotspot",
            },
        ],
    },
    "client_detail": {
        "label": "Client",
        "items": [
            {"key": "clients", "label": "All clients", "url_name": "core:my_clients"},
            {"key": "usage", "label": "Usage analysis", "anchor": "client-usage"},
            {"key": "wifi", "label": "Wi‑Fi settings", "anchor": "client-wifi"},
            {
                "key": "package",
                "label": "Recharge account",
                "action": "open_modal",
                "modal": "client-recharge-modal",
            },
            {"key": "billing", "label": "Payments", "anchor": "client-billing"},
        ],
    },
    "billing": {
        "label": "Billings",
        "items": [
            {"key": "billing", "label": "Billing overview", "url_name": "billing:dashboard"},
            {
                "key": "leads_billing",
                "label": "Lead payments",
                "url_name": "billing:lead_payments",
            },
            {"key": "packages", "label": "Packages", "url_name": "billing:packages"},
            {
                "key": "register_package",
                "label": "Register package",
                "action": "open_modal",
                "modal": "billing-package-modal",
            },
        ],
    },
    "account": {
        "label": "My account",
        "items": [
            {
                "key": "account_profile",
                "label": "Company profile",
                "url_name": "core:my_account",
            },
            {
                "key": "account_payments",
                "label": "Packages",
                "url_name": "core:my_account_payments",
            },
            {
                "key": "account_communications",
                "label": "Communications",
                "url_name": "core:my_account_communications",
            },
        ],
    },
    "leads": {
        "label": "Leads",
        "items": [
            {"key": "leads", "label": "All leads", "url_name": "core:leads"},
            {
                "key": "leads_billing",
                "label": "Leads billing",
                "url_name": "billing:lead_payments",
            },
        ],
    },
    "technicians": {
        "label": "Technicians",
        "items": [
            {"key": "technicians", "label": "Technician team", "url_name": "core:technicians"},
        ],
    },
    "shop": {
        "label": "Shop",
        "items": [
            {"key": "shop", "label": "Shop", "url_name": "core:shop"},
        ],
    },
    "referral": {
        "label": "Referrals",
        "items": [
            {"key": "referral", "label": "My referral link", "url_name": "core:referrals"},
        ],
    },
    "settings": {
        "label": "My system settings",
        "items": [
            {
                "key": "company_settings",
                "label": "ISP Acc. Settings",
                "url_name": "core:system_settings",
            },
            {
                "key": "communications",
                "label": "Communication settings",
                "url_name": "core:settings_communications",
            },
            {
                "key": "stk_payment_settings",
                "label": "STK Payment Settings",
                "url_name": "core:settings_payments",
            },
        ],
    },
}


def resolve_organization(user, request=None):
    """Resolve the active organization once per request when possible."""
    if request is not None and getattr(request, "_resolved_organization_done", False):
        return getattr(request, "_resolved_organization", None)

    org = None
    if request is not None:
        employee = getattr(user, "employee_profile", None)
        client_org = get_client_view_organization(request, employee)
        if client_org is not None:
            org = client_org

    if org is None:
        org = Organization.objects.filter(owner=user).first()
    if org is None:
        profile = getattr(user, "employee_profile", None)
        if profile:
            org = profile.organization

    if request is not None:
        request._resolved_organization = org
        request._resolved_organization_done = True
    return org


def client_workspace_required(view_func):
    """Allow organization owners and staff client-view sessions."""

    @wraps(view_func)
    @login_required
    def _wrapped(request, *args, **kwargs):
        employee = getattr(request.user, "employee_profile", None)
        viewing_client = bool(employee and is_viewing_as_client(request, employee))
        if employee is not None and not viewing_client:
            return redirect(home_url_for_user(request.user, request))
        return view_func(request, *args, **kwargs)

    return _wrapped


def _background_mikrotik_ops() -> bool:
    """Heavy RouterOS pushes run in the background on hosted servers."""
    return bool(getattr(settings, "HOSTED", False))


def _router_api_host(router) -> str:
    """Dial address for NAS API — LAN host locally, WireGuard when hosted."""
    raw = (getattr(router, "api_host", None) or getattr(router, "host", None) or "").strip()
    try:
        return dial_host(raw) or raw
    except Exception:
        return raw


def _router_uses_tunnel(router) -> bool:
    tunnel = (getattr(router, "vpn_address", None) or "").strip()
    if tunnel:
        return True
    host = (getattr(router, "host", None) or getattr(router, "api_host", None) or "").strip()
    try:
        from core.mikrotik_connect import _is_wireguard_tunnel_host

        return _is_wireguard_tunnel_host(host)
    except Exception:
        return host.startswith("10.9.")


def _router_tunnel_cache_key(router) -> str:
    tunnel = (getattr(router, "vpn_address", None) or "").strip()
    if not tunnel:
        host = (getattr(router, "host", None) or "").strip()
        try:
            from core.mikrotik_connect import _is_wireguard_tunnel_host

            if _is_wireguard_tunnel_host(host):
                tunnel = host
        except Exception:
            tunnel = ""
    return f"mikrotik_tunnel_ok:{getattr(router, 'pk', 0)}:{tunnel or 'none'}"


def _clear_router_tunnel_cache(router) -> None:
    cache.delete(_router_tunnel_cache_key(router))


def _wan_rollback_cache_key(router_pk: int) -> str:
    return f"mikrotik_wan_rollback:{router_pk}"


def _build_wan_rollback_script(old_wan: str, new_wan: str = "") -> str:
    """RouterOS script to undo a single-WAN port switch (restore the previous Internet port)."""
    old_wan = (old_wan or "").strip()
    new_wan = (new_wan or "").strip()
    if not old_wan:
        return ""
    retire = [new_wan] if new_wan and new_wan != old_wan else []
    return build_single_wan_recovery_script(old_wan, retire_ports=retire)


def _store_wan_switch_rollback(
    router: MikroTikRouter, *, old_wan: str, new_wan: str
) -> None:
    old_wan = (old_wan or "").strip()
    new_wan = (new_wan or "").strip()
    if not old_wan or not new_wan or old_wan == new_wan:
        return
    script = _build_wan_rollback_script(old_wan, new_wan)
    if not script:
        return
    cache.set(
        _wan_rollback_cache_key(router.pk),
        {
            "old_wan": old_wan,
            "new_wan": new_wan,
            "rollback_script": script,
        },
        3600,
    )


def _wan_switch_rollback_payload(router: MikroTikRouter) -> dict | None:
    data = cache.get(_wan_rollback_cache_key(router.pk))
    if not isinstance(data, dict):
        return None
    old_wan = (data.get("old_wan") or "").strip()
    script = (data.get("rollback_script") or "").strip()
    if not old_wan or not script:
        return None
    return {
        "old_wan": old_wan,
        "new_wan": (data.get("new_wan") or "").strip(),
        "rollback_script": script,
    }


def _router_tunnel_verified(router, *, force: bool = False) -> bool:
    """Live check: WireGuard peer answers API (or recent handshake on hosted)."""
    tunnel = (getattr(router, "vpn_address", None) or "").strip()
    if not tunnel:
        host = (getattr(router, "host", None) or "").strip()
        try:
            from core.mikrotik_connect import _is_wireguard_tunnel_host

            if not _is_wireguard_tunnel_host(host):
                return False
        except Exception:
            return False
    cache_key = _router_tunnel_cache_key(router)
    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            return bool(cached)
    try:
        result = check_router_tunnel_management(router, timeout=3.0)
        verified = bool(result.get("verified"))
    except Exception:
        verified = False
    cache.set(cache_key, verified, 45 if verified else 8)
    return verified


def _uplink_api_hosts_for_router(router) -> list[str]:
    """Prefer WireGuard, then LAN host, for phased uplink apply reconnect."""
    hosts: list[str] = []
    for raw in (
        (getattr(router, "vpn_address", None) or "").strip(),
        _router_api_host(router),
        (getattr(router, "host", None) or "").strip(),
    ):
        value = (raw or "").strip()
        if value and value not in hosts:
            hosts.append(value)
    return hosts


def _finalize_uplink_apply_result(router: MikroTikRouter, result: dict) -> dict:
    """After bond/failover/balance, reconnect API and attach recovery script."""
    result = dict(result or {})
    if not result.get("recovery_script"):
        mode = (result.get("mode") or "").strip() or "uplink"
        members = list(result.get("members") or result.get("ports") or [])
        result["recovery_script"] = build_uplink_recovery_script(
            mode,
            members=members,
            bond_name=(result.get("bond_name") or getattr(router, "bond_interface", "") or ""),
            unbridged=result.get("unbridged") or [],
            primary_port=(result.get("primary") or result.get("wan_interface") or ""),
        )
    if not result.get("ok"):
        return result
    try:
        reconnect = reconnect_after_uplink_apply(router)
    except Exception as exc:
        reconnect = {"ok": False, "error": str(exc)}
    result["reconnect"] = reconnect
    if reconnect.get("ok") and reconnect.get("host"):
        dial = (reconnect.get("host") or "").strip()
        tunnel = (getattr(router, "vpn_address", None) or "").strip()
        result["management_host"] = dial
        if dial and dial == tunnel:
            cache.set(f"mikrotik_tunnel_ok:{router.pk}:{tunnel}", True, 120)
            # Hosted billing should dial the tunnel; keep LAN host on local PC.
            if not on_router_lan() and (router.host or "").strip() != dial:
                router.host = dial
                try:
                    router.save(update_fields=["host", "updated_at"])
                except Exception:
                    pass
    elif result.get("ok"):
        # Apply succeeded on the router but we cannot dial yet — keep OK with note.
        note = (
            " Uplink applied on the MikroTik; reconnecting over WireGuard/LAN…"
            if (router.vpn_address or "").strip()
            else " Uplink applied; if the page loses contact, use the Winbox recovery script."
        )
        result["message"] = (result.get("message") or "").rstrip() + note
    return result


def _cpe_router_failure_class(probe: dict | None = None, *, nas_ok: bool = True) -> str:
    """Map probe/NAS outcome to a stable UI failure class."""
    if not nas_ok:
        return "nas_down"
    probe = probe or {}
    if probe.get("ok"):
        return "ok"
    if not probe.get("session_active"):
        return "offline"
    if probe.get("ping_ok"):
        if probe.get("api_ok"):
            return "web_blocked"
        return "wan_mgmt_blocked"
    return "unreachable"


def _cpe_router_guidance(
    *,
    failure_class: str,
    access_mode: str = "",
    gateway: str = "",
    nas_name: str = "",
    via_tunnel: bool = False,
    detail: str = "",
) -> list[str]:
    """Operator steps for each remote-access failure class."""
    gateway = (gateway or MK_PPPOE_LOCAL_ADDRESS).strip() or MK_PPPOE_LOCAL_ADDRESS
    nas = (nas_name or "the ISP MikroTik").strip()
    mode = (access_mode or "pppoe").strip().lower()
    fc = (failure_class or "").strip().lower()

    if fc == "nas_down":
        steps = [
            f"The billing server cannot reach {nas} right now.",
        ]
        if via_tunnel:
            steps.extend(
                [
                    "Confirm the WireGuard tunnel is up (MikroTik page → tunnel / Reconnect).",
                    "On the MikroTik, paste the ISPCENTRIC tunnel script if the peer never connected.",
                    "On the VPS, confirm the peer is on wg0 (`wg show`) and has a recent handshake.",
                ]
            )
        else:
            steps.extend(
                [
                    "Confirm this PC/server can reach the MikroTik LAN (or set a WireGuard tunnel address).",
                    "Open the MikroTik page and use Reconnect / Check now.",
                ]
            )
        if detail:
            steps.append(detail)
        return steps

    if fc == "offline":
        if mode == "dhcp":
            return [
                "Confirm the client router has an active DHCP lease on the ISP LAN.",
                "Power-cycle the client router, wait for it to come online, then retry.",
            ]
        if mode == "static":
            return [
                "Confirm the saved router IP is online on the ISP LAN.",
                "Power-cycle the client router, then retry.",
            ]
        return [
            "Confirm the client is online on PPPoE.",
            "Power-cycle the client router, wait for PPPoE to dial, then retry.",
        ]

    if fc == "wan_mgmt_blocked":
        return [
            "Open the router admin page from the client’s own Wi‑Fi/LAN.",
            "Enable Remote / WAN Web Management (Tenda: Administration).",
            f"If it asks for an allowed address, use the ISP gateway {gateway}.",
            "Save, then retry from this page.",
        ]

    if fc == "web_blocked":
        return [
            "MikroTik API is reachable. Retry once — WebFig sometimes needs a few seconds after enable.",
            "In Winbox → IP → Services, confirm www is enabled and not limited to the LAN subnet only.",
        ]

    if fc == "unreachable":
        return [
            f"Confirm the client router is powered on and reachable from {gateway}.",
            "Retry after the session comes up.",
        ]

    if fc == "needs_password":
        return [
            "Enter the client router’s admin password below (not the PPPoE password).",
            "Save & connect — it will be stored on this client for next time.",
        ]

    return [detail] if detail else []


def _mikrotik_live_cache_key(org_pk: int, router_pk: int) -> str:
    return f"mikrotik_live:{org_pk}:{router_pk}"


def _cached_mikrotik_live_snapshot(org_pk: int, router_pk: int) -> dict | None:
    """Last live snapshot from cache — no RouterOS API call."""
    cached = cache.get(_mikrotik_live_cache_key(org_pk, router_pk))
    if cached is None:
        return None
    return dict(cached)


def _apply_remote_live_fallback(router, org, failed: dict) -> dict:
    """
    When the router is tunnel-managed on the VPS but this PC cannot dial it,
    return cached read-only data plus a hosted dashboard link for real control.
    """
    from core.mikrotik_connect import (
        hosted_dashboard_url,
        resolve_router_management_mode,
    )

    if failed.get("ok"):
        return failed
    if resolve_router_management_mode(router) != "remote_only":
        return failed

    hosted = hosted_dashboard_url()
    deferred_reason = (
        "This PC is off the router LAN and cannot open the WireGuard tunnel. "
        "The router stays online — open the hosted ISPCENTRIC dashboard to "
        "change settings, push Hotspot/PPPoE, and reconnect."
    )
    if hosted:
        deferred_reason += f" Manage at {hosted}"

    cached = _cached_mikrotik_live_snapshot(org.pk, router.pk)
    base = dict(cached) if cached and cached.get("ok") else {
        "identity": router.name,
        "board": "",
        "serial_number": router.serial_number or "",
        "software_id": router.software_id or "",
        "version": "",
        "uptime": "—",
        "cpu_load": None,
        "memory_used_pct": None,
        "memory_free": "—",
        "memory_total": "—",
        "ports_up": None,
        "ports_total": None,
        "online_users": None,
        "pppoe_active": 0,
        "hotspot_active": 0,
        "wifi_label": "—",
        "wan_summary": "Router is online on WireGuard — use the hosted dashboard to control it.",
    }
    out = {
        **base,
        "ok": True,
        "online": True,
        "remote_management_only": True,
        "management_deferred": True,
        "controls_live": False,
        "remote_manage_url": hosted,
        "deferred_reason": deferred_reason,
        "router_id": router.pk,
        "host": router.host,
        "api_host": (router.api_host or router.host or "").strip(),
        "management_mode": "remote_only",
    }
    return out


def _remote_management_only_response(router):
    """Block router control actions when this PC must use the hosted dashboard."""
    from core.mikrotik_connect import hosted_dashboard_url, resolve_router_management_mode

    if resolve_router_management_mode(router) != "remote_only":
        return None
    hosted = hosted_dashboard_url()
    message = (
        "This PC is off the router LAN and cannot open the WireGuard tunnel. "
        "Open the hosted ISPCENTRIC dashboard to control this MikroTik."
    )
    if hosted:
        message += f" Manage at {hosted}"
    return JsonResponse(
        {
            "ok": False,
            "error": message,
            "remote_management_only": True,
            "remote_manage_url": hosted,
        },
        status=409,
    )


def _invalidate_mikrotik_router_caches(org_pk: int, router_pk: int) -> None:
    cache.delete_many(
        [
            f"mikrotik_status:{org_pk}",
            _mikrotik_live_cache_key(org_pk, router_pk),
            _wifi_fields_cache_key(org_pk, router_pk),
            f"mikrotik_ports_live:{org_pk}:{router_pk}",
            f"mikrotik_discover:{org_pk}:quick",
            f"mikrotik_discover:{org_pk}:full",
        ]
    )


def _mikrotik_status_cache_ttl(all_connected: bool) -> int:
    if getattr(settings, "HOSTED", False):
        return 20 if all_connected else 15
    return 5 if all_connected else 3


def _redirect_with_mikrotik_job(request, url_name: str, router_id: int, job_type: str):
    from django.http import HttpResponseRedirect

    base = reverse(url_name, kwargs={"router_id": router_id})
    return HttpResponseRedirect(f"{base}?job={job_type}")


def build_client_nav(active_nav: str, *, referral_enabled: bool = False) -> dict:
    """Dashboard at top, page links in the middle, settings + logout at the bottom."""
    sidebar = CLIENT_SIDEBARS.get(active_nav, CLIENT_SIDEBARS["workspace"])
    reserved = {"workspace", "settings", "logout"}
    page_items = []
    for item in sidebar.get("items", []):
        if item.get("key") in reserved:
            continue
        if item.get("key") == "referral" and not referral_enabled:
            continue
        row = dict(item)
        if row.get("url_name") and row.get("query") and not row.get("href"):
            try:
                row["href"] = f"{reverse(row['url_name'])}?{row['query']}"
            except Exception:  # noqa: BLE001 — keep plain url_name fallback
                pass
        elif row.get("url_name") and row.get("tab") and not row.get("href"):
            try:
                row["href"] = f"{reverse(row['url_name'])}?tab={row['tab']}"
            except Exception:  # noqa: BLE001 — keep plain url_name fallback
                pass
        elif row.get("url_name") and row.get("anchor") and not row.get("href"):
            try:
                row["href"] = f"{reverse(row['url_name'])}#{row['anchor']}"
            except Exception:  # noqa: BLE001 — keep plain url_name fallback
                pass
        page_items.append(row)
    return {
        "main": [
            *CLIENT_COMMON_NAV_START,
            *page_items,
        ],
        "end": list(CLIENT_COMMON_NAV_END),
    }


def _mikrotik_login_credentials_changed(router: MikroTikRouter, cleaned: dict) -> bool:
    return (
        (cleaned.get("host") or "").strip() != (router.host or "").strip()
        or (cleaned.get("username") or "").strip() != (router.username or "").strip()
        or (cleaned.get("password") or "") != (router.password or "")
    )


def _apply_mikrotik_login_credentials(
    router: MikroTikRouter,
    org,
    *,
    new_host: str,
    new_username: str,
    new_password: str,
) -> dict:
    """Push login credential changes to the live router and update the saved record."""
    current_host = router.host
    current_username = router.username
    current_password = router.password
    current_wifi_ssid = router.wifi_ssid or ""
    current_wifi_password = router.wifi_password or ""

    result = apply_mikrotik_access_changes(
        current_host=current_host,
        current_username=current_username,
        current_password=current_password,
        current_wifi_ssid=current_wifi_ssid,
        current_wifi_password=current_wifi_password,
        new_host=new_host,
        new_username=new_username,
        new_password=new_password,
        new_wifi_ssid=current_wifi_ssid,
        new_wifi_password=current_wifi_password,
    )
    if result.get("ok"):
        live = MikroTikRouter.objects.get(pk=router.pk)
        live.host = new_host or live.host
        live.username = new_username or live.username
        live.password = new_password or live.password
        live.save(
            update_fields=[
                "host",
                "username",
                "password",
                "updated_at",
            ]
        )
        _invalidate_mikrotik_router_caches(org.pk, router.pk)
    return result


def _schedule_mikrotik_login_credentials(
    request,
    router: MikroTikRouter,
    org,
    *,
    new_host: str,
    new_username: str,
    new_password: str,
    redirect_url_name: str,
):
    """Apply login credential changes in the background."""
    set_job(router.pk, "credentials", "pending")

    def _apply_login():
        return _apply_mikrotik_login_credentials(
            router,
            org,
            new_host=new_host,
            new_username=new_username,
            new_password=new_password,
        )

    schedule_mikrotik_job(
        _apply_login,
        name=f"credentials-{router.pk}",
        router_id=router.pk,
        job_type="credentials",
    )
    messages.success(
        request,
        "Updating login credentials on the MikroTik in the background. "
        "This page will show progress shortly.",
    )
    return _redirect_with_mikrotik_job(request, redirect_url_name, router.pk, "credentials")


def build_mikrotik_detail_nav(
    router: MikroTikRouter,
    *,
    wifi_enabled: bool = False,
    clean_uplink_enabled: bool = False,
    is_suspended: bool = False,
    include_modals: bool = True,
) -> list[dict]:
    """Sidebar items for a single router (overview + ports + access + optional modal actions)."""
    detail_url = reverse("core:mikrotik_detail", kwargs={"router_id": router.pk})
    ports_url = reverse("core:mikrotik_ports", kwargs={"router_id": router.pk})
    assigned_ports_url = reverse(
        "core:mikrotik_assigned_ports", kwargs={"router_id": router.pk}
    )
    access_url = reverse("core:mikrotik_pppoe_settings", kwargs={"router_id": router.pk})
    clean_url = reverse("core:mikrotik_clean_uplink", kwargs={"router_id": router.pk})
    nav: list[dict] = [
        {"key": "overview", "label": "Router overview", "href": detail_url},
        {"key": "ports", "label": "Port setup", "href": ports_url},
        {"key": "assigned_ports", "label": "Assigned ports", "href": assigned_ports_url},
        {
            "key": "pppoe_hotspot_settings",
            "label": "PPPoE & Hotspot settings",
            "href": access_url,
        },
        {"key": "clean_uplink", "label": "Clean uplink", "href": clean_url},
    ]
    if not include_modals:
        return nav

    for item in CLIENT_SIDEBARS["mikrotik_detail"]["items"]:
        if item.get("key") == "ports":
            continue
        row = dict(item)
        if row.get("key") == "toggle_wifi":
            row["label"] = "Deactivate Wi‑Fi" if wifi_enabled else "Activate Wi‑Fi"
        nav.append(row)
    return nav


def apply_mikrotik_detail_sidebar(ctx: dict, router: MikroTikRouter, *, detail_nav: list[dict]) -> dict:
    """Replace middle nav with router detail links (keep Dashboard + settings/logout)."""
    ctx["client_nav_main"] = [
        *CLIENT_COMMON_NAV_START,
        *detail_nav,
    ]
    ctx["sidebar_label"] = router.name or "MikroTik"
    ctx["router"] = router
    return ctx


@client_workspace_required
@require_GET
def mikrotik_assigned_ports(request, router_id: int):
    """Live router ISP analysis and per-client WAN mapping for this MikroTik."""
    org = resolve_organization(request.user, request)
    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect("core:mikrotik")

    router = get_object_or_404(MikroTikRouter, pk=router_id, organization=org)
    is_suspended = router.account_status == MikroTikRouter.AccountStatus.SUSPENDED
    detail_nav = build_mikrotik_detail_nav(
        router,
        is_suspended=is_suspended,
        include_modals=False,
    )
    uplink_mode = router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE
    ctx = client_page_context(
        request,
        active_nav="mikrotik_detail",
        sidebar_active="assigned_ports",
        page_title=f"{router.name} — Assigned ports",
        page_subtitle="Live ISP analysis and which internet link each customer is using.",
        router=router,
        ports_loading=not is_suspended,
        ports_live_url=(
            reverse("core:mikrotik_ports_live", args=[router.pk]) if not is_suspended else ""
        ),
        is_suspended=is_suspended,
        uplink_mode=uplink_mode,
        uplink_mode_label=dict(MikroTikRouter.UplinkMode.choices).get(
            uplink_mode, "Single WAN"
        ),
        mikrotik_quicknav_active="assigned_ports",
    )
    return render(
        request,
        "core/mikrotik_assigned_ports.html",
        apply_mikrotik_detail_sidebar(ctx, router, detail_nav=detail_nav),
    )


def get_org_router(request, router_id: int):
    """Return (org, router) for the active workspace, or (org, None)."""
    org = resolve_organization(request.user, request)
    if not org:
        return None, None
    router = (
        MikroTikRouter.objects.filter(pk=router_id, organization=org)
        .only(
            "id",
            "name",
            "host",
            "username",
            "password",
            "lan_bridge",
            "wan_interface",
            "organization_id",
            "account_status",
            "model",
            "wifi_ssid",
            "wifi_password",
            "clean_uplink_enabled",
        )
        .first()
    )
    return org, router


def customer_supports_live_usage(customer) -> bool:
    """Whether this client can show live NAS usage (PPPoE session or Hotspot MAC)."""
    if customer.service_type == Customer.ServiceType.PPPOE:
        return bool(customer.router_id and customer.pppoe_username)
    if customer.service_type == Customer.ServiceType.HOTSPOT:
        if (customer.hotspot_mac or "").strip():
            return True
        try:
            from billing.devices import hotspot_macs_for_customer

            return bool(hotspot_macs_for_customer(customer))
        except Exception:
            return False
    return False


def customer_can_pause_package(customer) -> bool:
    """Whether the subscriber's active package can be paused."""
    return bool(
        customer.package_end
        and not customer_package_is_paused(customer)
        and not customer_subscription_expired(customer)
        and customer.status == Customer.Status.ACTIVE
    )


def customer_can_resume_package(customer) -> bool:
    """Whether a paused package can be resumed."""
    return customer_package_is_paused(customer)


def resolve_client_usage_router(customer, org=None):
    """MikroTik to query for this client's live usage."""
    router = getattr(customer, "router", None)
    if router is not None and router.account_status != MikroTikRouter.AccountStatus.SUSPENDED:
        return router
    if customer.service_type != Customer.ServiceType.HOTSPOT:
        return None
    organization = org or getattr(customer, "organization", None)
    macs: list[str] = []
    primary = (customer.hotspot_mac or "").strip()
    if primary:
        macs.append(primary)
    try:
        from billing.devices import hotspot_macs_for_customer

        for mac in hotspot_macs_for_customer(customer):
            if mac and mac not in macs:
                macs.append(mac)
    except Exception:
        pass
    for mac in macs:
        found = find_hotspot_router_for_mac(organization, mac)
        if found is not None and found.account_status != MikroTikRouter.AccountStatus.SUSPENDED:
            return found
    # Only fall back when the org has a single active router — guessing among
    # many NASes silently probes the wrong box and records empty usage.
    active = list(
        MikroTikRouter.objects.filter(
            organization=organization,
            account_status=MikroTikRouter.AccountStatus.ACTIVE,
        ).order_by("id")[:2]
    )
    if len(active) == 1:
        return active[0]
    return None


def _hotspot_macs_for_usage(customer) -> list[str]:
    """MACs to probe for Hotspot live usage (primary first)."""
    seen: set[str] = set()
    out: list[str] = []

    def _add(raw: str) -> None:
        compact = "".join(ch for ch in (raw or "") if ch.isalnum()).upper()
        if len(compact) != 12 or compact in seen:
            return
        seen.add(compact)
        out.append(raw.strip())

    _add(getattr(customer, "hotspot_mac", "") or "")
    try:
        from billing.devices import hotspot_macs_for_customer

        for mac in hotspot_macs_for_customer(customer):
            _add(mac)
    except Exception:
        pass
    return out


def _usage_bytes_label(num: int) -> str:
    n = max(0, int(num or 0))
    if n >= 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024 * 1024):.2f} GB"
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.2f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def _usage_bps_label(bps: int | float | None) -> str:
    n = max(0, int(bps or 0))
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f} Mbps"
    if n >= 1000:
        return f"{n / 1000:.1f} Kbps"
    return f"{n} bps"


def build_client_detail_nav(customer, *, can_access_wifi: bool = False) -> list[dict]:
    """Sidebar items for a single client (navigation only — actions live on the detail page)."""
    nav: list[dict] = [
        {
            "key": "overview",
            "label": "Client overview",
            "href": reverse("core:client_detail", kwargs={"customer_id": customer.pk}),
        },
        {
            "key": "billing",
            "label": "Client billing",
            "href": reverse(
                "core:client_billing",
                kwargs={"customer_id": customer.pk},
            ),
        },
    ]
    if customer_supports_live_usage(customer):
        nav.append(
            {
                "key": "usage",
                "label": "Client usage",
                "href": reverse(
                    "core:client_usage_analysis",
                    kwargs={"customer_id": customer.pk},
                ),
            }
        )
    if can_access_wifi:
        nav.append(
            {
                "key": "router_wifi",
                "label": "Router & Wi‑Fi",
                "href": reverse(
                    "core:client_wifi_settings",
                    kwargs={"customer_id": customer.pk},
                ),
            }
        )
    nav.append(
        {
            "key": "clients",
            "label": "All clients",
            "href": f"{reverse('core:my_clients')}?tab={customer.service_type}",
        }
    )
    return nav


def customer_can_access_router(customer, org=None) -> bool:
    """True when this client supports remote router / CPE Wi‑Fi management."""
    return bool(org and customer_cpe_access_eligible(customer))


def apply_client_shared_forms(ctx: dict, customer, org) -> dict:
    """Attach shared client edit forms used by sidebar modals."""
    ctx["details_form"] = CustomerDetailsEditForm(
        instance=customer, organization=org
    )
    ctx.setdefault("open_client_modal", "")
    return ctx


def resolve_port_role(router: MikroTikRouter, port_name: str) -> str:
    """Return stored role for a port, defaulting WAN from wan_interface / uplink mode."""
    roles = router.port_roles if isinstance(router.port_roles, dict) else {}
    stored = (roles.get(port_name) or "").strip().lower()
    valid = {choice.value for choice in MikroTikRouter.PortRole}
    if stored == MikroTikRouter.PortRole.WAN_PRIMARY:
        return MikroTikRouter.PortRole.WAN
    if stored in valid and stored != MikroTikRouter.PortRole.NONE:
        return stored

    uplink_ports = router.uplink_ports if isinstance(router.uplink_ports, list) else []
    uplink_ports = [str(p).strip() for p in uplink_ports if str(p).strip()]
    mode = (router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE).strip()

    if mode == MikroTikRouter.UplinkMode.BOND and port_name in uplink_ports:
        return MikroTikRouter.PortRole.BOND
    if mode in {
        MikroTikRouter.UplinkMode.FAILOVER,
        *_weighted_share_uplink_modes(),
    } and uplink_ports:
        if port_name == uplink_ports[0]:
            return MikroTikRouter.PortRole.WAN
        if port_name in uplink_ports[1:]:
            return MikroTikRouter.PortRole.WAN_BACKUP
    if port_name == (router.wan_interface or "").strip():
        return MikroTikRouter.PortRole.WAN
    return MikroTikRouter.PortRole.NONE


def _is_primary_wan_role(role: str) -> bool:
    return (role or "").strip().lower() in {
        MikroTikRouter.PortRole.WAN,
        MikroTikRouter.PortRole.WAN_PRIMARY,
    }


def resolve_wan_speed_interfaces(router: MikroTikRouter) -> list[dict]:
    """Ordered WAN ports to monitor for live download/upload speeds."""
    uplink_ports = router.uplink_ports if isinstance(router.uplink_ports, list) else []
    uplink_ports = [str(p).strip() for p in uplink_ports if str(p).strip()]
    mode = (router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE).strip()
    roles = router.port_roles if isinstance(router.port_roles, dict) else {}
    wan_iface = (router.wan_interface or "").strip()

    if mode == MikroTikRouter.UplinkMode.BOND:
        bond_name = (router.bond_interface or "bond-wan").strip() or "bond-wan"
        return [
            {
                "role": "primary",
                "interface": bond_name,
                "label": f"Bonded WAN · {bond_name}",
            }
        ]

    primary = ""
    secondary = ""
    extra_balance_ports: list[str] = []
    if mode in {
        MikroTikRouter.UplinkMode.FAILOVER,
        *_weighted_share_uplink_modes(),
    } and uplink_ports:
        primary = uplink_ports[0]
        if len(uplink_ports) > 1:
            secondary = uplink_ports[1]
        if _is_weighted_share_mode(mode) and len(uplink_ports) > 2:
            extra_balance_ports = [
                str(p).strip() for p in uplink_ports[2:] if str(p).strip()
            ]
    else:
        for name, role in roles.items():
            port_name = str(name or "").strip()
            if not port_name:
                continue
            normalized = str(role or "").strip().lower()
            if _is_primary_wan_role(normalized) and not primary:
                primary = port_name
            elif (
                normalized == MikroTikRouter.PortRole.WAN_BACKUP
                and not secondary
                and port_name != primary
            ):
                secondary = port_name
        if not primary and uplink_ports:
            primary = uplink_ports[0]
            if len(uplink_ports) > 1:
                secondary = uplink_ports[1]
        if not primary and wan_iface:
            primary = wan_iface

    ports: list[dict] = []
    if primary:
        ports.append(
            {
                "role": "primary",
                "interface": primary,
                "label": (
                    f"Balanced WAN · {primary}"
                    if _is_weighted_share_mode(mode)
                    else f"Primary WAN · {primary}"
                ),
            }
        )
    if secondary and secondary != primary:
        ports.append(
            {
                "role": "secondary",
                "interface": secondary,
                "label": (
                    f"Balanced WAN · {secondary}"
                    if _is_weighted_share_mode(mode)
                    else f"Secondary WAN · {secondary}"
                ),
            }
        )
    for name in extra_balance_ports:
        if name in {primary, secondary}:
            continue
        ports.append(
            {
                "role": "secondary",
                "interface": name,
                "label": f"Balanced WAN · {name}",
            }
        )
    return ports


def _weighted_share_uplink_modes() -> set[str]:
    return {
        MikroTikRouter.UplinkMode.BALANCE,
        MikroTikRouter.UplinkMode.SMART_BALANCE,
    }


def _is_weighted_share_mode(mode: str) -> bool:
    return (mode or "").strip() in _weighted_share_uplink_modes()


def _failover_active_wan_port(
    uplink_live: dict,
    *,
    primary_wan_ports: list[str],
    backup_wan_ports: list[str],
) -> str:
    """Best-effort map of the live failover default route to a physical WAN port."""
    checked = uplink_live.get("checked_routes") or []
    clients = uplink_live.get("failover_clients") or []
    active_route = next(
        (row for row in checked if row.get("active") and not row.get("disabled")),
        None,
    )
    if active_route and clients:
        dist = str(active_route.get("distance") or "1")
        for client in clients:
            if client.get("disabled"):
                continue
            if str(client.get("distance") or "1") == dist:
                return (client.get("interface") or "").strip()
    for client in clients:
        if not client.get("disabled"):
            return (client.get("interface") or "").strip()
    if primary_wan_ports:
        return str(primary_wan_ports[0]).strip()
    if backup_wan_ports:
        return str(backup_wan_ports[0]).strip()
    return ""


def _mac_compact_key(mac: str) -> str:
    return "".join(ch for ch in (mac or "").lower() if ch.isalnum())


def _build_router_client_analysis(
    router: MikroTikRouter,
    *,
    uplink_mode: str,
    uplink_live: dict,
    wan_share: dict,
    smart_balance_status: dict,
    primary_wan_ports: list[str],
    backup_wan_ports: list[str],
    usage: dict,
) -> dict:
    """Merge billing customers with live WAN usage for the ports page."""
    from billing.models import Customer

    mode = (uplink_mode or MikroTikRouter.UplinkMode.SINGLE).strip()
    member_ports = [
        str(p).strip()
        for p in (
            list(router.uplink_ports or [])
            or list(primary_wan_ports) + list(backup_wan_ports)
        )
        if str(p).strip()
    ]
    weights = (
        dict(router.uplink_weights)
        if isinstance(router.uplink_weights, dict)
        else {}
    )
    share_by_port = {
        (row.get("name") or "").strip(): row
        for row in (wan_share.get("shares") or [])
        if (row.get("name") or "").strip()
    }
    slow_ports = set(
        str(p).strip()
        for p in (smart_balance_status.get("slow_ports") or [])
        if str(p).strip()
    )
    member_status = smart_balance_status.get("members") or {}

    def _isp_label(port_name: str, index: int) -> str:
        port_name = (port_name or "").strip()
        if not port_name:
            return "Unknown"
        if len(member_ports) > 1:
            return f"ISP {index + 1} · {port_name}"
        return port_name

    isps: list[dict] = []
    for index, port_name in enumerate(member_ports):
        share_row = share_by_port.get(port_name) or {}
        weight = weights.get(port_name) or weights.get(str(port_name))
        status = "active"
        member_row = member_status.get(port_name) or {}
        if port_name in slow_ports or member_row.get("slow"):
            status = "slow"
        elif member_row.get("disabled") or member_row.get("sidelined"):
            status = "sidelined"
        isps.append(
            {
                "port": port_name,
                "label": _isp_label(port_name, index),
                "weight": weight,
                "share_pct": share_row.get("pct"),
                "rate_label": share_row.get("rate_label") or "—",
                "status": status,
                "client_count": 0,
                "connection_count": 0,
            }
        )
    if not isps:
        fallback_port = (
            (primary_wan_ports[0] if primary_wan_ports else "")
            or (router.wan_interface or "")
        ).strip()
        if fallback_port:
            share_row = share_by_port.get(fallback_port) or {}
            isps.append(
                {
                    "port": fallback_port,
                    "label": _isp_label(fallback_port, 0),
                    "weight": weights.get(fallback_port),
                    "share_pct": share_row.get("pct"),
                    "rate_label": share_row.get("rate_label") or "—",
                    "status": "active",
                    "client_count": 0,
                    "connection_count": 0,
                }
            )
    isp_by_port = {row["port"]: row for row in isps}

    ip_usage = usage.get("ip_usage") if isinstance(usage.get("ip_usage"), dict) else {}
    sessions = usage.get("sessions") if isinstance(usage.get("sessions"), dict) else {}
    default_isp = (usage.get("default_isp_port") or "").strip()

    customers = list(
        Customer.objects.filter(router=router).only(
            "pk",
            "full_name",
            "account_number",
            "pppoe_username",
            "hotspot_mac",
            "cpe_ip",
            "cpe_mac",
            "service_type",
            "status",
        )
    )

    ip_to_customer: dict[str, Customer] = {}
    username_to_customer = {
        (c.pppoe_username or "").strip().lower(): c
        for c in customers
        if (c.pppoe_username or "").strip()
    }
    mac_to_customer = {
        _mac_compact_key(c.hotspot_mac or c.cpe_mac or ""): c
        for c in customers
        if _mac_compact_key(c.hotspot_mac or c.cpe_mac or "")
    }
    for customer in customers:
        static_ip = (customer.cpe_ip or "").strip()
        if static_ip:
            ip_to_customer[_parse_connection_address(static_ip)] = customer

    for ip, session in sessions.items():
        if ip in ip_to_customer:
            continue
        username = (session.get("pppoe_username") or "").strip().lower()
        if username and username in username_to_customer:
            ip_to_customer[ip] = username_to_customer[username]
            continue
        mac = _mac_compact_key(session.get("mac") or "")
        if mac and mac in mac_to_customer:
            ip_to_customer[ip] = mac_to_customer[mac]

    client_rows: list[dict] = []
    seen_customer_ids: set[int] = set()

    def _append_client(customer: Customer, *, ip: str, usage_row: dict | None) -> None:
        if customer.pk in seen_customer_ids:
            return
        seen_customer_ids.add(customer.pk)
        usage_row = usage_row or {}
        isp_port = (usage_row.get("isp_port") or default_isp or "").strip()
        isp_row = isp_by_port.get(isp_port) or {}
        isp_label = isp_row.get("label") or isp_port or "—"
        online = bool(ip)
        connections = int(usage_row.get("connections") or 0)
        source = (usage_row.get("source") or "").strip()
        if isp_port and isp_port in isp_by_port and online:
            isp_by_port[isp_port]["client_count"] = (
                int(isp_by_port[isp_port].get("client_count") or 0) + 1
            )
            isp_by_port[isp_port]["connection_count"] = (
                int(isp_by_port[isp_port].get("connection_count") or 0) + connections
            )
        client_rows.append(
            {
                "customer_id": customer.pk,
                "name": customer.full_name,
                "account_number": customer.account_number,
                "service_type": customer.service_type,
                "status": customer.status,
                "online": online,
                "ip": ip,
                "isp_port": isp_port,
                "isp_label": isp_label,
                "connection_count": connections,
                "assignment_source": source or ("offline" if not online else "default_wan"),
            }
        )

    for ip, usage_row in ip_usage.items():
        customer = ip_to_customer.get(ip)
        if customer:
            _append_client(customer, ip=ip, usage_row=usage_row)

    for customer in customers:
        if customer.pk in seen_customer_ids:
            continue
        matched_ip = ""
        usage_row: dict | None = None
        static_ip = _parse_connection_address(customer.cpe_ip or "")
        if static_ip and static_ip in ip_usage:
            matched_ip = static_ip
            usage_row = ip_usage[static_ip]
        else:
            username = (customer.pppoe_username or "").strip().lower()
            if username:
                for ip, session in sessions.items():
                    if (session.get("pppoe_username") or "").strip().lower() == username:
                        matched_ip = ip
                        usage_row = ip_usage.get(ip)
                        break
            if not matched_ip:
                mac = _mac_compact_key(customer.hotspot_mac or customer.cpe_mac or "")
                if mac:
                    for ip, session in sessions.items():
                        if _mac_compact_key(session.get("mac") or "") == mac:
                            matched_ip = ip
                            usage_row = ip_usage.get(ip)
                            break
        _append_client(customer, ip=matched_ip, usage_row=usage_row)

    client_rows.sort(
        key=lambda row: (
            0 if row.get("online") else 1,
            (row.get("isp_label") or "").lower(),
            (row.get("name") or "").lower(),
        )
    )

    online_clients = sum(1 for row in client_rows if row.get("online"))
    total_connections = sum(int(row.get("connection_count") or 0) for row in client_rows)

    mode_notes = {
        MikroTikRouter.UplinkMode.SINGLE: "All online clients use the single Internet port.",
        MikroTikRouter.UplinkMode.BOND: "Clients share the bonded uplink.",
        MikroTikRouter.UplinkMode.FAILOVER: "Clients use whichever ISP is active on the default route.",
        MikroTikRouter.UplinkMode.BALANCE: (
            "Per-connection PCC split — a client may use different ISPs for different sessions."
            if usage.get("uses_connection_marks")
            else "Weighted balance configured — apply on the MikroTik to see live per-connection ISP."
        ),
        MikroTikRouter.UplinkMode.SMART_BALANCE: (
            "Smart balance active — slow ISPs are sidelined from new connections."
            if usage.get("uses_connection_marks")
            else "Smart balance configured — apply on the MikroTik for live ISP tracking."
        ),
    }

    return {
        "ok": True,
        "usage_ok": bool(usage.get("ok")),
        "error": usage.get("error") or "",
        "mode": mode,
        "mode_label": dict(MikroTikRouter.UplinkMode.choices).get(mode, mode),
        "mode_note": mode_notes.get(mode, ""),
        "uses_connection_marks": bool(usage.get("uses_connection_marks")),
        "default_isp_port": default_isp,
        "isps": isps,
        "summary": {
            "total_clients": len(client_rows),
            "online_clients": online_clients,
            "offline_clients": max(0, len(client_rows) - online_clients),
            "total_connections": total_connections,
        },
        "clients": client_rows,
    }


def _parse_connection_address(addr: str) -> str:
    raw = (addr or "").strip()
    if not raw:
        return ""
    return raw.split("/")[0].strip()


def _allowed_roles_for_uplink_mode(mode: str) -> set[str]:
    """Roles operators may assign for the selected internet setup."""
    base = {
        MikroTikRouter.PortRole.NONE,
        MikroTikRouter.PortRole.LAN,
        MikroTikRouter.PortRole.UNUSED,
    }
    mode = (mode or MikroTikRouter.UplinkMode.SINGLE).strip()
    if mode == MikroTikRouter.UplinkMode.BOND:
        return base | {MikroTikRouter.PortRole.BOND}
    if mode in {
        MikroTikRouter.UplinkMode.FAILOVER,
        *_weighted_share_uplink_modes(),
    }:
        return base | {
            MikroTikRouter.PortRole.WAN,
            MikroTikRouter.PortRole.WAN_BACKUP,
        }
    return base | {MikroTikRouter.PortRole.WAN}


def _role_allowed_for_uplink_mode(role: str, mode: str) -> bool:
    return (role or "").strip().lower() in _allowed_roles_for_uplink_mode(mode)


def _role_label_for_mode_error(role: str) -> str:
    return dict(MikroTikRouter.PortRole.choices).get(
        (role or "").strip().lower(), role or "role"
    )


def _normalize_port_roles_for_uplink_mode(
    router: MikroTikRouter,
    mode: str,
    *,
    live_ports: list[dict] | None = None,
) -> dict[str, str]:
    """Drop roles that do not belong on the chosen internet setup."""
    roles = dict(router.port_roles) if isinstance(router.port_roles, dict) else {}
    mode = (mode or MikroTikRouter.UplinkMode.SINGLE).strip()
    allowed = _allowed_roles_for_uplink_mode(mode)
    by_name = {
        (p.get("name") or "").strip(): p
        for p in (live_ports or [])
        if (p.get("name") or "").strip()
    }
    primary = ""
    for name, value in roles.items():
        if _is_primary_wan_role(value):
            primary = (name or "").strip()
            break
    if not primary:
        primary = _current_primary_wan_port(router)

    for name, existing in list(roles.items()):
        role = (existing or "").strip().lower()
        if role in allowed:
            continue
        row = by_name.get(name) or {}
        if role in {
            MikroTikRouter.PortRole.WAN,
            MikroTikRouter.PortRole.WAN_PRIMARY,
            MikroTikRouter.PortRole.WAN_BACKUP,
            MikroTikRouter.PortRole.BOND,
        }:
            if row.get("is_bridged") or row.get("running"):
                roles[name] = MikroTikRouter.PortRole.LAN
            else:
                roles[name] = MikroTikRouter.PortRole.UNUSED
        else:
            roles[name] = MikroTikRouter.PortRole.NONE

    if mode == MikroTikRouter.UplinkMode.SINGLE:
        wan_names = [
            name
            for name, value in roles.items()
            if _is_primary_wan_role(value)
        ]
        keep = primary or (wan_names[0] if wan_names else "")
        for name in wan_names:
            if name != keep:
                roles[name] = MikroTikRouter.PortRole.UNUSED
    return roles


def _port_has_live_uplink(port_name: str, live_ports: list[dict]) -> bool:
    """Soft check: link up or uplink kind present (UI hints)."""
    by_name = {
        (p.get("name") or "").strip(): p
        for p in live_ports
        if (p.get("name") or "").strip()
    }
    row = by_name.get((port_name or "").strip()) or {}
    return bool(row.get("running")) or bool((row.get("uplink_kind") or "").strip())


def _port_has_verified_internet(port_name: str, live_ports: list[dict]) -> bool:
    """Strict check: DHCP bound or PPPoE connected before uplink apply."""
    by_name = {
        (p.get("name") or "").strip(): p
        for p in live_ports
        if (p.get("name") or "").strip()
    }
    row = by_name.get((port_name or "").strip()) or {}
    return bool(assess_port_internet_readiness(row).get("verified"))


def _guard_touch_ports_internet(
    touch_ports: list[str],
    live_ports: list[dict],
    *,
    action_label: str = "apply this change",
) -> tuple[bool, str]:
    """Block uplink apply when target ports lack verified ISP internet."""
    check = assess_touch_ports_internet(
        touch_ports, live_ports, require_all_verified=True
    )
    if check.get("ok"):
        return True, ""
    blocking = check.get("blocking") or []
    if blocking:
        return False, blocking[0]
    return (
        False,
        f"Cannot {action_label} — each port needs live ISP internet (DHCP bound or PPPoE up).",
    )


def _guard_bond_members_internet(
    member_ports: list[str],
    live_ports: list[dict],
) -> tuple[bool, str]:
    """Block bond apply when members are down; warn when ISP is unconfirmed."""
    check = assess_bond_members_readiness(member_ports, live_ports)
    if check.get("ok"):
        return True, ""
    blocking = check.get("blocking") or []
    if blocking:
        return False, blocking[0]
    return False, "Bond needs at least two connected members before applying."


def _apply_single_wan_on_router(
    router: MikroTikRouter,
    api_host: str,
    *,
    wan_interface: str,
    retire_ports: list[str] | None = None,
    live_ports: list[dict] | None = None,
) -> dict:
    """Push a full single-WAN switch to RouterOS.

    Behind-provider layouts (DHCP on the LAN bridge, ISP modem on a bridge
    member) must not be unbridged automatically — that drops customers and can
    hang the API. In that case roles are saved in the app only.
    """
    wan_interface = (wan_interface or "").strip()
    by_name = {
        (p.get("name") or "").strip(): p
        for p in (live_ports or [])
        if (p.get("name") or "").strip()
    }
    row = by_name.get(wan_interface) or {}
    via_bridge = bool((row.get("uplink_iface") or "").strip()) and (
        str(row.get("uplink_iface") or "").lower().startswith("bridge")
        or (row.get("is_bridged") and row.get("uplink_active"))
    )
    if row.get("is_bridged") and (
        via_bridge or (row.get("uplink_kind") == "dhcp" and row.get("uplink_active"))
    ):
        return {
            "ok": True,
            "skipped": True,
            "wan_interface": wan_interface,
            "message": (
                f"Saved {wan_interface} as Internet. "
                "It stays on the LAN bridge (behind-provider) — not unbridged."
            ),
        }

    old_mode = (router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE).strip()
    clear_multi = old_mode in {
        MikroTikRouter.UplinkMode.FAILOVER,
        *_weighted_share_uplink_modes(),
        MikroTikRouter.UplinkMode.BOND,
    }
    return switch_mikrotik_single_wan(
        api_host,
        router.username,
        router.password or "",
        wan_interface=wan_interface,
        retire_ports=retire_ports or [],
        clear_multi_uplink=clear_multi,
    )


def _port_role_choices_for_ui(mode: str | None = None) -> list[tuple[str, str]]:
    """Roles shown in the ports UI (WAN primary is merged into WAN)."""
    uplink_mode = (mode or MikroTikRouter.UplinkMode.SINGLE).strip()
    backup_label = (
        "Shared ISP"
        if _is_weighted_share_mode(uplink_mode)
        else "Backup internet"
    )
    labels = {
        MikroTikRouter.PortRole.NONE: "Unassigned",
        MikroTikRouter.PortRole.WAN: "Internet",
        MikroTikRouter.PortRole.WAN_BACKUP: backup_label,
        MikroTikRouter.PortRole.BOND: "Bonded internet",
        MikroTikRouter.PortRole.LAN: "Customers",
        MikroTikRouter.PortRole.UNUSED: "Unused",
    }
    hidden = {MikroTikRouter.PortRole.WAN_PRIMARY}
    return [
        (value, labels.get(value, label))
        for value, label in MikroTikRouter.PortRole.choices
        if value not in hidden
    ]


def _friendly_role_label(role: str, *, mode: str | None = None) -> str:
    labels = dict(_port_role_choices_for_ui(mode))
    return labels.get((role or "").strip().lower(), "Unassigned")


def _balance_apply_readiness(
    primary_wan_ports: list[str],
    backup_wan_ports: list[str],
    physical_ports: list[dict],
) -> tuple[bool, str]:
    """Whether balance can be applied and an operator-facing hint."""
    if not primary_wan_ports:
        return False, "Set one port to Internet on the cards below."
    if len(primary_wan_ports) > 1:
        names = ", ".join(primary_wan_ports)
        return False, f"Keep only one Internet port ({names} assigned)."
    if not backup_wan_ports:
        return False, "Set at least one other ISP port to Shared ISP."
    down: list[str] = []
    no_inet: list[str] = []
    for name in primary_wan_ports + backup_wan_ports:
        if not _port_has_live_uplink(name, physical_ports):
            down.append(name)
        elif not _port_has_verified_internet(name, physical_ports):
            no_inet.append(name)
    if down:
        return False, f"Link must be up: {', '.join(down)}."
    if no_inet:
        return (
            False,
            "Live ISP internet required before applying: "
            + ", ".join(no_inet)
            + " (wait for DHCP/PPPoE).",
        )
    return True, "Ready — enter Mbps and click Apply load balance."


def _live_isp_member_ports(
    live_ports: list[dict],
    *,
    suggested_wan: str = "",
    saved_wan: str = "",
) -> list[str]:
    """Ordered ISP ports with live uplinks — primary first — for balance modes."""
    physical = [p for p in live_ports if not _is_bond_port_row(p)]
    by_name = {(p.get("name") or "").strip(): p for p in physical}
    primary = _pick_auto_wan(
        physical,
        suggested_wan=suggested_wan,
        saved_wan=saved_wan,
    )
    members: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        name = (name or "").strip()
        if not name or name in seen:
            return
        row = by_name.get(name) or {}
        if not _port_has_verified_internet(name, physical):
            return
        seen.add(name)
        members.append(name)

    if primary:
        add(primary)
    for row in physical:
        name = (row.get("name") or "").strip()
        if not name or name in seen:
            continue
        kind = (row.get("uplink_kind") or "").strip()
        if kind not in {"dhcp", "pppoe"}:
            continue
        if not _port_has_verified_internet(name, physical):
            continue
        if row.get("is_bridged") and not row.get("uplink_active"):
            continue
        add(name)
    return members


def _suggest_balance_weights(
    members: list[str],
    live_ports: list[dict],
    existing: dict | None = None,
) -> dict[str, int]:
    """Default Mbps weights for balance / smart balance (equal unless saved)."""
    existing = existing if isinstance(existing, dict) else {}
    weights: dict[str, int] = {}
    for name in members:
        name = (name or "").strip()
        if not name:
            continue
        raw = existing.get(name, existing.get(name.lower()))
        try:
            weights[name] = max(1, min(10000, int(raw)))
        except (TypeError, ValueError):
            weights[name] = 100
    return weights


def _live_bond_candidate_ports(live_ports: list[dict]) -> list[str]:
    """Physical ports with link up — prefer same-ISP style (no separate DHCP/PPPoE yet)."""
    physical = [p for p in live_ports if not _is_bond_port_row(p)]
    preferred: list[str] = []
    fallback: list[str] = []
    for row in physical:
        name = (row.get("name") or "").strip()
        if not name or _is_bridge_port_name(name):
            continue
        if row.get("disabled") or not row.get("running"):
            continue
        if row.get("is_wireless") or row.get("is_bridged"):
            continue
        if (row.get("uplink_kind") or "").strip() and row.get("uplink_active"):
            fallback.append(name)
        else:
            preferred.append(name)
    ordered = preferred if len(preferred) >= 2 else preferred + fallback
    return ordered


def _auto_assign_bond_roles(
    router: MikroTikRouter,
    live_ports: list[dict],
) -> dict:
    """Mark linked ports as bond members when bonding mode is selected."""
    members = _bond_ports_from_roles(router)
    if len(members) >= 2:
        ready, _ = _bond_apply_readiness(members, live_ports)
        return {
            "ok": ready,
            "changed": False,
            "members": members,
        }

    candidates = _live_bond_candidate_ports(live_ports)
    pick: list[str] = []
    if len(members) == 1:
        extra = [c for c in candidates if c != members[0]]
        if extra:
            pick = [members[0], extra[0]]
    elif len(candidates) >= 2:
        pick = candidates[:2]

    if len(pick) < 2:
        return {
            "ok": False,
            "changed": False,
            "error": (
                "Need two cables from the same ISP with link up — "
                "plug both in, then try again."
            ),
        }

    if members == pick:
        return {"ok": True, "changed": False, "members": pick}

    roles = dict(router.port_roles) if isinstance(router.port_roles, dict) else {}
    by_name = {
        (p.get("name") or "").strip(): p
        for p in live_ports
        if (p.get("name") or "").strip()
    }
    pick_set = set(pick)
    for name, existing in list(roles.items()):
        if (existing or "").strip().lower() != MikroTikRouter.PortRole.BOND:
            continue
        if name in pick_set:
            continue
        row = by_name.get(name) or {}
        roles[name] = (
            MikroTikRouter.PortRole.LAN
            if row.get("is_bridged") or row.get("running")
            else MikroTikRouter.PortRole.UNUSED
        )

    for name in pick:
        roles[name] = MikroTikRouter.PortRole.BOND

    router.port_roles = roles
    router.uplink_mode = MikroTikRouter.UplinkMode.BOND
    router.uplink_ports = pick
    router.save(
        update_fields=["port_roles", "uplink_mode", "uplink_ports", "updated_at"]
    )
    return {
        "ok": True,
        "changed": True,
        "members": pick,
        "message": f"Auto-assigned bond members: {', '.join(pick)}.",
    }


def _bond_apply_readiness(
    bond_member_ports: list[str],
    physical_ports: list[dict],
) -> tuple[bool, str]:
    """Whether bonding can be applied and an operator-facing hint."""
    if len(bond_member_ports) < 2:
        return False, "Need two ports set to Bonded internet — or use Detect & apply."
    check = assess_bond_members_readiness(bond_member_ports, physical_ports)
    if not check.get("ok"):
        blocking = check.get("blocking") or []
        return False, blocking[0] if blocking else "Bond members are not ready."
    warnings = check.get("warnings") or []
    if warnings:
        return True, warnings[0]
    return True, "Ready — both cables linked. Click Apply bonding."


def _auto_assign_smart_balance_roles(
    router: MikroTikRouter,
    live_ports: list[dict],
    *,
    suggested_wan: str = "",
) -> dict:
    """Pick Internet + Shared ISP from live links when smart balance is selected."""
    return _auto_assign_multi_isp_roles(
        router,
        live_ports,
        mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
        suggested_wan=suggested_wan,
    )


def _roles_complete_for_uplink_mode(
    router: MikroTikRouter,
    mode: str,
    live_ports: list[dict] | None = None,
) -> bool:
    """Whether port roles match the minimum for the chosen internet setup."""
    mode = (mode or MikroTikRouter.UplinkMode.SINGLE).strip()
    if mode == MikroTikRouter.UplinkMode.BOND:
        return len(_bond_ports_from_roles(router)) >= 2
    primary, backups = _failover_ports_from_roles(router)
    if mode == MikroTikRouter.UplinkMode.SINGLE:
        return bool(primary)
    if mode in {
        MikroTikRouter.UplinkMode.FAILOVER,
        *_weighted_share_uplink_modes(),
    }:
        return bool(primary) and len(backups) >= 1
    return True


def _multi_isp_roles_match_live(
    router: MikroTikRouter,
    live_ports: list[dict],
    *,
    suggested_wan: str = "",
) -> bool:
    members = _live_isp_member_ports(
        live_ports,
        suggested_wan=suggested_wan,
        saved_wan=router.wan_interface or "",
    )
    if len(members) < 2:
        return True
    primary, backups = _failover_ports_from_roles(router)
    ordered = [primary, *backups] if primary else []
    return ordered == members


def _auto_assign_multi_isp_roles(
    router: MikroTikRouter,
    live_ports: list[dict],
    *,
    mode: str,
    suggested_wan: str = "",
) -> dict:
    """Assign Internet + backup/shared ports from live ISP links."""
    mode = (mode or "").strip()
    members = _live_isp_member_ports(
        live_ports,
        suggested_wan=suggested_wan,
        saved_wan=router.wan_interface or "",
    )
    primary, backups = _failover_ports_from_roles(router)
    if len(members) < 2:
        if primary and backups:
            return {
                "ok": True,
                "changed": False,
                "primary": primary,
                "backups": backups,
            }
        return {
            "ok": False,
            "changed": False,
            "error": "Need two live ISP links on different ports.",
        }

    new_primary = members[0]
    new_backups = members[1:]
    if primary == new_primary and backups == new_backups:
        return {
            "ok": True,
            "changed": False,
            "primary": new_primary,
            "backups": new_backups,
        }

    roles = dict(router.port_roles) if isinstance(router.port_roles, dict) else {}
    by_name = {
        (p.get("name") or "").strip(): p
        for p in live_ports
        if (p.get("name") or "").strip()
    }
    member_set = set(members)
    for name, existing in list(roles.items()):
        role = (existing or "").strip().lower()
        if role not in {
            MikroTikRouter.PortRole.WAN,
            MikroTikRouter.PortRole.WAN_PRIMARY,
            MikroTikRouter.PortRole.WAN_BACKUP,
            MikroTikRouter.PortRole.BOND,
            MikroTikRouter.PortRole.LAN,
            MikroTikRouter.PortRole.NONE,
        }:
            continue
        if name in member_set:
            continue
        row = by_name.get(name) or {}
        roles[name] = (
            MikroTikRouter.PortRole.LAN
            if row.get("is_bridged") or row.get("is_wireless")
            else MikroTikRouter.PortRole.UNUSED
        )

    roles[new_primary] = MikroTikRouter.PortRole.WAN
    for backup in new_backups:
        roles[backup] = MikroTikRouter.PortRole.WAN_BACKUP

    weights: dict[str, int] = {}
    update_fields = [
        "port_roles",
        "wan_interface",
        "uplink_ports",
        "uplink_mode",
        "updated_at",
    ]
    if mode in _weighted_share_uplink_modes():
        weights = _suggest_balance_weights(
            members,
            live_ports,
            router.uplink_weights if isinstance(router.uplink_weights, dict) else {},
        )
        router.uplink_weights = weights
        update_fields.append("uplink_weights")

    router.port_roles = roles
    router.wan_interface = new_primary
    router.uplink_ports = members
    router.uplink_mode = mode
    router.save(update_fields=update_fields)

    backup_label = (
        "backup"
        if mode == MikroTikRouter.UplinkMode.FAILOVER
        else "shared"
    )
    mode_label = dict(MikroTikRouter.UplinkMode.choices).get(mode, mode)
    return {
        "ok": True,
        "changed": True,
        "primary": new_primary,
        "backups": new_backups,
        "weights": weights,
        "message": (
            f"Auto-assigned {mode_label}: Internet {new_primary}, "
            f"{backup_label} {', '.join(new_backups)}."
        ),
    }


def _auto_assign_single_wan_roles(
    router: MikroTikRouter,
    live_ports: list[dict],
    *,
    suggested_wan: str = "",
) -> dict:
    """Ensure one Internet port is assigned for single-WAN mode."""
    roles = dict(router.port_roles) if isinstance(router.port_roles, dict) else {}
    wan_ports = [
        name
        for name, value in roles.items()
        if _is_primary_wan_role(value)
    ]
    if len(wan_ports) == 1:
        return {"ok": True, "changed": False, "wan": wan_ports[0]}

    suggested_roles = suggest_port_roles(
        live_ports,
        suggested_wan=suggested_wan,
        saved_wan=router.wan_interface or "",
    )
    router.port_roles = suggested_roles
    normalized = _normalize_port_roles_for_uplink_mode(
        router,
        MikroTikRouter.UplinkMode.SINGLE,
        live_ports=live_ports,
    )
    primary = next(
        (name for name, role in normalized.items() if _is_primary_wan_role(role)),
        "",
    )
    if not primary:
        return {"ok": False, "changed": False, "error": "No live ISP port detected yet."}

    if roles == normalized and wan_ports == [primary]:
        return {"ok": True, "changed": False, "wan": primary}

    router.port_roles = normalized
    router.wan_interface = primary
    router.uplink_ports = [primary]
    router.uplink_mode = MikroTikRouter.UplinkMode.SINGLE
    router.save(
        update_fields=[
            "port_roles",
            "wan_interface",
            "uplink_ports",
            "uplink_mode",
            "updated_at",
        ]
    )
    return {
        "ok": True,
        "changed": True,
        "wan": primary,
        "message": f"Auto-assigned Internet on {primary}.",
    }


def _auto_sync_port_roles_for_uplink_mode(
    router: MikroTikRouter,
    live_ports: list[dict],
    *,
    suggested_wan: str = "",
) -> dict:
    """Keep port card roles aligned with the selected internet setup and live links."""
    mode = (router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE).strip()
    complete = _roles_complete_for_uplink_mode(router, mode, live_ports)
    stale_multi = mode in {
        MikroTikRouter.UplinkMode.FAILOVER,
        *_weighted_share_uplink_modes(),
    } and not _multi_isp_roles_match_live(
        router, live_ports, suggested_wan=suggested_wan
    )

    if complete and not stale_multi:
        if mode == MikroTikRouter.UplinkMode.BOND:
            if len(_bond_ports_from_roles(router)) >= 2:
                return {"ok": True, "changed": False}
        else:
            return {"ok": True, "changed": False}

    if mode == MikroTikRouter.UplinkMode.SINGLE:
        return _auto_assign_single_wan_roles(
            router, live_ports, suggested_wan=suggested_wan
        )
    if mode == MikroTikRouter.UplinkMode.BOND:
        return _auto_assign_bond_roles(router, live_ports)
    if mode == MikroTikRouter.UplinkMode.FAILOVER:
        return _auto_assign_multi_isp_roles(
            router,
            live_ports,
            mode=mode,
            suggested_wan=suggested_wan,
        )
    if mode == MikroTikRouter.UplinkMode.BALANCE:
        return _auto_assign_multi_isp_roles(
            router,
            live_ports,
            mode=mode,
            suggested_wan=suggested_wan,
        )
    if mode == MikroTikRouter.UplinkMode.SMART_BALANCE:
        return _auto_assign_multi_isp_roles(
            router,
            live_ports,
            mode=mode,
            suggested_wan=suggested_wan,
        )
    return {"ok": True, "changed": False}


def _suggested_roles_for_uplink_mode(
    mode: str,
    live_ports: list[dict],
    *,
    suggested_wan: str = "",
    saved_wan: str = "",
) -> dict[str, str]:
    """Expected role per port for the current setup — used for card hints."""
    mode = (mode or MikroTikRouter.UplinkMode.SINGLE).strip()
    out: dict[str, str] = {}
    if mode == MikroTikRouter.UplinkMode.SINGLE:
        wan = _pick_auto_wan(
            live_ports, suggested_wan=suggested_wan, saved_wan=saved_wan
        )
        for row in live_ports:
            if _is_bond_port_row(row):
                continue
            name = (row.get("name") or "").strip()
            if not name or _is_bridge_port_name(name):
                continue
            if name == wan:
                out[name] = MikroTikRouter.PortRole.WAN
            elif row.get("is_bridged") or row.get("is_wireless"):
                out[name] = MikroTikRouter.PortRole.LAN
            elif row.get("disabled"):
                out[name] = MikroTikRouter.PortRole.UNUSED
        return out

    if mode == MikroTikRouter.UplinkMode.BOND:
        for name in _live_bond_candidate_ports(live_ports)[:2]:
            out[name] = MikroTikRouter.PortRole.BOND
        return out

    if mode in {
        MikroTikRouter.UplinkMode.FAILOVER,
        *_weighted_share_uplink_modes(),
    }:
        members = _live_isp_member_ports(
            live_ports, suggested_wan=suggested_wan, saved_wan=saved_wan
        )
        if members:
            out[members[0]] = MikroTikRouter.PortRole.WAN
            for backup in members[1:]:
                out[backup] = MikroTikRouter.PortRole.WAN_BACKUP
    return out


PORTS_ASSIGN_HINTS = {
    MikroTikRouter.UplinkMode.SINGLE: (
        "Roles update automatically from live links. Tap Internet to move the ISP cable."
    ),
    MikroTikRouter.UplinkMode.BOND: (
        "Linked ports are marked Bonded internet automatically. Adjust any card if needed."
    ),
    MikroTikRouter.UplinkMode.FAILOVER: (
        "Live ISP ports are assigned as Internet and Backup internet as they come online."
    ),
    MikroTikRouter.UplinkMode.BALANCE: (
        "Live ISP ports are assigned as Internet and Shared ISP — ISP badges refresh every few seconds."
    ),
    MikroTikRouter.UplinkMode.SMART_BALANCE: (
        "Live ISP ports auto-fill as Internet and Shared ISP. Apply smart balance when all show ISP online."
    ),
}


def _smart_balance_health(uplink_live: dict, uplink_mode: str) -> dict:
    """Whether smart balance is fully active on the MikroTik (PCC + ping monitor)."""
    mode = (uplink_mode or "").strip()
    live = uplink_live if uplink_live.get("ok") else {}
    live_mode = (live.get("mode") or "").strip()
    pcc_rules = int(live.get("balance_pcc_rules") or 0)
    monitor_on = bool(live.get("smart_balance_enabled"))
    if mode != MikroTikRouter.UplinkMode.SMART_BALANCE:
        return {
            "applies": False,
            "effective": False,
            "needs_apply": False,
            "monitor_on": monitor_on,
            "pcc_rules": pcc_rules,
        }
    effective = live_mode == "smart_balance" and pcc_rules >= 2 and monitor_on
    needs_apply = not effective
    return {
        "applies": True,
        "effective": effective,
        "needs_apply": needs_apply,
        "needs_monitor_repair": (
            live_mode == "smart_balance" and pcc_rules >= 2 and not monitor_on
        ),
        "monitor_on": monitor_on,
        "pcc_rules": pcc_rules,
        "live_mode": live_mode,
    }


def _smart_balance_auto_cache_key(router_pk: int) -> str:
    return f"smart_balance_auto:{router_pk}"


def _try_auto_apply_smart_balance(
    router: MikroTikRouter,
    api_host: str,
    *,
    member_ports: list[str],
    member_weights: dict[str, int],
    uplink_live: dict,
    live_ports: list[dict] | None = None,
    force: bool = False,
) -> dict:
    """Push smart balance to RouterOS when configured in the app but not yet effective."""
    health = _smart_balance_health(uplink_live, router.uplink_mode)
    if not health.get("applies") or health.get("effective"):
        return {}
    ordered = [str(p).strip() for p in (member_ports or []) if str(p).strip()]
    ordered = list(dict.fromkeys(ordered))
    if len(ordered) < 2:
        return {"skipped": True, "reason": "need_two_members"}

    ok_inet, inet_err = _guard_touch_ports_internet(
        ordered,
        live_ports or [],
        action_label="auto-apply smart balance",
    )
    if not ok_inet:
        return {"skipped": True, "reason": inet_err or "ports_need_internet"}

    cache_key = _smart_balance_auto_cache_key(router.pk)
    if not force and cache.get(cache_key):
        return {"skipped": True, "reason": "throttled"}

    cache.set(cache_key, True, 90)
    weights = _suggest_balance_weights(
        ordered,
        [],
        member_weights if isinstance(member_weights, dict) else {},
    )
    result = apply_mikrotik_uplink_balance(
        api_host,
        router.username,
        router.password or "",
        member_ports=ordered,
        member_weights=weights,
        smart_balance=True,
        api_hosts=_uplink_api_hosts_for_router(router),
    )
    result = _finalize_uplink_apply_result(router, result)
    if result.get("ok"):
        cache.delete(cache_key)
        ordered_ports = result.get("ports") or ordered
        router.uplink_mode = MikroTikRouter.UplinkMode.SMART_BALANCE
        router.uplink_ports = ordered_ports
        router.uplink_weights = result.get("weights") or weights
        router.wan_interface = result.get("wan_interface") or ordered[0]
        router.uplink_unbridged = result.get("unbridged") or []
        router.port_roles = _sync_roles_for_uplink(
            router,
            mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            ports=ordered_ports,
        )
        router.save(
            update_fields=[
                "uplink_mode",
                "uplink_ports",
                "uplink_weights",
                "wan_interface",
                "uplink_unbridged",
                "port_roles",
                "updated_at",
            ]
        )
        return {
            "ok": True,
            "auto_applied": True,
            "message": result.get("message")
            or "Smart balance applied on the MikroTik (PCC + slow-link monitor).",
            "ports": ordered_ports,
            "weights": router.uplink_weights,
        }
    cache.set(cache_key, (result.get("error") or "failed")[:200], 45)
    return {
        "ok": False,
        "auto_applied": False,
        "error": result.get("error") or "Could not auto-apply smart balance.",
    }


def _is_bond_port_row(row: dict) -> bool:
    name = (row.get("name") or "").strip().lower()
    iface_type = (row.get("type") or "").strip().lower()
    return iface_type == "bond" or name.startswith("bond")


def _is_bridge_port_name(name: str) -> bool:
    n = (name or "").strip().lower()
    return n.startswith("bridge") or n in {"br-lan", "br0", "br1"}


def _port_viable_for_wan(row: dict | None) -> bool:
    """True when a physical port can reasonably be Internet."""
    if not row:
        return False
    if row.get("disabled") or row.get("is_wireless") or _is_bond_port_row(row):
        return False
    name = (row.get("name") or "").strip()
    if not name or _is_bridge_port_name(name):
        return False
    if row.get("running"):
        return True
    if (row.get("uplink_kind") or "").strip() and row.get("uplink_active"):
        return True
    return False


def _pick_auto_wan(ports: list[dict], *, suggested_wan: str, saved_wan: str) -> str:
    """Choose the best Internet port from live data (DHCP, PPPoE, or ether)."""
    physical = [p for p in ports if not _is_bond_port_row(p)]
    by_name = {(p.get("name") or "").strip(): p for p in physical}

    def _try(name: str) -> str:
        name = (name or "").strip()
        if not name or _is_bridge_port_name(name):
            return ""
        row = by_name.get(name)
        if _port_viable_for_wan(row):
            return name
        return ""

    # 1) Live default-route suggestion (physical when bridge→host resolved).
    picked = _try(suggested_wan)
    if picked:
        return picked

    # 2) Active PPPoE, then active DHCP (skip stale unbound clients).
    for kind in ("pppoe", "dhcp"):
        for p in physical:
            if (p.get("uplink_kind") or "") != kind:
                continue
            if not p.get("uplink_active") and not p.get("running"):
                continue
            name = _try(p.get("name") or "")
            if name:
                return name

    # 3) Saved WAN only if it still looks viable.
    picked = _try(saved_wan)
    if picked:
        return picked

    # 4) Running non-bridged ether (typical dedicated WAN).
    running_ether = [
        p
        for p in physical
        if p.get("running")
        and not p.get("is_wireless")
        and not p.get("disabled")
    ]
    unbridged = [p for p in running_ether if not p.get("is_bridged")]
    if unbridged:
        return (unbridged[0].get("name") or "").strip()

    # 5) Classic default ether1 only when present and viable.
    picked = _try("ether1")
    if picked:
        return picked

    any_ether = [
        p
        for p in physical
        if not p.get("is_wireless") and not p.get("disabled")
    ]
    if any_ether:
        for p in any_ether:
            if (p.get("uplink_kind") or "").strip():
                return (p.get("name") or "").strip()
        return (any_ether[0].get("name") or "").strip()
    return ""


def _management_hosts_for_router(router: MikroTikRouter) -> list[str]:
    """Hosts used to read which RouterOS interface carries management IP."""
    hosts: list[str] = []
    for raw in (
        getattr(router, "host", None),
        getattr(router, "vpn_address", None),
    ):
        value = (raw or "").strip()
        if value and value not in hosts:
            hosts.append(value)
    return hosts


def _check_uplink_apply_confirmation(request, risk: dict) -> tuple[bool, str | None]:
    """Return whether POST may proceed and an optional operator error message."""
    if risk.get("blocking"):
        return (
            False,
            risk.get("summary")
            or "This change cannot be applied until the issue is fixed.",
        )
    if risk.get("safe"):
        return True, None
    confirm = (request.POST.get("confirm_risk") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    if not confirm:
        return (
            False,
            "Confirm you understand the connection risk before continuing.",
        )
    return True, None


def _assess_uplink_mode_apply(
    router: MikroTikRouter,
    mode: str,
    touch_ports: list[str],
    live_ports: list[dict],
    management_iface_by_host: dict[str, str] | None,
    *,
    tunnel_verified: bool | None = None,
) -> dict:
    if tunnel_verified is None:
        tunnel_verified = _router_tunnel_verified(router)
    risk = assess_uplink_mode_apply_risk(
        mode=mode,
        touch_ports=touch_ports,
        ports=live_ports,
        management_host=(router.host or "").strip(),
        tunnel_address=(router.vpn_address or "").strip(),
        management_iface_by_host=management_iface_by_host or {},
        uses_tunnel=_router_uses_tunnel(router),
        tunnel_verified=tunnel_verified,
    )
    risk["recovery_script"] = build_uplink_recovery_script(
        mode,
        members=touch_ports,
        bond_name=(router.bond_interface or "").strip(),
        primary_port=(touch_ports[0] if touch_ports else ""),
    )
    risk["tunnel_setup_url"] = reverse("core:mikrotik_detail", args=[router.pk])
    return risk


def _touch_ports_for_clear(router: MikroTikRouter) -> list[str]:
    unbridged = (
        list(router.uplink_unbridged)
        if isinstance(router.uplink_unbridged, list)
        else []
    )
    uplink = (
        list(router.uplink_ports) if isinstance(router.uplink_ports, list) else []
    )
    bond_name = (router.bond_interface or "").strip()
    merged: list[str] = []
    for raw in (*unbridged, *uplink):
        name = str(raw).strip()
        if not name or name.lower().startswith("bond") or name == bond_name:
            continue
        if name not in merged:
            merged.append(name)
    return merged


def _build_uplink_apply_risks(
    router: MikroTikRouter,
    *,
    live_ports: list[dict],
    management_iface_by_host: dict[str, str] | None,
    bond_member_ports: list[str],
    primary_wan_ports: list[str],
    backup_wan_ports: list[str],
    tunnel_verified: bool | None = None,
) -> dict[str, dict]:
    """Pre-compute apply risks for bond / failover / balance / clear (live JSON + UI)."""
    mgmt = management_iface_by_host or {}
    risks: dict[str, dict] = {}
    uplink_mode = (router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE).strip()

    if len(bond_member_ports) >= 2:
        risks["bond"] = _assess_uplink_mode_apply(
            router, "bond", bond_member_ports, live_ports, mgmt, tunnel_verified=tunnel_verified
        )

    if len(primary_wan_ports) == 1 and backup_wan_ports:
        touch = [primary_wan_ports[0], *backup_wan_ports]
        risks["failover"] = _assess_uplink_mode_apply(
            router, "failover", touch, live_ports, mgmt, tunnel_verified=tunnel_verified
        )
        risks["balance"] = _assess_uplink_mode_apply(
            router, "balance", touch, live_ports, mgmt, tunnel_verified=tunnel_verified
        )
        risks["smart_balance"] = _assess_uplink_mode_apply(
            router, "balance", touch, live_ports, mgmt, tunnel_verified=tunnel_verified
        )

    if uplink_mode != MikroTikRouter.UplinkMode.SINGLE:
        risks["clear"] = _assess_uplink_mode_apply(
            router,
            "clear",
            _touch_ports_for_clear(router),
            live_ports,
            mgmt,
            tunnel_verified=tunnel_verified,
        )

    return risks


def _build_wan_switch_risks(
    router: MikroTikRouter,
    *,
    live_ports: list[dict],
    management_iface_by_host: dict[str, str] | None,
    primary_wan_ports: list[str],
    tunnel_verified: bool | None = None,
) -> dict[str, dict]:
    """Per-port risk when assigning Internet in single-WAN mode (for UI + POST guard)."""
    mode = (router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE).strip()
    if mode != MikroTikRouter.UplinkMode.SINGLE:
        return {}

    current = (primary_wan_ports[0] if primary_wan_ports else "") or _current_primary_wan_port(
        router
    )
    mgmt = management_iface_by_host or {}
    if tunnel_verified is None:
        tunnel_verified = _router_tunnel_verified(router)
    risks: dict[str, dict] = {}
    for row in live_ports:
        if _is_bond_port_row(row):
            continue
        name = (row.get("name") or "").strip()
        if not name or name == current:
            continue
        risk = assess_uplink_switch_risk(
            new_wan=name,
            old_wan=current,
            ports=live_ports,
            management_host=(router.host or "").strip(),
            tunnel_address=(router.vpn_address or "").strip(),
            management_iface_by_host=mgmt,
            uses_tunnel=_router_uses_tunnel(router),
            tunnel_verified=_router_tunnel_verified(router),
        )
        rollback = _build_wan_rollback_script(current, name)
        risk["rollback_recovery_script"] = rollback
        risk["recovery_script"] = rollback
        risks[name] = risk
    return risks


def _build_uplink_health_alerts(
    *,
    uplink_mode: str,
    uplink_live: dict,
    wan_share: dict,
    primary_wan_ports: list[str],
    backup_wan_ports: list[str],
    bond_member_ports: list[str],
    physical_ports: list[dict],
    uplink_weights: dict,
    balance_router_applied: bool = False,
    smart_balance_status: dict | None = None,
    smart_balance_applied: bool | None = None,
) -> list[dict]:
    """Operator-facing health warnings for bond / failover / balance."""
    alerts: list[dict] = []
    mode = (uplink_mode or "").strip()
    by_name = {
        (p.get("name") or "").strip(): p
        for p in physical_ports
        if (p.get("name") or "").strip()
    }

    if mode == MikroTikRouter.UplinkMode.BOND and bond_member_ports:
        down = []
        for name in bond_member_ports:
            row = by_name.get(name) or {}
            if row.get("disabled") or not row.get("running"):
                down.append(name)
        bond_rows = uplink_live.get("bonds") or []
        bond_live = bond_rows[0] if bond_rows else {}
        if down:
            alerts.append(
                {
                    "level": "warn",
                    "code": "bond_slave_down",
                    "message": f"Bond member(s) down: {', '.join(down)}.",
                }
            )
        elif bond_live and not bond_live.get("running"):
            alerts.append(
                {
                    "level": "warn",
                    "code": "bond_not_running",
                    "message": "Bond interface is not running on the MikroTik yet.",
                }
            )

    if mode == MikroTikRouter.UplinkMode.FAILOVER and (
        primary_wan_ports or backup_wan_ports
    ):
        primary_down = []
        for name in primary_wan_ports:
            row = by_name.get(name) or {}
            if row.get("disabled") or not row.get("running"):
                primary_down.append(name)
        backup_up = []
        for name in backup_wan_ports:
            row = by_name.get(name) or {}
            if row.get("running") and not row.get("disabled"):
                backup_up.append(name)
        checked = uplink_live.get("checked_routes") or []
        active = next((r for r in checked if r.get("active") and not r.get("disabled")), None)
        clients = uplink_live.get("failover_clients") or []
        on_backup = False
        if active and clients:
            dist = str(active.get("distance") or "1")
            for c in clients:
                if c.get("disabled"):
                    continue
                if str(c.get("distance") or "1") != dist:
                    continue
                iface = (c.get("interface") or "").strip()
                if iface in backup_wan_ports:
                    on_backup = True
                    break
        elif primary_down and backup_up:
            on_backup = True
        if on_backup:
            alerts.append(
                {
                    "level": "warn",
                    "code": "failover_on_backup",
                    "message": (
                        "Failover is carrying traffic on backup"
                        + (f" ({', '.join(backup_up)})" if backup_up else "")
                        + " — primary is down or failing gateway checks."
                    ),
                }
            )
        for name in backup_wan_ports:
            row = by_name.get(name) or {}
            if row.get("disabled") or not row.get("running"):
                alerts.append(
                    {
                        "level": "info",
                        "code": "backup_down",
                        "message": f"Backup {name} has no link — failover has no standby.",
                    }
                )

    if _is_weighted_share_mode(mode) and (
        primary_wan_ports or backup_wan_ports
    ):
        members = list(primary_wan_ports) + list(backup_wan_ports)
        down = []
        no_inet = []
        for name in members:
            row = by_name.get(name) or {}
            if row.get("disabled") or not row.get("running"):
                down.append(name)
            elif not _port_has_verified_internet(name, physical_ports):
                no_inet.append(name)
        if down:
            alerts.append(
                {
                    "level": "warn",
                    "code": "balance_member_down",
                    "message": (
                        f"Shared ISP link down: {', '.join(down)} — "
                        "traffic shifts to surviving links after apply."
                    ),
                }
            )
        if no_inet:
            alerts.append(
                {
                    "level": "warn",
                    "code": "balance_member_no_inet",
                    "message": (
                        f"No verified ISP on: {', '.join(no_inet)} — "
                        "wait for DHCP/PPPoE before applying or you may lose connection."
                    ),
                }
            )
        if len(members) >= 2 and not balance_router_applied:
            label = (
                "Smart balance"
                if mode == MikroTikRouter.UplinkMode.SMART_BALANCE
                else "Load balance"
            )
            apply_hint = (
                "auto-applies when ISP links are up"
                if mode == MikroTikRouter.UplinkMode.SMART_BALANCE
                else "click Apply load balance"
            )
            alerts.append(
                {
                    "level": "info",
                    "code": "balance_not_applied",
                    "message": (
                        f"{label} is configured here but not on the MikroTik yet — "
                        f"{apply_hint}."
                    ),
                }
            )

    if mode == MikroTikRouter.UplinkMode.SMART_BALANCE:
        if smart_balance_applied is False and balance_router_applied:
            alerts.append(
                {
                    "level": "warn",
                    "code": "smart_balance_monitor_off",
                    "message": (
                        "PCC balance is on the MikroTik but the slow-link monitor is "
                        "missing — smart balance will re-apply automatically."
                    ),
                }
            )
        slow_ports = []
        if isinstance(smart_balance_status, dict):
            slow_ports = [
                str(p).strip()
                for p in (smart_balance_status.get("slow_ports") or [])
                if str(p).strip()
            ]
        if slow_ports:
            alerts.append(
                {
                    "level": "warn",
                    "code": "smart_balance_slow",
                    "message": (
                        "Slow ISP sidelined from new connections: "
                        + ", ".join(slow_ports)
                        + "."
                    ),
                }
            )

    if _is_weighted_share_mode(mode) and wan_share.get("ok"):
        shares = wan_share.get("shares") or []
        weights = {}
        for k, v in (uplink_weights or {}).items():
            name = str(k).strip()
            if not name:
                continue
            try:
                weights[name] = max(1, int(v))
            except (TypeError, ValueError):
                continue
        if shares and weights and len(shares) >= 2:
            total_w = sum(weights.get(s.get("name") or "", 0) for s in shares) or 0
            if total_w > 0:
                drifted = []
                for s in shares:
                    name = (s.get("name") or "").strip()
                    actual = s.get("pct")
                    if actual is None or name not in weights:
                        continue
                    target = round(100 * weights[name] / total_w)
                    try:
                        actual_i = int(actual)
                    except (TypeError, ValueError):
                        continue
                    if abs(actual_i - target) >= 25 and (wan_share.get("total_bps") or 0) > 0:
                        drifted.append(f"{name} ~{actual_i}% (target ~{target}%)")
                if drifted:
                    alerts.append(
                        {
                            "level": "info",
                            "code": "balance_share_drift",
                            "message": (
                                "Live bandwidth share differs from connection weights: "
                                + "; ".join(drifted)
                                + " (PCC splits new sessions, not every byte)."
                            ),
                        }
                    )

    return alerts


def _record_ports_audit(
    request,
    *,
    action: str,
    router: MikroTikRouter,
    detail: dict | None = None,
) -> None:
    """Best-effort audit for WAN / uplink changes on the ports page."""
    try:
        from accounts.audit import record_audit

        record_audit(
            action=(action or "ports_change")[:64],
            request=request,
            target=f"mikrotik:{router.pk}:{router.name}",
            detail={
                "router_id": router.pk,
                "router_name": router.name,
                "host": router.host,
                **(detail or {}),
            },
        )
    except Exception:
        pass


def _wan_switch_confirmed(request, risk: dict) -> tuple[bool, str]:
    """Return whether a single-WAN port switch may proceed."""
    if risk.get("blocking"):
        return (
            False,
            risk.get("summary")
            or "This change cannot be applied until the issue is fixed.",
        )
    confirm_risk = (request.POST.get("confirm_risk") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    if not risk.get("safe") and not confirm_risk:
        return (
            False,
            "Confirm you understand the connection risk before switching the Internet port.",
        )
    return True, ""


def _current_primary_wan_port(router: MikroTikRouter) -> str:
    wan = (router.wan_interface or "").strip()
    if wan:
        return wan
    roles = router.port_roles if isinstance(router.port_roles, dict) else {}
    for name, role in roles.items():
        if _is_primary_wan_role(role):
            return (name or "").strip()
    return ""


def _build_uplink_prompt(
    router: MikroTikRouter,
    *,
    suggested_wan: str,
    live_ports: list[dict],
    management_iface_by_host: dict[str, str] | None,
) -> dict | None:
    """Return uplink detection payload when live WAN differs from stored Internet port."""
    suggested_wan = (suggested_wan or "").strip()
    if not suggested_wan:
        return None

    mode = (router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE).strip()
    if mode != MikroTikRouter.UplinkMode.SINGLE:
        return None

    current = _current_primary_wan_port(router)
    if not current or current == suggested_wan:
        return None

    by_name = {(p.get("name") or "").strip(): p for p in live_ports}
    new_row = by_name.get(suggested_wan)
    if not new_row:
        return None

    if not new_row.get("running") and not (new_row.get("uplink_kind") or "").strip():
        return None

    uses_tunnel = _router_uses_tunnel(router)
    risk = assess_uplink_switch_risk(
        new_wan=suggested_wan,
        old_wan=current,
        ports=live_ports,
        management_host=(router.host or "").strip(),
        tunnel_address=(router.vpn_address or "").strip(),
        management_iface_by_host=management_iface_by_host or {},
        uses_tunnel=uses_tunnel,
        tunnel_verified=_router_tunnel_verified(router),
    )

    kind = (new_row.get("uplink_kind") or "").strip()
    kind_label = {"pppoe": "PPPoE", "dhcp": "DHCP"}.get(kind, "link up")
    recovery_script = _build_wan_rollback_script(current, suggested_wan)

    return {
        "port": suggested_wan,
        "current_port": current,
        "uplink_kind": kind,
        "uplink_kind_label": kind_label,
        "running": bool(new_row.get("running")),
        "risk": risk,
        "recovery_script": recovery_script,
        "rollback_recovery_script": recovery_script,
        "message": (
            f"Internet detected on {suggested_wan} ({kind_label}). "
            f"Current Internet port is {current}."
        ),
    }


def _build_backup_uplink_prompt(
    router: MikroTikRouter,
    *,
    live_ports: list[dict],
    management_iface_by_host: dict[str, str] | None,
) -> dict | None:
    """Prompt when a second live ISP port is detected for failover/balance setups."""
    mode = (router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE).strip()
    if mode not in {
        MikroTikRouter.UplinkMode.FAILOVER,
        *_weighted_share_uplink_modes(),
    }:
        return None

    primary = _current_primary_wan_port(router)
    if not primary:
        return None

    roles = router.port_roles if isinstance(router.port_roles, dict) else {}
    uplink_ports = router.uplink_ports if isinstance(router.uplink_ports, list) else []
    known_backups = {
        name
        for name, role in roles.items()
        if (role or "").strip().lower() == MikroTikRouter.PortRole.WAN_BACKUP
    }
    for name in uplink_ports[1:]:
        known_backups.add(str(name).strip())

    by_name = {(p.get("name") or "").strip(): p for p in live_ports}
    candidate = ""
    candidate_row: dict = {}
    for row in live_ports:
        name = (row.get("name") or "").strip()
        if not name or name == primary or name in known_backups:
            continue
        if not (row.get("running") or (row.get("uplink_kind") or "").strip()):
            continue
        candidate = name
        candidate_row = row
        break

    if not candidate:
        return None

    uses_tunnel = _router_uses_tunnel(router)
    risk = assess_uplink_switch_risk(
        new_wan=candidate,
        old_wan=primary,
        ports=live_ports,
        management_host=(router.host or "").strip(),
        tunnel_address=(router.vpn_address or "").strip(),
        management_iface_by_host=management_iface_by_host or {},
        uses_tunnel=uses_tunnel,
        tunnel_verified=_router_tunnel_verified(router),
    )
    kind = (candidate_row.get("uplink_kind") or "").strip()
    kind_label = {"pppoe": "PPPoE", "dhcp": "DHCP"}.get(kind, "link up")
    mode_apply = (
        "failover"
        if mode == MikroTikRouter.UplinkMode.FAILOVER
        else "smart balance"
        if mode == MikroTikRouter.UplinkMode.SMART_BALANCE
        else "load balance"
    )

    return {
        "port": candidate,
        "current_port": primary,
        "uplink_kind": kind,
        "uplink_kind_label": kind_label,
        "running": bool(candidate_row.get("running")),
        "risk": risk,
        "kind": "add_backup",
        "message": (
            f"Second ISP detected on {candidate} ({kind_label}). "
            + (
                f"Mark it as Shared ISP, then apply {mode_apply}."
                if _is_weighted_share_mode(mode)
                else f"Mark it as Backup internet, then apply {mode_apply}."
            )
        ),
    }


def apply_detected_uplink(
    router: MikroTikRouter,
    port_name: str,
    live_ports: list[dict],
) -> dict:
    """Move Internet role to a newly detected uplink port and sync RouterOS WAN list."""
    port_name = (port_name or "").strip()
    if not port_name:
        return {"ok": False, "error": "No Internet port was selected."}

    old_wan = _current_primary_wan_port(router)
    by_name = {(p.get("name") or "").strip(): p for p in live_ports}
    if port_name not in by_name:
        return {"ok": False, "error": f"Port “{port_name}” was not found on the router."}

    roles = dict(router.port_roles) if isinstance(router.port_roles, dict) else {}

    if old_wan and old_wan != port_name:
        old_row = by_name.get(old_wan) or {}
        if (old_row.get("uplink_kind") or "").strip():
            roles[old_wan] = MikroTikRouter.PortRole.NONE
        elif old_row.get("is_bridged") or old_row.get("running"):
            roles[old_wan] = MikroTikRouter.PortRole.LAN
        else:
            roles[old_wan] = MikroTikRouter.PortRole.UNUSED

    for name, existing in list(roles.items()):
        if name == port_name:
            continue
        if _is_primary_wan_role(existing) or existing == MikroTikRouter.PortRole.BOND:
            roles[name] = MikroTikRouter.PortRole.NONE

    roles[port_name] = MikroTikRouter.PortRole.WAN
    router.port_roles = roles
    router.wan_interface = port_name
    router.uplink_mode = MikroTikRouter.UplinkMode.SINGLE
    router.uplink_ports = [port_name]
    router.save(
        update_fields=[
            "port_roles",
            "wan_interface",
            "uplink_mode",
            "uplink_ports",
            "updated_at",
        ]
    )

    kind = (by_name[port_name].get("uplink_kind") or "").strip()
    kind_note = {"pppoe": "PPPoE", "dhcp": "DHCP"}.get(kind, "live link")
    return {
        "ok": True,
        "wan": port_name,
        "old_wan": old_wan,
        "message": (
            f"Internet moved to {port_name} ({kind_note})"
            + (f" from {old_wan}." if old_wan and old_wan != port_name else ".")
        ),
    }


def apply_detected_backup(router: MikroTikRouter, port_name: str, live_ports: list[dict]) -> dict:
    """Mark a detected port as Backup internet without applying failover/balance yet."""
    port_name = (port_name or "").strip()
    if not port_name:
        return {"ok": False, "error": "No backup port was selected."}

    by_name = {(p.get("name") or "").strip(): p for p in live_ports}
    if port_name not in by_name:
        return {"ok": False, "error": f"Port “{port_name}” was not found on the router."}

    primary = _current_primary_wan_port(router)
    if port_name == primary:
        return {"ok": False, "error": "Choose a different port than the primary Internet port."}

    roles = dict(router.port_roles) if isinstance(router.port_roles, dict) else {}
    roles[port_name] = MikroTikRouter.PortRole.WAN_BACKUP
    router.port_roles = roles
    if primary:
        router.uplink_ports = [primary, port_name]
    router.save(update_fields=["port_roles", "uplink_ports", "updated_at"])
    return {
        "ok": True,
        "port": port_name,
        "message": f"{port_name} marked as Backup internet. Apply failover or load balance when ready.",
    }


def suggest_port_roles(
    ports: list[dict],
    *,
    suggested_wan: str = "",
    saved_wan: str = "",
) -> dict[str, str]:
    """
    Auto map ports for any ISP uplink:
    - one Internet (WAN) from default route / bridge-host gateway / PPPoE / live uplink
    - bridge members + Wi‑Fi → Customers (LAN), except the Internet port
    - disabled / quiet unused ports → Unused
    """
    roles: dict[str, str] = {}
    wan = _pick_auto_wan(ports, suggested_wan=suggested_wan, saved_wan=saved_wan)

    for row in ports:
        name = (row.get("name") or "").strip()
        if not name or _is_bond_port_row(row) or _is_bridge_port_name(name):
            continue
        if wan and name == wan:
            roles[name] = MikroTikRouter.PortRole.WAN
            continue
        if row.get("disabled"):
            roles[name] = MikroTikRouter.PortRole.UNUSED
            continue
        # Secondary live ISP uplinks stay unassigned so the operator can mark backup.
        if (
            (row.get("uplink_kind") or "") in {"pppoe", "dhcp"}
            and row.get("uplink_active")
            and name != wan
            and not row.get("is_bridged")
        ):
            roles[name] = MikroTikRouter.PortRole.NONE
            continue
        # Stale DHCP/PPPoE on a down, non-bridged port is unused — not a customer port.
        if (
            (row.get("uplink_kind") or "") in {"pppoe", "dhcp"}
            and not row.get("uplink_active")
            and not row.get("running")
            and not row.get("is_bridged")
        ):
            roles[name] = MikroTikRouter.PortRole.UNUSED
            continue
        if row.get("is_bridged") or row.get("is_wireless"):
            roles[name] = MikroTikRouter.PortRole.LAN
            continue
        if row.get("running"):
            roles[name] = MikroTikRouter.PortRole.LAN
        else:
            roles[name] = MikroTikRouter.PortRole.UNUSED
    return roles


def apply_suggested_port_roles(router: MikroTikRouter, ports: list[dict], *, suggested_wan: str = "") -> dict:
    """Persist auto-assigned roles and single-WAN uplink fields."""
    roles = suggest_port_roles(
        ports,
        suggested_wan=suggested_wan,
        saved_wan=router.wan_interface or "",
    )
    wan = next(
        (name for name, role in roles.items() if _is_primary_wan_role(role)),
        (router.wan_interface or "ether1").strip() or "ether1",
    )
    router.port_roles = roles
    router.wan_interface = wan
    router.uplink_mode = MikroTikRouter.UplinkMode.SINGLE
    router.uplink_ports = [wan] if wan else []
    router.save(
        update_fields=[
            "port_roles",
            "wan_interface",
            "uplink_mode",
            "uplink_ports",
            "updated_at",
        ]
    )
    lan_count = sum(1 for role in roles.values() if role == MikroTikRouter.PortRole.LAN)
    unused_count = sum(
        1 for role in roles.values() if role == MikroTikRouter.PortRole.UNUSED
    )
    return {
        "wan": wan,
        "lan_count": lan_count,
        "unused_count": unused_count,
        "roles": roles,
        "message": (
            f"Auto-assigned Internet on {wan}"
            + (f", {lan_count} customer port{'s' if lan_count != 1 else ''}" if lan_count else "")
            + (f", {unused_count} unused" if unused_count else "")
            + "."
        ),
    }


def _sync_roles_for_uplink(
    router: MikroTikRouter,
    *,
    mode: str,
    ports: list[str],
) -> dict[str, str]:
    """Rewrite uplink-related roles while keeping LAN / unused assignments."""
    roles = dict(router.port_roles) if isinstance(router.port_roles, dict) else {}
    uplink_role_values = {
        MikroTikRouter.PortRole.WAN,
        MikroTikRouter.PortRole.WAN_PRIMARY,
        MikroTikRouter.PortRole.WAN_BACKUP,
        MikroTikRouter.PortRole.BOND,
    }
    for name, existing in list(roles.items()):
        if existing in uplink_role_values:
            roles[name] = MikroTikRouter.PortRole.NONE

    if mode == MikroTikRouter.UplinkMode.BOND:
        for name in ports:
            roles[name] = MikroTikRouter.PortRole.BOND
    elif mode in {
        MikroTikRouter.UplinkMode.FAILOVER,
        *_weighted_share_uplink_modes(),
    } and ports:
        roles[ports[0]] = MikroTikRouter.PortRole.WAN
        for name in ports[1:]:
            roles[name] = MikroTikRouter.PortRole.WAN_BACKUP
    elif mode == MikroTikRouter.UplinkMode.SINGLE and ports:
        roles[ports[0]] = MikroTikRouter.PortRole.WAN
    return roles


def _ports_by_role(roles: dict, role: str) -> list[str]:
    # Preserve role-map insertion order (operator click order) — important for
    # bond primary slave and failover distance ranking.
    return [
        name
        for name, value in roles.items()
        if (value or "").strip().lower() == role
    ]


def _bond_ports_from_roles(router: MikroTikRouter) -> list[str]:
    roles = router.port_roles if isinstance(router.port_roles, dict) else {}
    return _ports_by_role(roles, MikroTikRouter.PortRole.BOND)


def _failover_ports_from_roles(router: MikroTikRouter) -> tuple[str, list[str]]:
    roles = router.port_roles if isinstance(router.port_roles, dict) else {}
    primary = ""
    backups: list[str] = []
    for name, value in roles.items():
        role = (value or "").strip().lower()
        if _is_primary_wan_role(role) and not primary:
            primary = name
        elif role == MikroTikRouter.PortRole.WAN_BACKUP:
            backups.append(name)
    return primary, backups




def client_page_context(request, *, active_nav: str, sidebar_active: str | None = None, **extra):
    employee = getattr(request.user, "employee_profile", None)
    viewing_client = bool(employee and is_viewing_as_client(request, employee))
    org = resolve_organization(request.user, request)
    is_owner = bool(org and (org.owner_id == request.user.id or viewing_client))
    # Org owners can edit their login via the topbar popup.
    can_edit_owner_profile = True
    sidebar = CLIENT_SIDEBARS.get(active_nav, CLIENT_SIDEBARS["workspace"])
    referral_enabled = bool(ClientSettings.get_solo().referral_enabled)
    nav = build_client_nav(active_nav, referral_enabled=referral_enabled)

    owner_profile_form = extra.pop("owner_profile_form", None)
    open_owner_profile_modal = bool(extra.pop("open_owner_profile_modal", False))
    if owner_profile_form is None and org and org.owner_id == request.user.id:
        owner_profile_form = OwnerProfileForm(
            user=request.user,
            organization=org,
            initial={
                "username": org.login_code if org else "",
                "first_name": request.user.first_name,
                "last_name": request.user.last_name,
                "email": request.user.email,
            },
        )

    ctx = {
        "organization": org,
        "is_owner": is_owner,
        "active_nav": active_nav,
        "sidebar_label": sidebar["label"],
        "sidebar_active": sidebar_active or active_nav,
        "client_nav_main": nav["main"],
        "client_nav_end": nav["end"],
        "referral_enabled": referral_enabled,
        "is_viewing_as_client": viewing_client,
        "can_switch_roles": can_switch_roles(employee) if employee else False,
        "can_access_client_portal": (
            can_access_client_portal(employee) if employee else False
        ),
        "can_edit_owner_profile": bool(owner_profile_form),
        "owner_profile_form": owner_profile_form,
        "open_owner_profile_modal": open_owner_profile_modal,
        "employee_profile": employee,
    }
    ctx.update(extra)
    return ctx


@client_workspace_required
def workspace(request):
    """Main ISPCENTRIC workspace home — live day analytics."""
    org = resolve_organization(request.user, request)
    snapshot = _workspace_day_snapshot(org)
    live_routers = cache.get(f"mikrotik_status:{org.pk}") if org else None
    try:
        from core.mikrotik_status_samples import (
            mikrotik_performance_drops,
            mikrotik_performance_trend,
            status_catalog,
        )

        snapshot["mikrotik_trend"] = mikrotik_performance_trend(org, hours=24)
        snapshot["mikrotik_drops"] = mikrotik_performance_drops(
            org, hours=24, live_routers=live_routers or []
        )
        snapshot["mikrotik_status_catalog"] = status_catalog()
    except Exception:
        snapshot["mikrotik_trend"] = {
            "ok": False,
            "labels": [],
            "datasets": [],
            "routers": [],
        }
        snapshot["mikrotik_drops"] = {"ok": False, "events": [], "current_count": 0}
        snapshot["mikrotik_status_catalog"] = {}
    try:
        from billing.usage_samples import (
            network_performance_drops,
            router_network_performance_trend,
        )

        snapshot["network_trend"] = router_network_performance_trend(org, hours=24)
        snapshot["network_drops"] = network_performance_drops(org, hours=24)
    except Exception:
        snapshot["network_trend"] = {
            "ok": False,
            "labels": [],
            "datasets": [],
            "routers": [],
            "summary": {"clients_online": 0, "peak_download_bps": 0},
        }
        snapshot["network_drops"] = {"ok": False, "events": [], "current_count": 0}
    referral_enabled = bool(ClientSettings.get_solo().referral_enabled)
    referral_count = 0
    referral_active_count = 0
    referral_pending_count = 0
    if referral_enabled and org:
        referred_qs = Organization.objects.filter(referred_by=org)
        referral_count = referred_qs.count()
        referral_active_count = referred_qs.filter(
            referral_status=Organization.ReferralStatus.ACTIVE
        ).count()
        referral_pending_count = referred_qs.filter(
            referral_status=Organization.ReferralStatus.PENDING
        ).count()
    return render(
        request,
        "core/workspace.html",
        client_page_context(
            request,
            active_nav="workspace",
            page_title="Dashboard",
            page_kicker="Live today",
            page_subtitle="Collections, renewals, and network health for today.",
            analytics=snapshot,
            analytics_json=json.dumps(snapshot),
            analytics_url=reverse("core:workspace_analytics"),
            mikrotik_status_url=reverse("core:mikrotik_status"),
            referral_count=referral_count,
            referral_active_count=referral_active_count,
            referral_pending_count=referral_pending_count,
        ),
    )


def _local_day_bounds():
    """Return (day_start, day_end, today_date) in the active timezone."""
    from datetime import timedelta

    from django.utils import timezone as dj_tz

    now = dj_tz.localtime()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return day_start, day_start + timedelta(days=1), now.date()


def _workspace_day_snapshot(org) -> dict:
    """Fast DB-backed analytics for the workspace dashboard (no MikroTik probes)."""
    from datetime import timedelta

    from django.utils import timezone as dj_tz

    day_start, day_end, today = _local_day_bounds()
    empty = {
        "ok": True,
        "day": today.isoformat(),
        "day_label": day_start.strftime("%A, %d %b %Y"),
        "customers": 0,
        "active_customers": 0,
        "pending_invoices": 0,
        "collected_today": 0,
        "payments_today": 0,
        "revenue_all_time": 0,
        "expired_count": 0,
        "expired_pppoe_count": 0,
        "expired_hotspot_count": 0,
        "expiring_count": 0,
        "attention_count": 0,
        "routers_total": 0,
        "routers_suspended": 0,
        "stk_pending": 0,
        "stk_failed_today": 0,
        "expired": [],
        "expiring": [],
        "recent_payments": [],
        "outages": [],
        "mikrotik": {
            "connected": 0,
            "total": 0,
            "score": None,
            "label": "Checking…",
            "online_ratio": None,
        },
    }
    if not org:
        empty["ok"] = False
        return empty

    customer_stats = Customer.objects.filter(organization=org).aggregate(
        customers=Count("id"),
        active_customers=Count(
            "id", filter=Q(status=Customer.Status.ACTIVE)
        ),
    )
    invoice_pending = (
        Invoice.objects.filter(
            organization=org, status=Invoice.Status.PENDING
        ).count()
    )
    revenue_all = (
        Payment.objects.filter(organization=org).aggregate(total=Sum("amount"))[
            "total"
        ]
        or 0
    )
    today_pay = Payment.objects.filter(
        organization=org,
        received_at__gte=day_start,
        received_at__lt=day_end,
    ).aggregate(total=Sum("amount"), count=Count("id"))
    recent_payments = list(
        Payment.objects.filter(
            organization=org,
            received_at__gte=day_start,
            received_at__lt=day_end,
        )
        .select_related("invoice", "invoice__customer")
        .order_by("-received_at")[:8]
    )
    attention = customers_needing_renewal_attention(org)
    expired_rows = [row for row in attention if row["attention"] == "expired"]
    expiring_rows = [
        row for row in attention if row["attention"] == "three_quarters"
    ]
    # Also treat packages ending within 2 calendar days as expiring if not already listed.
    soon = dj_tz.localtime() + timedelta(days=2)
    soon_ids = {row["customer"].pk for row in expiring_rows}
    for customer in (
        Customer.objects.filter(
            organization=org,
            package_end__isnull=False,
            package_end__lte=soon,
            package_end__gte=dj_tz.localtime(),
        )
        .select_related("plan")
        .order_by("package_end")[:40]
    ):
        if customer.pk in soon_ids:
            continue
        if customer_subscription_expired(customer):
            continue
        if any(row["customer"].pk == customer.pk for row in expired_rows):
            continue
        from billing.services import subscription_period_progress

        expiring_rows.append(
            {
                "customer": customer,
                "progress": subscription_period_progress(customer),
                "attention": "three_quarters",
            }
        )
        soon_ids.add(customer.pk)

    routers_total = MikroTikRouter.objects.filter(organization=org).count()
    routers_suspended = MikroTikRouter.objects.filter(
        organization=org,
        account_status=MikroTikRouter.AccountStatus.SUSPENDED,
    ).count()
    stk_pending = StkPushRequest.objects.filter(
        organization=org, status=StkPushRequest.Status.PENDING
    ).count()
    stk_failed_today = StkPushRequest.objects.filter(
        organization=org,
        status=StkPushRequest.Status.FAILED,
        created_at__gte=day_start,
        created_at__lt=day_end,
    ).count()

    def _attention_payload(rows, limit=48):
        out = []
        for row in rows[:limit]:
            customer = row["customer"]
            progress = row.get("progress") or {}
            out.append(
                {
                    "id": customer.pk,
                    "full_name": customer.full_name,
                    "account_number": customer.account_number,
                    "phone": customer.phone,
                    "service_type": customer.service_type or "",
                    "plan_name": customer.plan.name if customer.plan_id else "",
                    "plan_price": str(customer.plan.price)
                    if customer.plan_id and customer.plan.price is not None
                    else "",
                    "package_end": (
                        dj_tz.localtime(customer.package_end).strftime("%d %b %Y %H:%M")
                        if customer.package_end
                        else ""
                    ),
                    "percent": progress.get("percent"),
                    "attention": row.get("attention") or "",
                    "url": reverse(
                        "core:client_detail", kwargs={"customer_id": customer.pk}
                    ),
                }
            )
        return out

    expired_payload = _attention_payload(expired_rows)
    expired_pppoe_count = sum(
        1
        for row in expired_rows
        if getattr(row["customer"], "service_type", "")
        in (Customer.ServiceType.PPPOE, Customer.ServiceType.STATIC)
    )
    expired_hotspot_count = sum(
        1
        for row in expired_rows
        if getattr(row["customer"], "service_type", "")
        == Customer.ServiceType.HOTSPOT
    )

    return {
        "ok": True,
        "day": today.isoformat(),
        "day_label": day_start.strftime("%A, %d %b %Y"),
        "customers": customer_stats["customers"] or 0,
        "active_customers": customer_stats["active_customers"] or 0,
        "pending_invoices": invoice_pending,
        "collected_today": float(today_pay["total"] or 0),
        "payments_today": today_pay["count"] or 0,
        "revenue_all_time": float(revenue_all or 0),
        "expired_count": len(expired_rows),
        "expired_pppoe_count": expired_pppoe_count,
        "expired_hotspot_count": expired_hotspot_count,
        "expiring_count": len(expiring_rows),
        "attention_count": len(expired_rows) + len(expiring_rows),
        "routers_total": routers_total,
        "routers_suspended": routers_suspended,
        "stk_pending": stk_pending,
        "stk_failed_today": stk_failed_today,
        "expired": expired_payload,
        "expiring": _attention_payload(expiring_rows),
        "recent_payments": [
            {
                "id": pay.pk,
                "amount": float(pay.amount or 0),
                "method": pay.get_method_display(),
                "reference": pay.reference or "",
                "received_at": dj_tz.localtime(pay.received_at).strftime("%H:%M"),
                "customer_name": (
                    pay.invoice.customer.full_name
                    if pay.invoice_id and pay.invoice.customer_id
                    else "—"
                ),
                "customer_url": (
                    reverse(
                        "core:client_detail",
                        kwargs={"customer_id": pay.invoice.customer_id},
                    )
                    if pay.invoice_id and pay.invoice.customer_id
                    else ""
                ),
            }
            for pay in recent_payments
        ],
        "outages": [],
        "mikrotik": {
            "connected": 0,
            "total": routers_total,
            "score": None,
            "label": "Checking…",
            "online_ratio": None,
        },
    }


def _mikrotik_performance_from_status(routers: list[dict]) -> dict:
    """Derive outage list + average performance score from mikrotik_status rows."""
    if not routers:
        return {
            "connected": 0,
            "total": 0,
            "score": None,
            "label": "No routers",
            "online_ratio": None,
            "outages": [],
        }

    from core.mikrotik_status_samples import (
        _OUTAGE_STATUSES,
        _STATUS_SCORE,
        status_reason,
    )

    scores = []
    connected = 0
    outages = []
    for row in routers:
        status = (row.get("status") or "disconnected").strip().lower()
        scores.append(int(_STATUS_SCORE.get(status, 0)))
        if status == "connected":
            connected += 1
        if status in _OUTAGE_STATUSES:
            outages.append(
                {
                    "id": row.get("id"),
                    "name": row.get("name") or "MikroTik",
                    "host": row.get("host") or "",
                    "status": status,
                    "error": row.get("error") or "",
                    "reason": status_reason(status, row.get("error")),
                    "url": reverse(
                        "core:mikrotik_detail", kwargs={"router_id": row["id"]}
                    )
                    if row.get("id")
                    else reverse("core:mikrotik"),
                }
            )

    avg = round(sum(scores) / len(scores), 1) if scores else None
    if avg is None:
        label = "No routers"
    elif avg >= 85:
        label = "Excellent"
    elif avg >= 70:
        label = "Good"
    elif avg >= 45:
        label = "Fair"
    else:
        label = "Poor"

    return {
        "connected": connected,
        "total": len(routers),
        "score": avg,
        "label": label,
        "online_ratio": round((connected / len(routers)) * 100, 1) if routers else 0,
        "outages": outages,
    }


@client_workspace_required
@require_GET
def workspace_analytics(request):
    """Live dashboard payload for day money/renewals + MikroTik performance trend."""
    org = resolve_organization(request.user, request)
    snapshot = _workspace_day_snapshot(org)
    if not org:
        return JsonResponse(snapshot, status=400)

    routers = cache.get(f"mikrotik_status:{org.pk}")
    if routers is not None:
        perf = _mikrotik_performance_from_status(routers)
        snapshot["mikrotik"] = {
            "connected": perf["connected"],
            "total": perf["total"],
            "score": perf["score"],
            "label": perf["label"],
            "online_ratio": perf["online_ratio"],
        }
        snapshot["outages"] = perf["outages"]
    hours = 24
    try:
        hours = max(1, min(int(request.GET.get("hours") or 24), 168))
    except (TypeError, ValueError):
        hours = 24
    try:
        from core.mikrotik_status_samples import (
            mikrotik_performance_drops,
            mikrotik_performance_trend,
            status_catalog,
        )

        snapshot["mikrotik_trend"] = mikrotik_performance_trend(
            org, hours=hours, live_routers=routers or []
        )
        snapshot["mikrotik_drops"] = mikrotik_performance_drops(
            org, hours=hours, live_routers=routers or []
        )
        snapshot["mikrotik_status_catalog"] = status_catalog()
    except Exception:
        snapshot["mikrotik_trend"] = {
            "ok": False,
            "labels": [],
            "datasets": [],
            "routers": [],
        }
        snapshot["mikrotik_drops"] = {"ok": False, "events": [], "current_count": 0}
        snapshot["mikrotik_status_catalog"] = {}

    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    try:
        from billing.usage_samples import (
            network_performance_drops,
            router_network_performance_trend,
            sample_organization_usage,
        )

        # Never force the org-wide MikroTik usage sweep from the dashboard poll —
        # refresh=1 already re-probes router health elsewhere. Sampling stays
        # gated so back/focus navigation does not stall the previous page.
        try:
            sample_organization_usage(org, force=False)
        except Exception:
            pass
        snapshot["network_trend"] = router_network_performance_trend(
            org, hours=hours, use_cache=not force
        )
        snapshot["network_drops"] = network_performance_drops(org, hours=hours)
    except Exception:
        snapshot["network_trend"] = {
            "ok": False,
            "labels": [],
            "datasets": [],
            "routers": [],
            "summary": {"clients_online": 0, "peak_download_bps": 0},
        }
        snapshot["network_drops"] = {"ok": False, "events": [], "current_count": 0}

    return JsonResponse(snapshot)


def _mikrotik_list_routers(org):
    return (
        MikroTikRouter.objects.filter(organization=org)
        .annotate(customer_count=Count("customers"))
        .only(
            "id",
            "name",
            "model",
            "location",
            "location_lat",
            "location_lng",
            "host",
            "username",
            "wifi_ssid",
            "internet_provider",
            "account_status",
            "serial_number",
            "software_id",
        )
        .order_by("name")
        if org
        else MikroTikRouter.objects.none()
    )


def _find_router_by_hardware(
    org,
    *,
    serial_number: str = "",
    software_id: str = "",
    host: str = "",
):
    """Return an onboarded router that matches RouterBOARD serial, software-id, or host."""
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
    # Fallback for rows onboarded before serial capture existed.
    host_value = (host or "").strip()
    if host_value:
        return (
            MikroTikRouter.objects.filter(organization=org, host__iexact=host_value)
            .order_by("id")
            .first()
        )
    return None


def _apply_hardware_ids(router, *, serial_number: str = "", software_id: str = "") -> list[str]:
    """Copy serial / software-id onto the router; return changed field names."""
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


def _mikrotik_hardware_probe_hosts(
    *,
    connect_host: str = "",
    tunnel_host: str = "",
    session_host: str = "",
    target_host: str = "",
    router_host: str = "",
    discovered_host: str = "",
    lan_changed: bool = False,
    lan_result: dict | None = None,
) -> list[str]:
    """Order API dial targets after onboard — discovered/LAN first on a local PC."""
    lan_result = lan_result or {}
    lan_first = (
        discovered_host,
        connect_host,
        lan_result.get("verified_host"),
        lan_result.get("management_host"),
        session_host,
        target_host if not lan_changed else "",
        router_host,
    )
    tunnel_first = (tunnel_host,)
    ordered = (
        (*lan_first, *tunnel_first)
        if on_router_lan()
        else (*tunnel_first, *lan_first)
    )
    hosts: list[str] = []
    for host in ordered:
        host = normalize_mikrotik_host(host or "")
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def _probe_mikrotik_hardware(
    hosts: list[str],
    username: str,
    password: str,
    *,
    timeout: float = 5.0,
    attempts: int = 1,
) -> tuple[dict, str, str]:
    """Try API login on each host; return (result, session_host, last_error)."""
    last_error = ""
    for _ in range(max(1, attempts)):
        for host in hosts:
            result = test_mikrotik_api_login(
                host,
                username,
                password,
                timeout=timeout,
            )
            if result.get("ok"):
                return result, host, ""
            last_error = result.get("error") or last_error
        if attempts > 1:
            time.sleep(0.6)
    return {"ok": False}, "", last_error


def _render_mikrotik_list(
    request,
    *,
    org,
    routers=None,
    onboard_form=None,
    edit_form=None,
    open_onboard=False,
    open_edit=False,
    editing_router_id=None,
):
    client_settings = ClientSettings.get_solo()
    router_qs = routers if routers is not None else _mikrotik_list_routers(org)
    router_list = list(router_qs)
    suspended_count = sum(
        1 for r in router_list if getattr(r, "account_status", "") == "suspended"
    )
    active_count = len(router_list) - suspended_count
    try:
        from core.mikrotik_connect import hotspot_unlock_commands

        hotspot_unlock = hotspot_unlock_commands()
    except Exception:
        hotspot_unlock = {
            "commands": "",
            "preferred_ip": "",
            "local_ips": [],
        }
    return render(
        request,
        "core/mikrotik.html",
        client_page_context(
            request,
            active_nav="mikrotik",
            page_title="MikroTik",
            page_subtitle="Manage MikroTik routers, interfaces, and device health for this ISP.",
            routers=router_list,
            routers_total=len(router_list),
            routers_active=active_count,
            routers_suspended=suspended_count,
            onboard_form=onboard_form or MikroTikOnboardForm(),
            edit_form=edit_form or MikroTikEditDetailsForm(),
            mikrotik_models=mikrotik_model_catalog(),
            open_mikrotik_onboard=open_onboard,
            open_mikrotik_edit=open_edit,
            editing_router_id=editing_router_id,
            wireguard_ready=wireguard.configured(),
            hosted_server=bool(getattr(settings, "HOSTED", False)),
            onboarding_fee_enabled=client_settings.onboarding_fee_ready,
            onboarding_fee_amount=str(client_settings.onboarding_fee_amount or "0"),
            hotspot_unlock=hotspot_unlock,
        ),
    )


@client_workspace_required
def mikrotik(request):
    org = resolve_organization(request.user, request)
    routers = _mikrotik_list_routers(org)
    form = MikroTikOnboardForm()
    open_onboard = False

    if request.method == "POST":
        form = MikroTikOnboardForm(request.POST)
        if not org:
            messages.error(request, "No organization is linked to this workspace.")
            return redirect("core:mikrotik")
        from core.mikrotik_status_samples import mark_mikrotik_onboarding_active

        mark_mikrotik_onboarding_active(
            org.pk, user_id=request.user.pk, org_wide=True
        )
        if form.is_valid():
            router = form.save(commit=False)
            router.organization = org
            wifi_ssid = (router.wifi_ssid or "").strip()
            wifi_password = router.wifi_password or ""
            original_ssid = (request.POST.get("wifi_ssid_original") or "").strip()
            original_password = request.POST.get("wifi_password_original") or ""
            wifi_mode = (request.POST.get("wifi_mode") or "").strip()
            apply_ssid = wifi_ssid != original_ssid
            apply_password = wifi_password != original_password
            wants_wifi = bool(wifi_ssid or wifi_password)
            wifi_changed = apply_ssid or apply_password
            wifi_result = None

            connect_host = normalize_mikrotik_host(
                request.POST.get("host_original") or ""
            )
            tunnel_host = normalize_mikrotik_host(
                request.POST.get("tunnel_address") or ""
            )
            target_host = normalize_mikrotik_host(router.host)
            lan_ip_applied_at_connect = (
                request.POST.get("lan_ip_applied") or ""
            ).strip() == "1"
            session_host = connect_host or target_host
            api_hosts = [
                host
                for host in (tunnel_host, connect_host, target_host)
                if host
            ]

            script_lan = ""
            if tunnel_host:
                reservation = WireGuardReservation.objects.filter(
                    address=tunnel_host
                ).first()
                if reservation:
                    script_lan = (reservation.lan_address or "").strip()

            # One management IP for the whole onboard flow — assigned at Connect
            # (or by the Winbox script) and saved unchanged here.
            lan_changed = False
            lan_result: dict = {}
            if script_lan:
                discovered_save = discover_local_mikrotik_host(
                    tunnel_address=tunnel_host,
                    reservation_label=(reservation.label if reservation else ""),
                    prefer_host=connect_host or script_lan,
                )
                router.host = normalize_mikrotik_host(
                    discovered_save or connect_host or script_lan
                )
                if tunnel_host:
                    router.vpn_address = tunnel_host
                target_host = router.host
                session_host = connect_host or router.host
                api_hosts = [
                    host
                    for host in (tunnel_host, connect_host, script_lan, target_host)
                    if host
                ]
                messages.info(
                    request,
                    (
                        f"MikroTik LAN IP {router.host} saved"
                        + (
                            f" (remote tunnel {tunnel_host})"
                            if tunnel_host and tunnel_host != router.host
                            else ""
                        )
                        + "."
                    ),
                )
            elif lan_ip_applied_at_connect or (
                connect_host and target_host and connect_host == target_host
            ):
                router.host = target_host or connect_host
                target_host = router.host
                session_host = connect_host or target_host
                if lan_ip_applied_at_connect:
                    messages.info(
                        request,
                        f"MikroTik management IP {router.host} was set during Connect.",
                    )
            elif is_transient_onboard_host(connect_host) or is_transient_onboard_host(
                target_host
            ):
                if not connect_host:
                    form.add_error(
                        "host",
                        "Reconnect to the MikroTik, then Connect again.",
                    )
                    open_onboard = True
                    messages.error(request, str(next(iter(form.errors.values()))[0]))
                    return _render_mikrotik_list(
                        request,
                        org=org,
                        routers=routers,
                        onboard_form=form,
                        open_onboard=True,
                    )
                lan_result = change_mikrotik_lan_ip(
                    connect_host,
                    router.username,
                    router.password,
                    target_host,
                    api_hosts=api_hosts,
                )
                if not lan_result.get("ok"):
                    form.add_error(
                        "host",
                        lan_result.get("error")
                        or "Could not change the MikroTik LAN IP.",
                    )
                    open_onboard = True
                    messages.error(request, str(next(iter(form.errors.values()))[0]))
                    return _render_mikrotik_list(
                        request,
                        org=org,
                        routers=routers,
                        onboard_form=form,
                        open_onboard=True,
                    )
                lan_changed = True
                router.host = resolve_onboard_management_host(
                    connect_host=connect_host,
                    tunnel_host=tunnel_host,
                    lan_result=lan_result,
                    fallback=target_host,
                )
                target_host = router.host
                session_host = (
                    lan_result.get("verified_host")
                    or tunnel_host
                    or lan_result.get("management_host")
                    or connect_host
                    or target_host
                )
                if tunnel_host and not (router.vpn_address or "").strip():
                    router.vpn_address = tunnel_host
                messages.info(
                    request,
                    f"MikroTik management IP set to {router.host}.",
                )
            elif connect_host and target_host and connect_host != target_host:
                lan_result = change_mikrotik_lan_ip(
                    connect_host,
                    router.username,
                    router.password,
                    target_host,
                    api_hosts=api_hosts,
                )
                if not lan_result.get("ok"):
                    form.add_error(
                        "host",
                        lan_result.get("error")
                        or "Could not change the MikroTik LAN IP.",
                    )
                    open_onboard = True
                    messages.error(request, str(next(iter(form.errors.values()))[0]))
                    return _render_mikrotik_list(
                        request,
                        org=org,
                        routers=routers,
                        onboard_form=form,
                        open_onboard=True,
                    )
                lan_changed = True
                router.host = resolve_onboard_management_host(
                    connect_host=connect_host,
                    tunnel_host=tunnel_host,
                    lan_result=lan_result,
                    fallback=target_host,
                )
                target_host = router.host
                session_host = (
                    lan_result.get("verified_host")
                    or tunnel_host
                    or lan_result.get("management_host")
                    or connect_host
                    or target_host
                )
                if tunnel_host and not (router.vpn_address or "").strip():
                    router.vpn_address = tunnel_host

            # Read hardware IDs so we can detect the same physical MikroTik.
            # Prefer the path Connect already proved (and tunnel) — never dial the
            # brand-new LAN subnet first (this PC often cannot route there yet).
            connect_serial = (request.POST.get("connect_serial_number") or "").strip()
            connect_software_id = (request.POST.get("connect_software_id") or "").strip()
            reservation = (
                WireGuardReservation.objects.filter(address=tunnel_host).first()
                if tunnel_host
                else None
            )
            discovered_lan = discover_local_mikrotik_host(
                tunnel_address=tunnel_host,
                reservation_label=(reservation.label if reservation else ""),
                prefer_host=connect_host or target_host,
            )
            if discovered_lan:
                discovered_lan = normalize_mikrotik_host(discovered_lan)
                if discovered_lan != connect_host:
                    connect_host = discovered_lan
                    session_host = discovered_lan
                planned = normalize_mikrotik_host(script_lan or target_host or "")
                if not planned or planned == "192.168.88.1" or planned != discovered_lan:
                    router.host = discovered_lan
                    target_host = discovered_lan
            lan_result_data = lan_result if lan_changed else {}
            hardware_hosts = _mikrotik_hardware_probe_hosts(
                connect_host=connect_host,
                tunnel_host=tunnel_host,
                session_host=session_host,
                target_host=target_host,
                router_host=router.host,
                discovered_host=discovered_lan,
                lan_changed=lan_changed,
                lan_result=lan_result_data,
            )
            hardware, probe_host, last_hardware_error = _probe_mikrotik_hardware(
                hardware_hosts,
                router.username,
                router.password,
                timeout=8.0 if lan_changed else 5.0,
                attempts=3 if lan_changed else 1,
            )
            if hardware.get("ok"):
                session_host = probe_host or session_host
            serial_number = ""
            software_id = ""
            if not hardware.get("ok"):
                if lan_changed and lan_result_data.get("ok"):
                    serial_number = (
                        (lan_result_data.get("serial_number") or "").strip()
                        or connect_serial
                    )
                    software_id = (
                        (lan_result_data.get("software_id") or "").strip()
                        or connect_software_id
                    )
                    if serial_number or software_id:
                        hardware = {"ok": True}
                        session_host = (
                            tunnel_host
                            or lan_result_data.get("verified_host")
                            or lan_result_data.get("management_host")
                            or connect_host
                            or session_host
                        )
                        messages.info(
                            request,
                            (
                                f"MikroTik LAN IP set to {router.host}. "
                                "This PC cannot reach the router on API port 8728 right now — "
                                "hardware IDs were taken from the Connect step. "
                                "Use the WireGuard tunnel IP for management until your PC is on the new LAN."
                            ),
                        )
            if hardware.get("ok"):
                serial_number = (
                    serial_number
                    or (hardware.get("serial_number") or "").strip()
                )
                software_id = (
                    software_id or (hardware.get("software_id") or "").strip()
                )
            if not hardware.get("ok"):
                tried = ", ".join(hardware_hosts) if hardware_hosts else "(none)"
                lan_hint = (discovered_lan or connect_host or router.host or "192.168.88.1").strip()
                extra = ""
                if tunnel_host and on_router_lan():
                    if discovered_lan and discovered_lan != (script_lan or "192.168.88.1"):
                        extra = (
                            f" This router was found at {discovered_lan} on your network — "
                            f"Connect there (not {script_lan or '192.168.88.1'}). "
                            f"Tunnel {tunnel_host} is only reachable from the VPS."
                        )
                    else:
                        extra = (
                            f" From this PC, Connect at the LAN IP ({lan_hint}) first — "
                            f"tunnel {tunnel_host} is only reachable from the VPS."
                        )
                form.add_error(
                    "host",
                    (
                        f"{last_hardware_error or 'Could not reach this MikroTik on API port 8728.'} "
                        f"Tried: {tried}.{extra}"
                    ),
                )
                open_onboard = True
                messages.error(request, str(next(iter(form.errors.values()))[0]))
                return _render_mikrotik_list(
                    request,
                    org=org,
                    routers=routers,
                    onboard_form=form,
                    open_onboard=True,
                )

            serial_number = (hardware.get("serial_number") or "").strip()
            software_id = (hardware.get("software_id") or "").strip()
            if not serial_number and not software_id:
                form.add_error(
                    "host",
                    "Could not read this MikroTik’s serial number. Enable RouterOS API and try again.",
                )
                open_onboard = True
                messages.error(request, str(next(iter(form.errors.values()))[0]))
                return _render_mikrotik_list(
                    request,
                    org=org,
                    routers=routers,
                    onboard_form=form,
                    open_onboard=True,
                )

            existing = _find_router_by_hardware(
                org,
                serial_number=serial_number,
                software_id=software_id,
                host=router.host,
            )
            if existing:
                form.add_error(
                    "host",
                    (
                        f'This MikroTik is already onboarded as “{existing.name}”. '
                        f"Open it from the list or use Reconnect — you cannot register the same device twice."
                    ),
                )
                open_onboard = True
                messages.error(request, str(next(iter(form.errors.values()))[0]))
                return _render_mikrotik_list(
                    request,
                    org=org,
                    routers=routers,
                    onboard_form=form,
                    open_onboard=True,
                )

            _apply_hardware_ids(
                router, serial_number=serial_number, software_id=software_id
            )

            # Wi‑Fi must succeed before the router record is saved.
            if wants_wifi and wifi_changed:
                if wifi_password and not wifi_ssid:
                    form.add_error("wifi_ssid", "Enter a Wi‑Fi name when setting a Wi‑Fi password.")
                elif apply_password and wifi_password and len(wifi_password) < 8:
                    form.add_error("wifi_password", "Wi‑Fi password must be at least 8 characters.")
                else:
                    wifi_host = tunnel_host or session_host
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
                        form.add_error(
                            "wifi_ssid",
                            wifi_result.get("error") or "Could not apply Wi‑Fi settings on the router.",
                        )

                if form.errors:
                    open_onboard = True
                    first_error = next(iter(form.errors.values()))
                    messages.error(request, str(first_error[0]))
                    return _render_mikrotik_list(
                        request,
                        org=org,
                        routers=routers,
                        onboard_form=form,
                        open_onboard=True,
                    )
                if wifi_result and wifi_result.get("updated"):
                    messages.success(
                        request,
                        f"MikroTik “{router.name}” onboarded and Wi‑Fi updated.",
                    )
                else:
                    messages.success(request, f"MikroTik “{router.name}” onboarded.")
            else:
                messages.success(request, f"MikroTik “{router.name}” onboarded.")

            finalize_onboard_addresses(
                router,
                lan_host=router.host,
                tunnel_host=tunnel_host,
            )
            router.save()
            # If Connect used a reserved tunnel address, attach that WireGuard peer.
            wireguard.adopt_reservation_for_router(router)
            # First MikroTik for a referred ISP → active referral.
            if org and org.referred_by_id:
                was_first = (
                    MikroTikRouter.objects.filter(organization=org)
                    .exclude(pk=router.pk)
                    .count()
                    == 0
                )
                if was_first and org.mark_referral_active():
                    messages.info(
                        request,
                        "Referral marked active — your first MikroTik is onboarded.",
                    )
            router_pk = router.pk

            try:
                from core.hotspot_portal import public_base_url, remember_org_portal_base

                remember_org_portal_base(org.pk, public_base_url(request))
            except Exception:
                pass

            schedule_post_onboard_nas_refresh(
                router,
                organization_id=org.pk,
                user_id=request.user.pk,
                tunnel=bool((router.vpn_address or tunnel_host or "").strip()),
            )
            if org and getattr(org, "pppoe_compulsory", False):
                messages.info(
                    request,
                    "Latest PPPoE and Hotspot settings are being applied on this MikroTik "
                    "in the background — paid PPPoE clients surf automatically; other "
                    "devices use Hotspot.",
                )
            elif org and getattr(org, "hotspot_enabled", False):
                messages.info(
                    request,
                    "Latest Hotspot settings are being applied on this MikroTik in the "
                    "background.",
                )
            return _redirect_with_mikrotik_job(
                request, "core:mikrotik_detail", router.pk, "nas_refresh"
            )
        open_onboard = True
        first_error = next(iter(form.errors.values()), None)
        detail = first_error[0] if first_error else "Check the onboard form and try again."
        messages.error(request, str(detail))

    return _render_mikrotik_list(
        request,
        org=org,
        routers=routers,
        onboard_form=form,
        open_onboard=open_onboard,
    )


@client_workspace_required
@require_http_methods(["GET", "POST"])
def mikrotik_edit(request, router_id: int):
    """Edit name, model, location, and credentials from the routers list."""
    org = resolve_organization(request.user, request)
    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect("core:mikrotik")

    router = get_object_or_404(MikroTikRouter, pk=router_id, organization=org)

    if request.method == "GET":
        return _render_mikrotik_list(
            request,
            org=org,
            edit_form=MikroTikEditDetailsForm(instance=router),
            open_edit=True,
            editing_router_id=router.pk,
        )

    edit_form = MikroTikEditDetailsForm(request.POST, instance=router)
    if edit_form.is_valid():
        cleaned = edit_form.cleaned_data
        login_changed = _mikrotik_login_credentials_changed(router, cleaned)
        if login_changed and router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
            edit_form.add_error(
                None,
                "Activate this MikroTik account before changing login credentials.",
            )
            return _render_mikrotik_list(
                request,
                org=org,
                edit_form=edit_form,
                open_edit=True,
                editing_router_id=router.pk,
            )

        if login_changed:
            new_host = cleaned.get("host") or ""
            new_username = cleaned.get("username") or ""
            new_password = cleaned.get("password") or ""
            if _background_mikrotik_ops():
                edit_form.save()
                cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
                return _schedule_mikrotik_login_credentials(
                    request,
                    router,
                    org,
                    new_host=new_host,
                    new_username=new_username,
                    new_password=new_password,
                    redirect_url_name="core:mikrotik",
                )

            apply_result = _apply_mikrotik_login_credentials(
                router,
                org,
                new_host=new_host,
                new_username=new_username,
                new_password=new_password,
            )
            if not apply_result.get("ok"):
                edit_form.add_error(
                    None,
                    apply_result.get("error")
                    or "Could not update login credentials on the MikroTik.",
                )
                return _render_mikrotik_list(
                    request,
                    org=org,
                    edit_form=edit_form,
                    open_edit=True,
                    editing_router_id=router.pk,
                )

        edit_form.save()
        cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
        messages.success(request, f"Updated “{router.name}”.")
        return redirect("core:mikrotik")

    first_error = next(iter(edit_form.errors.values()), None)
    if first_error:
        messages.error(request, str(first_error[0]))
    return _render_mikrotik_list(
        request,
        org=org,
        edit_form=edit_form,
        open_edit=True,
        editing_router_id=router.pk,
    )


@client_workspace_required
@require_http_methods(["GET", "POST"])
def mikrotik_delete(request, router_id: int):
    """Remove an onboarded MikroTik from this organization."""
    org = resolve_organization(request.user, request)
    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect("core:mikrotik")

    router = get_object_or_404(MikroTikRouter, pk=router_id, organization=org)

    if request.method == "GET":
        return redirect("core:mikrotik")

    name = router.name
    router_pk = router.pk
    router.delete()
    cache.delete(f"mikrotik_live:{org.pk}:{router_pk}")
    cache.delete(_wifi_fields_cache_key(org.pk, router_pk))
    messages.success(
        request,
        f"Deleted “{name}” from this workspace. Linked clients were kept and unassigned.",
    )
    return redirect("core:mikrotik")


@client_workspace_required
@require_http_methods(["GET", "POST"])
def mikrotik_suspend(request, router_id: int):
    """Suspend or activate a MikroTik account from the routers list."""
    org = resolve_organization(request.user, request)
    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect("core:mikrotik")

    router = get_object_or_404(MikroTikRouter, pk=router_id, organization=org)

    if request.method == "GET":
        return redirect("core:mikrotik")

    form = MikroTikSuspendForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Confirm to continue.")
        return redirect("core:mikrotik")

    if router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
        router.account_status = MikroTikRouter.AccountStatus.ACTIVE
        router.save(update_fields=["account_status", "updated_at"])
        messages.success(request, f"“{router.name}” account activated.")
    else:
        router.account_status = MikroTikRouter.AccountStatus.SUSPENDED
        router.save(update_fields=["account_status", "updated_at"])
        messages.success(request, f"“{router.name}” account suspended.")

    cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
    return redirect("core:mikrotik")


def _wifi_fields_cache_key(org_id: int, router_id: int) -> str:
    return f"mikrotik_wifi_fields:{org_id}:{router_id}"


def sync_router_wifi_from_live(router: MikroTikRouter) -> tuple[MikroTikRouter, dict]:
    """Fill Wi‑Fi name/password from the live MikroTik when readable."""
    empty = {
        "wifi_ssid": "",
        "wifi_password": "",
        "wifi_mode": "",
        "wifi_enabled": False,
        "interface_count": 0,
    }
    if router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
        return router, empty
    if not (router.host or "").strip() or not (router.username or "").strip():
        return router, empty

    cache_key = _wifi_fields_cache_key(router.organization_id, router.pk)
    live = cache.get(cache_key)
    if live is None:
        live = read_mikrotik_wifi(
            router.host,
            router.username,
            router.password or "",
            timeout=4.0,
        )
        cache.set(cache_key, live, 90)

    ssid = (live.get("wifi_ssid") or "").strip()
    password = live.get("wifi_password") or ""
    update_fields: list[str] = []
    if ssid and ssid != (router.wifi_ssid or ""):
        router.wifi_ssid = ssid
        update_fields.append("wifi_ssid")
    if password and password != (router.wifi_password or ""):
        router.wifi_password = password
        update_fields.append("wifi_password")
    if update_fields:
        update_fields.append("updated_at")
        router.save(update_fields=update_fields)
    return router, live


@client_workspace_required
def mikrotik_detail(request, router_id: int):
    """View onboarded MikroTik router details for the active organization."""
    org = resolve_organization(request.user, request)
    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect("core:mikrotik")

    router = get_object_or_404(MikroTikRouter, pk=router_id, organization=org)
    is_suspended = router.account_status == MikroTikRouter.AccountStatus.SUSPENDED

    job_type = (request.GET.get("job") or "").strip()
    if request.method == "GET" and job_type == NAS_REFRESH_JOB and not is_suspended:
        ensure_nas_refresh_job(router.pk)

    # Live Wi‑Fi probe is deferred to mikrotik_wifi (AJAX) so the page paints fast.
    wifi_enabled = False
    wifi_ssid_display = (router.wifi_ssid or "").strip()
    wifi_password_display = router.wifi_password or ""
    wifi_checking = not is_suspended

    edit_form = MikroTikEditDetailsForm(instance=router)
    credentials_form = MikroTikCredentialsForm(instance=router)
    wifi_form = MikroTikWifiToggleForm()
    clean_uplink_enabled = bool(router.clean_uplink_enabled)
    open_modal = ""

    # Detail sidebar: overview + ports + modal actions (labels flip with state).
    detail_nav = build_mikrotik_detail_nav(
        router,
        wifi_enabled=wifi_enabled,
        clean_uplink_enabled=clean_uplink_enabled,
        is_suspended=is_suspended,
    )

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action == "edit_details":
            edit_form = MikroTikEditDetailsForm(request.POST, instance=router)
            if edit_form.is_valid():
                cleaned = edit_form.cleaned_data
                login_changed = _mikrotik_login_credentials_changed(router, cleaned)
                if login_changed and is_suspended:
                    edit_form.add_error(
                        None,
                        "Activate this MikroTik account before changing login credentials.",
                    )
                    open_modal = "mikrotik-edit-modal"
                elif login_changed:
                    new_host = cleaned.get("host") or ""
                    new_username = cleaned.get("username") or ""
                    new_password = cleaned.get("password") or ""
                    if _background_mikrotik_ops():
                        edit_form.save()
                        cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
                        return _schedule_mikrotik_login_credentials(
                            request,
                            router,
                            org,
                            new_host=new_host,
                            new_username=new_username,
                            new_password=new_password,
                            redirect_url_name="core:mikrotik_detail",
                        )

                    apply_result = _apply_mikrotik_login_credentials(
                        router,
                        org,
                        new_host=new_host,
                        new_username=new_username,
                        new_password=new_password,
                    )
                    if not apply_result.get("ok"):
                        edit_form.add_error(
                            None,
                            apply_result.get("error")
                            or "Could not update login credentials on the MikroTik.",
                        )
                        open_modal = "mikrotik-edit-modal"
                    else:
                        edit_form.save()
                        cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
                        messages.success(request, "MikroTik details updated.")
                        return redirect("core:mikrotik_detail", router_id=router.pk)
                else:
                    edit_form.save()
                    cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
                    messages.success(request, "MikroTik details updated.")
                    return redirect("core:mikrotik_detail", router_id=router.pk)
            else:
                open_modal = "mikrotik-edit-modal"
        elif action == "change_credentials":
            if is_suspended:
                messages.error(
                    request,
                    "Activate this MikroTik account before changing Wi‑Fi credentials.",
                )
                return redirect("core:mikrotik_detail", router_id=router.pk)

            current_host = router.host
            current_username = router.username
            current_password = router.password
            current_wifi_ssid = router.wifi_ssid or ""
            current_wifi_password = router.wifi_password or ""
            credentials_form = MikroTikCredentialsForm(request.POST, instance=router)
            if credentials_form.is_valid():
                cleaned = credentials_form.cleaned_data

                def _apply_wifi_credentials():
                    result = apply_mikrotik_access_changes(
                        current_host=current_host,
                        current_username=current_username,
                        current_password=current_password,
                        current_wifi_ssid=current_wifi_ssid,
                        current_wifi_password=current_wifi_password,
                        new_host=current_host,
                        new_username=current_username,
                        new_password=current_password,
                        new_wifi_ssid=cleaned.get("wifi_ssid") or "",
                        new_wifi_password=cleaned.get("wifi_password") or "",
                    )
                    if result.get("ok"):
                        live = MikroTikRouter.objects.get(pk=router.pk)
                        if cleaned.get("wifi_ssid"):
                            live.wifi_ssid = cleaned.get("wifi_ssid") or live.wifi_ssid
                        if cleaned.get("wifi_password"):
                            live.wifi_password = (
                                cleaned.get("wifi_password") or live.wifi_password
                            )
                        live.save(
                            update_fields=[
                                "wifi_ssid",
                                "wifi_password",
                                "updated_at",
                            ]
                        )
                        _invalidate_mikrotik_router_caches(org.pk, router.pk)
                    return result

                if _background_mikrotik_ops():
                    set_job(router.pk, "credentials", "pending")
                    schedule_mikrotik_job(
                        _apply_wifi_credentials,
                        name=f"credentials-{router.pk}",
                        router_id=router.pk,
                        job_type="credentials",
                    )
                    messages.success(
                        request,
                        "Updating Wi‑Fi credentials on the MikroTik in the background. "
                        "This page will show progress shortly.",
                    )
                    return _redirect_with_mikrotik_job(
                        request, "core:mikrotik_detail", router.pk, "credentials"
                    )

                apply_result = _apply_wifi_credentials()
                if not apply_result.get("ok"):
                    credentials_form.add_error(
                        None,
                        apply_result.get("error")
                        or "Could not update Wi‑Fi credentials on the MikroTik.",
                    )
                    open_modal = "mikrotik-credentials-modal"
                else:
                    messages.success(
                        request,
                        apply_result.get("message")
                        or "Wi‑Fi credentials updated on the MikroTik.",
                    )
                    return redirect("core:mikrotik_detail", router_id=router.pk)
            else:
                open_modal = "mikrotik-credentials-modal"
        elif action == "toggle_wifi":
            if is_suspended:
                messages.error(
                    request,
                    "Activate this MikroTik account before changing Wi‑Fi.",
                )
                return redirect("core:mikrotik_detail", router_id=router.pk)

            wifi_form = MikroTikWifiToggleForm(request.POST)
            if wifi_form.is_valid():
                api_host = _router_api_host(router)

                def _toggle_wifi():
                    result = toggle_mikrotik_wifi(
                        api_host,
                        router.username,
                        router.password or "",
                        wifi_ssid=router.wifi_ssid or "",
                        wifi_password=router.wifi_password or "",
                    )
                    if result.get("ok"):
                        ssid = (result.get("wifi_ssid") or "").strip()
                        password = result.get("wifi_password") or ""
                        update_fields: list[str] = []
                        live = MikroTikRouter.objects.get(pk=router.pk)
                        if ssid and ssid != (live.wifi_ssid or ""):
                            live.wifi_ssid = ssid
                            update_fields.append("wifi_ssid")
                        if password and password != (live.wifi_password or ""):
                            live.wifi_password = password
                            update_fields.append("wifi_password")
                        if update_fields:
                            update_fields.append("updated_at")
                            live.save(update_fields=update_fields)
                        cache.delete_many(
                            [
                                f"mikrotik_live:{org.pk}:{router.pk}",
                                _wifi_fields_cache_key(org.pk, router.pk),
                            ]
                        )
                    return result

                if _background_mikrotik_ops():
                    set_job(router.pk, "wifi", "pending")
                    schedule_mikrotik_job(
                        _toggle_wifi,
                        name=f"wifi-{router.pk}",
                        router_id=router.pk,
                        job_type="wifi",
                    )
                    messages.success(
                        request,
                        "Updating Wi‑Fi on the MikroTik in the background. "
                        "This page will show progress shortly.",
                    )
                    return _redirect_with_mikrotik_job(
                        request, "core:mikrotik_detail", router.pk, "wifi"
                    )

                result = _toggle_wifi()
                if not result.get("ok"):
                    wifi_form.add_error(
                        None,
                        result.get("error") or "Could not update Wi‑Fi on the MikroTik.",
                    )
                    wifi_enabled = bool(result.get("wifi_enabled"))
                    open_modal = "mikrotik-wifi-modal"
                else:
                    messages.success(
                        request,
                        result.get("message") or "Wi‑Fi updated on the MikroTik.",
                    )
                    return redirect("core:mikrotik_detail", router_id=router.pk)
            else:
                open_modal = "mikrotik-wifi-modal"

    # Keep sidebar labels in sync if a failed POST left the modal open.
    detail_nav = build_mikrotik_detail_nav(
        router,
        wifi_enabled=wifi_enabled,
        clean_uplink_enabled=clean_uplink_enabled,
        is_suspended=is_suspended,
    )

    ctx = client_page_context(
        request,
        active_nav="mikrotik_detail",
        sidebar_active="overview",
        page_title=router.name,
        page_subtitle="Router details and connection settings for this MikroTik.",
        router=router,
        router_model_image=mikrotik_model_image(router.model),
        edit_form=edit_form,
        credentials_form=credentials_form,
        wifi_form=wifi_form,
        open_mikrotik_modal=open_modal,
        is_suspended=is_suspended,
        wifi_enabled=wifi_enabled,
        wifi_checking=wifi_checking,
        wifi_ssid_display=wifi_ssid_display,
        wifi_password_display=wifi_password_display,
        wifi_live_url=(
            reverse("core:mikrotik_wifi", args=[router.pk]) if wifi_checking else ""
        ),
        clean_uplink_enabled=clean_uplink_enabled,
        mikrotik_models=mikrotik_model_catalog(),
    )
    # Replace middle nav with detail-only actions (keep Dashboard + settings/logout).
    ctx["client_nav_main"] = [
        *CLIENT_COMMON_NAV_START,
        *detail_nav,
    ]
    ctx["sidebar_label"] = "MikroTik"
    from core.mikrotik_auto_restore import get_auto_restore_record

    ctx["auto_restore"] = get_auto_restore_record(router.pk)
    initial_live = None
    if not is_suspended:
        initial_live = _cached_mikrotik_live_snapshot(org.pk, router.pk)
        if initial_live is not None:
            initial_live["auto_restore"] = ctx["auto_restore"]
    ctx["initial_live"] = initial_live
    from core.mikrotik_connect import hosted_dashboard_url, resolve_router_management_mode

    ctx["hosted_dashboard_url"] = hosted_dashboard_url()
    ctx["router_management_mode"] = resolve_router_management_mode(router)
    return render(request, "core/mikrotik_detail.html", ctx)



@client_workspace_required
def mikrotik_ports(request, router_id: int):
    """List router ports; enable/disable, assign roles, bond or failover uplinks."""
    org = resolve_organization(request.user, request)
    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect("core:mikrotik")

    router = get_object_or_404(MikroTikRouter, pk=router_id, organization=org)
    is_suspended = router.account_status == MikroTikRouter.AccountStatus.SUSPENDED
    api_host = _router_api_host(router)
    role_choices = _port_role_choices_for_ui(router.uplink_mode)
    bond_mode_choices = [
        ("balance-xor", "Combine cables (recommended)"),
        ("active-backup", "Redundancy — one active cable"),
    ]
    bond_mode_advanced_choices = [
        ("802.3ad", "LACP 802.3ad (switch must support)"),
        ("balance-rr", "Round-robin"),
    ]

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()

        if is_suspended:
            messages.error(
                request,
                "Activate this MikroTik account before managing ports.",
            )
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "auto_assign_ports":
            listed = list_mikrotik_ports(
                api_host,
                router.username,
                router.password or "",
                timeout=12.0,
                management_hosts=_management_hosts_for_router(router),
            )
            if not listed.get("ok"):
                messages.error(
                    request,
                    listed.get("error") or "Could not read ports from the MikroTik.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            result = apply_suggested_port_roles(
                router,
                listed.get("ports") or [],
                suggested_wan=listed.get("suggested_wan") or "",
            )
            # Best-effort: put the chosen Internet port on the router WAN list.
            wan_name = (result.get("wan") or "").strip()
            live_ports = listed.get("ports") or []
            if wan_name:
                old_wan = _current_primary_wan_port(router)
                retire = [old_wan] if old_wan and old_wan != wan_name else []
                if old_wan and old_wan != wan_name:
                    _store_wan_switch_rollback(router, old_wan=old_wan, new_wan=wan_name)
                switch = _apply_single_wan_on_router(
                    router,
                    api_host,
                    wan_interface=wan_name,
                    retire_ports=retire,
                    live_ports=live_ports,
                )
                if not switch.get("ok"):
                    messages.warning(
                        request,
                        switch.get("error")
                        or f"Saved {wan_name} as Internet, but could not configure it on the router.",
                    )
                elif switch.get("skipped"):
                    messages.info(request, switch.get("message") or "")
            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            messages.success(request, result.get("message") or "Ports auto-assigned.")
            _record_ports_audit(
                request,
                action="ports_auto_assign",
                router=router,
                detail={"wan": result.get("wan") or ""},
            )
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "accept_detected_uplink":
            port_name = (request.POST.get("port_name") or "").strip()
            if not port_name:
                messages.error(request, "No Internet port was selected.")
                return redirect("core:mikrotik_ports", router_id=router.pk)

            listed = list_mikrotik_ports(
                api_host,
                router.username,
                router.password or "",
                timeout=6.0,
                management_hosts=_management_hosts_for_router(router),
            )
            if not listed.get("ok"):
                messages.error(
                    request,
                    listed.get("error") or "Could not read ports from the MikroTik.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            live_ports = listed.get("ports") or []
            suggested_wan = (listed.get("suggested_wan") or "").strip()
            current = _current_primary_wan_port(router)
            if port_name != suggested_wan:
                messages.error(
                    request,
                    f"Live detection points to {suggested_wan or 'no port'} — refresh and try again.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            risk = assess_uplink_switch_risk(
                new_wan=port_name,
                old_wan=current,
                ports=live_ports,
                management_host=(router.host or "").strip(),
                tunnel_address=(router.vpn_address or "").strip(),
                management_iface_by_host=listed.get("management_iface_by_host") or {},
                uses_tunnel=_router_uses_tunnel(router),
                tunnel_verified=_router_tunnel_verified(router),
            )
            ok, err = _wan_switch_confirmed(request, risk)
            if not ok:
                messages.error(request, err)
                return redirect("core:mikrotik_ports", router_id=router.pk)

            ok_inet, inet_err = _guard_touch_ports_internet(
                [port_name],
                live_ports,
                action_label="switch Internet port",
            )
            if not ok_inet:
                messages.error(request, inet_err)
                return redirect("core:mikrotik_ports", router_id=router.pk)

            result = apply_detected_uplink(router, port_name, live_ports)
            if not result.get("ok"):
                messages.error(
                    request,
                    result.get("error") or "Could not switch the Internet port.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            old_wan = (result.get("old_wan") or current or "").strip()
            retire = [old_wan] if old_wan and old_wan != port_name else []
            _store_wan_switch_rollback(router, old_wan=old_wan, new_wan=port_name)
            sync = _apply_single_wan_on_router(
                router,
                api_host,
                wan_interface=port_name,
                retire_ports=retire,
            )
            if not sync.get("ok"):
                messages.warning(
                    request,
                    sync.get("error")
                    or (
                        f"Saved {port_name} as Internet, but could not configure it on the router."
                    ),
                )
            else:
                messages.success(
                    request,
                    sync.get("message") or result.get("message") or "Internet port switched.",
                )

            _record_ports_audit(
                request,
                action="ports_accept_detected_uplink",
                router=router,
                detail={
                    "old_wan": old_wan,
                    "new_wan": port_name,
                    "router_ok": bool(sync.get("ok")),
                },
            )
            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "accept_detected_backup":
            port_name = (request.POST.get("port_name") or "").strip()
            if not port_name:
                messages.error(request, "No backup port was selected.")
                return redirect("core:mikrotik_ports", router_id=router.pk)

            listed = list_mikrotik_ports(
                api_host,
                router.username,
                router.password or "",
                timeout=6.0,
                management_hosts=_management_hosts_for_router(router),
            )
            if not listed.get("ok"):
                messages.error(
                    request,
                    listed.get("error") or "Could not read ports from the MikroTik.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            live_ports = listed.get("ports") or []
            primary = _current_primary_wan_port(router)
            risk = assess_uplink_switch_risk(
                new_wan=port_name,
                old_wan=primary,
                ports=live_ports,
                management_host=(router.host or "").strip(),
                tunnel_address=(router.vpn_address or "").strip(),
                management_iface_by_host=listed.get("management_iface_by_host") or {},
                uses_tunnel=_router_uses_tunnel(router),
                tunnel_verified=_router_tunnel_verified(router),
            )
            ok, err = _check_uplink_apply_confirmation(request, risk)
            if not ok:
                messages.error(request, err)
                return redirect("core:mikrotik_ports", router_id=router.pk)

            result = apply_detected_backup(router, port_name, live_ports)
            if not result.get("ok"):
                messages.error(
                    request,
                    result.get("error") or "Could not mark the backup port.",
                )
            else:
                messages.success(request, result.get("message") or "Backup port saved.")

            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action in {"toggle_port", "set_port_role"}:
            port_name = (request.POST.get("port_name") or "").strip()
            if not port_name:
                messages.error(request, "Select a port to update.")
                return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "toggle_port":
            port_name = (request.POST.get("port_name") or "").strip()
            result = toggle_mikrotik_port(
                api_host,
                router.username,
                router.password or "",
                interface_name=port_name,
            )
            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            if result.get("ok"):
                messages.success(
                    request,
                    result.get("message")
                    or f"Port {port_name} updated.",
                )
            else:
                messages.error(
                    request,
                    result.get("error") or f"Could not update port {port_name}.",
                )
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "set_uplink_goal":
            goal = (request.POST.get("goal") or "").strip().lower()
            valid_goals = {
                MikroTikRouter.UplinkMode.SINGLE,
                MikroTikRouter.UplinkMode.BOND,
                MikroTikRouter.UplinkMode.FAILOVER,
                MikroTikRouter.UplinkMode.BALANCE,
                MikroTikRouter.UplinkMode.SMART_BALANCE,
            }
            if goal not in valid_goals:
                messages.error(request, "Choose a valid internet setup.")
                return redirect("core:mikrotik_ports", router_id=router.pk)

            old_mode = (router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE).strip()
            listed = list_mikrotik_ports(
                api_host,
                router.username,
                router.password or "",
                timeout=6.0,
                management_hosts=_management_hosts_for_router(router),
            )
            live_ports = (listed.get("ports") or []) if listed.get("ok") else []

            router.uplink_mode = goal
            roles = _normalize_port_roles_for_uplink_mode(
                router, goal, live_ports=live_ports
            )
            router.port_roles = roles
            primary = ""
            for name, value in roles.items():
                if _is_primary_wan_role(value):
                    primary = (name or "").strip()
                    break
            if live_ports:
                assign = _auto_sync_port_roles_for_uplink_mode(
                    router,
                    live_ports,
                    suggested_wan=(listed.get("suggested_wan") or ""),
                )
                if assign.get("ok") and assign.get("changed"):
                    router.refresh_from_db(
                        fields=[
                            "port_roles",
                            "wan_interface",
                            "uplink_ports",
                            "uplink_weights",
                            "uplink_mode",
                            "updated_at",
                        ]
                    )
                    roles = dict(router.port_roles)
                    primary = (
                        assign.get("primary")
                        or assign.get("wan")
                        or primary
                        or ""
                    ).strip()
                    if assign.get("message"):
                        messages.info(request, assign["message"])
                elif not assign.get("ok") and assign.get("error"):
                    messages.info(request, assign["error"])
            update_fields = ["uplink_mode", "port_roles", "updated_at"]

            if goal == MikroTikRouter.UplinkMode.SINGLE:
                router.uplink_ports = [primary] if primary else []
                router.uplink_weights = {}
                router.wan_interface = primary or router.wan_interface
                update_fields.extend(
                    ["uplink_ports", "uplink_weights", "wan_interface"]
                )
            elif goal == MikroTikRouter.UplinkMode.BOND:
                members = _bond_ports_from_roles(router)
                router.uplink_ports = members
                update_fields.append("uplink_ports")
            else:
                failover_primary, backups = _failover_ports_from_roles(router)
                if failover_primary:
                    router.wan_interface = failover_primary
                    router.uplink_ports = [failover_primary, *backups]
                    update_fields.extend(["wan_interface", "uplink_ports"])
                else:
                    router.uplink_ports = []
                    update_fields.append("uplink_ports")

            router.save(update_fields=update_fields)

            if (
                old_mode
                in {
                    MikroTikRouter.UplinkMode.FAILOVER,
                    *_weighted_share_uplink_modes(),
                    MikroTikRouter.UplinkMode.BOND,
                }
                and goal == MikroTikRouter.UplinkMode.SINGLE
            ):
                restore = (
                    list(router.uplink_unbridged)
                    if isinstance(router.uplink_unbridged, list)
                    else []
                )
                cleared = clear_mikrotik_uplink_multi(
                    api_host,
                    router.username,
                    router.password or "",
                    restore_bridged=restore,
                    lan_bridge=router.lan_bridge or "bridgeLocal",
                )
                router.uplink_unbridged = []
                router.save(update_fields=["uplink_unbridged", "updated_at"])
                if primary:
                    switch = _apply_single_wan_on_router(
                        router,
                        api_host,
                        wan_interface=primary,
                        retire_ports=[],
                    )
                    if not switch.get("ok"):
                        messages.warning(
                            request,
                            switch.get("error")
                            or "Switched to single internet, but could not configure the WAN port.",
                        )
                if not cleared.get("ok"):
                    messages.warning(
                        request,
                        cleared.get("error")
                        or "Switched to single internet, but could not clear old multi-uplink settings.",
                    )

            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            label = dict(MikroTikRouter.UplinkMode.choices).get(goal, goal)
            messages.success(request, f"Internet setup changed to {label}.")
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "set_port_role":
            port_name = (request.POST.get("port_name") or "").strip()
            role = (request.POST.get("role") or "").strip().lower()
            if role == MikroTikRouter.PortRole.WAN_PRIMARY:
                role = MikroTikRouter.PortRole.WAN
            valid_roles = {choice.value for choice in MikroTikRouter.PortRole}
            if role not in valid_roles:
                messages.error(request, "Choose a valid port role.")
                return redirect("core:mikrotik_ports", router_id=router.pk)

            uplink_mode = (router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE).strip()
            if not _role_allowed_for_uplink_mode(role, uplink_mode):
                mode_label = dict(MikroTikRouter.UplinkMode.choices).get(
                    uplink_mode, uplink_mode
                )
                role_label = _role_label_for_mode_error(role)
                messages.error(
                    request,
                    f"{role_label} is not available in “{mode_label}” mode. "
                    "Change the internet setup in Step 2 first.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            roles = dict(router.port_roles) if isinstance(router.port_roles, dict) else {}
            update_fields = ["port_roles", "updated_at"]
            old_wan = _current_primary_wan_port(router)
            retire_ports: list[str] = []

            if role == MikroTikRouter.PortRole.WAN:
                if (
                    uplink_mode == MikroTikRouter.UplinkMode.SINGLE
                    and port_name != old_wan
                ):
                    listed = list_mikrotik_ports(
                        api_host,
                        router.username,
                        router.password or "",
                        timeout=6.0,
                        management_hosts=_management_hosts_for_router(router),
                    )
                    live_ports = (listed.get("ports") or []) if listed.get("ok") else []
                    risk = assess_uplink_switch_risk(
                        new_wan=port_name,
                        old_wan=old_wan,
                        ports=live_ports,
                        management_host=(router.host or "").strip(),
                        tunnel_address=(router.vpn_address or "").strip(),
                        management_iface_by_host=(
                            listed.get("management_iface_by_host")
                            if listed.get("ok")
                            else {}
                        ),
                        uses_tunnel=_router_uses_tunnel(router),
                        tunnel_verified=_router_tunnel_verified(router),
                    )
                    ok, err = _wan_switch_confirmed(request, risk)
                    if not ok:
                        messages.error(request, err)
                        return redirect("core:mikrotik_ports", router_id=router.pk)

                demoted_to_backup: list[str] = []
                for name, existing in list(roles.items()):
                    if name == port_name:
                        continue
                    if _is_primary_wan_role(existing):
                        if uplink_mode in {
                            MikroTikRouter.UplinkMode.FAILOVER,
                            MikroTikRouter.UplinkMode.BALANCE,
                        }:
                            # Swap: previous Internet becomes Backup internet.
                            roles[name] = MikroTikRouter.PortRole.WAN_BACKUP
                            demoted_to_backup.append(name)
                        else:
                            roles[name] = MikroTikRouter.PortRole.UNUSED
                            retire_ports.append(name)
                    elif existing == MikroTikRouter.PortRole.BOND:
                        roles[name] = MikroTikRouter.PortRole.NONE
                    elif (
                        existing == MikroTikRouter.PortRole.WAN_BACKUP
                        and uplink_mode == MikroTikRouter.UplinkMode.SINGLE
                    ):
                        roles[name] = MikroTikRouter.PortRole.UNUSED
                roles[port_name] = MikroTikRouter.PortRole.WAN
                router.wan_interface = port_name

                if uplink_mode in {
                    MikroTikRouter.UplinkMode.FAILOVER,
                    MikroTikRouter.UplinkMode.BALANCE,
                }:
                    backup_ports = [
                        key
                        for key, value in roles.items()
                        if (value or "").strip().lower()
                        == MikroTikRouter.PortRole.WAN_BACKUP
                    ]
                    router.uplink_ports = [port_name, *backup_ports]
                else:
                    router.uplink_mode = MikroTikRouter.UplinkMode.SINGLE
                    router.uplink_ports = [port_name]
                    update_fields.append("uplink_mode")
                update_fields.extend(["wan_interface", "uplink_ports"])

                if uplink_mode == MikroTikRouter.UplinkMode.SINGLE and port_name != old_wan:
                    _store_wan_switch_rollback(router, old_wan=old_wan, new_wan=port_name)
                    ok_inet, inet_err = _guard_touch_ports_internet(
                        [port_name],
                        live_ports,
                        action_label="switch Internet port",
                    )
                    if not ok_inet:
                        messages.error(request, inet_err)
                        return redirect("core:mikrotik_ports", router_id=router.pk)
                    sync = _apply_single_wan_on_router(
                        router,
                        api_host,
                        wan_interface=port_name,
                        retire_ports=retire_ports or ([old_wan] if old_wan and old_wan != port_name else []),
                    )
                    _record_ports_audit(
                        request,
                        action="ports_wan_switch",
                        router=router,
                        detail={
                            "old_wan": old_wan,
                            "new_wan": port_name,
                            "router_ok": bool(sync.get("ok")),
                        },
                    )
                    if not sync.get("ok"):
                        messages.warning(
                            request,
                            sync.get("error")
                            or f"Saved {port_name} as Internet, but could not configure it on the router.",
                        )
                    else:
                        messages.success(
                            request,
                            sync.get("message") or f"{port_name} is now the Internet port.",
                        )
                else:
                    label = dict(MikroTikRouter.PortRole.choices).get(role, role)
                    swap_note = ""
                    if demoted_to_backup:
                        swap_note = (
                            f" Previous Internet ({', '.join(demoted_to_backup)}) "
                            "moved to Backup internet."
                        )
                    apply_mode = (
                        "failover"
                        if uplink_mode == MikroTikRouter.UplinkMode.FAILOVER
                        else "smart balance"
                        if uplink_mode == MikroTikRouter.UplinkMode.SMART_BALANCE
                        else "load balance"
                    )
                    messages.success(
                        request,
                        f"{port_name} role set to {label}.{swap_note} Apply "
                        f"{apply_mode} when all ISP links are assigned.",
                    )
                    _record_ports_audit(
                        request,
                        action="ports_wan_role",
                        router=router,
                        detail={
                            "port": port_name,
                            "role": role,
                            "mode": uplink_mode,
                            "demoted_to_backup": demoted_to_backup,
                        },
                    )
            elif role == MikroTikRouter.PortRole.WAN_BACKUP:
                roles[port_name] = MikroTikRouter.PortRole.WAN_BACKUP
                primary = next(
                    (
                        name
                        for name, existing in roles.items()
                        if name != port_name and _is_primary_wan_role(existing)
                    ),
                    "",
                )
                if not primary:
                    messages.error(
                        request,
                        "Assign Internet to the main ISP port before adding a backup.",
                    )
                    return redirect("core:mikrotik_ports", router_id=router.pk)
                # Clear this port from primary if it somehow had wan role already.
                if port_name == primary:
                    messages.error(
                        request,
                        "Choose a different port than the primary Internet port.",
                    )
                    return redirect("core:mikrotik_ports", router_id=router.pk)
                router.wan_interface = primary
                backup_ports = [
                    name
                    for name, existing in roles.items()
                    if (existing or "").strip().lower()
                    == MikroTikRouter.PortRole.WAN_BACKUP
                ]
                router.uplink_ports = [primary, *backup_ports]
                update_fields.extend(["wan_interface", "uplink_ports"])
            elif role == MikroTikRouter.PortRole.BOND:
                roles[port_name] = MikroTikRouter.PortRole.BOND
            else:
                roles[port_name] = role

            router.port_roles = roles
            router.save(update_fields=update_fields)
            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            if role != MikroTikRouter.PortRole.WAN or uplink_mode != MikroTikRouter.UplinkMode.SINGLE:
                label = dict(MikroTikRouter.PortRole.choices).get(role, role)
                if role != MikroTikRouter.PortRole.WAN:
                    messages.success(request, f"{port_name} role set to {label}.")
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "apply_bond":
            member_ports = _bond_ports_from_roles(router)
            if len(member_ports) < 2:
                messages.error(
                    request,
                    "Assign Bond member to at least two ports in the table above, then apply bonding.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            bond_name = (request.POST.get("bond_name") or "").strip() or (
                router.bond_interface or DEFAULT_BOND_NAME
            )
            bond_mode = (request.POST.get("bond_mode") or "").strip() or (
                router.bond_mode or "balance-xor"
            )
            if bond_mode not in BOND_MODES:
                bond_mode = "balance-xor"

            listed = list_mikrotik_ports(
                api_host,
                router.username,
                router.password or "",
                timeout=6.0,
                management_hosts=_management_hosts_for_router(router),
            )
            live_ports = (listed.get("ports") or []) if listed.get("ok") else []
            ok_inet, inet_err = _guard_bond_members_internet(
                member_ports,
                live_ports,
            )
            if not ok_inet:
                messages.error(request, inet_err)
                return redirect("core:mikrotik_ports", router_id=router.pk)
            bond_risk = _assess_uplink_mode_apply(
                router,
                "bond",
                member_ports,
                live_ports,
                listed.get("management_iface_by_host") if listed.get("ok") else {},
            )
            ok, err = _check_uplink_apply_confirmation(request, bond_risk)
            if not ok:
                messages.error(request, err)
                return redirect("core:mikrotik_ports", router_id=router.pk)

            router_pk = router.pk
            org_pk = org.pk
            bond_ports = list(member_ports)

            def _apply_bond_job(
                ports=bond_ports,
                bname=bond_name,
                bmode=bond_mode,
                pk=router_pk,
                organization_pk=org_pk,
            ):
                live = MikroTikRouter.objects.get(pk=pk)
                host = _router_api_host(live)
                job_result = apply_mikrotik_uplink_bond(
                    host,
                    live.username,
                    live.password or "",
                    member_ports=ports,
                    bond_name=bname,
                    bond_mode=bmode,
                    api_hosts=_uplink_api_hosts_for_router(live),
                )
                job_result = _finalize_uplink_apply_result(live, job_result)
                if job_result.get("ok"):
                    members = job_result.get("members") or ports
                    live.uplink_mode = MikroTikRouter.UplinkMode.BOND
                    live.uplink_ports = members
                    live.bond_interface = job_result.get("bond_name") or bname
                    live.bond_mode = job_result.get("bond_mode") or bmode
                    live.wan_interface = job_result.get("wan_interface") or bname
                    live.uplink_unbridged = job_result.get("unbridged") or []
                    live.port_roles = _sync_roles_for_uplink(
                        live, mode=MikroTikRouter.UplinkMode.BOND, ports=members
                    )
                    live.save(
                        update_fields=[
                            "uplink_mode",
                            "uplink_ports",
                            "bond_interface",
                            "bond_mode",
                            "wan_interface",
                            "uplink_unbridged",
                            "port_roles",
                            "updated_at",
                        ]
                    )
                    _invalidate_mikrotik_router_caches(organization_pk, pk)
                return job_result

            if _background_mikrotik_ops():
                set_job(router.pk, "uplink_bond", "pending")
                schedule_mikrotik_job(
                    _apply_bond_job,
                    name=f"uplink-bond-{router.pk}",
                    router_id=router.pk,
                    job_type="uplink_bond",
                )
                messages.success(
                    request,
                    "Applying bonded uplinks on the MikroTik in the background. "
                    "This page will show progress shortly.",
                )
                return _redirect_with_mikrotik_job(
                    request, "core:mikrotik_ports", router.pk, "uplink_bond"
                )

            result = apply_mikrotik_uplink_bond(
                api_host,
                router.username,
                router.password or "",
                member_ports=member_ports,
                bond_name=bond_name,
                bond_mode=bond_mode,
                api_hosts=_uplink_api_hosts_for_router(router),
            )
            result = _finalize_uplink_apply_result(router, result)
            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            if not result.get("ok"):
                messages.error(
                    request,
                    result.get("error") or "Could not apply bonded uplinks.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            members = result.get("members") or member_ports
            router.uplink_mode = MikroTikRouter.UplinkMode.BOND
            router.uplink_ports = members
            router.bond_interface = result.get("bond_name") or bond_name
            router.bond_mode = result.get("bond_mode") or bond_mode
            router.wan_interface = result.get("wan_interface") or bond_name
            router.uplink_unbridged = result.get("unbridged") or []
            router.port_roles = _sync_roles_for_uplink(
                router, mode=MikroTikRouter.UplinkMode.BOND, ports=members
            )
            router.save(
                update_fields=[
                    "uplink_mode",
                    "uplink_ports",
                    "bond_interface",
                    "bond_mode",
                    "wan_interface",
                    "uplink_unbridged",
                    "port_roles",
                    "updated_at",
                ]
            )
            messages.success(request, result.get("message") or "Bonded uplinks applied.")
            _record_ports_audit(
                request,
                action="ports_apply_bond",
                router=router,
                detail={"members": members, "bond": router.bond_interface},
            )
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "apply_failover":
            primary, backups = _failover_ports_from_roles(router)
            if not primary:
                messages.error(
                    request,
                    "Assign WAN / Internet (primary) to one port in the table above.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)
            if not backups:
                messages.error(
                    request,
                    "Assign WAN backup to at least one other port in the table above.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            listed = list_mikrotik_ports(
                api_host,
                router.username,
                router.password or "",
                timeout=6.0,
                management_hosts=_management_hosts_for_router(router),
            )
            live_ports = (listed.get("ports") or []) if listed.get("ok") else []
            touch = [primary, *backups]
            ok_inet, inet_err = _guard_touch_ports_internet(
                touch,
                live_ports,
                action_label="apply failover",
            )
            if not ok_inet:
                messages.error(request, inet_err)
                return redirect("core:mikrotik_ports", router_id=router.pk)
            failover_risk = _assess_uplink_mode_apply(
                router,
                "failover",
                touch,
                live_ports,
                listed.get("management_iface_by_host") if listed.get("ok") else {},
            )
            ok, err = _check_uplink_apply_confirmation(request, failover_risk)
            if not ok:
                messages.error(request, err)
                return redirect("core:mikrotik_ports", router_id=router.pk)

            router_pk = router.pk
            org_pk = org.pk
            failover_primary = primary
            failover_backups = list(backups)

            def _apply_failover_job(
                primary_port=failover_primary,
                backup_ports=failover_backups,
                pk=router_pk,
                organization_pk=org_pk,
            ):
                live = MikroTikRouter.objects.get(pk=pk)
                host = _router_api_host(live)
                job_result = apply_mikrotik_uplink_failover(
                    host,
                    live.username,
                    live.password or "",
                    primary_port=primary_port,
                    backup_ports=backup_ports,
                    api_hosts=_uplink_api_hosts_for_router(live),
                )
                job_result = _finalize_uplink_apply_result(live, job_result)
                if job_result.get("ok"):
                    ordered = job_result.get("ports") or [primary_port, *backup_ports]
                    live.uplink_mode = MikroTikRouter.UplinkMode.FAILOVER
                    live.uplink_ports = ordered
                    live.wan_interface = job_result.get("wan_interface") or primary_port
                    live.uplink_unbridged = job_result.get("unbridged") or []
                    live.port_roles = _sync_roles_for_uplink(
                        live,
                        mode=MikroTikRouter.UplinkMode.FAILOVER,
                        ports=ordered,
                    )
                    live.save(
                        update_fields=[
                            "uplink_mode",
                            "uplink_ports",
                            "wan_interface",
                            "uplink_unbridged",
                            "port_roles",
                            "updated_at",
                        ]
                    )
                    _invalidate_mikrotik_router_caches(organization_pk, pk)
                return job_result

            if _background_mikrotik_ops():
                set_job(router.pk, "uplink_failover", "pending")
                schedule_mikrotik_job(
                    _apply_failover_job,
                    name=f"uplink-failover-{router.pk}",
                    router_id=router.pk,
                    job_type="uplink_failover",
                )
                messages.success(
                    request,
                    "Applying failover uplinks on the MikroTik in the background. "
                    "This page will show progress shortly.",
                )
                return _redirect_with_mikrotik_job(
                    request, "core:mikrotik_ports", router.pk, "uplink_failover"
                )

            result = apply_mikrotik_uplink_failover(
                api_host,
                router.username,
                router.password or "",
                primary_port=primary,
                backup_ports=backups,
                api_hosts=_uplink_api_hosts_for_router(router),
            )
            result = _finalize_uplink_apply_result(router, result)
            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            if not result.get("ok"):
                messages.error(
                    request,
                    result.get("error") or "Could not apply failover uplinks.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            ordered = result.get("ports") or [primary, *backups]
            router.uplink_mode = MikroTikRouter.UplinkMode.FAILOVER
            router.uplink_ports = ordered
            router.wan_interface = result.get("wan_interface") or primary
            router.uplink_unbridged = result.get("unbridged") or []
            router.port_roles = _sync_roles_for_uplink(
                router, mode=MikroTikRouter.UplinkMode.FAILOVER, ports=ordered
            )
            router.save(
                update_fields=[
                    "uplink_mode",
                    "uplink_ports",
                    "wan_interface",
                    "uplink_unbridged",
                    "port_roles",
                    "updated_at",
                ]
            )
            messages.success(request, result.get("message") or "Failover uplinks applied.")
            _record_ports_audit(
                request,
                action="ports_apply_failover",
                router=router,
                detail={"ports": ordered},
            )
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "auto_setup_bond":
            bond_name = (request.POST.get("bond_name") or "").strip() or (
                router.bond_interface or DEFAULT_BOND_NAME
            )
            bond_mode = (request.POST.get("bond_mode") or "").strip() or (
                router.bond_mode or "balance-xor"
            )
            if bond_mode not in BOND_MODES:
                bond_mode = "balance-xor"

            listed = list_mikrotik_ports(
                api_host,
                router.username,
                router.password or "",
                timeout=8.0,
                management_hosts=_management_hosts_for_router(router),
            )
            if not listed.get("ok"):
                messages.error(
                    request,
                    listed.get("error") or "Could not read ports from the MikroTik.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            live_ports = listed.get("ports") or []
            router.uplink_mode = MikroTikRouter.UplinkMode.BOND
            assign = _auto_assign_bond_roles(router, live_ports)
            if not assign.get("ok"):
                messages.error(
                    request,
                    assign.get("error") or "Need two linked cables from the same ISP.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)
            if assign.get("message"):
                messages.info(request, assign["message"])

            member_ports = list(assign.get("members") or _bond_ports_from_roles(router))
            ok_bond, bond_err = _guard_bond_members_internet(member_ports, live_ports)
            if not ok_bond:
                messages.error(request, bond_err)
                return redirect("core:mikrotik_ports", router_id=router.pk)

            bond_risk = _assess_uplink_mode_apply(
                router,
                "bond",
                member_ports,
                live_ports,
                listed.get("management_iface_by_host") if listed.get("ok") else {},
            )
            ok, err = _check_uplink_apply_confirmation(request, bond_risk)
            if not ok:
                messages.error(request, err)
                return redirect("core:mikrotik_ports", router_id=router.pk)

            result = apply_mikrotik_uplink_bond(
                api_host,
                router.username,
                router.password or "",
                member_ports=member_ports,
                bond_name=bond_name,
                bond_mode=bond_mode,
                api_hosts=_uplink_api_hosts_for_router(router),
            )
            result = _finalize_uplink_apply_result(router, result)
            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            if not result.get("ok"):
                messages.error(
                    request,
                    result.get("error") or "Could not apply bonding.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            members = result.get("members") or member_ports
            router.uplink_mode = MikroTikRouter.UplinkMode.BOND
            router.uplink_ports = members
            router.bond_interface = result.get("bond_name") or bond_name
            router.bond_mode = result.get("bond_mode") or bond_mode
            router.wan_interface = result.get("wan_interface") or bond_name
            router.uplink_unbridged = result.get("unbridged") or []
            router.port_roles = _sync_roles_for_uplink(
                router,
                mode=MikroTikRouter.UplinkMode.BOND,
                ports=members,
            )
            router.save(
                update_fields=[
                    "uplink_mode",
                    "uplink_ports",
                    "bond_interface",
                    "bond_mode",
                    "wan_interface",
                    "uplink_unbridged",
                    "port_roles",
                    "updated_at",
                ]
            )
            messages.success(
                request,
                result.get("message")
                or f"Bonding active on {', '.join(members)}.",
            )
            _record_ports_audit(
                request,
                action="ports_auto_setup_bond",
                router=router,
                detail={
                    "members": members,
                    "bond_name": router.bond_interface,
                    "bond_mode": router.bond_mode,
                },
            )
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "auto_setup_smart_balance":
            listed = list_mikrotik_ports(
                api_host,
                router.username,
                router.password or "",
                timeout=8.0,
                management_hosts=_management_hosts_for_router(router),
            )
            if not listed.get("ok"):
                messages.error(
                    request,
                    listed.get("error") or "Could not read ports from the MikroTik.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            live_ports = listed.get("ports") or []
            router.uplink_mode = MikroTikRouter.UplinkMode.SMART_BALANCE
            assign = _auto_assign_smart_balance_roles(
                router,
                live_ports,
                suggested_wan=(listed.get("suggested_wan") or ""),
            )
            if not assign.get("ok"):
                messages.error(
                    request,
                    assign.get("error") or "Need two live ISP links for smart balance.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)
            if assign.get("message"):
                messages.info(request, assign["message"])

            primary = (assign.get("primary") or "").strip()
            backups = list(assign.get("backups") or [])
            ordered = [primary, *backups] if primary else []
            weights = dict(assign.get("weights") or router.uplink_weights or {})
            if len(ordered) < 2:
                messages.error(request, "Assign Internet and Shared ISP before applying.")
                return redirect("core:mikrotik_ports", router_id=router.pk)

            ok_inet, inet_err = _guard_touch_ports_internet(
                ordered,
                live_ports,
                action_label="apply smart balance",
            )
            if not ok_inet:
                messages.error(request, inet_err)
                return redirect("core:mikrotik_ports", router_id=router.pk)

            cache.delete(_smart_balance_auto_cache_key(router.pk))
            result = apply_mikrotik_uplink_balance(
                api_host,
                router.username,
                router.password or "",
                member_ports=ordered,
                member_weights=weights,
                smart_balance=True,
                api_hosts=_uplink_api_hosts_for_router(router),
            )
            result = _finalize_uplink_apply_result(router, result)
            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            if not result.get("ok"):
                messages.error(
                    request,
                    result.get("error") or "Could not apply smart balance.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            ordered = result.get("ports") or ordered
            router.uplink_mode = MikroTikRouter.UplinkMode.SMART_BALANCE
            router.uplink_ports = ordered
            router.uplink_weights = result.get("weights") or weights
            router.wan_interface = result.get("wan_interface") or primary
            router.uplink_unbridged = result.get("unbridged") or []
            router.port_roles = _sync_roles_for_uplink(
                router,
                mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
                ports=ordered,
            )
            router.save(
                update_fields=[
                    "uplink_mode",
                    "uplink_ports",
                    "uplink_weights",
                    "wan_interface",
                    "uplink_unbridged",
                    "port_roles",
                    "updated_at",
                ]
            )
            messages.success(
                request,
                result.get("message")
                or "Smart balance is active — PCC sharing plus slow-link monitor.",
            )
            _record_ports_audit(
                request,
                action="ports_auto_setup_smart_balance",
                router=router,
                detail={"ports": ordered, "weights": router.uplink_weights},
            )
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action in {"apply_balance", "apply_smart_balance"}:
            smart_balance = action == "apply_smart_balance"
            target_mode = (
                MikroTikRouter.UplinkMode.SMART_BALANCE
                if smart_balance
                else MikroTikRouter.UplinkMode.BALANCE
            )
            apply_label = "smart balance" if smart_balance else "load balance"
            primary, backups = _failover_ports_from_roles(router)
            if not primary:
                messages.error(
                    request,
                    "Assign WAN / Internet to one port in the table above.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)
            if not backups:
                messages.error(
                    request,
                    "Assign at least one other port as Shared ISP for "
                    + apply_label
                    + ".",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            ordered = [primary, *backups]
            weights: dict[str, int] = {}
            for name in ordered:
                raw = (request.POST.get(f"weight_{name}") or "").strip()
                if not raw:
                    continue
                try:
                    weights[name] = max(1, min(10000, int(raw)))
                except (TypeError, ValueError):
                    continue
            if len(weights) < len(ordered):
                for name in ordered:
                    weights.setdefault(name, 100)

            listed = list_mikrotik_ports(
                api_host,
                router.username,
                router.password or "",
                timeout=6.0,
                management_hosts=_management_hosts_for_router(router),
            )
            live_ports = (listed.get("ports") or []) if listed.get("ok") else []
            ok_inet, inet_err = _guard_touch_ports_internet(
                ordered,
                live_ports,
                action_label=f"apply {apply_label}",
            )
            if not ok_inet:
                messages.error(request, inet_err)
                return redirect("core:mikrotik_ports", router_id=router.pk)
            balance_risk = _assess_uplink_mode_apply(
                router,
                "smart_balance" if smart_balance else "balance",
                ordered,
                live_ports,
                listed.get("management_iface_by_host") if listed.get("ok") else {},
            )
            ok, err = _check_uplink_apply_confirmation(request, balance_risk)
            if not ok:
                messages.error(request, err)
                return redirect("core:mikrotik_ports", router_id=router.pk)

            router_pk = router.pk
            org_pk = org.pk
            balance_ports = list(ordered)
            balance_weights = dict(weights)

            def _apply_balance_job(
                ports=balance_ports,
                port_weights=balance_weights,
                pk=router_pk,
                organization_pk=org_pk,
                smart=smart_balance,
                mode=target_mode,
            ):
                live = MikroTikRouter.objects.get(pk=pk)
                host = _router_api_host(live)
                job_result = apply_mikrotik_uplink_balance(
                    host,
                    live.username,
                    live.password or "",
                    member_ports=ports,
                    member_weights=port_weights,
                    smart_balance=smart,
                    api_hosts=_uplink_api_hosts_for_router(live),
                )
                job_result = _finalize_uplink_apply_result(live, job_result)
                if job_result.get("ok"):
                    ordered_ports = job_result.get("ports") or ports
                    live.uplink_mode = mode
                    live.uplink_ports = ordered_ports
                    live.uplink_weights = job_result.get("weights") or port_weights
                    live.wan_interface = job_result.get("wan_interface") or ports[0]
                    live.uplink_unbridged = job_result.get("unbridged") or []
                    live.port_roles = _sync_roles_for_uplink(
                        live,
                        mode=mode,
                        ports=ordered_ports,
                    )
                    live.save(
                        update_fields=[
                            "uplink_mode",
                            "uplink_ports",
                            "uplink_weights",
                            "wan_interface",
                            "uplink_unbridged",
                            "port_roles",
                            "updated_at",
                        ]
                    )
                    _invalidate_mikrotik_router_caches(organization_pk, pk)
                return job_result

            job_type = "uplink_smart_balance" if smart_balance else "uplink_balance"
            if _background_mikrotik_ops():
                set_job(router.pk, job_type, "pending")
                schedule_mikrotik_job(
                    _apply_balance_job,
                    name=f"{job_type}-{router.pk}",
                    router_id=router.pk,
                    job_type=job_type,
                )
                messages.success(
                    request,
                    f"Applying {apply_label} uplinks on the MikroTik in the background. "
                    "This page will show progress shortly.",
                )
                return _redirect_with_mikrotik_job(
                    request, "core:mikrotik_ports", router.pk, job_type
                )

            result = apply_mikrotik_uplink_balance(
                api_host,
                router.username,
                router.password or "",
                member_ports=ordered,
                member_weights=weights,
                smart_balance=smart_balance,
                api_hosts=_uplink_api_hosts_for_router(router),
            )
            result = _finalize_uplink_apply_result(router, result)
            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            if not result.get("ok"):
                messages.error(
                    request,
                    result.get("error") or f"Could not apply {apply_label} uplinks.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            ordered = result.get("ports") or ordered
            router.uplink_mode = target_mode
            router.uplink_ports = ordered
            router.uplink_weights = result.get("weights") or weights
            router.wan_interface = result.get("wan_interface") or primary
            router.uplink_unbridged = result.get("unbridged") or []
            router.port_roles = _sync_roles_for_uplink(
                router, mode=target_mode, ports=ordered
            )
            router.save(
                update_fields=[
                    "uplink_mode",
                    "uplink_ports",
                    "uplink_weights",
                    "wan_interface",
                    "uplink_unbridged",
                    "port_roles",
                    "updated_at",
                ]
            )
            messages.success(
                request,
                result.get("message")
                or (f"{apply_label.title()} uplinks applied."),
            )
            _record_ports_audit(
                request,
                action="ports_apply_smart_balance" if smart_balance else "ports_apply_balance",
                router=router,
                detail={
                    "ports": ordered,
                    "weights": router.uplink_weights,
                    "smart_balance": smart_balance,
                },
            )
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "clear_multi_uplink":
            listed = list_mikrotik_ports(
                api_host,
                router.username,
                router.password or "",
                timeout=6.0,
                management_hosts=_management_hosts_for_router(router),
            )
            live_ports = (listed.get("ports") or []) if listed.get("ok") else []
            clear_risk = _assess_uplink_mode_apply(
                router,
                "clear",
                _touch_ports_for_clear(router),
                live_ports,
                listed.get("management_iface_by_host") if listed.get("ok") else {},
            )
            ok, err = _check_uplink_apply_confirmation(request, clear_risk)
            if not ok:
                messages.error(request, err)
                return redirect("core:mikrotik_ports", router_id=router.pk)

            restore = (
                list(router.uplink_unbridged)
                if isinstance(router.uplink_unbridged, list)
                else []
            )
            result = clear_mikrotik_uplink_multi(
                api_host,
                router.username,
                router.password or "",
                restore_bridged=restore,
                lan_bridge=router.lan_bridge or "bridgeLocal",
            )
            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            if not result.get("ok"):
                messages.error(
                    request,
                    result.get("error") or "Could not clear bonded / failover settings.",
                )
                return redirect("core:mikrotik_ports", router_id=router.pk)

            single_wan = (router.wan_interface or "ether1").strip()
            bond_name = (router.bond_interface or "").strip()
            if (
                not single_wan
                or single_wan == bond_name
                or single_wan.lower().startswith("bond")
            ):
                members = [
                    str(p).strip()
                    for p in (router.uplink_ports or [])
                    if str(p).strip()
                    and not str(p).strip().lower().startswith("bond")
                    and str(p).strip() != bond_name
                ]
                single_wan = members[0] if members else "ether1"
            router.uplink_mode = MikroTikRouter.UplinkMode.SINGLE
            router.uplink_ports = [single_wan] if single_wan else []
            router.uplink_weights = {}
            router.wan_interface = single_wan or "ether1"
            router.uplink_unbridged = []
            router.port_roles = _sync_roles_for_uplink(
                router,
                mode=MikroTikRouter.UplinkMode.SINGLE,
                ports=[router.wan_interface],
            )
            router.save(
                update_fields=[
                    "uplink_mode",
                    "uplink_ports",
                    "uplink_weights",
                    "wan_interface",
                    "uplink_unbridged",
                    "port_roles",
                    "updated_at",
                ]
            )
            # Push a full single-WAN config so the router is not left without a WAN.
            switch = _apply_single_wan_on_router(
                router,
                api_host,
                wan_interface=router.wan_interface,
                retire_ports=[],
            )
            _record_ports_audit(
                request,
                action="ports_clear_multi_uplink",
                router=router,
                detail={
                    "wan": router.wan_interface,
                    "clear_ok": bool(result.get("ok")),
                    "wan_sync_ok": bool(switch.get("ok")),
                },
            )
            if not switch.get("ok"):
                messages.warning(
                    request,
                    switch.get("error")
                    or (
                        f"Cleared multi-uplink settings, but could not configure "
                        f"single WAN on {router.wan_interface}."
                    ),
                )
            else:
                messages.success(
                    request,
                    result.get("message")
                    or "Bonded / failover / balance uplink settings cleared.",
                )
            return redirect("core:mikrotik_ports", router_id=router.pk)

        messages.error(request, "Unknown ports action.")
        return redirect("core:mikrotik_ports", router_id=router.pk)

    # Live RouterOS I/O is deferred to mikrotik_ports_live (AJAX).
    ports: list[dict] = []
    ports_error = "Activate this MikroTik account to manage ports." if is_suspended else ""
    ports_loading = not is_suspended
    uplink_live: dict = {}
    suggested_wan = ""
    auto_assigned = False
    physical_ports: list[dict] = []
    bond_member_ports: list[str] = []
    primary_wan_ports: list[str] = []
    backup_wan_ports: list[str] = []
    lan_ports: list[str] = []
    unused_ports: list[str] = []
    unassigned_ports: list[str] = []
    can_apply_bond = False
    can_apply_failover = False
    quick_roles = [
        (MikroTikRouter.PortRole.WAN, "Internet"),
        (MikroTikRouter.PortRole.LAN, "Customers"),
        (MikroTikRouter.PortRole.UNUSED, "Unused"),
    ]
    advanced_roles = [
        (MikroTikRouter.PortRole.WAN_BACKUP, "Backup internet"),
        (MikroTikRouter.PortRole.BOND, "Bonded internet"),
        (MikroTikRouter.PortRole.NONE, "Unassigned"),
    ]

    detail_nav = build_mikrotik_detail_nav(
        router,
        is_suspended=is_suspended,
        include_modals=False,
    )
    uplink_mode = router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE

    ctx = client_page_context(
        request,
        active_nav="mikrotik_detail",
        sidebar_active="ports",
        page_title=f"{router.name} — Ports",
        page_subtitle="Tap a role on each port, or auto-assign from live links.",
        router=router,
        router_model_image=mikrotik_model_image(router.model),
        ports=ports,
        physical_ports=physical_ports,
        ports_error=ports_error,
        ports_loading=ports_loading,
        ports_live_url=(
            reverse("core:mikrotik_ports_live", args=[router.pk]) if ports_loading else ""
        ),
        role_choices=role_choices,
        quick_roles=quick_roles,
        advanced_roles=advanced_roles,
        bond_mode_choices=bond_mode_choices,
        bond_mode_advanced_choices=bond_mode_advanced_choices,
        bond_member_ports=bond_member_ports,
        primary_wan_ports=primary_wan_ports,
        backup_wan_ports=backup_wan_ports,
        lan_ports=lan_ports,
        unused_ports=unused_ports,
        unassigned_ports=unassigned_ports,
        can_apply_bond=can_apply_bond,
        can_apply_failover=can_apply_failover,
        can_apply_balance=False,
        uplink_mode=uplink_mode,
        uplink_mode_label=dict(MikroTikRouter.UplinkMode.choices).get(
            uplink_mode, "Single WAN"
        ),
        failover_backup_label=", ".join(
            str(p).strip()
            for p in (router.uplink_ports or [])[1:]
            if str(p).strip()
        ),
        uplink_live=uplink_live if uplink_live.get("ok") else {},
        is_suspended=is_suspended,
        default_bond_name=router.bond_interface or DEFAULT_BOND_NAME,
        default_bond_mode=router.bond_mode or "balance-xor",
        suggested_wan=suggested_wan,
        auto_assigned=auto_assigned,
        api_terminal_script=build_api_enable_terminal_script(),
    )
    return render(
        request,
        "core/mikrotik_ports.html",
        apply_mikrotik_detail_sidebar(ctx, router, detail_nav=detail_nav),
    )


@client_workspace_required
@require_http_methods(["GET", "POST"])
def mikrotik_clean_uplink(request, router_id: int):
    """Enable/disable clean uplink (bypass or behind provider) for one router."""
    org = resolve_organization(request.user, request)
    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect("core:mikrotik")

    router = get_object_or_404(MikroTikRouter, pk=router_id, organization=org)
    is_suspended = router.account_status == MikroTikRouter.AccountStatus.SUSPENDED
    clean_uplink_enabled = bool(router.clean_uplink_enabled)
    form = MikroTikCleanUplinkForm(
        initial={
            "mode": router.clean_uplink_mode or MikroTikRouter.CleanUplinkMode.BYPASS,
            "wan_interface": router.wan_interface or "ether1",
            "lan_bridge": router.lan_bridge or "bridgeLocal",
            "provider_gateway": router.provider_gateway or "192.168.1.1",
            "separate_wan": router.clean_uplink_separate_wan,
        }
    )

    if request.method == "POST":
        if is_suspended:
            messages.error(
                request,
                "Activate this MikroTik account before changing clean uplink.",
            )
            return redirect("core:mikrotik_clean_uplink", router_id=router.pk)

        form = MikroTikCleanUplinkForm(request.POST)
        if form.is_valid():
            cleaned = form.cleaned_data
            turn_on = not clean_uplink_enabled
            api_host = _router_api_host(router)
            was_bridged = bool(router.clean_uplink_wan_was_bridged)

            def _apply_clean_uplink():
                result = set_mikrotik_clean_uplink(
                    api_host,
                    router.username,
                    router.password or "",
                    enabled=turn_on,
                    mode=cleaned.get("mode") or MikroTikRouter.CleanUplinkMode.BYPASS,
                    wan_interface=cleaned.get("wan_interface") or "ether1",
                    lan_bridge=cleaned.get("lan_bridge") or "bridgeLocal",
                    provider_gateway=cleaned.get("provider_gateway") or "",
                    separate_wan=bool(cleaned.get("separate_wan")),
                    restore_wan_to_bridge=was_bridged,
                )
                if result.get("ok"):
                    live = MikroTikRouter.objects.get(pk=router.pk)
                    live.clean_uplink_enabled = bool(result.get("enabled"))
                    live.clean_uplink_mode = (
                        cleaned.get("mode") or MikroTikRouter.CleanUplinkMode.BYPASS
                    )
                    live.wan_interface = cleaned.get("wan_interface") or "ether1"
                    live.lan_bridge = cleaned.get("lan_bridge") or "bridgeLocal"
                    live.provider_gateway = cleaned.get("provider_gateway") or ""
                    live.clean_uplink_separate_wan = bool(cleaned.get("separate_wan"))
                    if turn_on:
                        live.clean_uplink_wan_was_bridged = bool(
                            result.get("wan_was_bridged")
                        )
                    else:
                        live.clean_uplink_wan_was_bridged = False
                    live.save(
                        update_fields=[
                            "clean_uplink_enabled",
                            "clean_uplink_mode",
                            "wan_interface",
                            "lan_bridge",
                            "provider_gateway",
                            "clean_uplink_separate_wan",
                            "clean_uplink_wan_was_bridged",
                            "updated_at",
                        ]
                    )
                    cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
                    if not result.get("message"):
                        result["message"] = (
                            "Clean uplink enabled on the MikroTik."
                            if turn_on
                            else "Clean uplink disabled on the MikroTik."
                        )
                return result

            if _background_mikrotik_ops():
                set_job(router.pk, "clean_uplink", "pending")
                schedule_mikrotik_job(
                    _apply_clean_uplink,
                    name=f"clean-uplink-{router.pk}",
                    router_id=router.pk,
                    job_type="clean_uplink",
                )
                messages.success(
                    request,
                    "Applying clean uplink on the MikroTik in the background. "
                    "This page will show progress shortly.",
                )
                return _redirect_with_mikrotik_job(
                    request, "core:mikrotik_clean_uplink", router.pk, "clean_uplink"
                )

            result = _apply_clean_uplink()
            if not result.get("ok"):
                form.add_error(
                    None,
                    result.get("error")
                    or "Could not update clean uplink on the MikroTik.",
                )
            else:
                messages.success(
                    request,
                    result.get("message")
                    or (
                        "Clean uplink enabled on the MikroTik."
                        if turn_on
                        else "Clean uplink disabled on the MikroTik."
                    ),
                )
                return redirect("core:mikrotik_clean_uplink", router_id=router.pk)

    detail_nav = build_mikrotik_detail_nav(
        router,
        clean_uplink_enabled=bool(router.clean_uplink_enabled),
        is_suspended=is_suspended,
        include_modals=False,
    )
    ctx = client_page_context(
        request,
        active_nav="mikrotik_detail",
        sidebar_active="clean_uplink",
        page_title=f"{router.name} — Clean uplink",
        page_kicker="Uplink",
        page_subtitle=(
            f"Pass only internet through {router.name} and block provider settings."
        ),
        form=form,
        is_suspended=is_suspended,
        clean_uplink_enabled=bool(router.clean_uplink_enabled),
    )
    return render(
        request,
        "core/mikrotik_clean_uplink.html",
        apply_mikrotik_detail_sidebar(ctx, router, detail_nav=detail_nav),
    )


def _ports_live_payload(router: MikroTikRouter) -> dict:
    """Read live ports/uplink and optionally auto-assign empty role maps."""
    from concurrent.futures import ThreadPoolExecutor

    # Ports list and uplink multi-read are independent RouterOS sessions —
    # run them together so the ports page fills in sooner.
    api_host = _router_api_host(router)
    member_ports_for_read = [
        str(p).strip() for p in (router.uplink_ports or []) if str(p).strip()
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        ports_future = pool.submit(
            list_mikrotik_ports,
            api_host,
            router.username,
            router.password or "",
            timeout=5.0,
            management_hosts=_management_hosts_for_router(router),
        )
        uplink_future = pool.submit(
            read_mikrotik_uplink_multi,
            api_host,
            router.username,
            router.password or "",
            timeout=8.0,
            member_ports=member_ports_for_read or None,
        )
        listed = ports_future.result()
        try:
            uplink_live = uplink_future.result()
        except Exception:
            uplink_live = {"ok": False}

    wan_rollback = _wan_switch_rollback_payload(router)

    if not listed.get("ok"):
        payload = {
            "ok": False,
            "error": listed.get("error") or "Could not read ports from the MikroTik.",
            "ports": [],
            "auto_assigned": False,
            "terminal_script": listed.get("terminal_script") or "",
        }
        if wan_rollback:
            payload["wan_rollback"] = wan_rollback
        return payload

    suggested_wan = (listed.get("suggested_wan") or "").strip()
    live_ports = listed.get("ports") or []
    auto_assigned = False
    auto_assigned_router_warning = ""

    stored_roles = router.port_roles if isinstance(router.port_roles, dict) else {}
    assigned = {
        name: role
        for name, role in stored_roles.items()
        if (role or "").strip()
        and (role or "").strip().lower() not in {"", MikroTikRouter.PortRole.NONE}
    }
    if live_ports and not assigned:
        apply_suggested_port_roles(
            router,
            live_ports,
            suggested_wan=suggested_wan,
        )
        auto_assigned = True
        router.refresh_from_db(
            fields=["port_roles", "wan_interface", "uplink_mode", "uplink_ports"]
        )
        # Keep RouterOS in sync with the first auto-assign (same as the button).
        wan_name = (router.wan_interface or "").strip()
        if wan_name:
            try:
                sync = _apply_single_wan_on_router(
                    router,
                    api_host,
                    wan_interface=wan_name,
                    retire_ports=[],
                    live_ports=live_ports,
                )
                if not sync.get("ok"):
                    auto_assigned_router_warning = (
                        sync.get("error")
                        or f"Saved {wan_name} as Internet, but could not configure it on the router."
                    )
                elif sync.get("skipped"):
                    auto_assigned_router_warning = ""
            except Exception:
                auto_assigned_router_warning = (
                    f"Saved {wan_name} as Internet, but could not configure it on the router."
                )

    uplink_mode = router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE
    role_sync_message = ""

    if listed.get("ok"):
        role_result = _auto_sync_port_roles_for_uplink_mode(
            router,
            live_ports,
            suggested_wan=suggested_wan,
        )
        if role_result.get("changed"):
            role_sync_message = role_result.get("message") or ""
            router.refresh_from_db(
                fields=[
                    "port_roles",
                    "wan_interface",
                    "uplink_ports",
                    "uplink_weights",
                    "uplink_mode",
                    "updated_at",
                ]
            )

    suggested_roles = _suggested_roles_for_uplink_mode(
        uplink_mode,
        live_ports,
        suggested_wan=suggested_wan,
        saved_wan=router.wan_interface or "",
    )

    ports: list[dict] = []
    for row in live_ports:
        name = row.get("name") or ""
        role = resolve_port_role(router, name)
        inet = assess_port_internet_readiness(row)
        suggested = (suggested_roles.get(name) or "").strip()
        ports.append(
            {
                **row,
                "role": role,
                "role_label": _friendly_role_label(role, mode=uplink_mode),
                "suggested_role": suggested,
                "suggested_role_label": (
                    _friendly_role_label(suggested, mode=uplink_mode) if suggested else ""
                ),
                "role_matches_setup": not suggested or suggested == (role or "").strip(),
                "is_bond_iface": _is_bond_port_row(row),
                "internet_verified": bool(inet.get("verified")),
                "internet_hint": (inet.get("message") or "").strip(),
                "internet_level": (inet.get("level") or "").strip(),
            }
        )

    physical_ports = [p for p in ports if not p.get("is_bond_iface")]
    bond_member_ports = [
        p["name"] for p in physical_ports if p.get("role") == MikroTikRouter.PortRole.BOND
    ]
    primary_wan_ports = [
        p["name"] for p in physical_ports if _is_primary_wan_role(p.get("role") or "")
    ]
    backup_wan_ports = [
        p["name"]
        for p in physical_ports
        if p.get("role") == MikroTikRouter.PortRole.WAN_BACKUP
    ]
    lan_ports = [
        p["name"] for p in physical_ports if p.get("role") == MikroTikRouter.PortRole.LAN
    ]
    unused_ports = [
        p["name"]
        for p in physical_ports
        if p.get("role") == MikroTikRouter.PortRole.UNUSED
    ]
    unassigned_ports = [
        p["name"]
        for p in physical_ports
        if p.get("role") in {"", MikroTikRouter.PortRole.NONE, None}
    ]

    # Live % share across multi-WAN ports — from rx/tx counters already on
    # the ports list (no third API session). Prefer byte-delta rate when a
    # recent snapshot exists; otherwise cumulative bytes.
    wan_share: dict = {"ok": False, "shares": [], "total_bps": 0}
    share_ports = [
        str(p).strip()
        for p in (list(primary_wan_ports) + list(backup_wan_ports))
        if str(p).strip()
    ]
    if len(share_ports) >= 2 and uplink_mode in _weighted_share_uplink_modes():
        by_name = {p.get("name"): p for p in physical_ports}
        samples = []
        for name in share_ports:
            row = by_name.get(name) or {}
            traffic = (
                (row.get("traffic_iface") or "").strip()
                or (row.get("uplink_iface") or "").strip()
                or name
            )
            samples.append(
                {
                    "name": name,
                    "monitor": traffic,
                    "rx_byte": row.get("rx_byte") or 0,
                    "tx_byte": row.get("tx_byte") or 0,
                }
            )
        try:
            share_cache_key = f"mikrotik_wan_bytes:{router.pk}"
            previous = cache.get(share_cache_key)
            wan_share, next_state = build_wan_traffic_share(
                samples, previous=previous if isinstance(previous, dict) else None
            )
            if next_state:
                cache.set(share_cache_key, next_state, 90)
        except Exception:
            wan_share = {"ok": False, "shares": [], "total_bps": 0}

    uplink_prompt = _build_uplink_prompt(
        router,
        suggested_wan=suggested_wan,
        live_ports=live_ports,
        management_iface_by_host=listed.get("management_iface_by_host") or {},
    )
    backup_uplink_prompt = _build_backup_uplink_prompt(
        router,
        live_ports=live_ports,
        management_iface_by_host=listed.get("management_iface_by_host") or {},
    )
    tunnel_management = check_router_tunnel_management(router, timeout=3.0)
    tunnel_verified = bool(tunnel_management.get("verified"))
    uplink_apply_risks = _build_uplink_apply_risks(
        router,
        live_ports=live_ports,
        management_iface_by_host=listed.get("management_iface_by_host") or {},
        bond_member_ports=bond_member_ports,
        primary_wan_ports=primary_wan_ports,
        backup_wan_ports=backup_wan_ports,
        tunnel_verified=tunnel_verified,
    )

    dual_wan_ready = (
        len(primary_wan_ports) == 1
        and len(backup_wan_ports) >= 1
        and all(
            _port_has_verified_internet(name, physical_ports)
            for name in (primary_wan_ports + backup_wan_ports)
        )
    )
    bond_ready, bond_apply_hint = _bond_apply_readiness(
        bond_member_ports, physical_ports
    )
    balance_ready, balance_apply_hint = _balance_apply_readiness(
        primary_wan_ports, backup_wan_ports, physical_ports
    )
    if uplink_mode == MikroTikRouter.UplinkMode.SMART_BALANCE and balance_ready:
        balance_apply_hint = (
            "Ready — smart balance auto-applies on the MikroTik when links stay up."
        )

    smart_balance_health = _smart_balance_health(
        uplink_live if uplink_live.get("ok") else {},
        uplink_mode,
    )
    smart_balance_auto: dict = {}
    if (
        listed.get("ok")
        and uplink_mode == MikroTikRouter.UplinkMode.SMART_BALANCE
        and balance_ready
        and smart_balance_health.get("needs_apply")
    ):
        smart_balance_auto = _try_auto_apply_smart_balance(
            router,
            api_host,
            member_ports=list(primary_wan_ports) + list(backup_wan_ports),
            member_weights=(
                dict(router.uplink_weights)
                if isinstance(router.uplink_weights, dict)
                else {}
            ),
            uplink_live=uplink_live if uplink_live.get("ok") else {},
            live_ports=physical_ports,
        )
        if smart_balance_auto.get("ok"):
            try:
                uplink_live = read_mikrotik_uplink_multi(
                    api_host,
                    router.username,
                    router.password or "",
                    timeout=8.0,
                    member_ports=list(router.uplink_ports or []),
                )
            except Exception:
                pass

    balance_router_applied = (
        _is_weighted_share_mode(uplink_mode)
        and bool(uplink_live.get("ok"))
        and (uplink_live.get("mode") or "").strip() in _weighted_share_uplink_modes()
    )
    smart_balance_applied = (
        balance_router_applied
        and (
            uplink_mode != MikroTikRouter.UplinkMode.SMART_BALANCE
            or bool(smart_balance_health.get("effective"))
            or bool(smart_balance_auto.get("ok"))
        )
    )
    if smart_balance_auto.get("ok"):
        smart_balance_health = _smart_balance_health(
            uplink_live if uplink_live.get("ok") else {},
            uplink_mode,
        )
        smart_balance_applied = bool(smart_balance_health.get("effective"))
    smart_balance_status = (
        uplink_live.get("smart_balance_status")
        if isinstance(uplink_live.get("smart_balance_status"), dict)
        else {}
    )
    allowed_roles = sorted(_allowed_roles_for_uplink_mode(uplink_mode))
    wan_switch_risks = _build_wan_switch_risks(
        router,
        live_ports=live_ports,
        management_iface_by_host=listed.get("management_iface_by_host") or {},
        primary_wan_ports=primary_wan_ports,
        tunnel_verified=tunnel_verified,
    )
    uplink_health_alerts = _build_uplink_health_alerts(
        uplink_mode=uplink_mode,
        uplink_live=uplink_live if uplink_live.get("ok") else {},
        wan_share=wan_share if wan_share.get("ok") else {},
        primary_wan_ports=primary_wan_ports,
        backup_wan_ports=backup_wan_ports,
        bond_member_ports=bond_member_ports,
        physical_ports=physical_ports,
        uplink_weights=(
            dict(router.uplink_weights)
            if isinstance(router.uplink_weights, dict)
            else {}
        ),
        balance_router_applied=balance_router_applied,
        smart_balance_status=smart_balance_status,
        smart_balance_applied=smart_balance_applied,
    )

    member_ports = [
        str(p).strip()
        for p in (
            list(router.uplink_ports or [])
            or list(primary_wan_ports) + list(backup_wan_ports)
        )
        if str(p).strip()
    ]
    failover_active = ""
    if uplink_mode == MikroTikRouter.UplinkMode.FAILOVER and uplink_live.get("ok"):
        failover_active = _failover_active_wan_port(
            uplink_live,
            primary_wan_ports=primary_wan_ports,
            backup_wan_ports=backup_wan_ports,
        )
    try:
        client_usage = read_client_wan_usage(
            api_host,
            router.username,
            router.password or "",
            uplink_mode=uplink_mode,
            member_ports=member_ports,
            primary_wan=(primary_wan_ports[0] if primary_wan_ports else router.wan_interface or ""),
            failover_active_port=failover_active,
            bond_interface=router.bond_interface or "",
            timeout=6.0,
        )
    except Exception:
        client_usage = {"ok": False, "error": "Could not read client WAN usage."}
    router_analysis = _build_router_client_analysis(
        router,
        uplink_mode=uplink_mode,
        uplink_live=uplink_live if uplink_live.get("ok") else {},
        wan_share=wan_share if wan_share.get("ok") else {},
        smart_balance_status=smart_balance_status,
        primary_wan_ports=primary_wan_ports,
        backup_wan_ports=backup_wan_ports,
        usage=client_usage if isinstance(client_usage, dict) else {},
    )

    auto_msg = ""
    if auto_assigned:
        auto_msg = (
            "Ports were auto-assigned from live links and applied on the MikroTik. "
            "Change any role with one tap, or run Auto-assign again."
        )
        if auto_assigned_router_warning:
            auto_msg = (
                "Ports were auto-assigned from live links. "
                + auto_assigned_router_warning
            )
    elif role_sync_message:
        auto_msg = role_sync_message
    elif smart_balance_auto.get("ok"):
        auto_msg = smart_balance_auto.get("message") or "Smart balance applied on the MikroTik."

    return {
        "ok": True,
        "ports": ports,
        "physical_ports": physical_ports,
        "suggested_wan": suggested_wan,
        "auto_assigned": auto_assigned,
        "auto_assigned_message": auto_msg,
        "ports_assign_hint": PORTS_ASSIGN_HINTS.get(
            uplink_mode,
            PORTS_ASSIGN_HINTS[MikroTikRouter.UplinkMode.SINGLE],
        ),
        "role_sync_message": role_sync_message,
        "uplink_live": uplink_live if uplink_live.get("ok") else {},
        "wan_share": wan_share if wan_share.get("ok") else {"ok": False, "shares": [], "total_bps": 0},
        "bond_member_ports": bond_member_ports,
        "primary_wan_ports": primary_wan_ports,
        "backup_wan_ports": backup_wan_ports,
        "lan_ports": lan_ports,
        "unused_ports": unused_ports,
        "unassigned_ports": unassigned_ports,
        "allowed_roles": allowed_roles,
        "wan_switch_risks": wan_switch_risks,
        "uplink_health_alerts": uplink_health_alerts,
        "can_apply_bond": (
            uplink_mode == MikroTikRouter.UplinkMode.BOND and bond_ready
        ),
        "bond_apply_hint": bond_apply_hint,
        "can_auto_setup_bond": (
            uplink_mode == MikroTikRouter.UplinkMode.BOND
            and len(_live_bond_candidate_ports(live_ports)) >= 2
            and not (
                uplink_live.get("ok")
                and (uplink_live.get("bonds") or [{}])[0].get("running")
            )
        ),
        "can_apply_failover": (
            uplink_mode == MikroTikRouter.UplinkMode.FAILOVER and dual_wan_ready
        ),
        "can_apply_balance": (
            uplink_mode == MikroTikRouter.UplinkMode.BALANCE and balance_ready
        ),
        "can_apply_smart_balance": (
            uplink_mode == MikroTikRouter.UplinkMode.SMART_BALANCE and balance_ready
        ),
        "balance_apply_hint": balance_apply_hint,
        "balance_router_applied": balance_router_applied,
        "smart_balance_applied": smart_balance_applied,
        "smart_balance_health": smart_balance_health,
        "smart_balance_auto": smart_balance_auto,
        "can_auto_setup_smart_balance": len(
            _live_isp_member_ports(
                live_ports,
                suggested_wan=suggested_wan,
                saved_wan=router.wan_interface or "",
            )
        )
        >= 2,
        "smart_balance_status": smart_balance_status if smart_balance_status else {"ok": False, "members": {}, "slow_ports": []},
        "uplink_mode": uplink_mode,
        "uplink_mode_label": dict(MikroTikRouter.UplinkMode.choices).get(
            uplink_mode, "Single WAN"
        ),
        "wan_interface": router.wan_interface or "",
        "bond_interface": router.bond_interface or "",
        "bond_mode": router.bond_mode or "",
        "uplink_ports": list(router.uplink_ports or []),
        "uplink_weights": (
            dict(router.uplink_weights)
            if isinstance(router.uplink_weights, dict)
            else {}
        ),
        "failover_backup_label": ", ".join(
            str(p).strip() for p in (router.uplink_ports or [])[1:] if str(p).strip()
        ),
        "uplink_prompt": uplink_prompt,
        "backup_uplink_prompt": backup_uplink_prompt,
        "uplink_apply_risks": uplink_apply_risks,
        "tunnel_management": tunnel_management,
        "router_analysis": router_analysis,
        "wan_rollback": wan_rollback,
    }


@client_workspace_required
@require_GET
def mikrotik_ports_live(request, router_id: int):
    """JSON live ports + uplink for mikrotik_ports shell page."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization."}, status=400)

    router = get_object_or_404(MikroTikRouter, pk=router_id, organization=org)
    if router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
        return JsonResponse(
            {
                "ok": False,
                "error": "Activate this MikroTik account to manage ports.",
                "suspended": True,
            }
        )

    cache_key = f"mikrotik_ports_live:{org.pk}:{router.pk}"
    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    if force:
        _clear_router_tunnel_cache(router)
    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            return JsonResponse(cached)

    payload = _ports_live_payload(router)
    payload["router_id"] = router.pk
    # Auto-assign mutates DB — do not serve a stale empty role map.
    ttl = 3 if (payload.get("auto_assigned") or payload.get("role_sync_message")) else (8 if payload.get("ok") else 4)
    cache.set(cache_key, payload, ttl)
    return JsonResponse(payload)


@client_workspace_required
@require_POST
def mikrotik_reconnect(request, router_id: int):
    """Repair clean-uplink lockout and bring an onboarded MikroTik back online."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse(
            {"ok": False, "error": "No organization is linked to this workspace."},
            status=400,
        )

    router = get_object_or_404(MikroTikRouter, pk=router_id, organization=org)
    if router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
        return JsonResponse(
            {
                "ok": False,
                "error": "Activate this MikroTik account before reconnecting.",
            },
            status=400,
        )
    blocked = _remote_management_only_response(router)
    if blocked is not None:
        return blocked

    candidate_hosts: list[str] = []
    devices = []
    try:
        devices = discover_mikrotik_devices(timeout=2.5, full_scan=False) or []
    except Exception:
        devices = []

    vpn = (router.vpn_address or "").strip()
    router_name = (router.name or "").strip().casefold()
    wifi_ssid = (router.wifi_ssid or "").strip().casefold()
    scored: list[tuple[int, str]] = []
    discovered_vpn = ""
    for device in devices:
        ip = (device.get("ip") or device.get("host") or "").strip()
        if not ip:
            continue
        ident = (
            (device.get("identity") or device.get("name") or "").strip().casefold()
        )
        if ident.startswith("ispcentric.") and not discovered_vpn:
            maybe = ident.split("ispcentric.", 1)[-1].strip()
            if maybe.count(".") == 3:
                discovered_vpn = maybe
        score = 0
        if vpn and f"ispcentric.{vpn}".casefold() in ident:
            score = 40
        elif ident.startswith("ispcentric."):
            score = 30
        elif router_name and router_name in ident:
            score = 20
        elif wifi_ssid and wifi_ssid in ident:
            score = 18
        elif ip == (router.host or "").strip():
            score = 10
        # Common Hotspot/gateway defaults — try last unless they scored above.
        if ip in {"10.50.50.1", "192.168.88.1"} and score < 20:
            score = -10
        scored.append((score, ip))
    scored.sort(key=lambda item: (-item[0], item[1]))
    for _score, ip in scored:
        if ip not in candidate_hosts:
            candidate_hosts.append(ip)

    try:
        # Optional password from the auth popup (overrides saved credentials for this attempt).
        posted_username = (request.POST.get("username") or "").strip()
        posted_password = request.POST.get("password")
        use_username = posted_username or router.username
        use_password = (
            posted_password
            if posted_password is not None and str(posted_password) != ""
            else (router.password or "")
        )

        result = recover_mikrotik_connection(
            router.host,
            use_username,
            use_password,
            wan_interface=router.wan_interface or "ether1",
            lan_bridge=router.lan_bridge or "bridgeLocal",
            candidate_hosts=candidate_hosts,
            router=router,
            restore_bridge=False,
            remove_clean_rules=False,
            timeout=8.0,
        )
    except Exception as exc:
        return JsonResponse(
            {
                "ok": False,
                "error": f"Reconnect failed unexpectedly: {exc}",
            },
            status=400,
        )

    if not result.get("ok"):
        return JsonResponse(
            {
                "ok": False,
                "error": result.get("error")
                or "Could not reconnect to this MikroTik.",
                "firewall_lockout": bool(result.get("firewall_lockout")),
                "hotspot_lockout": bool(result.get("hotspot_lockout")),
                "api_disabled": bool(result.get("api_disabled")),
                "auth_error": bool(result.get("auth_error")),
                "pingable_hosts": result.get("pingable_hosts") or [],
                "unlock_commands": result.get("unlock_commands") or "",
                "unlock_ip": result.get("unlock_ip") or "",
                "local_ips": result.get("local_ips") or [],
                "username": use_username,
                "host": result.get("host") or router.host,
                "name": router.name,
            },
            status=400,
        )

    update_fields = ["updated_at"]
    new_host = (result.get("host") or "").strip()
    if new_host:
        unify_fields = apply_unified_management_host(router, new_host)
        update_fields.extend(unify_fields)
    if discovered_vpn and not (router.vpn_address or "").strip():
        router.vpn_address = discovered_vpn
        update_fields.append("vpn_address")
        unify_fields = apply_unified_management_host(router, discovered_vpn)
        for field in unify_fields:
            if field not in update_fields:
                update_fields.append(field)

    # Persist credentials from the popup once they work.
    if posted_username and posted_username != (router.username or ""):
        router.username = posted_username
        update_fields.append("username")
    if posted_password is not None and str(posted_password) != "":
        if posted_password != (router.password or ""):
            router.password = posted_password
            update_fields.append("password")

    if router.clean_uplink_enabled:
        router.clean_uplink_enabled = False
        update_fields.append("clean_uplink_enabled")
    if router.clean_uplink_wan_was_bridged:
        router.clean_uplink_wan_was_bridged = False
        update_fields.append("clean_uplink_wan_was_bridged")

    router.save(update_fields=update_fields)

    # Capture hardware IDs once reconnect proves API login works.
    try:
        hardware = test_mikrotik_api_login(
            router.host,
            router.username,
            router.password or "",
            timeout=3.0,
        )
        if hardware.get("ok"):
            hw_fields = _apply_hardware_ids(
                router,
                serial_number=hardware.get("serial_number") or "",
                software_id=hardware.get("software_id") or "",
            )
            if hw_fields:
                router.save(update_fields=hw_fields + ["updated_at"])
    except Exception:
        pass

    cache.delete_many(
        [
            f"mikrotik_status:{org.pk}",
            f"mikrotik_live:{org.pk}:{router.pk}",
            _wifi_fields_cache_key(org.pk, router.pk),
            f"mikrotik_discover:{org.pk}:quick",
            f"mikrotik_discover:{org.pk}:full",
        ]
    )

    router_pk = router.pk

    try:
        from core.hotspot_portal import public_base_url, remember_org_portal_base

        remember_org_portal_base(org.pk, public_base_url(request))
    except Exception:
        pass

    schedule_nas_refresh(router_pk)

    return JsonResponse(
        {
            "ok": True,
            "id": router.pk,
            "host": router.host,
            "host_changed": bool(result.get("host_changed")),
            "online": True,
            "serial_number": router.serial_number or "",
            "software_id": router.software_id or "",
            "message": result.get("message")
            or "MikroTik is back online.",
            "repaired": result.get("repaired") or [],
        }
    )


@client_workspace_required
@require_POST
def mikrotik_reboot(request, router_id: int):
    """Reboot an onboarded MikroTik (configuration is preserved)."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse(
            {"ok": False, "error": "No organization is linked to this workspace."},
            status=400,
        )

    router = get_object_or_404(MikroTikRouter, pk=router_id, organization=org)
    if router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
        return JsonResponse(
            {
                "ok": False,
                "error": "Activate this MikroTik account before restarting it.",
            },
            status=400,
        )
    blocked = _remote_management_only_response(router)
    if blocked is not None:
        return blocked

    dial = (router.api_host or router.host or "").strip()
    if not dial:
        return JsonResponse(
            {"ok": False, "error": "Router host is missing."},
            status=400,
        )

    result = reboot_mikrotik(
        dial,
        router.username or "",
        router.password or "",
        timeout=8.0,
    )
    if not result.get("ok"):
        return JsonResponse(
            {
                "ok": False,
                "error": result.get("error") or "Could not restart this MikroTik.",
                "auth_error": "login" in (result.get("error") or "").lower(),
            },
            status=400,
        )

    cache.delete_many(
        [
            f"mikrotik_status:{org.pk}",
            f"mikrotik_live:{org.pk}:{router.pk}",
            f"mikrotik_auth_ok:{org.pk}:{router.id}",
        ]
    )

    return JsonResponse(
        {
            "ok": True,
            "id": router.pk,
            "message": result.get("message")
            or "Reboot command sent. The MikroTik is restarting.",
        }
    )


@client_workspace_required
@require_GET
def mikrotik_wifi(request, router_id: int):
    """JSON live Wi‑Fi fields for one router (async for mikrotik_detail)."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization."}, status=400)

    router = get_object_or_404(MikroTikRouter, pk=router_id, organization=org)
    if router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
        return JsonResponse(
            {
                "ok": False,
                "wifi_enabled": False,
                "suspended": True,
                "error": "This MikroTik account is suspended.",
            }
        )

    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    if force:
        cache.delete(_wifi_fields_cache_key(org.pk, router.pk))

    router, live = sync_router_wifi_from_live(router)
    return JsonResponse(
        {
            "ok": True,
            "router_id": router.pk,
            "wifi_enabled": bool(live.get("wifi_enabled")),
            "wifi_ssid": (live.get("wifi_ssid") or router.wifi_ssid or "").strip(),
            "wifi_password": live.get("wifi_password") or router.wifi_password or "",
            "wifi_mode": live.get("wifi_mode") or "",
            "interface_count": live.get("interface_count") or 0,
            "error": live.get("error") or "",
        }
    )


@client_workspace_required
@require_GET
def mikrotik_live(request, router_id: int):
    """JSON live health snapshot for one onboarded MikroTik."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "online": False, "error": "No organization."}, status=400)

    router = get_object_or_404(
        MikroTikRouter.objects.only(
            "id",
            "name",
            "host",
            "username",
            "password",
            "account_status",
            "organization_id",
            "internet_provider",
            "vpn_address",
            "serial_number",
            "software_id",
        ),
        pk=router_id,
        organization=org,
    )
    if router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
        return JsonResponse(
            {
                "ok": False,
                "online": False,
                "suspended": True,
                "error": "This MikroTik account is suspended.",
            }
        )

    cache_key = _mikrotik_live_cache_key(org.pk, router.pk)
    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    if not force:
        cached = _cached_mikrotik_live_snapshot(org.pk, router.pk)
        if cached is not None:
            from core.mikrotik_auto_restore import get_auto_restore_record

            cached["auto_restore"] = get_auto_restore_record(router.pk)
            if not cached.get("ok"):
                rollback = _wan_switch_rollback_payload(router)
                if rollback:
                    cached["wan_rollback"] = rollback
            return JsonResponse(cached)

    from core.mikrotik_connect import is_off_lan_tunnel_managed, resolve_router_management_mode
    from core.wireguard import server_on_tunnel

    if is_off_lan_tunnel_managed(router) and not server_on_tunnel():
        if resolve_router_management_mode(router) == "remote_only":
            snapshot = _apply_remote_live_fallback(
                router, org, {"ok": False, "error": "off-lan"}
            )
            snapshot["router_id"] = router.pk
            snapshot["host"] = router.host
            snapshot["api_host"] = (router.api_host or router.host or "").strip()
            from core.mikrotik_auto_restore import get_auto_restore_record

            snapshot["auto_restore"] = get_auto_restore_record(router.pk)
            cache.set(cache_key, snapshot, 60)
            return JsonResponse(snapshot)

    # Try LAN + tunnel candidates (same order as dashboard status probes).
    snapshot = fetch_mikrotik_live_snapshot_for_router(
        router,
        timeout=5.0,
        discover=False,
    )
    dial = (snapshot.get("dial_host") or router.api_host or router.host or "").strip()
    if not snapshot.get("ok"):
        snapshot = _apply_remote_live_fallback(router, org, snapshot)
    snapshot["router_id"] = router.pk
    snapshot["host"] = router.host
    snapshot["api_host"] = dial

    if snapshot.get("ok"):
        hw_fields = _apply_hardware_ids(
            router,
            serial_number=snapshot.get("serial_number") or "",
            software_id=snapshot.get("software_id") or "",
        )
        if hw_fields:
            try:
                # Avoid unique conflicts when a duplicate row already owns this serial.
                serial = (snapshot.get("serial_number") or "").strip()
                if "serial_number" in hw_fields and serial:
                    taken = (
                        MikroTikRouter.objects.filter(
                            organization=org, serial_number=serial
                        )
                        .exclude(pk=router.pk)
                        .exists()
                    )
                    if taken:
                        hw_fields = [f for f in hw_fields if f != "serial_number"]
                if hw_fields:
                    router.save(update_fields=hw_fields + ["updated_at"])
            except Exception:
                pass
        snapshot["serial_number"] = router.serial_number or snapshot.get("serial_number") or ""
        snapshot["software_id"] = router.software_id or snapshot.get("software_id") or ""
    else:
        snapshot["serial_number"] = router.serial_number or ""
        snapshot["software_id"] = router.software_id or ""
        rollback = _wan_switch_rollback_payload(router)
        if rollback:
            snapshot["wan_rollback"] = rollback

    saved_provider = (router.internet_provider or "").strip()
    detected_provider = (snapshot.get("wan_provider_detected") or "").strip()
    provider = detected_provider or saved_provider
    snapshot["wan_provider"] = provider
    snapshot["wan_provider_label"] = provider or "—"
    if detected_provider and snapshot.get("wan_port"):
        snapshot["wan_summary"] = (
            f"{detected_provider} internet entering on {snapshot['wan_port']}"
        )
    elif detected_provider:
        snapshot["wan_summary"] = f"Internet from {detected_provider}"
    elif saved_provider and snapshot.get("wan_port"):
        snapshot["wan_summary"] = (
            f"{saved_provider} internet entering on {snapshot['wan_port']}"
        )
    elif saved_provider:
        snapshot["wan_summary"] = f"Internet from {saved_provider}"

    # Cache successes a bit longer; failures briefly so recovery shows soon.
    from core.mikrotik_auto_restore import get_auto_restore_record

    snapshot["auto_restore"] = get_auto_restore_record(router.pk)
    # Shorter than the 10s UI poll so each refresh gets fresh WAN speeds.
    ttl = 4
    if snapshot.get("management_deferred"):
        ttl = 60
    cache.set(cache_key, snapshot, ttl)
    return JsonResponse(snapshot)


@client_workspace_required
@require_GET
def mikrotik_places(request):
    """Live location suggestions (Google Maps first, Nominatim fallback)."""
    query = (request.GET.get("q") or "").strip()
    result = search_locations(query, limit=6)
    return JsonResponse(result)


@client_workspace_required
@require_GET
def mikrotik_place_details(request):
    """Resolve a place_id or free-text location to coordinates."""
    place_id = (request.GET.get("place_id") or "").strip()
    query = (request.GET.get("q") or "").strip()
    details = resolve_location(query, place_id=place_id)
    if not details:
        return JsonResponse({"ok": False, "error": "Place not found."}, status=404)
    return JsonResponse({"ok": True, **details})


@client_workspace_required
@require_GET
def mikrotik_discover(request):
    """Live discovery of connected MikroTik devices (new + already onboarded)."""
    org = resolve_organization(request.user, request)
    onboarded_hosts = []
    if org:
        onboarded_hosts = list(
            MikroTikRouter.objects.filter(organization=org).values_list("host", flat=True)
        )

    # full=1 forces a deep /24 scan; default/interval polls stay quick.
    full_scan = (request.GET.get("full") or "").strip() in {"1", "true", "yes"}
    org_key = org.pk if org else 0
    cache_key = f"mikrotik_discover:{org_key}:{'full' if full_scan else 'quick'}"
    cached = cache.get(cache_key)
    if cached is not None:
        annotated = annotate_onboarded(cached, onboarded_hosts)
    else:
        try:
            devices = discover_mikrotik_devices(
                timeout=3.0 if full_scan else 2.0,
                full_scan=full_scan,
            )
            cache.set(cache_key, devices, 12)
            annotated = annotate_onboarded(devices, onboarded_hosts)
        except Exception as exc:
            return JsonResponse(
                {
                    "ok": False,
                    "error": "Discovery failed.",
                    "detail": str(exc),
                    "devices": [],
                },
                status=500,
            )

    new_count = sum(1 for d in annotated if not d.get("onboarded"))
    onboarded_count = sum(1 for d in annotated if d.get("onboarded"))

    return JsonResponse(
        {
            "ok": True,
            "count": len(annotated),
            "new_count": new_count,
            "onboarded_count": onboarded_count,
            "devices": [
                {
                    "host": d.get("host") or "",
                    "name": d.get("name") or "",
                    "identity": d.get("identity") or "",
                    "board": d.get("board") or "",
                    "version": d.get("version") or "",
                    "mac": d.get("mac") or "",
                    "model": d.get("model") or "other",
                    "source": d.get("source") or "",
                    "alive": True,
                    "onboarded": bool(d.get("onboarded")),
                }
                for d in annotated
            ],
        }
    )


@client_workspace_required
@require_POST
def mikrotik_tunnel_script(request):
    """Reserve a WireGuard peer and return the RouterOS paste script for Connect."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization is linked."}, status=400)

    if not wireguard.configured():
        return JsonResponse(
            {
                "ok": False,
                "configured": False,
                "error": (
                    "Billing tunnel is not configured on this server. "
                    "Set WIREGUARD_ENDPOINT and WIREGUARD_SERVER_PUBLIC_KEY, "
                    "then restart the app."
                ),
            },
            status=400,
        )

    label = (request.POST.get("label") or "").strip() or "New MikroTik"
    client_settings = ClientSettings.get_solo()
    paid_stk_id = 0
    if client_settings.onboarding_fee_ready:
        raw_stk = (request.POST.get("stk_id") or "").strip()
        try:
            paid_stk_id = int(raw_stk)
        except (TypeError, ValueError):
            paid_stk_id = 0
        if not paid_stk_id:
            return JsonResponse(
                {
                    "ok": False,
                    "configured": True,
                    "payment_required": True,
                    "amount": str(client_settings.onboarding_fee_amount),
                    "error": (
                        f"Pay KES {client_settings.onboarding_fee_amount} via STK Push "
                        "to generate the onboarding script."
                    ),
                },
                status=402,
            )
        paid = consume_mikrotik_onboarding_payment(
            organization=org,
            user=request.user,
            stk_id=paid_stk_id,
            label=label,
            mark_used=False,
        )
        if not paid.get("ok"):
            return JsonResponse(
                {
                    "ok": False,
                    "configured": True,
                    "payment_required": True,
                    "amount": str(client_settings.onboarding_fee_amount),
                    "error": paid.get("error") or "Complete payment before generating the script.",
                    "stk_id": paid_stk_id,
                    "status": paid.get("status") or "",
                },
                status=402,
            )

    try:
        reservation, peer_sync = wireguard.reserve_peer(label)
        payload = wireguard.peer_payload(
            reservation.label,
            reservation.address,
            reservation.private_key,
            reservation.public_key,
            lan_address=(reservation.lan_address or ""),
        )
    except ValueError as exc:
        return JsonResponse({"ok": False, "configured": True, "error": str(exc)}, status=400)
    except Exception as exc:
        return JsonResponse(
            {"ok": False, "configured": True, "error": f"Could not reserve tunnel peer: {exc}"},
            status=500,
        )

    if paid_stk_id:
        consume_mikrotik_onboarding_payment(
            organization=org,
            user=request.user,
            stk_id=paid_stk_id,
            label=label,
            mark_used=True,
        )

    sync_info = wireguard.peer_sync_report(peer_sync)
    from core.mikrotik_status_samples import mark_mikrotik_onboarding_active

    mark_mikrotik_onboarding_active(
        org.pk, user_id=request.user.pk, org_wide=True
    )
    discovered_lan = ""
    if on_router_lan():
        discovered_lan = pick_local_onboard_connect_host(
            tunnel_address=reservation.address,
            reservation_label=reservation.label,
            planned_lan=payload.get("lan_address") or "",
        )
    return JsonResponse(
        {
            "ok": True,
            "configured": True,
            "label": payload["label"],
            "address": payload["address"],
            "lan_address": payload.get("lan_address") or "",
            "discovered_lan": discovered_lan,
            "script": payload["script"],
            "server_peer": payload["server_peer"],
            "endpoint": payload["endpoint"],
            "peer_synced": sync_info["peer_synced"],
            "peer_sync_skipped": sync_info["peer_sync_skipped"],
            "peer_sync_required": sync_info["peer_sync_required"],
            "peer_sync_error": sync_info["peer_sync_error"],
            "peer_sync_reason": sync_info["peer_sync_reason"],
            "status_token": signing.dumps(
                {"address": payload["address"], "user_id": request.user.pk},
                salt="mikrotik-tunnel-status",
                compress=True,
            ),
            "hint": sync_info["peer_sync_hint"],
        }
    )


def _mikrotik_rsc_response(*, address: str, kind: str, request=None):
    """Build HttpResponse for install or post-reset .rsc from a reservation address."""
    from django.http import HttpResponse

    from accounts.audit import record_audit
    from core.models import WireGuardReservation

    address = (address or "").strip()
    kind = (kind or "install").strip().lower()
    if not wireguard.rsc_download_allowed(address):
        record_audit(
            action="rsc_download",
            request=request,
            target=address,
            detail={"kind": kind, "blocked": True, "reason": "rate_limit"},
        )
        return HttpResponse(
            "download rate limit exceeded — try again later\n",
            status=429,
            content_type="text/plain",
        )

    reservation = WireGuardReservation.objects.filter(address=address).first()
    if reservation is None:
        return HttpResponse("reservation not found\n", status=404, content_type="text/plain")

    if kind in {"post-reset", "reset", "post_reset", "p"}:
        body = wireguard.post_reset_rsc_body(
            reservation.address,
            reservation.private_key,
            lan_address=(reservation.lan_address or ""),
        )
        filename = "ispcentric-post-reset.rsc"
    else:
        body = wireguard.install_rsc_body(
            reservation.address,
            reservation.private_key,
            lan_address=(reservation.lan_address or ""),
        )
        filename = "ispcentric-install.rsc"

    record_audit(
        action="rsc_download",
        request=request,
        target=address,
        detail={"kind": kind, "filename": filename},
    )

    response = HttpResponse(body + "\n", content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    response["Cache-Control"] = "no-store"
    return response


@require_GET
def mikrotik_tunnel_rsc(request):
    """
    MikroTik /tool fetch target: signed .rsc for tunnel install or post-reset.

    Prefer the short /app/m/<addr>/<mac>/<i|p>/ URL in new pastes (Winbox-safe).
    """
    from django.core import signing
    from django.http import HttpResponse

    token = (request.GET.get("token") or "").strip()
    kind = (request.GET.get("kind") or "install").strip().lower()
    # Shorter TTL reduces leaked-URL window (MikroTik fetch is near-immediate).
    max_age = int(getattr(settings, "WIREGUARD_RSC_TOKEN_MAX_AGE", 7200) or 7200)
    try:
        signed = signing.loads(token, salt="mikrotik-tunnel-rsc", max_age=max_age)
    except signing.BadSignature:
        return HttpResponse("invalid or expired token\n", status=403, content_type="text/plain")

    return _mikrotik_rsc_response(
        address=signed.get("address") or "",
        kind=kind,
        request=request,
    )


@require_GET
def mikrotik_tunnel_rsc_short(request, address: str, mac: str, kind: str):
    """
    Short Winbox-safe .rsc URL: /app/m/10.9.0.12/<hmac12>/i or .../p

    HMAC uses SECRET_KEY — no long query token that wraps mid-paste.
    """
    from django.http import HttpResponse

    address = (address or "").strip()
    if not wireguard.verify_rsc_download_mac(address, mac):
        return HttpResponse("invalid mac\n", status=403, content_type="text/plain")
    return _mikrotik_rsc_response(address=address, kind=kind, request=request)


@client_workspace_required
@require_POST
def mikrotik_onboarding_stk(request):
    """Start STK Push for the platform MikroTik onboarding fee."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization is linked."}, status=400)

    result = start_mikrotik_onboarding_stk_payment(
        organization=org,
        phone=(request.POST.get("phone") or "").strip(),
        label=(request.POST.get("label") or "").strip(),
        user=request.user,
        request=request,
    )
    status = 200 if result.get("ok") else 400
    return JsonResponse(result, status=status)


@client_workspace_required
@require_GET
def mikrotik_onboarding_stk_status(request, stk_id: int):
    """Poll STK status for MikroTik onboarding fee payment."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization is linked."}, status=400)

    stk = get_object_or_404(
        StkPushRequest,
        pk=stk_id,
        organization=org,
        purpose=StkPushRequest.Purpose.MIKROTIK_ONBOARDING,
    )
    if stk.initiated_by_id and stk.initiated_by_id != request.user.pk:
        return JsonResponse({"ok": False, "error": "This payment belongs to another user."}, status=403)
    return JsonResponse(refresh_stk_status(stk))


@client_workspace_required
@require_http_methods(["GET", "POST"])
def mikrotik_tunnel_status(request):
    """Check whether a newly reserved tunnel reaches RouterOS API port 8728."""
    token = (request.POST.get("token") or request.GET.get("token") or "").strip()
    try:
        signed = signing.loads(token, salt="mikrotik-tunnel-status", max_age=3600)
    except signing.BadSignature:
        return JsonResponse({"ok": False, "error": "This tunnel check has expired."}, status=400)

    if signed.get("user_id") != request.user.pk:
        return JsonResponse({"ok": False, "error": "This tunnel check is not yours."}, status=403)

    address = (signed.get("address") or "").strip()
    reservation = WireGuardReservation.objects.filter(address=address).first()
    if not address or reservation is None:
        return JsonResponse({"ok": False, "error": "Tunnel reservation was not found."}, status=404)

    # A local development machine is not a WireGuard peer. Use MNDP/LAN
    # discovery instead. On a hosted VPS, missing 10.9.0.1 means wg0 is down —
    # never fall back to LAN discovery (that only works on a tech laptop).
    if not wireguard.server_on_tunnel():
        if getattr(settings, "HOSTED", False):
            server = str(wireguard.server_address())
            message = (
                f"This VPS is not holding the WireGuard server address {server}. "
                "Bring up the tunnel before onboarding: "
                f"sudo wg-quick up {(getattr(settings, 'WIREGUARD_INTERFACE', None) or 'wg0').strip() or 'wg0'} "
                "(or systemctl enable --now wg-quick@wg0), confirm "
                f"`ip -4 addr show` lists {server}, set WIREGUARD_SYNC_COMMAND if the "
                "app user cannot write wg0.conf, then Check now."
            )
            checks = [
                {
                    "key": "tunnel",
                    "status": "fail",
                    "label": "VPS WireGuard",
                    "message": f"Server address {server} is not bound on this host",
                },
                {
                    "key": "vps_peer",
                    "status": "fail",
                    "label": "VPS peer sync",
                    "message": "Cannot register peers until wg0 is up on this VPS",
                },
                {
                    "key": "billing_ping",
                    "status": "waiting",
                    "label": f"Ping billing server {server}",
                    "message": "Waiting for VPS WireGuard",
                },
                {
                    "key": "api",
                    "status": "waiting",
                    "label": "API port 8728",
                    "message": "Waiting for tunnel path from MikroTik → VPS",
                },
                {
                    "key": "firewall",
                    "status": "waiting",
                    "label": "Firewall API rule",
                    "message": "Waiting for Winbox script on the router",
                },
            ]
            return JsonResponse(
                {
                    "ok": True,
                    "address": address,
                    "tunnel_reachable": False,
                    "api_enabled": False,
                    "script_installed": False,
                    "ready": False,
                    "no_tunnel_route": True,
                    "hosted_wg_down": True,
                    "local_mode": False,
                    "via": "",
                    "message": message,
                    "checks": checks,
                    "peer_state": "missing",
                    "peer_synced": False,
                    "peer_present": False,
                }
            )

        org = resolve_organization(request.user, request)
        cache_key = f"mikrotik_tunnel_local_devices:{org.pk if org else 0}"
        # Always refresh — identity marker appears only after Winbox paste.
        cache.delete(cache_key)
        devices = discover_mikrotik_devices(timeout=1.2, full_scan=False)
        known_hosts = (
            MikroTikRouter.objects.filter(organization=org)
            .values_list("host", flat=True)
            if org
            else []
        )
        devices = annotate_onboarded(devices, known_hosts)
        cache.set(cache_key, devices, 8)

        candidates = [device for device in devices if not device.get("onboarded")]
        planned_lan = (getattr(reservation, "lan_address", None) or "").strip()
        requested_lan = (
            request.POST.get("lan_host") or request.GET.get("lan_host") or ""
        ).strip()
        candidate = next(
            (
                device
                for device in candidates
                if requested_lan and device.get("host") == requested_lan
            ),
            None,
        )
        if candidate is None and len(candidates) == 1:
            candidate = candidates[0]
        if candidate is None and candidates:
            wanted = (reservation.label or "").strip().casefold()
            candidate = next(
                (
                    device
                    for device in candidates
                    if wanted
                    and wanted
                    in (
                        device.get("identity")
                        or device.get("name")
                        or ""
                    ).strip().casefold()
                ),
                None,
            )
        # Prefer the router advertising this paste's identity marker.
        if candidate is None:
            candidate = next(
                (
                    device
                    for device in candidates
                    if wireguard.identity_marks_script_ready(
                        device.get("identity") or device.get("name") or "",
                        address,
                    )
                ),
                None,
            )

        lan_address = (candidate or {}).get("host") or ""
        if not lan_address and requested_lan:
            lan_address = requested_lan
        probe = (
            probe_mikrotik_for_onboarding(lan_address, base_timeout=1.2)
            if lan_address
            else {}
        )
        via = probe.get("via") or ""
        api_enabled = bool(probe.get("online") and via == "api")
        from core.hotspot_portal import local_ipv4_shares_subnet

        same_subnet, local_ip = (
            local_ipv4_shares_subnet(lan_address) if lan_address else (False, "")
        )
        subnet_mismatch = bool(lan_address and local_ip and not same_subnet and not api_enabled)

        # Credentials optional — paste is proven via MNDP identity, not login.
        check_user = (
            (request.POST.get("username") or "").strip()
            if request.method == "POST"
            else ""
        )
        check_pass = (
            (request.POST.get("password") or "")
            if request.method == "POST"
            else ""
        )

        script_info = (
            wireguard.lan_tunnel_script_installed(
                lan_address,
                address,
                username=check_user,
                password=check_pass,
                identity=(candidate or {}).get("identity")
                or (candidate or {}).get("name")
                or "",
                devices=candidates,
            )
            if not subnet_mismatch
            else {"installed": False, "via": "", "error": "", "marker": ""}
        )
        script_installed = bool(script_info.get("installed"))
        # LAN ready when script marker is present; API open is expected after paste.
        ready = bool(script_installed and api_enabled and lan_address)

        marker = wireguard.script_ready_identity(address)
        if ready:
            message = (
                f"All set — script confirmed on {lan_address} "
                f"(identity {marker}). Enter username and password, then Connect."
            )
        elif script_installed and not api_enabled:
            message = (
                f"Script marker seen ({marker}), but API :8728 is not open yet on "
                f"{lan_address or 'the router'}. Wait a few seconds, then Check now."
            )
        elif api_enabled and not script_installed:
            message = (
                f"Found {lan_address} with API open, but the Winbox script is not "
                f"confirmed yet. Paste the script and wait until the router identity "
                f"becomes {marker}, then Check now. Login comes after that."
            )
        elif subnet_mismatch:
            message = (
                f"Found the MikroTik at {lan_address}, but this computer is on "
                f"{local_ip} (different subnet), so API port 8728 cannot open. "
                f"Give this PC an address on the same LAN (for example "
                f"{'.'.join(lan_address.split('.')[:3])}.10), or change the "
                f"MikroTik LAN IP to match {local_ip.rsplit('.', 1)[0]}.x, then click Check now."
            )
        elif lan_address:
            message = (
                f"Found the MikroTik locally at {lan_address}, but API port 8728 "
                "is not available yet. Paste the latest script and wait for it to finish; "
                "it now permits API access from private LANs."
            )
        elif candidates:
            message = (
                "Several local MikroTik routers were found. Select the correct LAN IP "
                "in the MikroTik IP field, then click Check now."
            )
        else:
            message = (
                "Local mode is active, but no MikroTik was discovered on this LAN. "
                "Connect this computer to the router network, paste the latest script, "
                "then click Check now."
            )

        checks = wireguard.tunnel_verification_checks(
            local_mode=True,
            address=address,
            tunnel_reachable=False,
            api_enabled=api_enabled,
            lan_address=lan_address,
            subnet_mismatch=subnet_mismatch,
            multiple_devices=len(candidates) > 1,
            script_installed=script_installed,
        )

        return JsonResponse(
            {
                "ok": True,
                "address": address,
                "tunnel_reachable": False,
                "api_enabled": api_enabled,
                "script_installed": script_installed,
                "script_via": script_info.get("via") or "",
                "script_marker": marker,
                "script_needs_login": False,
                "ready": ready,
                "no_tunnel_route": True,
                "local_mode": True,
                "lan_address": lan_address,
                "script_lan_address": planned_lan,
                "local_ip": local_ip,
                "subnet_mismatch": subnet_mismatch,
                "local_devices": [
                    {
                        "host": device.get("host") or "",
                        "name": device.get("identity") or device.get("name") or "",
                    }
                    for device in candidates
                ],
                "via": via,
                "message": message,
                "checks": checks,
            }
        )

    probe = probe_mikrotik_for_onboarding(address, base_timeout=1.5)
    via = probe.get("via") or ""
    api_enabled = bool(probe.get("online") and via == "api")
    tunnel_reachable = bool(probe.get("online"))

    diagnosis = {"code": "ok", "message": "", "peer_sync": {}, "peer": {}}
    if not tunnel_reachable:
        diagnosis = wireguard.ensure_reservation_peer(reservation)
        # Peer may have just been applied — re-probe once.
        if diagnosis.get("peer_sync", {}).get("ok"):
            probe = probe_mikrotik_for_onboarding(address, base_timeout=1.5)
            via = probe.get("via") or ""
            api_enabled = bool(probe.get("online") and via == "api")
            tunnel_reachable = bool(probe.get("online"))
            if tunnel_reachable:
                diagnosis = {
                    "code": "ok",
                    "message": "",
                    "peer_sync": diagnosis.get("peer_sync") or {},
                    "peer": diagnosis.get("peer") or {},
                }

    if api_enabled:
        message = "Success — tunnel is online and RouterOS API is enabled on port 8728."
    elif tunnel_reachable:
        message = (
            "Tunnel is reachable, but RouterOS API port 8728 is not available. "
            "Wait for the script to finish or paste it again."
        )
    else:
        message = diagnosis.get("message") or (
            "Waiting for MikroTik… paste the script in Winbox → New Terminal."
        )

    if tunnel_reachable:
        peer_state = "ok"
    else:
        peer_state = diagnosis.get("code") or "unknown"
        if peer_state == "ok":
            peer_state = "unknown"

    checks = wireguard.tunnel_verification_checks(
        local_mode=False,
        address=address,
        tunnel_reachable=tunnel_reachable,
        api_enabled=api_enabled,
        peer_state=peer_state,
    )

    peer_sync = diagnosis.get("peer_sync") or {}
    peer_info = diagnosis.get("peer") or {}
    # On the VPS, reaching the tunnel IP means the Winbox script created the peer.
    script_installed = bool(tunnel_reachable or api_enabled)
    script_lan = (getattr(reservation, "lan_address", None) or "").strip()
    return JsonResponse(
        {
            "ok": True,
            "address": address,
            "tunnel_reachable": tunnel_reachable,
            "api_enabled": api_enabled,
            "script_installed": script_installed,
            "ready": api_enabled,
            "no_tunnel_route": False,
            "hosted_wg_down": False,
            "local_mode": False,
            "lan_address": script_lan,
            "script_lan_address": script_lan,
            "via": via,
            "message": message,
            "checks": checks,
            "peer_state": peer_state,
            "peer_synced": bool(peer_sync.get("ok") or peer_info.get("present") or tunnel_reachable),
            "peer_present": bool(peer_info.get("present") or tunnel_reachable),
            "handshake_age_sec": peer_info.get("handshake_age_sec"),
            "peer_sync_error": (peer_sync.get("error") or "").strip(),
        }
    )


@client_workspace_required
@require_POST
def mikrotik_connect(request):
    """Verify RouterOS API credentials before onboard step."""
    host = (request.POST.get("host") or "").strip()
    username = (request.POST.get("username") or "").strip()
    password = request.POST.get("password") or ""
    org = resolve_organization(request.user, request)
    connect_host = normalize_mikrotik_host(host)
    script_lan = normalize_mikrotik_host(request.POST.get("script_lan") or "")
    tunnel_host = normalize_mikrotik_host(request.POST.get("tunnel_host") or "")

    if tunnel_host:
        peer_gate = wireguard.onboard_tunnel_peer_ready(tunnel_host)
        if peer_gate.get("required") and not peer_gate.get("ok"):
            return JsonResponse(
                {
                    "ok": False,
                    "peer_sync_required": True,
                    "error": (
                        peer_gate.get("error")
                        or peer_gate.get("peer_sync_hint")
                        or "WireGuard peer is not registered on the VPS yet."
                    ),
                },
                status=400,
            )

    if on_router_lan():
        connect_host = pick_local_onboard_connect_host(
            tunnel_address=tunnel_host,
            planned_lan=script_lan,
            current=connect_host,
        )
    dial_host = connect_host

    result = test_mikrotik_api_login(dial_host, username, password)
    if not result.get("ok"):
        return JsonResponse(
            {"ok": False, "error": result.get("error") or "Connection failed."},
            status=400,
        )

    # While API is open, permanently free this PC from Hotspot lockout so
    # Fleet Reconnect keeps working after ISP Hotspot is pushed.
    try:
        with _api_session(dial_host, username, password, timeout=8.0) as sock:
            _ensure_hotspot_management_access(
                sock, username=username, password=password
            )
    except Exception:
        pass

    board = result.get("board") or ""
    serial_number = (result.get("serial_number") or "").strip()
    software_id = (result.get("software_id") or "").strip()
    existing = _find_router_by_hardware(
        org,
        serial_number=serial_number,
        software_id=software_id,
        host=result.get("host") or host,
    )
    if existing:
        detail_url = reverse("core:mikrotik_detail", args=[existing.pk])
        return JsonResponse(
            {
                "ok": False,
                "already_onboarded": True,
                "error": (
                    f'This MikroTik is already onboarded as “{existing.name}”. '
                    f"Open it from the list or use Reconnect — you cannot register the same device twice."
                ),
                "existing_router_id": existing.pk,
                "existing_router_name": existing.name,
                "existing_router_url": detail_url,
                "serial_number": serial_number,
                "software_id": software_id,
                "host": result.get("host") or host,
            },
            status=400,
        )

    if org:
        from core.mikrotik_status_samples import mark_mikrotik_onboarding_active

        mark_mikrotik_onboarding_active(org.pk, user_id=request.user.pk)

    final_host = connect_host or normalize_mikrotik_host(result.get("host") or host)
    lan_ip_applied = False
    lan_message = ""

    if is_transient_onboard_host(connect_host):
        suggested_lan_ip = suggest_unique_mikrotik_lan_ip(
            list(
                MikroTikRouter.objects.filter(organization=org).values_list(
                    "host", flat=True
                )
            )
            if org
            else []
        )
        if connect_host != suggested_lan_ip:
            lan_result = change_mikrotik_lan_ip(
                connect_host,
                username,
                password,
                suggested_lan_ip,
                api_hosts=[host for host in (tunnel_host, connect_host) if host],
            )
            if not lan_result.get("ok"):
                return JsonResponse(
                    {
                        "ok": False,
                        "error": lan_result.get("error")
                        or "Could not assign a unique LAN IP on this MikroTik.",
                    },
                    status=400,
                )
            lan_ip_applied = True
            final_host = resolve_onboard_management_host(
                connect_host=connect_host,
                tunnel_host=tunnel_host,
                lan_result=lan_result,
                fallback=suggested_lan_ip,
            )
            lan_message = (lan_result.get("message") or "").strip()
    elif tunnel_host and not on_router_lan():
        final_host = tunnel_host

    return JsonResponse(
        {
            "ok": True,
            "host": final_host,
            "connect_host": connect_host,
            "tunnel_host": tunnel_host,
            "name": result.get("name") or "",
            "identity": result.get("identity") or "",
            "version": result.get("version") or "",
            "board": board,
            "serial_number": serial_number,
            "software_id": software_id,
            "model": guess_model(board),
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
    )


@client_workspace_required
@require_POST
def mikrotik_onboarding_guard(request):
    """Keep fleet status probes paused while the onboard modal is open."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization is linked."}, status=400)

    from core.mikrotik_status_samples import (
        clear_mikrotik_onboarding_active,
        mark_mikrotik_onboarding_active,
    )

    action = (request.POST.get("action") or "ping").strip().lower()
    if action == "clear":
        clear_mikrotik_onboarding_active(
            org.pk, user_id=request.user.pk, org_wide=False
        )
    else:
        mark_mikrotik_onboarding_active(org.pk, user_id=request.user.pk)
    return JsonResponse({"ok": True, "action": action})


@client_workspace_required
@require_GET
def mikrotik_push_status(request, router_id: int):
    """Poll background MikroTik push jobs (credentials, uplink, PPPoE, etc.)."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization."}, status=403)
    if not MikroTikRouter.objects.filter(pk=router_id, organization=org).exists():
        return JsonResponse({"ok": False, "error": "Router not found."}, status=404)

    job_type = (request.GET.get("job") or "").strip()
    if job_type:
        if request.GET.get("recover") == "1" and job_type == NAS_REFRESH_JOB:
            ensure_nas_refresh_job(router_id)
        job = get_job(router_id, job_type) or {"status": "unknown"}
        return JsonResponse({"ok": True, "job": job})
    return JsonResponse({"ok": True, "jobs": get_router_jobs(router_id)})


@client_workspace_required
@require_GET
def mikrotik_status(request):
    """Live online/offline status for onboarded MikroTik routers."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from core.mikrotik_status_samples import (
        _HOSTED_AUTH_CACHE_TTL,
        build_router_probe_plan,
        classify_router_status_row,
        is_mikrotik_onboarding_active,
        pick_best_probe_for_router,
        probe_mikrotik_hosts,
        stabilize_live_status_rows,
    )

    org = resolve_organization(request.user, request)
    routers = (
        list(
            MikroTikRouter.objects.filter(organization=org).only(
                "id",
                "host",
                "name",
                "username",
                "password",
                "serial_number",
                "software_id",
                "vpn_address",
                "vpn_public_key",
            )
        )
        if org
        else []
    )
    if not routers:
        return JsonResponse({"ok": True, "routers": []})

    force_refresh = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    cache_key = f"mikrotik_status:{org.pk if org else 0}"
    onboarding_hold = bool(
        org
        and is_mikrotik_onboarding_active(org.pk, user_id=request.user.pk)
    )
    if onboarding_hold and not force_refresh:
        cached = cache.get(cache_key)
        if cached is not None:
            from core.mikrotik_auto_restore import attach_auto_restore_to_rows

            attach_auto_restore_to_rows(cached)
            return JsonResponse(
                {"ok": True, "routers": cached, "onboarding_hold": True}
            )
    if not force_refresh:
        cached = cache.get(cache_key)
        if cached is not None:
            from core.mikrotik_auto_restore import attach_auto_restore_to_rows

            attach_auto_restore_to_rows(cached)
            return JsonResponse({"ok": True, "routers": cached})

    results = {}

    router_candidates, unique_hosts, tunnel_by_router, off_lan_tunnel_by_router = build_router_probe_plan(routers)
    probe_by_host = probe_mikrotik_hosts(unique_hosts)

    def _best_probe_for_router(router):
        return pick_best_probe_for_router(
            router,
            router_candidates.get(router.id) or [],
            probe_by_host,
        )

    def _check(router):
        host, probe = _best_probe_for_router(router)
        via = (probe.get("via") or "").strip()
        auth_cache_key = f"mikrotik_auth_ok:{org.pk}:{router.id}"
        skip_login = (
            via == "api"
            and not force_refresh
            and getattr(settings, "HOSTED", False)
            and bool(cache.get(auth_cache_key))
        )
        item = classify_router_status_row(
            router,
            host=host,
            probe=probe,
            skip_login=skip_login,
        )
        backfill = {}
        if item.get("auth_ok"):
            if getattr(settings, "HOSTED", False) and not skip_login:
                cache.set(auth_cache_key, True, _HOSTED_AUTH_CACHE_TTL)
            live_serial = (item.get("serial_number") or "").strip()
            live_soft = (item.get("software_id") or "").strip()
            if live_serial and live_serial != (router.serial_number or "").strip():
                backfill["serial_number"] = live_serial
            if live_soft and live_soft != (router.software_id or "").strip():
                backfill["software_id"] = live_soft
        elif via == "api" and getattr(settings, "HOSTED", False):
            cache.delete(auth_cache_key)
        return router.id, {**item, "_backfill": backfill}

    workers = min(8, max(1, len(routers)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check, router) for router in routers]
        for future in as_completed(futures):
            try:
                router_id, payload = future.result()
                results[router_id] = payload
            except Exception:
                continue

    payload = []
    for router in routers:
        item = results.get(
            router.id,
            {
                "id": router.id,
                "host": router.host,
                "name": router.name,
                "online": False,
                "status": "disconnected",
                "via": "",
                "serial_number": (router.serial_number or "").strip(),
                "software_id": (router.software_id or "").strip(),
            },
        )
        backfill = item.pop("_backfill", None) or {}
        if backfill:
            try:
                serial = (backfill.get("serial_number") or "").strip()
                if serial:
                    taken = (
                        MikroTikRouter.objects.filter(
                            organization=org, serial_number=serial
                        )
                        .exclude(pk=router.id)
                        .exists()
                    )
                    if taken:
                        backfill.pop("serial_number", None)
                if backfill:
                    MikroTikRouter.objects.filter(pk=router.id).update(**backfill)
            except Exception:
                pass
        payload.append(item)
    probe_payload = [dict(row) for row in payload]
    payload = stabilize_live_status_rows(
        org.pk if org else 0,
        payload,
        force=force_refresh,
        tunnel_by_router=tunnel_by_router,
        off_lan_tunnel_by_router=off_lan_tunnel_by_router,
    )
    from core.mikrotik_auto_restore import attach_auto_restore_to_rows

    if not onboarding_hold:
        attach_auto_restore_to_rows(payload)
    # Keep the org-wide cache short. A 15s "any peer online" TTL left powered-off
    # routers showing Connected for a full dashboard poll cycle.
    all_connected = bool(payload) and all(
        (item.get("status") or "") == "connected" for item in payload
    )
    cache.set(cache_key, payload, _mikrotik_status_cache_ttl(all_connected))
    # Drop stale live snapshots so the detail page cannot keep showing Online
    # after status has already marked the router down.
    for item in payload:
        rid = item.get("id")
        if rid is None:
            continue
        if item.get("management_deferred"):
            continue
        if (item.get("status") or "") != "connected":
            cache.delete(f"mikrotik_live:{org.pk}:{rid}")
    if not onboarding_hold:
        try:
            from core.mikrotik_status_samples import record_mikrotik_status_samples

            record_mikrotik_status_samples(org, probe_payload)
        except Exception:
            pass
    return JsonResponse(
        {
            "ok": True,
            "routers": payload,
            "onboarding_hold": onboarding_hold,
        }
    )


@client_workspace_required
def my_clients(request):
    org = resolve_organization(request.user, request)

    open_modal = ""
    pppoe_form = PppoeClientRegisterForm(organization=org, default_activate=True)
    clients_view = (request.GET.get("view") or "").strip().lower()

    def _pppoe_pending_redirect():
        return redirect(f"{reverse('core:my_clients')}?tab=pppoe&view=pending")

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action == "activate_pppoe":
            if not org:
                messages.error(request, "No organization is linked to this workspace.")
                return redirect("core:my_clients")
            raw_id = (request.POST.get("customer_id") or "").strip()
            raw_date = (request.POST.get("activation_date") or "").strip()
            if not raw_id.isdigit():
                messages.error(request, "Choose a client to activate.")
                return _pppoe_pending_redirect()
            customer = (
                Customer.objects.select_related("plan", "router", "organization")
                .filter(
                    pk=int(raw_id),
                    organization=org,
                    service_type=Customer.ServiceType.PPPOE,
                    status=Customer.Status.INACTIVE,
                )
                .first()
            )
            if customer is None:
                messages.error(request, "That pending PPPoE client was not found.")
                return _pppoe_pending_redirect()
            try:
                from datetime import date as date_cls

                activation_day = (
                    date_cls.fromisoformat(raw_date)
                    if raw_date
                    else timezone.localdate()
                )
            except ValueError:
                messages.error(request, "Choose a valid activation date.")
                return _pppoe_pending_redirect()
            start = PppoeClientRegisterForm._activation_datetime(activation_day)
            customer.status = Customer.Status.ACTIVE
            customer.package_start = start
            if customer.plan_id:
                customer.package_end = compute_package_end(start, customer.plan)
            else:
                customer.package_end = None
            customer.save(
                update_fields=[
                    "status",
                    "package_start",
                    "package_end",
                ]
            )
            customer_pk = customer.pk
            full_name = customer.full_name
            account_number = customer.account_number

            def _bg_provision(pk: int = customer_pk) -> None:
                from django.db import connection

                try:
                    cust = Customer.objects.select_related(
                        "plan", "router", "organization"
                    ).get(pk=pk)
                    provision_customer_pppoe(cust, ensure_stack=False)
                except Exception:
                    pass
                finally:
                    connection.close()

            threading.Thread(target=_bg_provision, daemon=True).start()
            messages.success(
                request,
                (
                    f"PPPoE client “{full_name}” ({account_number}) activated "
                    f"from {activation_day.isoformat()}. "
                    "Enabling the MikroTik login in the background."
                ),
            )
            remaining = Customer.objects.filter(
                organization=org,
                service_type=Customer.ServiceType.PPPOE,
                status=Customer.Status.INACTIVE,
            ).exists()
            if remaining:
                return _pppoe_pending_redirect()
            return redirect(f"{reverse('core:my_clients')}?tab=pppoe")
        if action == "register_pppoe":
            if not org:
                messages.error(request, "No organization is linked to this workspace.")
                return redirect("core:my_clients")
            pppoe_form = PppoeClientRegisterForm(
                request.POST, organization=org, default_activate=True
            )
            if pppoe_form.is_valid():
                customer = pppoe_form.save()
                customer_pk = customer.pk
                account_number = customer.account_number
                full_name = customer.full_name
                activated = bool(pppoe_form.cleaned_data.get("activate_account"))

                def _bg_provision(pk: int = customer_pk) -> None:
                    from django.db import connection

                    try:
                        cust = Customer.objects.select_related(
                            "plan", "router", "organization"
                        ).get(pk=pk)
                        # Secret-only push: stack already lives on the onboarded router.
                        provision_customer_pppoe(cust, ensure_stack=False)
                    except Exception:
                        pass
                    finally:
                        connection.close()

                threading.Thread(target=_bg_provision, daemon=True).start()
                if activated:
                    messages.success(
                        request,
                        (
                            f"PPPoE client “{full_name}” registered "
                            f"({account_number}). "
                            "Installing the login on MikroTik in the background — "
                            "the CPE can dial once the push finishes."
                        ),
                    )
                else:
                    messages.success(
                        request,
                        (
                            f"PPPoE client “{full_name}” registered "
                            f"({account_number}) as inactive. "
                            "The CPE can dial in, but surfing stays blocked until activation."
                        ),
                    )
                return redirect(f"{reverse('core:my_clients')}?tab=pppoe")
            open_modal = "pppoe-register-modal"
            tab = "pppoe"
            clients_view = ""
        else:
            tab = (request.GET.get("tab") or "pppoe").strip().lower()
    else:
        tab = (request.GET.get("tab") or "pppoe").strip().lower()

    valid_tabs = {"pppoe", "static", "hotspot"}
    if tab not in valid_tabs:
        tab = "pppoe"
    pending_view = tab == "pppoe" and clients_view == "pending"

    base_qs = Customer.objects.filter(organization=org) if org else Customer.objects.none()
    counts = (
        base_qs.values("service_type")
        .annotate(total=Count("id"))
        if org
        else []
    )
    count_map = {row["service_type"]: row["total"] for row in counts}
    pppoe_count = count_map.get(Customer.ServiceType.PPPOE, 0)
    static_count = count_map.get(Customer.ServiceType.STATIC, 0)
    hotspot_count = count_map.get(Customer.ServiceType.HOTSPOT, 0)
    pending_activation_count = (
        base_qs.filter(
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.INACTIVE,
        ).count()
        if org
        else 0
    )

    service_type = {
        "pppoe": Customer.ServiceType.PPPOE,
        "static": Customer.ServiceType.STATIC,
        "hotspot": Customer.ServiceType.HOTSPOT,
    }[tab]

    clients_query = (request.GET.get("q") or "").strip()
    router_raw = (request.GET.get("router") or "").strip()
    clients_router_param = ""
    clients_router_id = None
    if router_raw.lower() in {"none", "unassigned", "0"}:
        clients_router_param = "none"
    elif router_raw.isdigit():
        clients_router_id = int(router_raw)
        clients_router_param = str(clients_router_id)

    client_routers = []
    router_cpe_defaults: dict[str, dict[str, str]] = {}
    if org:
        client_routers = list(
            MikroTikRouter.objects.filter(organization=org)
            .order_by("name", "host")
            .only("id", "name", "host")
        )
        for router in MikroTikRouter.objects.filter(organization=org).only(
            "id",
            "name",
            "default_cpe_username",
            "default_cpe_password",
            "location",
        ):
            default_password = (router.default_cpe_password or "").strip()
            router_cpe_defaults[str(router.pk)] = {
                "username": (router.default_cpe_username or "").strip() or "admin",
                "password": default_password,
                "has_password": bool(default_password),
                "address": (router.location or "").strip(),
                "router_name": (router.name or "").strip(),
            }
        if clients_router_id and not any(
            r.pk == clients_router_id for r in client_routers
        ):
            clients_router_id = None
            clients_router_param = ""

    tab_qs = (
        base_qs.filter(service_type=service_type)
        .select_related("plan", "router")
        .order_by("-created_at")
    )
    if pending_view:
        tab_qs = tab_qs.filter(status=Customer.Status.INACTIVE)
    if clients_router_param == "none":
        tab_qs = tab_qs.filter(router__isnull=True)
    elif clients_router_id:
        tab_qs = tab_qs.filter(router_id=clients_router_id)
    if clients_query:
        tab_qs = tab_qs.filter(
            Q(full_name__icontains=clients_query)
            | Q(phone__icontains=clients_query)
            | Q(account_number__icontains=clients_query)
            | Q(pppoe_username__icontains=clients_query)
        )
    paginator = Paginator(tab_qs, 100)
    page_obj = paginator.get_page(request.GET.get("page") or 1)
    page_customers = list(page_obj)

    pppoe_customers = page_customers if tab == "pppoe" else []
    static_customers = page_customers if tab == "static" else []
    hotspot_customers = page_customers if tab == "hotspot" else []

    if open_modal != "pppoe-register-modal" and request.method != "POST":
        pppoe_initial: dict = {}
        if clients_router_id:
            pppoe_initial["router"] = clients_router_id
        elif len(client_routers) == 1:
            pppoe_initial["router"] = client_routers[0].pk
        pppoe_form = PppoeClientRegisterForm(
            organization=org, initial=pppoe_initial, default_activate=True
        )

    ctx = client_page_context(
        request,
        active_nav="clients",
        sidebar_active=(
            "pending_activation" if pending_view else f"clients_{tab}"
        ),
        page_title="My clients",
        page_kicker="Subscribers",
        page_subtitle=(
            "Activate PPPoE accounts registered by technicians."
            if pending_view
            else "Browse subscribers by connection type and open a client for details."
        ),
        active_tab=tab,
        clients_view="pending" if pending_view else "",
        pending_view=pending_view,
        pending_activation_count=pending_activation_count,
        pppoe_customers=pppoe_customers,
        static_customers=static_customers,
        hotspot_customers=hotspot_customers,
        pppoe_count=pppoe_count,
        static_count=static_count,
        hotspot_count=hotspot_count,
        clients_page=page_obj,
        clients_query=clients_query,
        clients_match_count=paginator.count,
        client_routers=client_routers,
        clients_router_param=clients_router_param,
        clients_router_id=clients_router_id,
        pppoe_form=pppoe_form,
        router_cpe_defaults_json=json.dumps(router_cpe_defaults),
        open_client_modal=open_modal,
        today_iso=timezone.localdate().isoformat(),
        billing_plans_exist=bool(
            org
            and BillingPlan.objects.filter(organization=org, is_active=True).exists()
        ),
    )
    tab_badges = {
        "clients_pppoe": pppoe_count,
        "clients_static": static_count,
        "clients_hotspot": hotspot_count,
        "pending_activation": pending_activation_count,
    }
    base_path = reverse("core:my_clients")
    for item in ctx["client_nav_main"]:
        key = item.get("key")
        if key not in tab_badges:
            continue
        if key == "pending_activation":
            item["href"] = f"{base_path}?tab=pppoe&view=pending"
            item["badge"] = tab_badges[key]
            continue
        query_params = {"tab": key.replace("clients_", "")}
        if clients_query:
            query_params["q"] = clients_query
        if clients_router_param:
            query_params["router"] = clients_router_param
        item["href"] = f"{base_path}?{urlencode(query_params)}"
        item["badge"] = tab_badges[key]
    return render(request, "core/my_clients.html", ctx)


@client_workspace_required
def client_detail(request, customer_id: int):
    """Subscriber profile (topbar) + usage analysis + CPE Wi‑Fi for one client."""
    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("plan", "router", "organization"),
        pk=customer_id,
        organization=org,
    )
    nas = customer.router
    can_access_wifi = customer_can_access_router(customer, org)

    wifi_ssid_display = (customer.cpe_wifi_ssid or "").strip()
    wifi_password_display = customer.cpe_wifi_password or ""
    recharge_form = CustomerCashRechargeForm(organization=org, customer=customer)
    details_form = CustomerDetailsEditForm(instance=customer, organization=org)
    open_client_modal = ""

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    def _enqueue_pppoe_provision(customer_pk: int) -> None:
        def _bg_provision():
            from django.db import connection

            try:
                _cust = Customer.objects.select_related(
                    "plan", "router", "organization"
                ).get(pk=customer_pk)
                if _cust.pppoe_username and _cust.router_id:
                    provision_customer_pppoe(_cust, ensure_stack=False)
            except Exception:
                pass
            finally:
                connection.close()

        threading.Thread(target=_bg_provision, daemon=True).start()

    def _enqueue_static_dhcp_bind(customer_pk: int) -> None:
        def _bg_bind():
            from django.db import connection

            try:
                _cust = Customer.objects.select_related("router", "organization").get(
                    pk=customer_pk
                )
                provision_static_client_dhcp_lease(_cust)
            except Exception:
                pass
            finally:
                connection.close()

        threading.Thread(target=_bg_bind, daemon=True).start()

    def _package_json_response(
        customer,
        *,
        message: str,
        provision: bool,
        voucher_codes: list | None = None,
        kick_sessions: bool = False,
    ) -> JsonResponse:
        from django.utils import timezone as dj_tz

        allowed = customer_receives_internet(customer)
        expired = customer_subscription_expired(customer)
        paused = customer_package_is_paused(customer)
        is_hourly = bool(
            customer.plan_id
            and getattr(customer.plan, "duration", "") in ("hourly", "six_hours")
        )

        def _fmt(value):
            if not value:
                return ""
            local = dj_tz.localtime(value)
            return local.strftime("%H:%M") if is_hourly else local.strftime("%Y-%m-%d")

        remaining_seconds = package_remaining_seconds(customer)
        remaining_label = ""
        if remaining_seconds is not None:
            if remaining_seconds <= 0:
                remaining_label = "Ended"
            else:
                hours, rem = divmod(remaining_seconds, 3600)
                minutes, seconds = divmod(rem, 60)
                if hours:
                    remaining_label = f"{hours}h {minutes}m"
                elif minutes:
                    remaining_label = f"{minutes}m {seconds}s"
                else:
                    remaining_label = f"{seconds}s"

        codes = [str(code) for code in (voucher_codes or []) if code]
        return JsonResponse({
            "ok": True,
            "message": message,
            "package_start": _fmt(customer.package_start),
            "package_end": _fmt(customer.package_end),
            "plan_name": customer.plan.name if customer.plan_id else "",
            "plan_speed": customer.plan.speed_label if customer.plan_id else "",
            "plan_duration": customer.plan.get_duration_display() if customer.plan_id else "",
            "package_duration": getattr(customer.plan, "duration", "") if customer.plan_id else "",
            "subscription_active": allowed,
            "subscription_expired": expired,
            "subscription_paused": paused,
            "package_paused_at": (
                dj_tz.localtime(customer.package_paused_at).isoformat()
                if customer.package_paused_at
                else ""
            ),
            "remaining_seconds": remaining_seconds,
            "remaining_label": remaining_label,
            "syncing": provision,
            "kick_sessions": bool(kick_sessions),
            "voucher_codes": codes,
            "voucher_code": codes[0] if codes else "",
            "can_pause_package": customer_can_pause_package(customer),
            "can_resume_package": customer_can_resume_package(customer),
        })

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action == "update_router_password":
            router_password = (request.POST.get("cpe_password") or "").strip()
            if not router_password:
                if is_ajax:
                    return JsonResponse(
                        {"ok": False, "error": "Enter the client router admin password."},
                        status=400,
                    )
                messages.error(request, "Enter the client router admin password.")
                return redirect("core:client_detail", customer_id=customer.pk)

            customer.cpe_password = router_password
            if not (customer.cpe_username or "").strip():
                customer.cpe_username = "admin"
            customer.save(update_fields=["cpe_password", "cpe_username"])
            # A new credential invalidates the cached failure and stale snapshot.
            cache.delete(f"client_cpe_router_data:{org.pk}:{customer.pk}")

            if is_ajax:
                return JsonResponse({"ok": True, "message": "Router password saved."})
            messages.success(request, "Router password saved.")
            return redirect("core:client_detail", customer_id=customer.pk)

        if action == "update_client_details":
            details_form = CustomerDetailsEditForm(
                request.POST, instance=customer, organization=org
            )
            if details_form.is_valid():
                old_username = (customer.pppoe_username or "").strip()
                old_password = customer.pppoe_password or ""
                old_router_id = customer.router_id
                old_cpe_ip = (customer.cpe_ip or "").strip()
                old_cpe_mac = (customer.cpe_mac or "").strip()
                customer = details_form.save()
                router_changed = customer.router_id != old_router_id
                creds_changed = (
                    customer.service_type == Customer.ServiceType.PPPOE
                    and customer.router_id
                    and (
                        (customer.pppoe_username or "").strip() != old_username
                        or (customer.pppoe_password or "") != old_password
                    )
                )
                sync_pppoe = (
                    customer.service_type == Customer.ServiceType.PPPOE
                    and customer.router_id
                    and (creds_changed or router_changed)
                )
                static_dhcp_bind = (
                    customer.service_type == Customer.ServiceType.STATIC
                    and customer.router_id
                    and (customer.cpe_ip or "").strip()
                    and (customer.cpe_mac or "").strip()
                    and (
                        router_changed
                        or (customer.cpe_ip or "").strip() != old_cpe_ip
                        or (customer.cpe_mac or "").strip() != old_cpe_mac
                    )
                )
                if sync_pppoe:
                    _enqueue_pppoe_provision(customer.pk)
                if static_dhcp_bind:
                    _enqueue_static_dhcp_bind(customer.pk)
                if router_changed:
                    cache.delete(f"client_cpe_router_data:{org.pk}:{customer.pk}")
                    cache.delete(f"client_cpe_wifi:{org.pk}:{customer.pk}")
                    if customer.router_id and customer.pppoe_username:
                        enqueue_customer_subscription_sync(
                            customer.pk,
                            customer_needs_nas_provision(customer),
                            wait_first=True,
                            quick=True,
                        )

                if is_ajax:
                    router = customer.router
                    sync_message = ""
                    if router_changed and sync_pppoe:
                        sync_message = " Syncing PPPoE login to the new MikroTik…"
                    elif router_changed and static_dhcp_bind:
                        sync_message = " Binding static DHCP lease on the MikroTik…"
                    elif router_changed:
                        sync_message = " MikroTik router updated."
                    elif sync_pppoe:
                        sync_message = " Syncing PPPoE login to MikroTik…"
                    elif static_dhcp_bind:
                        sync_message = " Binding static DHCP lease on the MikroTik…"
                    return JsonResponse(
                        {
                            "ok": True,
                            "message": "Client details saved." + sync_message,
                            "full_name": customer.full_name,
                            "pppoe_username": customer.pppoe_username or "",
                            "pppoe_password": customer.pppoe_password or "",
                            "cpe_username": customer.cpe_username or "admin",
                            "cpe_password": customer.cpe_password or "",
                            "initial": (
                                customer.full_name[:1].upper()
                                if customer.full_name
                                else "C"
                            ),
                            "router_id": customer.router_id,
                            "router_name": router.name if router else "",
                            "router_host": router.host if router else "",
                            "router_url": (
                                reverse("core:mikrotik_detail", args=[router.pk])
                                if router
                                else ""
                            ),
                            "syncing": sync_pppoe or router_changed or static_dhcp_bind,
                        }
                    )
                if static_dhcp_bind:
                    messages.success(
                        request,
                        "Client details saved. Binding static DHCP lease on the MikroTik…",
                    )
                else:
                    messages.success(request, "Client details saved.")
                return redirect("core:client_detail", customer_id=customer.pk)

            if is_ajax:
                errors = json.loads(details_form.errors.as_json())
                return JsonResponse({"ok": False, "errors": errors}, status=400)
            open_client_modal = "client-details-modal"

        if action == "recharge_account":
            recharge_form = CustomerCashRechargeForm(
                request.POST,
                organization=org,
                customer=customer,
            )
            if recharge_form.is_valid():
                try:
                    result = recharge_customer_cash(
                        customer=customer,
                        organization=org,
                        plan=recharge_form.cleaned_data["plan"],
                        amount=recharge_form.cleaned_data["amount"],
                        reference=recharge_form.cleaned_data.get("reference") or "",
                        recorded_by=request.user,
                        period_start=recharge_form.cleaned_data.get("period_start"),
                        period_end=recharge_form.cleaned_data.get("period_end"),
                    )
                except ValueError as exc:
                    if is_ajax:
                        return JsonResponse({"ok": False, "error": str(exc)}, status=400)
                    messages.error(request, str(exc))
                    return redirect("core:client_detail", customer_id=customer.pk)

                customer = result["customer"]
                invoice = result["invoice"]
                voucher_codes = result.get("voucher_codes") or []
                kick_sessions = bool(result.get("kick_sessions"))
                provision = customer_needs_nas_provision(customer)
                enqueue_customer_subscription_sync(
                    customer.pk,
                    provision,
                    wait_first=True,
                    quick=True,
                    reauthenticate=True,
                )

                amount_label = f"{recharge_form.cleaned_data['amount']:.2f}"
                end_label = (
                    customer.package_end.isoformat()
                    if customer.package_end
                    else "—"
                )
                if result.get("partial"):
                    start_label = (
                        customer.package_start.isoformat()
                        if customer.package_start
                        else "—"
                    )
                    msg = (
                        f"Partial cash recharge of KES {amount_label} recorded "
                        f"({invoice.invoice_number}). Surfing window "
                        f"{start_label} → {end_label}."
                    )
                else:
                    msg = (
                        f"Cash recharge of KES {amount_label} recorded "
                        f"({invoice.invoice_number}). Package active until {end_label}."
                    )
                if voucher_codes:
                    codes_label = ", ".join(voucher_codes)
                    msg += (
                        f" New voucher{'s' if len(voucher_codes) != 1 else ''}: "
                        f"{codes_label}. Device session cleared — they can "
                        "autoconnect or enter a voucher on the pay page."
                    )
                if is_ajax:
                    return _package_json_response(
                        customer,
                        message=msg,
                        provision=provision,
                        voucher_codes=voucher_codes,
                        kick_sessions=kick_sessions,
                    )
                messages.success(request, msg)
                return redirect("core:client_detail", customer_id=customer.pk)

            if is_ajax:
                errors = json.loads(recharge_form.errors.as_json())
                return JsonResponse({"ok": False, "errors": errors}, status=400)
            open_client_modal = "client-recharge-modal"

        if action in ("pause_package", "resume_package"):
            try:
                if action == "pause_package":
                    pause_customer_package(customer)
                    msg = (
                        "Package paused. Surfing is blocked and the remaining "
                        "period is frozen until you resume."
                    )
                else:
                    resume_customer_package(customer)
                    msg = (
                        "Package resumed. The client continues with the time "
                        "left when the package was paused."
                    )
            except ValueError as exc:
                if is_ajax:
                    return JsonResponse({"ok": False, "error": str(exc)}, status=400)
                messages.error(request, str(exc))
                return redirect("core:client_detail", customer_id=customer.pk)

            customer.refresh_from_db()
            # Always attempt NAS sync on pause/resume — surfing must stop/start now.
            provision = True
            enqueue_customer_subscription_sync(
                customer.pk, provision, wait_first=True, quick=True
            )
            if is_ajax:
                return _package_json_response(
                    customer,
                    message=msg,
                    provision=provision,
                )
            messages.success(request, msg)
            return redirect("core:client_detail", customer_id=customer.pk)


    client_plans = list(recharge_form.fields["plan"].queryset)

    from billing.vouchers import vouchers_for_customer_billing

    voucher_rows = vouchers_for_customer_billing(customer, request=request) if org else []
    available_vouchers = [
        row for row in voucher_rows if row["status"] == AccessVoucher.Status.VALID
    ]
    used_voucher_count = sum(
        1 for row in voucher_rows if row["status"] != AccessVoucher.Status.VALID
    )
    try:
        plan_max_devices = (
            int(getattr(customer.plan, "max_devices", 0) or 0)
            if customer.plan_id
            else 0
        )
    except (TypeError, ValueError):
        plan_max_devices = 0
    show_available_vouchers = bool(available_vouchers) or bool(voucher_rows) or (
        customer.service_type == Customer.ServiceType.HOTSPOT and plan_max_devices > 1
    )

    invoice_count = Invoice.objects.filter(customer=customer).count()
    payment_count = Payment.objects.filter(invoice__customer=customer).count()
    voucher_count = AccessVoucher.objects.filter(customer=customer).count()

    ctx = client_page_context(
        request,
        active_nav="client_detail",
        sidebar_active="overview",
        page_title=customer.full_name,
        page_kicker="Client",
        page_subtitle=(
            f"{customer.get_service_type_display()} subscriber · "
            f"Account {customer.account_number}"
        ),
        customer=customer,
        back_url=f"{reverse('core:my_clients')}?tab={customer.service_type}",
        can_live_usage=customer_supports_live_usage(customer),
        can_access_wifi=can_access_wifi,
        wifi_ssid_display=wifi_ssid_display,
        wifi_password_display=wifi_password_display,
        recharge_form=recharge_form,
        details_form=details_form,
        package_duration=getattr(customer.plan, "duration", "") or "",
        package_duration_label=(
            customer.plan.get_duration_display() if customer.plan_id else ""
        ),
        plan_durations_map={str(p.pk): p.duration for p in client_plans},
        plan_prices_map={str(p.pk): str(p.price) for p in client_plans},
        subscription_active=customer_receives_internet(customer),
        subscription_expired=customer_subscription_expired(customer),
        subscription_paused=customer_package_is_paused(customer),
        can_pause_package=customer_can_pause_package(customer),
        can_resume_package=customer_can_resume_package(customer),
        renew_url=(
            (
                _hotspot_pay_url_for_org(customer.organization, request)
                if customer.service_type == Customer.ServiceType.HOTSPOT
                else _pppoe_pay_url_for_customer(customer, request)
            )
            if customer.pk and customer.organization_id
            else ""
        ),
        open_client_modal=open_client_modal,
        available_vouchers=available_vouchers,
        valid_voucher_count=len(available_vouchers),
        used_voucher_count=used_voucher_count,
        voucher_device_cap=plan_max_devices,
        show_available_vouchers=show_available_vouchers,
        voucher_billing_url=reverse(
            "core:client_billing", kwargs={"customer_id": customer.pk}
        ),
        invoice_count=invoice_count,
        payment_count=payment_count,
        voucher_count=voucher_count,
        delete_url=reverse("core:client_delete", kwargs={"customer_id": customer.pk}),
    )
    ctx["client_nav_main"] = [
        *CLIENT_COMMON_NAV_START,
        *build_client_detail_nav(customer, can_access_wifi=can_access_wifi),
    ]
    ctx["sidebar_label"] = "Client"
    apply_client_shared_forms(ctx, customer, org)
    return render(request, "core/client_detail.html", ctx)


@client_workspace_required
@require_http_methods(["GET", "POST"])
def client_delete(request, customer_id: int):
    """Confirm and permanently delete one subscriber (Customer)."""
    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("plan", "router", "organization"),
        pk=customer_id,
        organization=org,
    )
    can_access_wifi = customer_can_access_router(customer, org)
    list_url = f"{reverse('core:my_clients')}?tab={customer.service_type}"

    if request.method == "POST":
        name = customer.full_name
        service_tab = customer.service_type
        # Best-effort: disable PPPoE secret so the CPE cannot reconnect after delete.
        if (
            customer.service_type == Customer.ServiceType.PPPOE
            and (customer.pppoe_username or "").strip()
            and customer.router_id
        ):
            try:
                provision_customer_pppoe(
                    customer, ensure_stack=False, force_disabled=True
                )
            except Exception:
                pass
        # Best-effort: disable Hotspot MAC users and kick live sessions now,
        # before the customer (and device MACs) are removed from billing.
        elif customer.service_type == Customer.ServiceType.HOTSPOT:
            try:
                disconnect_hotspot_customer(customer)
            except Exception:
                pass
        customer.delete()
        messages.success(request, f"Deleted client {name}.")
        return redirect(f"{reverse('core:my_clients')}?tab={service_tab}")

    invoice_count = Invoice.objects.filter(customer=customer).count()
    payment_count = Payment.objects.filter(invoice__customer=customer).count()
    voucher_count = AccessVoucher.objects.filter(customer=customer).count()

    ctx = client_page_context(
        request,
        active_nav="client_detail",
        sidebar_active="delete",
        page_title=f"Delete · {customer.full_name}",
        customer=customer,
        can_access_wifi=can_access_wifi,
        back_url=reverse("core:client_detail", kwargs={"customer_id": customer.pk}),
        clients_list_url=list_url,
        invoice_count=invoice_count,
        payment_count=payment_count,
        voucher_count=voucher_count,
    )
    ctx["client_nav_main"] = [
        *CLIENT_COMMON_NAV_START,
        *build_client_detail_nav(customer, can_access_wifi=can_access_wifi),
    ]
    ctx["sidebar_label"] = "Client"
    apply_client_shared_forms(ctx, customer, org)
    return render(request, "core/client_delete.html", ctx)


_CPE_PROXY_SALT = "core.client-cpe-web.v1"
# The signed token carries a generous absolute lifetime; the effective session
# length is governed by a sliding idle window enforced server-side (below), so
# an actively-used router page never drops mid-session, but an abandoned one
# still closes. The absolute cap bounds the worst case if the idle-activity
# cache entry is ever lost (e.g. cache eviction / restart).
_CPE_PROXY_IDLE_AGE = 15 * 60
_CPE_PROXY_ABS_AGE = 8 * 60 * 60
_CPE_PROXY_MAX_BODY = 16 * 1024 * 1024
_CPE_HOP_HEADERS = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def _cpe_proxy_token(
    request,
    customer: Customer,
    cpe_port: int = 80,
    *,
    cpe_host: str = "",
    gateway: str = "",
    scope: str = "",
    mode: str = "",
) -> str:
    payload = {
        "customer_id": customer.pk,
        "user_id": request.user.pk,
        "cpe_port": int(cpe_port or 80),
    }
    # Cache the live CPE target in the signed token so each proxied asset does
    # not re-login to the NAS just to look up the same PPPoE/DHCP address.
    if (cpe_host or "").strip():
        payload["cpe_host"] = cpe_host.strip()
    if (gateway or "").strip():
        payload["gateway"] = gateway.strip()
    if (scope or "").strip():
        payload["scope"] = scope.strip()
    if (mode or "").strip():
        payload["mode"] = mode.strip()
    return signing.dumps(
        payload,
        salt=_CPE_PROXY_SALT,
        compress=True,
    )


def _load_cpe_proxy_token(request, customer: Customer, token: str) -> dict:
    try:
        payload = signing.loads(
            token,
            salt=_CPE_PROXY_SALT,
            max_age=_CPE_PROXY_ABS_AGE,
        )
    except signing.BadSignature as exc:
        raise PermissionError("This router-login link has expired.") from exc
    if (
        payload.get("customer_id") != customer.pk
        or payload.get("user_id") != request.user.pk
    ):
        raise PermissionError("This router-login link is not valid for this account.")
    return payload


def _recover_escaped_proxy_url(
    request, customer: Customer, token: str, router_path: str
) -> str | None:
    """
    Rebuild the URL for an asset whose relative "../" escaped the proxy prefix.

    Router UIs reference "../img/x.png" from their own web root; a real router
    clamps that at "/", but under our prefix ".." walks up one real segment and
    eats the signed token (…/router/img/visible.png → 403). The referring page
    still carries a valid token, so the lost segment is just the head of the
    CPE path and the request can be sent back in under that token.
    """
    referer = request.META.get("HTTP_REFERER") or ""
    if not referer:
        return None
    marker = f"/app/clients/{customer.pk}/router/"
    referer_path = urlsplit(referer).path
    head, sep, tail = referer_path.partition(marker)
    if not sep:
        return None
    referer_token = tail.split("/", 1)[0]
    if not referer_token or referer_token == token:
        return None
    try:
        _load_cpe_proxy_token(request, customer, referer_token)
    except PermissionError:
        return None

    cpe_path = "/".join(part for part in (token, router_path.strip("/")) if part)
    recovered = f"{head}{marker}{referer_token}/{cpe_path}"
    query = request.META.get("QUERY_STRING") or ""
    return f"{recovered}?{query}" if query else recovered


def _rewrite_cpe_body(body: bytes, content_type: str, prefix: str, cpe_host: str) -> bytes:
    """
    Rewrite absolute CPE paths so the browser stays under the proxy prefix.

    Must be idempotent: applying the rewrite to already-prefixed markup must not
    double the prefix (Tenda login posts break as …/router/TOKEN/app/clients/…/login/Auth).
    """
    lower_type = (content_type or "").lower()
    if not any(
        kind in lower_type
        for kind in ("text/html", "text/css", "javascript", "application/json")
    ):
        return body
    charset = "utf-8"
    match = re.search(r"charset=([^\s;]+)", lower_type)
    if match:
        charset = match.group(1).strip("\"'")
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")

    prefix = prefix if prefix.endswith("/") else (prefix + "/")
    # Path after the leading slash — used so we never rewrite "/{prefix}…" again.
    bare_prefix = prefix.lstrip("/")
    bare_re = re.escape(bare_prefix)

    for origin in (f"http://{cpe_host}", f"https://{cpe_host}"):
        text = text.replace(origin + "/", prefix)
        text = text.replace(origin, prefix.rstrip("/"))

    # href="/login" → href="{prefix}login"  (skip already-prefixed)
    text = re.sub(
        rf'(?i)\b(href|src|action|data-url|data-href)=(["\'])/(?!{bare_re})',
        rf"\1=\2{prefix}",
        text,
    )
    # CSS url(/img/…) — skip protocol-relative url(//…) and already-prefixed
    text = re.sub(
        rf"(?i)url\((['\"]?)/(?!/|{bare_re})",
        rf"url(\1{prefix}",
        text,
    )
    # JS / HTML string literals "/path" — never touch "//host" or already-prefixed
    if "javascript" in lower_type or "text/html" in lower_type:
        text = re.sub(
            rf'(["\'])/(?!/|{bare_re})',
            rf"\1{prefix}",
            text,
        )
    return text.encode(charset, errors="replace")


def _normalize_proxied_path(router_path: str, prefix: str) -> str:
    """
    Strip a duplicated proxy prefix from an inbound path.

    Browsers that already have a double-prefixed form action (from an older
    rewrite bug) would otherwise POST to the CPE as
    /app/clients/…/router/TOKEN/login/Auth instead of /login/Auth.
    """
    path = (router_path or "").lstrip("/")
    marker = (prefix or "").strip("/") + "/"
    if not marker or marker == "/":
        return "/" + path if path else "/"
    # Unwrap every leading copy of the proxy path.
    while path.startswith(marker):
        path = path[len(marker) :]
    return "/" + path if path else "/"


def _client_cpe_access_tab(request) -> str:
    tab = (request.GET.get("tab") or "").strip().lower()
    return "router" if tab == "router" else "wifi"


def _client_cpe_access_context(
    request,
    customer,
    org,
    *,
    can_access_wifi: bool,
    wifi_form=None,
    active_tab: str = "wifi",
) -> dict:
    """Shared template context for the combined router + Wi‑Fi page."""
    nas = customer.router
    via_tunnel = _router_uses_tunnel(nas) if nas else False
    dial = _router_api_host(nas) if nas else ""
    nas_url = (
        reverse("core:mikrotik_detail", kwargs={"router_id": nas.pk}) if nas else ""
    )
    ctx = client_page_context(
        request,
        active_nav="client_detail",
        sidebar_active="router_wifi",
        page_title=f"Router & Wi‑Fi · {customer.full_name}",
        customer=customer,
        can_access_wifi=can_access_wifi,
        active_tab=active_tab,
        wifi_form=wifi_form,
        wifi_ssid_display=(customer.cpe_wifi_ssid or "").strip(),
        wifi_password_display=customer.cpe_wifi_password or "",
        back_url=reverse("core:client_detail", kwargs={"customer_id": customer.pk}),
        wifi_url=reverse("core:client_cpe_wifi", kwargs={"customer_id": customer.pk}),
        router_data_url=reverse(
            "core:client_cpe_router_data", kwargs={"customer_id": customer.pk}
        ),
        start_url=reverse(
            "core:client_router_login_start", kwargs={"customer_id": customer.pk}
        ),
        cpe_username=(customer.cpe_username or "").strip() or "admin",
        cpe_password=customer.cpe_password or "",
        has_cpe_password=bool((customer.cpe_password or "").strip()),
        nas_name=(nas.name if nas else ""),
        nas_url=nas_url,
        nas_dial=dial,
        via_tunnel=via_tunnel,
        access_mode=customer_cpe_access_mode(customer),
        gateway=MK_PPPOE_LOCAL_ADDRESS,
        checked_ports=", ".join(str(p) for p in CPE_WEB_PORTS),
    )
    ctx["client_nav_main"] = [
        *CLIENT_COMMON_NAV_START,
        *build_client_detail_nav(customer, can_access_wifi=can_access_wifi),
    ]
    ctx["sidebar_label"] = "Client"
    apply_client_shared_forms(ctx, customer, org)
    return ctx


@client_workspace_required
@require_GET
def client_router_login(request, customer_id: int):
    """Legacy URL — opens the combined router + Wi‑Fi page on the Router tab."""
    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("router", "plan", "organization"),
        pk=customer_id,
        organization=org,
    )
    if not customer_can_access_router(customer, org):
        messages.error(
            request,
            "Router login requires a configured client (PPPoE, static IP, or DHCP MAC) and NAS.",
        )
        return redirect("core:client_detail", customer_id=customer.pk)

    url = reverse("core:client_wifi_settings", kwargs={"customer_id": customer.pk})
    return redirect(f"{url}?tab=router")


@client_workspace_required
@require_http_methods(["GET", "POST"])
def client_router_login_start(request, customer_id: int):
    """Probe (and if needed enable) CPE www, then return a signed proxy URL."""
    from core.connectivity_verification import evaluate_nas_connectivity

    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("router"),
        pk=customer_id,
        organization=org,
    )
    if not customer_can_access_router(customer, org):
        return JsonResponse(
            {
                "ok": False,
                "failure_class": "not_eligible",
                "error": "Router login requires a configured client and NAS.",
                "detail": "Router login requires a configured client and NAS.",
                "guidance": [
                    "PPPoE needs a username + assigned NAS; static needs CPE IP or MAC.",
                    "Hotspot accounts have no client router to open.",
                ],
            },
            status=400,
        )

    if request.method == "POST":
        router_password = (request.POST.get("cpe_password") or "").strip()
        if router_password:
            customer.cpe_password = router_password
            if not (customer.cpe_username or "").strip():
                customer.cpe_username = "admin"
            customer.save(update_fields=["cpe_password", "cpe_username"])
            cache.delete(f"client_cpe_router_data:{org.pk}:{customer.pk}")
            cache.delete(f"client_cpe_wifi:{org.pk}:{customer.pk}")

    nas = customer.router
    nas_host = _router_api_host(nas)
    via_tunnel = _router_uses_tunnel(nas)
    access_mode = customer_cpe_access_mode(customer)
    nas_url = reverse("core:mikrotik_detail", kwargs={"router_id": nas.pk})
    base_meta = {
        "nas_name": nas.name or "",
        "nas_dial": nas_host,
        "nas_url": nas_url,
        "via_tunnel": via_tunnel,
        "access_mode": access_mode,
        "gateway": MK_PPPOE_LOCAL_ADDRESS,
        "checked_ports": [str(p) for p in CPE_WEB_PORTS],
        "cpe_username": (customer.cpe_username or "").strip() or "admin",
        "needs_password": not (customer.cpe_password or "").strip(),
    }

    # Fail fast when the ISP NAS (LAN or WireGuard) is unreachable — otherwise
    # the CPE probe looks like "client offline" and operators chase the wrong layer.
    nas_check = evaluate_nas_connectivity(nas, timeout=3.0)
    if not nas_check.get("api_ok"):
        detail = (
            nas_check.get("hint")
            or nas_check.get("error")
            or f"Cannot reach {nas.name or nas_host}."
        )
        guidance = _cpe_router_guidance(
            failure_class="nas_down",
            access_mode=access_mode,
            gateway=MK_PPPOE_LOCAL_ADDRESS,
            nas_name=nas.name or "",
            via_tunnel=via_tunnel,
            detail=detail,
        )
        return JsonResponse(
            {
                **base_meta,
                "ok": False,
                "failure_class": "nas_down",
                "session_active": False,
                "ping_ok": False,
                "api_ok": False,
                "cpe_host": "",
                "detail": detail,
                "error": nas_check.get("error") or detail,
                "steps": [
                    f"NAS {nas.name or nas_host} unreachable"
                    + (" via WireGuard" if via_tunnel else "")
                ],
                "guidance": guidance,
            }
        )

    probe = probe_customer_cpe_web(
        nas_host,
        nas.username,
        nas.password or "",
        customer=customer,
        cpe_username=customer.cpe_username or "admin",
        cpe_password=customer.cpe_password or "",
        pppoe_password=customer.pppoe_password or "",
        timeout=20.0,
        auto_enable_www=True,
    )
    gateway = (probe.get("gateway") or MK_PPPOE_LOCAL_ADDRESS).strip() or MK_PPPOE_LOCAL_ADDRESS
    mode = (probe.get("mode") or access_mode or "").strip()
    base_meta["gateway"] = gateway
    base_meta["access_mode"] = mode or access_mode

    if not probe.get("ok"):
        failure_class = _cpe_router_failure_class(probe, nas_ok=True)
        detail = probe.get("hint") or probe.get("error") or ""
        # CPE online but www/API failed — always offer password entry/correction.
        # A wrong saved admin password often surfaces as "blocked" or "unreachable".
        show_password = failure_class not in {"nas_down", "offline"}
        guidance = _cpe_router_guidance(
            failure_class=failure_class,
            access_mode=mode,
            gateway=gateway,
            nas_name=nas.name or "",
            via_tunnel=via_tunnel,
            detail=detail,
        )
        if show_password:
            guidance = guidance + _cpe_router_guidance(failure_class="needs_password")
        return JsonResponse(
            {
                **base_meta,
                "ok": False,
                "failure_class": failure_class,
                "session_active": bool(probe.get("session_active")),
                "ping_ok": bool(probe.get("ping_ok")),
                "api_ok": bool(probe.get("api_ok")),
                "www_enabled": bool(probe.get("www_enabled")),
                "cpe_host": probe.get("cpe_host") or "",
                "detail": detail,
                "error": probe.get("error") or detail,
                "steps": list(probe.get("steps") or []),
                "guidance": guidance,
                "needs_password": show_password,
            }
        )

    token = _cpe_proxy_token(
        request,
        customer,
        probe.get("port") or 80,
        cpe_host=probe.get("cpe_host") or "",
        gateway=gateway,
        scope=customer_cpe_proxy_scope(customer),
        mode=mode,
    )
    proxy_url = reverse(
        "core:client_router_proxy_root",
        kwargs={"customer_id": customer.pk, "token": token},
    )
    if not proxy_url.endswith("/"):
        proxy_url += "/"

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    cookie_key = "cpe-web:" + token_hash
    existing = cache.get(f"cpe-web-customer:{org.pk}:{customer.pk}") or {}
    login = login_customer_cpe_web_session(
        nas_host,
        nas.username,
        nas.password or "",
        customer=customer,
        cpe_username=customer.cpe_username or "admin",
        cpe_password=customer.cpe_password or "",
        pppoe_password=customer.pppoe_password or "",
        cpe_port=int(probe.get("port") or 80),
        cpe_address=probe.get("cpe_host") or "",
        gateway_ip=gateway,
        session_cookies=dict(existing),
        api_ok=bool(probe.get("api_ok") or probe.get("www_enabled")),
        timeout=12.0,
    )
    cookies = dict(login.get("cookies") or existing or {})
    if cookies:
        cache.set(cookie_key, cookies, _CPE_PROXY_ABS_AGE)
        cache.set(f"cpe-web-customer:{org.pk}:{customer.pk}", cookies, _CPE_PROXY_ABS_AGE)
    basic_header = (login.get("basic_header") or "").strip()
    if basic_header:
        cache.set(
            "cpe-web-basic:" + token_hash,
            {"header": basic_header},
            _CPE_PROXY_ABS_AGE,
        )
    cache.set("cpe-web-activity:" + token_hash, time.time(), _CPE_PROXY_ABS_AGE)

    working_user = (login.get("cpe_username") or "").strip()
    working_pass = login.get("cpe_password")
    authenticated = bool(login.get("authenticated"))
    # Only persist passwords the operator entered (POST) or that were already empty —
    # never store guessed factory defaults from auto-login.
    password_from_operator = request.method == "POST" and bool(
        (request.POST.get("cpe_password") or "").strip()
    )
    if (
        authenticated
        and working_pass
        and not login.get("support_user")
        and password_from_operator
    ):
        # Operator explicitly entered the password — keep it as the saved CPE admin login.
        update_fields: list[str] = []
        if working_pass != (customer.cpe_password or ""):
            customer.cpe_password = working_pass
            update_fields.append("cpe_password")
        if working_user and working_user != (customer.cpe_username or ""):
            customer.cpe_username = working_user
            update_fields.append("cpe_username")
        if update_fields:
            customer.save(update_fields=update_fields)

    login_error = (login.get("error") or "").strip()
    # Web UI is open but auto-sign-in failed — ask for the admin password so the
    # operator can correct a wrong/outdated saved credential and reconnect.
    needs_password = (not authenticated) and (
        not (customer.cpe_password or "").strip()
        or bool(login_error)
        or password_from_operator
    )
    guidance = []
    if needs_password:
        guidance = _cpe_router_guidance(failure_class="needs_password")

    steps = list(probe.get("steps") or []) + list(login.get("steps") or [])
    return JsonResponse(
        {
            **base_meta,
            "ok": True,
            "failure_class": "ok" if authenticated else "needs_password",
            "proxy_url": proxy_url,
            "cpe_host": probe.get("cpe_host") or "",
            "port": int(probe.get("port") or 80),
            "ping_ok": bool(probe.get("ping_ok")),
            "api_ok": bool(probe.get("api_ok")),
            "www_enabled": bool(probe.get("www_enabled")),
            "authenticated": authenticated,
            "vendor": login.get("vendor") or "",
            "session_active": True,
            "steps": steps,
            "guidance": guidance,
            "cpe_username": working_user
            or (customer.cpe_username or "").strip()
            or "admin",
            "has_password": bool((customer.cpe_password or working_pass or "").strip()),
            "needs_password": needs_password,
            "login_error": login_error,
        }
    )


@csrf_exempt
@client_workspace_required
@require_http_methods(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def client_router_proxy(request, customer_id: int, token: str, router_path: str = ""):
    """Reverse-proxy a client router's HTTP admin UI through its ISP MikroTik."""
    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("router"),
        pk=customer_id,
        organization=org,
    )
    try:
        token_payload = _load_cpe_proxy_token(request, customer, token)
    except PermissionError as exc:
        recovered = _recover_escaped_proxy_url(request, customer, token, router_path)
        if recovered:
            # 307 keeps the method and body intact for escaped form posts.
            response = HttpResponse(status=307)
            response["Location"] = recovered
            return response
        return HttpResponse(str(exc), status=403, content_type="text/plain")

    # Sliding idle window: the signed token is valid for a long absolute span,
    # but a session that sees no traffic for _CPE_PROXY_IDLE_AGE is closed.
    # Each proxied request (including the router UI's background polls) refreshes
    # the window, so an in-use page stays open well past 15 minutes.
    activity_key = "cpe-web-activity:" + hashlib.sha256(token.encode()).hexdigest()
    last_seen = cache.get(activity_key)
    now = time.time()
    if last_seen is not None and (now - last_seen) > _CPE_PROXY_IDLE_AGE:
        cache.delete(activity_key)
        return HttpResponse(
            "This router session timed out after 15 minutes of inactivity. "
            "Reopen the client router to continue.",
            status=403,
            content_type="text/plain",
        )
    cache.set(activity_key, now, _CPE_PROXY_ABS_AGE)

    cpe_port = int(token_payload.get("cpe_port") or 80)
    cpe_is_tls = cpe_port in {443, 8443}
    if not customer_can_access_router(customer, org):
        return HttpResponse(
            "Router login is unavailable for this client.",
            status=409,
            content_type="text/plain",
        )

    nas = customer.router
    nas_host = _router_api_host(nas)
    cpe_host = (token_payload.get("cpe_host") or "").strip()
    gateway = (token_payload.get("gateway") or "").strip() or MK_PPPOE_LOCAL_ADDRESS
    cpe_scope = (token_payload.get("scope") or "").strip() or customer_cpe_proxy_scope(
        customer
    )
    used_token_host = bool(cpe_host)

    if not cpe_host:
        cpe_target = resolve_customer_cpe_target(
            nas_host,
            nas.username,
            nas.password or "",
            customer,
            timeout=8.0,
        )
        if not cpe_target.get("ok") or not cpe_target.get("session_active"):
            return HttpResponse(
                cpe_target.get("hint")
                or cpe_target.get("error")
                or "The client router is offline.",
                status=409,
                content_type="text/plain",
            )
        cpe_host = (cpe_target.get("address") or "").strip()
        gateway = (cpe_target.get("gateway") or "").strip() or MK_PPPOE_LOCAL_ADDRESS
        cpe_scope = (
            (cpe_target.get("scope") or "").strip() or customer_cpe_proxy_scope(customer)
        )

    prefix = reverse(
        "core:client_router_proxy_root",
        kwargs={"customer_id": customer.pk, "token": token},
    )
    if not prefix.endswith("/"):
        prefix += "/"
    target = _normalize_proxied_path(router_path, prefix)
    query = request.META.get("QUERY_STRING", "")
    if query:
        target += "?" + query
    cookie_key = "cpe-web:" + hashlib.sha256(token.encode()).hexdigest()
    router_cookies = dict(cache.get(cookie_key) or {})

    def _open_upstream(address: str, gw: str, scope: str):
        with customer_cpe_web_proxy(
            nas_host,
            nas.username,
            nas.password or "",
            cpe_scope=scope,
            cpe_address=address,
            gateway_ip=gw,
            cpe_port=cpe_port,
            timeout=10.0,
        ) as proxy_ctx:
            headers = {}
            for name, value in request.headers.items():
                lower = name.lower()
                if lower in _CPE_HOP_HEADERS or lower in {
                    "cookie",
                    "origin",
                    "referer",
                    "x-csrftoken",
                    "authorization",
                }:
                    continue
                headers[name] = value
            headers["Host"] = proxy_ctx["cpe_host"]
            headers["Accept-Encoding"] = "identity"
            if router_cookies:
                headers["Cookie"] = "; ".join(
                    f"{name}={value}" for name, value in router_cookies.items()
                )
            basic = cache.get(
                "cpe-web-basic:" + hashlib.sha256(token.encode()).hexdigest()
            ) or {}
            if basic.get("header"):
                headers["Authorization"] = basic["header"]

            if cpe_is_tls:
                connection = http.client.HTTPSConnection(
                    proxy_ctx["host"],
                    proxy_ctx["port"],
                    timeout=10.0,
                    context=ssl._create_unverified_context(),
                )
            else:
                connection = http.client.HTTPConnection(
                    proxy_ctx["host"],
                    proxy_ctx["port"],
                    timeout=10.0,
                )
            try:
                connection.request(
                    request.method,
                    target,
                    body=request.body if request.method not in {"GET", "HEAD"} else None,
                    headers=headers,
                )
                upstream = connection.getresponse()
                resp_body = upstream.read(_CPE_PROXY_MAX_BODY + 1)
                resp_headers = upstream.getheaders()
                resp_status = upstream.status
            finally:
                connection.close()
            return proxy_ctx, resp_body, resp_headers, resp_status

    try:
        proxy, body, upstream_headers, status = _open_upstream(
            cpe_host, gateway, cpe_scope
        )
    except (ConnectionError, OSError, TimeoutError, http.client.HTTPException) as exc:
        # Token may hold a stale PPPoE IP after renumber — one live re-resolve.
        if used_token_host:
            cpe_target = resolve_customer_cpe_target(
                nas_host,
                nas.username,
                nas.password or "",
                customer,
                timeout=8.0,
            )
            if cpe_target.get("ok") and cpe_target.get("session_active"):
                live_host = (cpe_target.get("address") or "").strip()
                live_gateway = (
                    (cpe_target.get("gateway") or "").strip() or MK_PPPOE_LOCAL_ADDRESS
                )
                live_scope = (
                    (cpe_target.get("scope") or "").strip()
                    or customer_cpe_proxy_scope(customer)
                )
                if live_host and live_host != cpe_host:
                    try:
                        proxy, body, upstream_headers, status = _open_upstream(
                            live_host, live_gateway, live_scope
                        )
                        cpe_host = live_host
                        gateway = live_gateway
                    except (
                        ConnectionError,
                        OSError,
                        TimeoutError,
                        http.client.HTTPException,
                    ) as retry_exc:
                        exc = retry_exc
                    else:
                        exc = None
        if exc is not None:
            detail = str(exc) or exc.__class__.__name__
            timed_out = "timed out" in detail.lower() or isinstance(exc, TimeoutError)
            hint = (
                f" The client router did not answer on port {cpe_port} through the ISP "
                "MikroTik. Enable Remote / WAN Web Management on the client's router "
                f"(limit it to the ISP gateway {gateway}), confirm the client is online, "
                "then try again."
                if timed_out
                else ""
            )
            return HttpResponse(
                f"Could not open the client router: {detail}.{hint}",
                status=502,
                content_type="text/plain",
            )

    if len(body) > _CPE_PROXY_MAX_BODY:
        return HttpResponse(
            "The client router response was too large.",
            status=502,
            content_type="text/plain",
        )

    for name, value in upstream_headers:
        if name.lower() == "set-cookie":
            parsed = SimpleCookie()
            try:
                parsed.load(value)
            except Exception:
                continue
            for cookie_name, morsel in parsed.items():
                router_cookies[cookie_name] = morsel.value
    cache.set(cookie_key, router_cookies, _CPE_PROXY_ABS_AGE)
    if router_cookies:
        # Let the client detail page reuse a successful web-admin login without
        # asking the router to create another administrator session.
        cache.set(
            f"cpe-web-customer:{customer.organization_id}:{customer.pk}",
            router_cookies,
            _CPE_PROXY_ABS_AGE,
        )

    content_type = next(
        (value for name, value in upstream_headers if name.lower() == "content-type"),
        "application/octet-stream",
    )
    content_encoding = next(
        (value.lower() for name, value in upstream_headers if name.lower() == "content-encoding"),
        "",
    )
    decoded_encoding = False
    try:
        if content_encoding == "gzip":
            body = gzip.decompress(body)
            decoded_encoding = True
        elif content_encoding == "deflate":
            body = zlib.decompress(body)
            decoded_encoding = True
    except (OSError, zlib.error):
        decoded_encoding = False
    if not content_encoding or decoded_encoding:
        body = _rewrite_cpe_body(body, content_type, prefix, proxy["cpe_host"])
    response = HttpResponse(
        b"" if request.method == "HEAD" else body,
        status=status,
        content_type=content_type,
    )
    for name, value in upstream_headers:
        lower = name.lower()
        if lower in _CPE_HOP_HEADERS or lower in {
            "content-type",
            "content-security-policy",
            "set-cookie",
            "x-frame-options",
        } or (lower == "content-encoding" and decoded_encoding):
            continue
        if lower == "location":
            location = urlsplit(value)
            path = location.path or "/"
            if location.scheme or location.netloc:
                # Absolute URL on the CPE — keep only the path under our prefix.
                path = path or "/"
            if path.startswith(prefix):
                value = path
            elif path.startswith("/"):
                value = prefix + path.lstrip("/")
            else:
                value = prefix + path
            if location.query:
                value += "?" + location.query
            if location.fragment:
                value += "#" + location.fragment
            response[name] = value
            continue
        response[name] = value
    response["Cache-Control"] = "no-store, private"
    response["Referrer-Policy"] = "no-referrer"
    response["X-Robots-Tag"] = "noindex, nofollow"
    return response


@client_workspace_required
@require_GET
def client_cpe_wifi(request, customer_id: int):
    """JSON live CPE Wi‑Fi / access status for one client (async for client_detail)."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization."}, status=400)

    customer = get_object_or_404(
        Customer.objects.select_related("router", "organization"),
        pk=customer_id,
        organization=org,
    )
    nas = customer.router
    can_access_wifi = customer_can_access_router(customer, org)
    if not can_access_wifi:
        return JsonResponse(
            {
                "ok": False,
                "auth_ok": False,
                "session_active": False,
                "error": "CPE Wi‑Fi is not available for this client.",
            },
            status=400,
        )

    cache_key = f"client_cpe_wifi:{org.pk}:{customer.pk}"
    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            return JsonResponse(cached)

    wifi_ssid = (customer.cpe_wifi_ssid or "").strip()
    wifi_password = customer.cpe_wifi_password or ""
    auth_ok = False
    session_active = False
    cpe_host = ""
    wifi_enabled = False
    wifi_mode = ""
    wifi_channel = ""
    wifi_security = ""
    wifi_hidden = False
    wifi_power = ""
    wifi_bandwidth = ""
    ssid_5g = ""
    source = ""
    hint = ""
    error = ""
    firewall_blocked = False
    prep_steps: list = []
    needs_password = False

    # Prefer the consumer CPE web API (Tenda, etc.) — this is where most
    # subscriber routers expose the live SSID/password/radio settings.
    nas_host = _router_api_host(nas)
    probe = probe_customer_cpe_web(
        nas_host,
        nas.username,
        nas.password or "",
        customer=customer,
        timeout=6.0,
    )
    session_active = bool(probe.get("session_active"))
    cpe_host = (probe.get("cpe_host") or "").strip()
    if probe.get("reachable") and probe.get("port"):
        web = fetch_customer_cpe_web_data(
            nas_host,
            nas.username,
            nas.password or "",
            customer=customer,
            cpe_password=customer.cpe_password or "",
            session_cookies=cache.get(f"cpe-web-customer:{org.pk}:{customer.pk}") or {},
            cpe_port=int(probe["port"]),
            timeout=8.0,
        )
        if web.get("ok"):
            wifi = web.get("wifi") or {}
            auth_ok = True
            source = "web"
            cpe_host = (web.get("cpe_host") or cpe_host).strip()
            wifi_ssid = (wifi.get("ssid") or "").strip() or wifi_ssid
            wifi_password = wifi.get("password") or wifi_password
            wifi_enabled = bool(wifi.get("enabled"))
            wifi_mode = (wifi.get("mode") or "").strip()
            wifi_channel = str(wifi.get("channel") or "")
            wifi_security = (wifi.get("security") or "").strip()
            wifi_hidden = bool(wifi.get("hidden"))
            wifi_power = (wifi.get("power") or "").strip()
            wifi_bandwidth = str(wifi.get("bandwidth_mhz") or "")
            ssid_5g = (wifi.get("ssid_5g") or "").strip()
        else:
            error = web.get("error") or ""
            needs_password = "password" in error.lower()
            hint = error

    # Fallback: RouterOS API on MikroTik CPEs (or when the web UI is locked).
    if not auth_ok:
        live = access_customer_cpe_wifi(
            nas_host,
            nas.username,
            nas.password or "",
            customer=customer,
            cpe_username=customer.cpe_username or "admin",
            cpe_password=customer.cpe_password or "",
            pppoe_password=customer.pppoe_password or "",
            timeout=6.0,
            auto_enable=(request.GET.get("setup") or "").strip() in {"1", "true", "yes"},
        )
        session_active = bool(live.get("session_active")) or session_active
        cpe_host = (live.get("cpe_host") or cpe_host).strip()
        auth_ok = bool(live.get("auth_ok"))
        prep_steps = list(live.get("prep_steps") or [])
        firewall_blocked = bool(live.get("firewall_blocked")) or (
            "firewall is blocking" in ((live.get("error") or "") + (live.get("hint") or "")).lower()
        )
        if auth_ok:
            source = "api"
            wifi_ssid = (live.get("wifi_ssid") or "").strip() or wifi_ssid
            wifi_password = live.get("wifi_password") or wifi_password
            wifi_enabled = bool(live.get("wifi_enabled"))
            wifi_mode = (live.get("wifi_mode") or "").strip() or wifi_mode
            error = ""
            hint = ""
            # Persist only credentials that actually authenticated — never
            # overwrite a stored password with a failed guess.
            working_user = (live.get("cpe_username") or "").strip()
            working_pass = live.get("cpe_password")
            cred_fields: list[str] = []
            if working_user and working_user != (customer.cpe_username or ""):
                customer.cpe_username = working_user
                cred_fields.append("cpe_username")
            if (
                working_pass is not None
                and working_pass != ""
                and working_pass != (customer.cpe_password or "")
            ):
                customer.cpe_password = working_pass
                cred_fields.append("cpe_password")
            if cred_fields:
                customer.save(update_fields=cred_fields)
        else:
            error = error or live.get("error") or ""
            hint = hint or live.get("hint") or ""
            err_l = f"{error} {hint}".lower()
            needs_password = needs_password or (
                not (customer.cpe_password or "").strip()
                or "password" in err_l
                or "login" in err_l
                or "auth" in err_l
                or "invalid" in err_l
                or "denied" in err_l
                or "rejected" in err_l
            )

    if auth_ok:
        update_fields = []
        if wifi_ssid and wifi_ssid != (customer.cpe_wifi_ssid or ""):
            customer.cpe_wifi_ssid = wifi_ssid
            update_fields.append("cpe_wifi_ssid")
        if wifi_password and wifi_password != (customer.cpe_wifi_password or ""):
            customer.cpe_wifi_password = wifi_password
            update_fields.append("cpe_wifi_password")
        if update_fields:
            customer.save(update_fields=update_fields)
    elif not needs_password and session_active and not firewall_blocked:
        # Reachable CPE but neither web nor API could authenticate — ask for
        # the router admin password so remote access can use the correct one.
        needs_password = not (customer.cpe_password or "").strip() or bool(error)

    payload = {
        "ok": True,
        "customer_id": customer.pk,
        "session_active": session_active,
        "auth_ok": auth_ok,
        "source": source,
        "cpe_host": cpe_host,
        "wifi_enabled": wifi_enabled if auth_ok else False,
        "wifi_ssid": wifi_ssid,
        "wifi_password": wifi_password if auth_ok else (customer.cpe_wifi_password or ""),
        "wifi_mode": wifi_mode,
        "wifi_channel": wifi_channel,
        "wifi_security": wifi_security,
        "wifi_hidden": wifi_hidden,
        "wifi_power": wifi_power,
        "wifi_bandwidth_mhz": wifi_bandwidth,
        "wifi_ssid_5g": ssid_5g,
        "hint": hint,
        "error": error if not auth_ok else "",
        "firewall_blocked": firewall_blocked,
        "prep_steps": prep_steps,
        "needs_password": bool(needs_password) and not auth_ok,
        "cpe_username": (customer.cpe_username or "").strip() or "admin",
    }
    cache.set(cache_key, payload, 12 if auth_ok else 5)
    return JsonResponse(payload)


@client_workspace_required
def client_wifi_settings(request, customer_id: int):
    """Dedicated page: live CPE Wi‑Fi settings and update form."""
    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("plan", "router", "organization"),
        pk=customer_id,
        organization=org,
    )
    nas = customer.router
    can_access_wifi = customer_can_access_router(customer, org)
    wifi_form = MikroTikWifiSettingsForm(
        initial={
            "wifi_ssid": (customer.cpe_wifi_ssid or "").strip(),
            "wifi_password": customer.cpe_wifi_password or "",
        }
    )

    if request.method == "POST" and can_access_wifi:
        action = (request.POST.get("action") or "").strip()
        if action == "update_router_password":
            router_password = (request.POST.get("cpe_password") or "").strip()
            if not router_password:
                messages.error(request, "Enter the client router admin password.")
            else:
                customer.cpe_password = router_password
                if not (customer.cpe_username or "").strip():
                    customer.cpe_username = "admin"
                customer.save(update_fields=["cpe_password", "cpe_username"])
                cache.delete(f"client_cpe_router_data:{org.pk}:{customer.pk}")
                cache.delete(f"client_cpe_wifi:{org.pk}:{customer.pk}")
                messages.success(request, "Router password saved.")
            return redirect("core:client_wifi_settings", customer_id=customer.pk)

        wifi_form = MikroTikWifiSettingsForm(request.POST)
        if wifi_form.is_valid():
            new_ssid = wifi_form.cleaned_data.get("wifi_ssid") or ""
            new_password = wifi_form.cleaned_data.get("wifi_password") or ""
            apply_ssid = bool(new_ssid)
            apply_password = bool(new_password)
            result: dict = {"ok": False, "error": "Could not reach the client router."}

            nas_host = _router_api_host(nas)
            probe = probe_customer_cpe_web(
                nas_host,
                nas.username,
                nas.password or "",
                customer=customer,
                timeout=8.0,
            )
            if probe.get("reachable") and probe.get("port"):
                result = configure_customer_cpe_web_wifi(
                    nas_host,
                    nas.username,
                    nas.password or "",
                    customer=customer,
                    cpe_password=customer.cpe_password or "",
                    wifi_ssid=new_ssid,
                    wifi_password=new_password,
                    apply_ssid=apply_ssid,
                    apply_password=apply_password,
                    session_cookies=cache.get(f"cpe-web-customer:{org.pk}:{customer.pk}") or {},
                    cpe_port=int(probe["port"]),
                    timeout=15.0,
                )
            elif not result.get("ok"):
                # MikroTik CPE path: prepare API access, then configure Wi‑Fi.
                prep = access_customer_cpe_wifi(
                    nas_host,
                    nas.username,
                    nas.password or "",
                    customer=customer,
                    cpe_username=customer.cpe_username or "admin",
                    cpe_password=customer.cpe_password or "",
                    pppoe_password=customer.pppoe_password or "",
                    timeout=10.0,
                    auto_enable=True,
                )
                if prep.get("auth_ok") and prep.get("cpe_host"):
                    result = configure_mikrotik_wifi(
                        prep["cpe_host"],
                        prep.get("cpe_username") or customer.cpe_username or "admin",
                        prep.get("cpe_password")
                        if prep.get("cpe_password") is not None
                        else (customer.cpe_password or ""),
                        wifi_ssid=new_ssid,
                        wifi_password=new_password,
                        apply_ssid=apply_ssid,
                        apply_password=apply_password,
                        nas_host=nas_host,
                        nas_username=nas.username,
                        nas_password=nas.password or "",
                        timeout=20.0,
                    )
                    if result.get("ok"):
                        result["wifi"] = {
                            "ssid": result.get("wifi_ssid") or new_ssid,
                            "password": result.get("wifi_password") or new_password,
                        }
                else:
                    result = {
                        "ok": False,
                        "error": prep.get("error")
                        or prep.get("hint")
                        or "Could not sign in to the client router to update Wi‑Fi.",
                        "needs_password": "password" in (
                            (prep.get("error") or "") + (prep.get("hint") or "")
                        ).lower(),
                    }

            if result.get("ok"):
                wifi = result.get("wifi") or {}
                saved_ssid = (wifi.get("ssid") or new_ssid or "").strip()
                saved_password = wifi.get("password") or new_password or ""
                update_fields = []
                if saved_ssid and saved_ssid != (customer.cpe_wifi_ssid or ""):
                    customer.cpe_wifi_ssid = saved_ssid
                    update_fields.append("cpe_wifi_ssid")
                if saved_password and saved_password != (customer.cpe_wifi_password or ""):
                    customer.cpe_wifi_password = saved_password
                    update_fields.append("cpe_wifi_password")
                if update_fields:
                    customer.save(update_fields=update_fields)
                cache.delete(f"client_cpe_router_data:{org.pk}:{customer.pk}")
                cache.delete(f"client_cpe_wifi:{org.pk}:{customer.pk}")
                messages.success(
                    request,
                    result.get("message")
                    or (
                        "Wi‑Fi updated on the client router."
                        if result.get("updated", True)
                        else "Wi‑Fi already matched."
                    ),
                )
                return redirect("core:client_wifi_settings", customer_id=customer.pk)

            wifi_form.add_error(
                None,
                result.get("error") or "Could not apply Wi‑Fi settings on the client router.",
            )

    ctx = _client_cpe_access_context(
        request,
        customer,
        org,
        can_access_wifi=can_access_wifi,
        wifi_form=wifi_form,
        active_tab=_client_cpe_access_tab(request),
    )
    return render(request, "core/client_cpe_access.html", ctx)


@client_workspace_required
@require_GET
def client_cpe_router_data(request, customer_id: int):
    """JSON snapshot of the client router's web status, WAN, Wi-Fi and devices."""
    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("router", "organization"),
        pk=customer_id,
        organization=org,
    )
    if not customer_can_access_router(customer, org):
        return JsonResponse(
            {"ok": False, "error": "Router data is unavailable for this client."},
            status=400,
        )

    cache_key = f"client_cpe_router_data:{org.pk}:{customer.pk}"
    force = (request.GET.get("refresh") or "").strip().lower() in {"1", "true", "yes"}
    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            return JsonResponse(cached)

    nas = customer.router
    nas_host = _router_api_host(nas)
    probe = probe_customer_cpe_web(
        nas_host,
        nas.username,
        nas.password or "",
        customer=customer,
        timeout=8.0,
    )
    if not probe.get("reachable") or not probe.get("port"):
        payload = {
            "ok": False,
            "cpe_host": probe.get("cpe_host") or "",
            "error": probe.get("hint") or probe.get("error")
            or "The client router web interface is unavailable.",
        }
        cache.set(cache_key, payload, 5)
        return JsonResponse(payload)

    payload = fetch_customer_cpe_web_data(
        nas_host,
        nas.username,
        nas.password or "",
        customer=customer,
        cpe_password=customer.cpe_password or "",
        session_cookies=cache.get(f"cpe-web-customer:{org.pk}:{customer.pk}") or {},
        cpe_port=int(probe["port"]),
        timeout=10.0,
    )
    payload["port"] = int(probe["port"])
    payload["needs_password"] = not payload.get("ok") and (
        "password" in (payload.get("error") or "").lower()
    )
    if payload.get("ok"):
        wifi = payload.get("wifi") or {}
        ssid = (wifi.get("ssid") or "").strip()
        password = wifi.get("password") or ""
        update_fields: list[str] = []
        if ssid and ssid != (customer.cpe_wifi_ssid or ""):
            customer.cpe_wifi_ssid = ssid
            update_fields.append("cpe_wifi_ssid")
        if password and password != (customer.cpe_wifi_password or ""):
            customer.cpe_wifi_password = password
            update_fields.append("cpe_wifi_password")
        if update_fields:
            customer.save(update_fields=update_fields)
    cache.set(cache_key, payload, 15 if payload.get("ok") else 5)
    return JsonResponse(payload)


@client_workspace_required
@require_GET
def client_subscription(request, customer_id: int):
    """JSON live subscription / package-period status for one client."""
    from django.utils import timezone as dj_tz
    from django.utils.formats import date_format

    from billing.services import (
        customer_package_is_paused,
        customer_receives_internet,
        customer_subscription_expired,
        package_remaining_seconds,
    )

    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization."}, status=400)

    customer = get_object_or_404(
        Customer.objects.select_related("plan", "router", "organization"),
        pk=customer_id,
        organization=org,
    )

    allowed = customer_receives_internet(customer)
    expired = customer_subscription_expired(customer)
    paused = customer_package_is_paused(customer)
    duration = getattr(customer.plan, "duration", "") or ""
    is_hourly = duration in ("hourly", "six_hours")
    now = dj_tz.localtime()

    def _fmt(value):
        if not value:
            return ""
        local = dj_tz.localtime(value)
        return date_format(local, "M j, g:i A" if is_hourly else "M j, Y")

    def _iso(value):
        return dj_tz.localtime(value).isoformat() if value else ""

    remaining_seconds = package_remaining_seconds(customer, now=now)
    remaining_label = ""
    if remaining_seconds is not None:
        if remaining_seconds <= 0:
            remaining_label = "Ended"
        else:
            hours, rem = divmod(remaining_seconds, 3600)
            minutes, seconds = divmod(rem, 60)
            if hours:
                remaining_label = f"{hours}h {minutes}m"
            elif minutes:
                remaining_label = f"{minutes}m {seconds}s"
            else:
                remaining_label = f"{seconds}s"

    sync_result = None
    want_sync = (request.GET.get("sync") or "").strip() in {"1", "true", "yes"}
    if want_sync and customer.pppoe_username and customer.router_id:
        sync_result = sync_customer_subscription_access(
            customer,
            provision=True,
        )

    return JsonResponse(
        {
            "ok": True,
            "customer_id": customer.pk,
            "now": now.isoformat(),
            "package_start": _fmt(customer.package_start),
            "package_end": _fmt(customer.package_end),
            "package_start_iso": _iso(customer.package_start),
            "package_end_iso": _iso(customer.package_end),
            "plan_name": customer.plan.name if customer.plan_id else "",
            "plan_speed": customer.plan.speed_label if customer.plan_id else "",
            "plan_duration": customer.plan.get_duration_display() if customer.plan_id else "",
            "package_duration": duration,
            "subscription_active": allowed,
            "subscription_expired": expired,
            "subscription_paused": paused,
            "package_paused_at": _iso(customer.package_paused_at),
            "remaining_seconds": remaining_seconds,
            "remaining_label": remaining_label,
            "can_pause_package": customer_can_pause_package(customer),
            "can_resume_package": customer_can_resume_package(customer),
            "sync": sync_result,
        }
    )


@client_workspace_required
@require_GET
def client_usage(request, customer_id: int):
    """JSON live PPPoE / Hotspot session traffic usage for one client."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization."}, status=400)

    customer = get_object_or_404(
        Customer.objects.select_related("router", "organization"),
        pk=customer_id,
        organization=org,
    )
    is_hotspot = customer.service_type == Customer.ServiceType.HOTSPOT
    is_pppoe = customer.service_type == Customer.ServiceType.PPPOE
    if not is_hotspot and not is_pppoe:
        return JsonResponse(
            {
                "ok": False,
                "session_active": False,
                "error": "Live usage is available for PPPoE and Hotspot clients.",
            }
        )
    if is_pppoe and not customer.pppoe_username:
        return JsonResponse(
            {
                "ok": False,
                "session_active": False,
                "error": "This client has no PPPoE username.",
            }
        )
    if is_hotspot and not _hotspot_macs_for_usage(customer):
        return JsonResponse(
            {
                "ok": False,
                "session_active": False,
                "error": "This client has no Hotspot device MAC.",
            }
        )

    router = resolve_client_usage_router(customer, org)
    if not router:
        return JsonResponse(
            {
                "ok": False,
                "session_active": False,
                "error": "No MikroTik router is available for this client.",
            }
        )
    if router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
        return JsonResponse(
            {
                "ok": False,
                "session_active": False,
                "suspended": True,
                "error": "The assigned MikroTik account is suspended.",
            }
        )

    cache_key = f"client_usage:v2:{org.pk}:{customer.pk}"
    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            return JsonResponse(cached)

    if is_hotspot:
        macs = _hotspot_macs_for_usage(customer)
        best = None
        best_total = -1
        connected_count = 0
        active_count = 0
        peak_down = 0
        peak_up = 0
        for mac in macs:
            candidate = fetch_customer_hotspot_usage(
                router.host,
                router.username,
                router.password or "",
                hotspot_mac=mac,
            )
            if not candidate.get("ok"):
                if best is None:
                    best = candidate
                continue
            connected = bool(
                candidate.get("connected") or candidate.get("session_active")
            )
            if connected:
                connected_count += 1
            if candidate.get("session_active"):
                active_count += 1
                bi = int(candidate.get("bytes_in") or 0)
                bo = int(candidate.get("bytes_out") or 0)
                peak_down = max(peak_down, int(candidate.get("download_bps") or 0))
                peak_up = max(peak_up, int(candidate.get("upload_bps") or 0))
                if bi + bo > best_total:
                    best_total = bi + bo
                    best = candidate
            elif connected and (best is None or not best.get("session_active")):
                best = candidate
            elif best is None:
                best = candidate

        payload = best or {
            "ok": False,
            "session_active": False,
            "connected": False,
            "error": "This client has no Hotspot device MAC.",
        }
        if active_count > 1 and payload.get("session_active"):
            # Prefer peak live rates from any gadget; keep the busiest session's
            # byte counters so trend deltas stay continuous (do not sum absolute
            # session totals across MACs — that spikes "data used").
            if peak_down:
                payload["download_bps"] = peak_down
                payload["download_label"] = _usage_bps_label(peak_down)
            if peak_up:
                payload["upload_bps"] = peak_up
                payload["upload_label"] = _usage_bps_label(peak_up)

        connected = connected_count > 0 or bool(
            payload.get("connected") or payload.get("session_active")
        )
        payload["connected"] = connected
        payload["devices_connected"] = connected_count or (1 if connected else 0)
        if connected_count > 1:
            payload["devices_label"] = f"{connected_count} gadgets"
            payload["devices_hint"] = f"{active_count} surfing · {connected_count} on Wi‑Fi"
        else:
            payload["devices_label"] = "1 gadget" if connected else "0"
            payload["devices_hint"] = (
                "Connected to Hotspot network"
                if connected
                else "Not seen on Hotspot network"
            )
        payload["speed_source"] = "nas"
        payload["cpe_host"] = (payload.get("address") or "").strip()
        payload["cpe_auth_ok"] = False

        from billing.services import customer_can_surf_via_hotspot

        internet_allowed = customer_can_surf_via_hotspot(customer)
        surfing = bool(payload.get("session_active") and internet_allowed)
        if surfing:
            session_state = "surfing"
            session_label = "Surfing"
            session_hint = "Online — internet OK"
        elif connected:
            session_state = "not_surfing"
            session_label = "Not surfing"
            session_hint = (
                payload.get("hint")
                or "Connected to Wi‑Fi — Hotspot session not active"
            )
        else:
            session_state = "disconnected"
            session_label = "Disconnected"
            session_hint = payload.get("hint") or "Not connected to a router"
        payload["internet_allowed"] = internet_allowed
        payload["surfing"] = surfing
        payload["session_state"] = session_state
        payload["session_label"] = session_label
        payload["hint"] = session_hint
        # Presence / trend charts track authenticated Hotspot surfing.
        if payload.get("ok") and payload.get("session_active"):
            payload["session_active"] = surfing
    else:
        payload = fetch_customer_pppoe_usage(
            router.host,
            router.username,
            router.password or "",
            pppoe_username=customer.pppoe_username,
        )
        payload["speed_source"] = "nas"
        payload["cpe_host"] = (payload.get("address") or "").strip()
        payload["cpe_auth_ok"] = False
        payload["devices_connected"] = None
        payload["devices_label"] = "—"
        payload["devices_hint"] = "Device count loads from CPE when reachable"
        payload["connected"] = bool(payload.get("session_active"))

        # Optional short CPE enrichment — never block the account page / live session.
        want_cpe = (request.GET.get("cpe") or "").strip() in {"1", "true", "yes"}
        if want_cpe and payload.get("session_active") and (customer.cpe_password or customer.pppoe_password):
            try:
                cpe = fetch_customer_cpe_live_usage(
                    router.host,
                    router.username,
                    router.password or "",
                    pppoe_username=customer.pppoe_username,
                    cpe_username=customer.cpe_username or "admin",
                    cpe_password=customer.cpe_password or "",
                    pppoe_password=customer.pppoe_password or "",
                    timeout=6.0,
                )
                if cpe.get("cpe_auth_ok"):
                    for key in (
                        "download_bps",
                        "upload_bps",
                        "download_label",
                        "upload_label",
                        "bytes_in",
                        "bytes_out",
                        "bytes_in_label",
                        "bytes_out_label",
                        "interface",
                        "devices_connected",
                        "devices_label",
                        "devices_hint",
                        "dhcp_leases",
                        "wifi_clients",
                        "speed_source",
                        "cpe_host",
                        "cpe_auth_ok",
                        "prep_steps",
                    ):
                        if key in cpe:
                            payload[key] = cpe.get(key)
                    working_user = (cpe.get("cpe_username") or "").strip()
                    if working_user and working_user != (customer.cpe_username or ""):
                        customer.cpe_username = working_user
                        customer.save(update_fields=["cpe_username"])
                elif cpe.get("devices_hint"):
                    payload["devices_hint"] = cpe.get("devices_hint")
                if cpe.get("cpe_error"):
                    payload["cpe_error"] = cpe.get("cpe_error")
            except Exception:
                payload["devices_hint"] = "CPE metrics unavailable — session still live from NAS"

    payload["customer_id"] = customer.pk
    payload["router_id"] = router.pk
    payload["router_name"] = router.name
    payload["wifi_ssid"] = (router.wifi_ssid or "").strip()

    try:
        from billing.usage_samples import record_customer_usage_sample

        # Only persist successful router reads — timeouts/errors must not look
        # like the client went offline.
        if payload.get("ok"):
            record_customer_usage_sample(customer, payload)
    except Exception:
        pass

    # Short cache so live speeds stay useful without hammering the API.
    cache.set(cache_key, payload, 8 if payload.get("session_active") else 4)
    return JsonResponse(payload)


def _clients_usage_router_filter(request, org):
    """Parse ?router= for usage analytics (all / none / MikroTik id)."""
    router_raw = (request.GET.get("router") or "").strip()
    clients_router_param = ""
    clients_router_id = None
    unassigned_only = False
    if router_raw.lower() in {"none", "unassigned", "0"}:
        clients_router_param = "none"
        unassigned_only = True
    elif router_raw.isdigit():
        clients_router_id = int(router_raw)
        clients_router_param = str(clients_router_id)
        if org and not MikroTikRouter.objects.filter(
            organization=org, pk=clients_router_id
        ).exists():
            clients_router_id = None
            clients_router_param = ""

    client_routers = []
    if org:
        client_routers = list(
            MikroTikRouter.objects.filter(organization=org)
            .order_by("name", "host")
            .only("id", "name", "host")
        )

    router_filter_label = ""
    if unassigned_only:
        router_filter_label = "No router assigned"
    elif clients_router_id:
        router_filter_label = next(
            (r.name for r in client_routers if r.pk == clients_router_id),
            "",
        )

    return {
        "client_routers": client_routers,
        "clients_router_param": clients_router_param,
        "clients_router_id": clients_router_id,
        "clients_router_unassigned": unassigned_only,
        "router_filter_label": router_filter_label,
    }


@client_workspace_required
def clients_general_usage(request):
    """Organization-wide usage analytics and highest-users ranking."""
    org = resolve_organization(request.user, request)
    from billing.usage_samples import (
        clamp_usage_hours,
        org_usage_payload,
        usage_range_label,
    )

    # First paint stays snappy: ranked preview from DB/cache only.
    # Live MikroTik sampling continues in the background via trends JSON.
    _USAGE_PAGE_PREVIEW = 30

    hours = clamp_usage_hours(request.GET.get("hours") or 72, default=72)
    tab = (request.GET.get("tab") or "pppoe").strip().lower()
    if tab not in {"pppoe", "hotspot"}:
        tab = "pppoe"
    router_ctx = _clients_usage_router_filter(request, org)

    if org:
        trends = org_usage_payload(
            org,
            hours=hours,
            auto_widen=True,
            use_cache=True,
            top_n=_USAGE_PAGE_PREVIEW,
            service=tab,
            router_id=router_ctx["clients_router_id"],
            unassigned_only=router_ctx["clients_router_unassigned"],
        )
        summary = trends.setdefault("summary", {})
        total_clients = int(summary.get("clients_total") or 0)
        preview_users = trends.get("top_users") or []
        trends["users_partial"] = total_clients > len(preview_users)
        trends["users_loaded"] = len(preview_users)
        trends["users_total_count"] = total_clients or len(preview_users)
        trends["progressive"] = True
    else:
        trends = {
            "ok": False,
            "hours": hours,
            "requested_hours": hours,
            "auto_widened": False,
            "service": tab,
            "sample_count": 0,
            "labels": [],
            "series": {
                "online_clients": [],
                "download_kbps": [],
                "upload_kbps": [],
                "data_used_mb": [],
            },
            "summary": {},
            "top_users": [],
            "top_chart": {"labels": [], "data_used_mb": []},
            "error": "No organization is linked to this workspace.",
            "range_label": usage_range_label(hours),
            "requested_range_label": usage_range_label(hours),
            "users_partial": False,
            "users_loaded": 0,
            "users_total_count": 0,
            "progressive": True,
        }

    effective_hours = trends.get("hours") or hours
    requested = trends.get("requested_hours") or hours
    return render(
        request,
        "core/clients_general_usage.html",
        client_page_context(
            request,
            active_nav="clients",
            sidebar_active="general_usage",
            page_title="General usage",
            page_kicker="Subscribers",
            page_subtitle="PPPoE and Hotspot usage analytics by service.",
            active_tab=tab,
            trend_hours=effective_hours,
            requested_hours=requested,
            auto_widened=bool(trends.get("auto_widened")),
            range_label=trends.get("range_label") or usage_range_label(effective_hours),
            requested_range_label=trends.get("requested_range_label")
            or usage_range_label(requested),
            trends=trends,
            trends_json=json.dumps(trends),
            top_users=trends.get("top_users") or [],
            trends_url=reverse("core:clients_general_usage_trends"),
            **router_ctx,
        ),
    )


@client_workspace_required
@require_GET
def clients_general_usage_trends(request):
    """JSON chart series for the general usage page."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization."}, status=400)
    from billing.usage_samples import (
        clamp_usage_hours,
        org_usage_payload,
        sample_organization_usage,
    )

    hours = clamp_usage_hours(request.GET.get("hours") or 72, default=72)
    tab = (request.GET.get("tab") or request.GET.get("service") or "pppoe").strip().lower()
    if tab not in {"pppoe", "hotspot"}:
        tab = "pppoe"
    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    router_ctx = _clients_usage_router_filter(request, org)

    try:
        # Always attempt a sweep; force=True on Refresh so statuses stay current
        # for every assigned client (online + offline markers).
        sample_organization_usage(org, force=force)
    except Exception:
        pass
    return JsonResponse(
        org_usage_payload(
            org,
            hours=hours,
            auto_widen=True,
            use_cache=not force,
            top_n=0,
            service=tab,
            router_id=router_ctx["clients_router_id"],
            unassigned_only=router_ctx["clients_router_unassigned"],
        )
    )


@client_workspace_required
def client_usage_analysis(request, customer_id: int):
    """Usage analysis page: uptime, throughput and data-used trends."""
    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("plan", "router", "organization"),
        pk=customer_id,
        organization=org,
    )
    usage_router = resolve_client_usage_router(customer, org)
    can_live = bool(
        customer_supports_live_usage(customer)
        and usage_router is not None
        and usage_router.account_status != MikroTikRouter.AccountStatus.SUSPENDED
    )
    can_access_wifi = customer_can_access_router(customer, org)
    from billing.usage_samples import clamp_usage_hours, usage_range_label, usage_trend_payload

    hours = clamp_usage_hours(request.GET.get("hours"), default=24)

    if can_live:
        trends = usage_trend_payload(customer, hours=hours)
    else:
        if customer.service_type == Customer.ServiceType.HOTSPOT:
            has_mac = bool(_hotspot_macs_for_usage(customer))
            error = (
                "No MikroTik router is available for this Hotspot gadget."
                if has_mac
                else "Add a device MAC to collect Hotspot gadget usage."
            )
        else:
            error = "Live usage trends are available for PPPoE clients with an assigned router."
        trends = {
            "ok": False,
            "hours": hours,
            "range_label": usage_range_label(hours),
            "sample_count": 0,
            "labels": [],
            "series": {
                "download_kbps": [],
                "upload_kbps": [],
                "data_used_mb": [],
                "online": [],
            },
            "markers": {"peak_index": None, "low_index": None, "stop_indexes": []},
            "summary": {},
            "error": error,
        }

    ctx = client_page_context(
        request,
        active_nav="client_detail",
        sidebar_active="usage",
        page_title=f"Usage · {customer.full_name}",
        customer=customer,
        can_live_usage=can_live,
        can_access_wifi=can_access_wifi,
        trend_hours=hours,
        range_label=trends.get("range_label") or usage_range_label(hours),
        trends=trends,
        trends_json=json.dumps(trends),
        back_url=reverse("core:client_detail", kwargs={"customer_id": customer.pk}),
        usage_url=reverse("core:client_usage", kwargs={"customer_id": customer.pk}),
        trends_url=reverse(
            "core:client_usage_trends", kwargs={"customer_id": customer.pk}
        ),
    )
    ctx["client_nav_main"] = [
        *CLIENT_COMMON_NAV_START,
        *build_client_detail_nav(customer, can_access_wifi=can_access_wifi),
    ]
    ctx["sidebar_label"] = "Client"
    apply_client_shared_forms(ctx, customer, org)
    return render(request, "core/client_usage_analysis.html", ctx)


def _payment_mpesa_reference(payment: Payment) -> str:
    """Prefer the real M-Pesa receipt over Safaricom CheckoutRequestID placeholders."""
    checkout_ids: set[str] = set()
    for stk in payment.stk_push_requests.all():
        receipt = (stk.mpesa_receipt or "").strip()
        if receipt:
            return receipt
        checkout_id = (stk.checkout_request_id or "").strip()
        if checkout_id:
            checkout_ids.add(checkout_id)
    ref = (payment.reference or "").strip()
    if not ref:
        return ""
    # Checkout IDs look like ws_CO_… and are not the SMS receipt number.
    if ref in checkout_ids or ref.startswith("ws_CO_"):
        return ""
    return ref


@client_workspace_required
def client_billing(request, customer_id: int):
    """Dedicated page listing successful payments and access vouchers for one client."""
    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("plan", "router", "organization"),
        pk=customer_id,
        organization=org,
    )
    can_access_wifi = customer_can_access_router(customer, org)
    payments = (
        list(
            Payment.objects.filter(invoice__customer=customer, organization=org)
            .select_related("invoice")
            .prefetch_related("stk_push_requests")
            .order_by("-received_at")[:100]
        )
        if org
        else []
    )
    for pay in payments:
        display_ref = _payment_mpesa_reference(pay)
        pay.display_reference = display_ref
        # Heal rows that still store CheckoutRequestID after the real receipt arrived.
        if not display_ref:
            continue
        current = (pay.reference or "").strip()
        linked_checkouts = {
            (stk.checkout_request_id or "").strip()
            for stk in pay.stk_push_requests.all()
            if (stk.checkout_request_id or "").strip()
        }
        if (
            not current
            or current in linked_checkouts
            or current.startswith("ws_CO_")
        ) and current != display_ref:
            pay.reference = display_ref[:100]
            pay.save(update_fields=["reference"])
    invoice_stats = (
        Invoice.objects.filter(customer=customer, organization=org).aggregate(
            total=Count("id"),
            pending=Count("id", filter=Q(status=Invoice.Status.PENDING)),
            paid=Count("id", filter=Q(status=Invoice.Status.PAID)),
            overdue=Count("id", filter=Q(status=Invoice.Status.OVERDUE)),
        )
        if org
        else {}
    )
    amount_paid = (
        Payment.objects.filter(invoice__customer=customer, organization=org).aggregate(
            total=Sum("amount")
        )["total"]
        if org
        else None
    ) or 0

    from billing.vouchers import vouchers_for_customer_billing

    voucher_rows = vouchers_for_customer_billing(customer, request=request) if org else []
    valid_voucher_count = sum(
        1 for row in voucher_rows if row["status"] == "valid"
    )

    ctx = client_page_context(
        request,
        active_nav="client_detail",
        sidebar_active="billing",
        page_title=f"Billing · {customer.full_name}",
        customer=customer,
        can_access_wifi=can_access_wifi,
        payments=payments,
        invoice_total=invoice_stats.get("total") or 0,
        invoice_pending=invoice_stats.get("pending") or 0,
        invoice_paid=invoice_stats.get("paid") or 0,
        invoice_overdue=invoice_stats.get("overdue") or 0,
        amount_paid=amount_paid,
        vouchers=voucher_rows,
        valid_voucher_count=valid_voucher_count,
        voucher_pay_url=(
            voucher_rows[0]["share"]["pay_url"] if voucher_rows else ""
        ),
        back_url=reverse("core:client_detail", kwargs={"customer_id": customer.pk}),
    )
    ctx["client_nav_main"] = [
        *CLIENT_COMMON_NAV_START,
        *build_client_detail_nav(customer, can_access_wifi=can_access_wifi),
    ]
    ctx["sidebar_label"] = "Client"
    apply_client_shared_forms(ctx, customer, org)
    return render(request, "core/client_billing.html", ctx)


@client_workspace_required
@require_GET
def client_usage_trends(request, customer_id: int):
    """JSON chart series for the usage analysis page."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization."}, status=400)
    customer = get_object_or_404(
        Customer.objects.select_related("router"),
        pk=customer_id,
        organization=org,
    )
    if not customer_supports_live_usage(customer):
        return JsonResponse(
            {"ok": False, "error": "Usage trends are unavailable for this client."},
            status=400,
        )
    if resolve_client_usage_router(customer, org) is None:
        return JsonResponse(
            {"ok": False, "error": "No MikroTik router is available for this client."},
            status=400,
        )
    from billing.usage_samples import clamp_usage_hours, usage_trend_payload

    hours = clamp_usage_hours(request.GET.get("hours"), default=24)
    sample = (request.GET.get("sample") or "").strip() in {"1", "true", "yes"}
    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    if sample or force:
        # Collect a fresh MikroTik snapshot so the open analysis page builds
        # history while it is watched (throttled inside record_customer_usage_sample).
        try:
            _record_live_usage_sample(customer, org, force=force)
        except Exception:
            pass
    return JsonResponse(
        usage_trend_payload(customer, hours=hours, use_cache=not force)
    )


def _record_live_usage_sample(customer, org, *, force: bool = False) -> bool:
    """Probe this client's NAS/Hotspot session and persist a trend sample."""
    from billing.usage_samples import record_customer_usage_sample

    router = resolve_client_usage_router(customer, org)
    if not router or router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
        return False

    cache_key = f"client_usage:v2:{org.pk}:{customer.pk}"
    if not force:
        cached = cache.get(cache_key)
        if isinstance(cached, dict) and cached.get("ok"):
            return bool(record_customer_usage_sample(customer, cached))

    if customer.service_type == Customer.ServiceType.HOTSPOT:
        macs = _hotspot_macs_for_usage(customer)
        if not macs:
            return False
        best = None
        best_total = -1
        peak_down = 0
        peak_up = 0
        active_count = 0
        for mac in macs:
            candidate = fetch_customer_hotspot_usage(
                router.host,
                router.username,
                router.password or "",
                hotspot_mac=mac,
            )
            if not candidate.get("ok"):
                continue
            if candidate.get("session_active"):
                active_count += 1
                bi = int(candidate.get("bytes_in") or 0)
                bo = int(candidate.get("bytes_out") or 0)
                peak_down = max(peak_down, int(candidate.get("download_bps") or 0))
                peak_up = max(peak_up, int(candidate.get("upload_bps") or 0))
                if bi + bo > best_total:
                    best_total = bi + bo
                    best = candidate
            elif best is None and candidate.get("connected"):
                best = candidate
        if not best or not best.get("ok"):
            return False
        payload = best
        if active_count > 1 and payload.get("session_active"):
            if peak_down:
                payload = {**payload, "download_bps": peak_down}
            if peak_up:
                payload = {**payload, "upload_bps": peak_up}
        try:
            from billing.services import customer_can_surf_via_hotspot

            if payload.get("session_active") and not customer_can_surf_via_hotspot(
                customer
            ):
                payload = {**payload, "session_active": False}
        except Exception:
            pass
    elif customer.service_type == Customer.ServiceType.PPPOE:
        if not customer.pppoe_username:
            return False
        payload = fetch_customer_pppoe_usage(
            router.host,
            router.username,
            router.password or "",
            pppoe_username=customer.pppoe_username,
        )
        if not payload.get("ok"):
            return False
    else:
        return False

    payload["customer_id"] = customer.pk
    payload["router_id"] = router.pk
    payload["router_name"] = router.name
    cache.set(cache_key, payload, 8 if payload.get("session_active") else 4)
    return bool(record_customer_usage_sample(customer, payload))


@client_workspace_required
@require_GET
def clients_surfing_status(request):
    """
    Live connection state for PPPoE or Hotspot clients in this organization.

    Hotspot responses distinguish devices seen on the Wi-Fi/LAN Hotspot host
    table from devices with an authenticated, active internet session.
    """
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization.", "clients": []}, status=400)

    service = (request.GET.get("service") or "pppoe").strip().lower()
    if service not in {"pppoe", "hotspot"}:
        return JsonResponse(
            {"ok": False, "error": "Unsupported client service.", "clients": []},
            status=400,
        )
    service_type = (
        Customer.ServiceType.HOTSPOT
        if service == "hotspot"
        else Customer.ServiceType.PPPOE
    )
    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    cache_key = f"clients_surfing:{org.pk}:{service}:v3"
    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            return JsonResponse(cached)

    customers = list(
        Customer.objects.filter(
            organization=org,
            service_type=service_type,
        )
        .select_related("router", "organization", "plan")
        .order_by("id")
    )

    routers_by_id = {
        router.pk: router
        for router in MikroTikRouter.objects.filter(
            organization=org,
            account_status=MikroTikRouter.AccountStatus.ACTIVE,
        )
    }
    for customer in customers:
        if customer.router_id and customer.router is not None:
            routers_by_id.setdefault(customer.router_id, customer.router)

    active_by_router: dict[int, set[str]] = {}
    connected_by_router: dict[int, set[str]] = {}
    nas_blocked_by_router: dict[int, set[str]] = {}
    router_errors: dict[int, str] = {}

    def _probe_router(router) -> tuple[int, set[str], set[str], set[str], str]:
        router_id = router.pk
        if router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
            return router_id, set(), set(), set(), "Router suspended"
        if service == "hotspot":
            result = fetch_hotspot_client_macs(
                router.host,
                router.username,
                router.password,
                timeout=4.0,
            )
            active = set(result.get("active_macs") or [])
            connected = set(result.get("connected_macs") or [])
            nas_blocked: set[str] = set()
        else:
            result = fetch_active_pppoe_usernames(
                router.host,
                router.username,
                router.password,
                timeout=4.0,
            )
            active = {name.lower() for name in (result.get("usernames") or [])}
            connected = set()
            nas_blocked = {name.lower() for name in (result.get("blocked") or [])}
        if result.get("ok"):
            return router_id, active, connected, nas_blocked, ""
        return (
            router_id,
            set(),
            set(),
            set(),
            result.get("error") or "Could not reach router",
        )

    if routers_by_id:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        workers = min(8, len(routers_by_id))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(_probe_router, router)
                for router in routers_by_id.values()
            ]
            for future in as_completed(futures):
                router_id, active, connected, nas_blocked, error = future.result()
                active_by_router[router_id] = active
                connected_by_router[router_id] = connected
                nas_blocked_by_router[router_id] = nas_blocked
                if error:
                    router_errors[router_id] = error

    clients_payload = []
    surfing_count = 0
    surfing_customers = []
    connected_count = 0
    active_any_router = set().union(*active_by_router.values()) if active_by_router else set()
    connected_any_router = (
        set().union(*connected_by_router.values()) if connected_by_router else set()
    )
    nas_blocked_any_router = (
        set().union(*nas_blocked_by_router.values()) if nas_blocked_by_router else set()
    )

    def _period_blocked_reason(customer) -> str:
        if customer_subscription_expired(customer):
            if plan_uses_clock_time(getattr(customer, "plan", None)):
                return "Subscription expired"
            return "Subscription ended at midnight — no internet"
        return "Outside package period — no internet"

    def _router_id_for_identity(
        identity: str,
        preferred_router_id: int | None,
        by_router: dict[int, set[str]],
    ) -> int | None:
        if not identity:
            return preferred_router_id
        if preferred_router_id and identity in (by_router.get(preferred_router_id) or set()):
            return preferred_router_id
        for rid, identities in by_router.items():
            if identity in identities:
                return rid
        return preferred_router_id

    for customer in customers:
        identity = (customer.pppoe_username or "").strip().lower()
        if service == "hotspot":
            identity = "".join(
                ch for ch in (customer.hotspot_mac or "") if ch.isalnum()
            ).upper()
        session_online = False
        connected = False
        reason = ""
        connection_reason = ""
        connected_router_id = None
        if not identity:
            reason = "No device MAC" if service == "hotspot" else "No PPPoE username"
            connection_reason = reason
        elif not customer.router_id:
            # Older/imported customers may not be assigned to a router. The
            # live NAS session is still authoritative, so match their unique
            # PPPoE username/MAC across every active organization router.
            session_online = identity in active_any_router
            connected = (
                identity in connected_any_router or session_online
                if service == "hotspot"
                else session_online
            )
            if not session_online:
                reason = (
                    next(iter(router_errors.values()), "")
                    or "No active session on any router"
                )
            if not connected:
                connection_reason = reason
        else:
            active_identities = active_by_router.get(customer.router_id) or set()
            connected_identities = connected_by_router.get(customer.router_id) or set()
            session_online = identity in active_identities
            connected = (
                identity in connected_identities or session_online
                if service == "hotspot"
                else session_online
            )
            # Hotspot clients can roam onto another org router — still count as connected.
            if service == "hotspot" and not connected:
                session_online = session_online or identity in active_any_router
                connected = identity in connected_any_router or session_online
            if not session_online:
                reason = router_errors.get(customer.router_id) or (
                    "Router not dialed — no active PPPoE session"
                    if service == "pppoe"
                    else "No active Hotspot session"
                )
            if not connected:
                connection_reason = (
                    router_errors.get(customer.router_id)
                    or "Device not seen on the Hotspot network"
                )

        if service == "hotspot" and connected and identity:
            connected_router_id = _router_id_for_identity(
                identity,
                customer.router_id,
                connected_by_router,
            )
            if not connected_router_id:
                connected_router_id = _router_id_for_identity(
                    identity,
                    customer.router_id,
                    active_by_router,
                )
            # Prefer live active session router when present.
            active_router_id = _router_id_for_identity(
                identity,
                customer.router_id,
                active_by_router,
            )
            if active_router_id and identity in (active_by_router.get(active_router_id) or set()):
                connected_router_id = active_router_id
                session_online = True

        internet_allowed = False
        nas_blocked = (
            (
                nas_blocked_by_router.get(customer.router_id)
                if customer.router_id
                else nas_blocked_any_router
            )
            or set()
        )
        on_blocked_profile = bool(identity) and identity in nas_blocked

        # MikroTik probe failed → treat as disconnected (not "not surfing").
        if customer.router_id:
            router_unreachable = bool(router_errors.get(customer.router_id))
            router_error = router_errors.get(customer.router_id) or ""
        elif identity:
            router_unreachable = bool(router_errors) and not active_any_router
            router_error = next(iter(router_errors.values()), "") if router_unreachable else ""
        else:
            router_unreachable = False
            router_error = ""

        surfing = False
        if customer.status != Customer.Status.ACTIVE:
            reason = customer.get_status_display()
        elif router_unreachable and not session_online and not connected:
            reason = router_error or "Router disconnected"
        else:
            from billing.services import (
                customer_can_surf_via_hotspot,
                customer_can_surf_via_pppoe,
            )

            if service == "hotspot":
                internet_allowed = customer_can_surf_via_hotspot(customer)
            else:
                internet_allowed = customer_can_surf_via_pppoe(customer)
            # Surfing = real internet right now: package still valid AND live
            # session AND (for PPPoE) not parked on the blocked NAS profile.
            surfing = bool(session_online and internet_allowed)
            if service == "pppoe" and surfing and on_blocked_profile:
                surfing = False
            if not internet_allowed:
                surfing = False
                if session_online:
                    reason = (
                        "Dialed in, but subscription ended — no internet"
                        if customer_subscription_expired(customer)
                        else "Dialed in, but outside package period — no internet"
                    )
                else:
                    reason = _period_blocked_reason(customer)
            elif on_blocked_profile and service == "pppoe":
                reason = "Dialed in, but blocked on the router — access not synced"
            elif surfing:
                reason = "Online — internet OK"
            elif internet_allowed and not session_online:
                # Keep router/error reason already set, or clarify package is OK.
                if not reason or reason.startswith("No active") or "not dialed" in reason:
                    deadline = subscription_access_deadline(customer)
                    if deadline and not plan_uses_clock_time(getattr(customer, "plan", None)):
                        reason = (
                            "Package active until midnight — router not dialed"
                        )
                    else:
                        reason = "Package active — router not dialed"
                if service == "hotspot" and connected:
                    reason = "Connected to Wi‑Fi — Hotspot session not active"

        subscription_expired = False
        try:
            subscription_expired = customer_subscription_expired(customer)
        except Exception:
            subscription_expired = False

        if surfing:
            state = "surfing"
            label = "Surfing"
            surfing_count += 1
            surfing_customers.append(customer)
        elif service == "hotspot":
            # Hotspot Session column: connected → Surfing/Not surfing, else Disconnected.
            if connected:
                state = "not_surfing"
                label = "Not surfing"
                if subscription_expired and (
                    not reason or "subscription" not in reason.lower()
                ):
                    reason = _period_blocked_reason(customer)
            else:
                state = "disconnected"
                label = "Disconnected"
                if not reason:
                    reason = router_error or "Device not seen on the Hotspot network"
        elif subscription_expired:
            # Package ended — Internet column shows Expired (even if still dialed).
            state = "expired"
            label = "Expired"
            if not reason or "subscription" not in reason.lower():
                reason = _period_blocked_reason(customer)
        elif not session_online:
            # No live PPPoE session — show Disconnected in the Internet column.
            state = "disconnected"
            label = "Disconnected"
            if not reason:
                reason = router_error or "Router not dialed — no active PPPoE session"
        else:
            # Dialed on the NAS but not getting internet (blocked, outside period, …).
            state = "not_surfing"
            label = "Not surfing"

        connected_router_name = ""
        connected_wifi_ssid = ""
        connection_label = "Disconnected" if service == "hotspot" else "Not connected"
        if connected:
            connected_count += 1
            live_router = (
                routers_by_id.get(connected_router_id)
                if connected_router_id
                else None
            )
            if live_router is None and customer.router_id:
                live_router = routers_by_id.get(customer.router_id) or customer.router
            connected_router_name = (
                (getattr(live_router, "name", None) or "").strip() or "MikroTik"
            )
            connected_wifi_ssid = (getattr(live_router, "wifi_ssid", None) or "").strip()
            if service == "hotspot":
                connection_label = connected_router_name
                connection_reason = (
                    f"Connected to {connected_router_name}"
                    + (f" · {connected_wifi_ssid}" if connected_wifi_ssid else "")
                )
            else:
                connection_label = "Connected"
                connection_reason = "Active PPPoE session"
        clients_payload.append(
            {
                "id": customer.pk,
                "full_name": customer.full_name or "",
                "account_number": customer.account_number or "",
                "plan_name": customer.plan.name if customer.plan_id else "",
                "service_type": customer.service_type,
                "url": reverse(
                    "core:client_detail", kwargs={"customer_id": customer.pk}
                ),
                "surfing": surfing,
                "state": state,
                "label": label,
                "reason": reason,
                "internet_allowed": internet_allowed,
                "session_online": session_online,
                "router_reachable": not router_unreachable,
                "connected": connected,
                "connection_label": connection_label,
                "connection_reason": connection_reason,
                "connected_router_name": connected_router_name,
                "connected_wifi_ssid": connected_wifi_ssid,
            }
        )

    if surfing_customers:
        try:
            from billing.vouchers import invalidate_vouchers_for_surfing_customers

            invalidate_vouchers_for_surfing_customers(surfing_customers)
        except Exception:
            pass

    payload = {
        "ok": True,
        "service": service,
        "clients": clients_payload,
        "surfing_count": surfing_count,
        "connected_count": connected_count,
        "checked": len(clients_payload),
    }
    cache.set(cache_key, payload, 8)
    return JsonResponse(payload)


@client_workspace_required
def _redirect_to_router_access(request, *, settings_name: str):
    """Send legacy /app/pppoe-hotspot/ links to the first onboarded router."""
    org = resolve_organization(request.user, request)
    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect("core:mikrotik")
    router = (
        MikroTikRouter.objects.filter(organization=org)
        .order_by("id")
        .only("id", "name")
        .first()
    )
    if not router:
        messages.info(
            request,
            "Onboard a MikroTik router first — PPPoE and Hotspot settings live on each router page.",
        )
        return redirect("core:mikrotik")
    return redirect(settings_name, router_id=router.pk)


@client_workspace_required
def pppoe_hotspot_redirect(request):
    return _redirect_to_router_access(request, settings_name="core:mikrotik_pppoe_settings")


@client_workspace_required
def pppoe_settings_redirect(request):
    return _redirect_to_router_access(request, settings_name="core:mikrotik_pppoe_settings")


@client_workspace_required
def hotspot_settings_redirect(request):
    return _redirect_to_router_access(request, settings_name="core:mikrotik_hotspot_settings")


def _pppoe_push_messages(request, result: dict, *, enabled: bool, saved: bool = False) -> None:
    prefix = "Settings saved. " if saved else ""
    if result.get("skipped"):
        messages.info(
            request,
            f"{prefix}{result.get('message') or 'Router is offline — PPPoE push skipped.'}",
        )
        return
    if not result.get("ok"):
        messages.warning(
            request,
            f"{prefix}{result.get('error') or 'Could not push PPPoE settings to this router.'}",
        )
        return
    secrets = int(result.get("secrets_synced") or 0)
    secret_bit = (
        f" Synced {secrets} PPPoE login{'s' if secrets != 1 else ''}."
        if secrets
        else " No registered PPPoE clients to sync yet."
    )
    name = result.get("router_name") or "router"
    if enabled:
        messages.success(
            request,
            (
                f"{prefix}PPPoE enforcement pushed to {name}.{secret_bit} "
                "Unregistered devices fall back to the Hotspot payment portal."
            ),
        )
        hotspot = result.get("hotspot") or {}
        if hotspot.get("skipped"):
            messages.warning(
                request,
                hotspot.get("message")
                or "Hotspot fallback was skipped because the router is offline.",
            )
        elif hotspot and not hotspot.get("ok"):
            messages.warning(
                request,
                hotspot.get("error")
                or "PPPoE enforcement is on, but Hotspot fallback could not be pushed.",
            )
        if result.get("portal_base_is_loopback"):
            messages.warning(
                request,
                "PUBLIC_BASE_URL is localhost — phones on Hotspot Wi‑Fi cannot reach the "
                "payment page. Set PUBLIC_BASE_URL to a LAN/public URL reachable from clients.",
            )
        else:
            from core.hotspot_portal import (
                public_base_url,
                unreachable_base_url_reason,
            )

            unreachable = unreachable_base_url_reason(public_base_url(request))
            if unreachable:
                messages.warning(request, unreachable)
    else:
        messages.success(
            request,
            f"{prefix}PPPoE server and logins pushed to {name}.{secret_bit}",
        )


@client_workspace_required
def mikrotik_pppoe_settings(request, router_id: int):
    org, router = get_org_router(request, router_id)
    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect("core:mikrotik")
    if not router:
        messages.error(request, "Router not found.")
        return redirect("core:mikrotik")

    employee = getattr(request.user, "employee_profile", None)
    viewing_client = bool(employee and is_viewing_as_client(request, employee))
    can_edit = bool(org.owner_id == request.user.id or viewing_client)
    pppoe_compulsory = bool(org.pppoe_compulsory)

    if request.method == "POST" and can_edit:
        action = (request.POST.get("action") or "save_policy").strip()
        if action == "push_policy":
            enabled = bool(org.pppoe_compulsory)
            router_pk = router.pk

            def _bg_push(pk: int = router_pk, compulsory: bool = enabled):
                live = MikroTikRouter.objects.select_related("organization").get(pk=pk)
                return apply_pppoe_enforcement_on_router(live, compulsory=compulsory)

            set_job(router_pk, "pppoe_push", "pending")
            schedule_mikrotik_job(
                _bg_push,
                name=f"pppoe-push-{router_pk}",
                router_id=router_pk,
                job_type="pppoe_push",
            )
            messages.success(
                request,
                f"Pushing PPPoE policy to {router.name} in the background. "
                "Refresh this page in a minute if clients are still catching up.",
            )
            return redirect("core:mikrotik_pppoe_settings", router_id=router.pk)

        form = PppoeSettingsForm(request.POST, instance=org)
        if form.is_valid():
            form.save()
            org.refresh_from_db()
            enabled = bool(form.cleaned_data.get("pppoe_compulsory"))
            router_pk = router.pk

            def _bg_save_push(pk: int = router_pk, compulsory: bool = enabled):
                live = MikroTikRouter.objects.select_related("organization").get(pk=pk)
                return apply_pppoe_enforcement_on_router(live, compulsory=compulsory)

            set_job(router_pk, "pppoe_push", "pending")
            schedule_mikrotik_job(
                _bg_save_push,
                name=f"pppoe-save-{router_pk}",
                router_id=router_pk,
                job_type="pppoe_push",
            )
            if enabled:
                messages.success(
                    request,
                    "PPPoE enforcement enabled. Pushing to this MikroTik in the background — "
                    "paid PPPoE clients will surf automatically; other devices use Hotspot.",
                )
            else:
                messages.success(
                    request,
                    "PPPoE enforcement disabled. Updating this MikroTik in the background.",
                )
            return redirect("core:mikrotik_pppoe_settings", router_id=router.pk)
    else:
        form = PppoeSettingsForm(instance=org) if can_edit else None

    pppoe_eligible_count = Customer.objects.filter(
        organization=org,
        service_type=Customer.ServiceType.PPPOE,
    ).exclude(pppoe_username="").count()

    blocked_count = 0
    if pppoe_compulsory:
        blocked_count = (
            Customer.objects.filter(organization=org)
            .exclude(service_type=Customer.ServiceType.PPPOE)
            .count()
            + Customer.objects.filter(
                organization=org,
                service_type=Customer.ServiceType.PPPOE,
                pppoe_username="",
            ).count()
        )

    detail_nav = build_mikrotik_detail_nav(
        router,
        clean_uplink_enabled=bool(router.clean_uplink_enabled),
        is_suspended=router.account_status == MikroTikRouter.AccountStatus.SUSPENDED,
        include_modals=False,
    )
    ctx = client_page_context(
        request,
        active_nav="mikrotik_detail",
        sidebar_active="pppoe_hotspot_settings",
        page_title=f"{router.name} — PPPoE & Hotspot",
        page_kicker="Access",
        page_subtitle=f"PPPoE enforcement and client logins for {router.name}.",
        form=form,
        can_edit=can_edit,
        organization=org,
        pppoe_compulsory=pppoe_compulsory,
        pppoe_eligible_count=pppoe_eligible_count,
        blocked_count=blocked_count,
        access_settings_tab="pppoe",
    )
    return render(
        request,
        "core/pppoe_settings.html",
        apply_mikrotik_detail_sidebar(ctx, router, detail_nav=detail_nav),
    )


@client_workspace_required
def mikrotik_hotspot_settings(request, router_id: int):
    org, router = get_org_router(request, router_id)
    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect("core:mikrotik")
    if not router:
        messages.error(request, "Router not found.")
        return redirect("core:mikrotik")

    employee = getattr(request.user, "employee_profile", None)
    viewing_client = bool(employee and is_viewing_as_client(request, employee))
    can_edit = bool(org.owner_id == request.user.id or viewing_client)

    from core.hotspot_portal import hotspot_portal_urls

    def _portal_urls_for(organization):
        return hotspot_portal_urls(organization.join_code, request)

    def _push_one(result: dict, *, enabled: bool, saved: bool = False) -> None:
        prefix = "Settings saved. " if saved else ""
        if result.get("skipped"):
            messages.info(
                request,
                f"{prefix}{result.get('message') or 'Router is offline — Hotspot push skipped.'}",
            )
            return
        if not result.get("ok"):
            messages.warning(
                request,
                f"{prefix}{result.get('error') or 'Could not push Hotspot to this router.'}",
            )
            return
        users = int(result.get("users_synced") or 0)
        user_bit = (
            f" Synced {users} Hotspot login{'s' if users != 1 else ''}."
            if users
            else " No Hotspot clients to sync yet."
        )
        name = result.get("router_name") or router.name
        if enabled:
            messages.success(
                request,
                (
                    f"{prefix}Hotspot pushed to {name}.{user_bit} "
                    "Connecting to Wi‑Fi should open the payment/login page."
                ),
            )
            notes = " ".join(str(n) for n in (result.get("notes") or []))
            if "payment login page was not installed" in notes:
                messages.warning(
                    request,
                    "Payment page could not be downloaded onto the router. "
                    "Set PUBLIC_BASE_URL to this PC’s LAN IP, restart the server, then push again.",
                )
        else:
            messages.success(request, f"{prefix}Hotspot removed from {name}.")

    if request.method == "POST" and can_edit:
        action = (request.POST.get("action") or "save_settings").strip()
        urls = _portal_urls_for(org)

        if action == "push_hotspot":
            enabled = bool(org.hotspot_enabled)
            redirect_url = (org.hotspot_redirect_url or "").strip()
            if enabled and org.hotspot_use_welcome_page:
                redirect_url = urls["welcome_url"]
                if org.hotspot_redirect_url != redirect_url:
                    org.hotspot_redirect_url = redirect_url
                    org.save(update_fields=["hotspot_redirect_url"])
            router_pk = router.pk
            org_pk = org.pk
            push_urls = {
                "redirect_url": redirect_url if enabled else "",
                "login_url": urls["login_url"] if enabled else "",
                "alogin_url": urls["alogin_url"] if enabled else "",
                "pay_url": urls["pay_url"] if enabled else "",
                "welcome_url": urls["welcome_url"] if enabled else "",
            }

            def _bg_hotspot_push(
                r_pk: int = router_pk,
                o_pk: int = org_pk,
                on: bool = enabled,
                portal: dict = push_urls,
            ):
                live_router = MikroTikRouter.objects.select_related(
                    "organization"
                ).get(pk=r_pk)
                live_org = Organization.objects.get(pk=o_pk)
                return apply_hotspot_on_router(
                    live_router,
                    enabled=on,
                    organization=live_org,
                    redirect_url=portal.get("redirect_url") or "",
                    login_url=portal.get("login_url") or "",
                    alogin_url=portal.get("alogin_url") or "",
                    pay_url=portal.get("pay_url") or "",
                    welcome_url=portal.get("welcome_url") or "",
                )

            set_job(router_pk, "hotspot_push", "pending")
            schedule_mikrotik_job(
                _bg_hotspot_push,
                name=f"hotspot-push-{router_pk}",
                router_id=router_pk,
                job_type="hotspot_push",
            )
            messages.success(
                request,
                (
                    f"{'Pushing Hotspot to' if enabled else 'Removing Hotspot from'} "
                    f"{router.name} in the background."
                ),
            )
            if enabled and org.pppoe_compulsory:
                messages.info(
                    request,
                    "PPPoE enforcement stays on: dialed PPPoE clients keep internet; "
                    "other devices must log in via Hotspot.",
                )
            if enabled and urls.get("base_is_loopback"):
                messages.warning(
                    request,
                    "PUBLIC_BASE_URL is localhost — phones on Hotspot Wi‑Fi cannot reach it. "
                    "Set PUBLIC_BASE_URL to this PC’s Hotspot LAN IP (e.g. http://10.10.0.168:8000) "
                    "and run: python manage.py runserver 0.0.0.0:8000",
                )
            elif enabled and urls.get("base_unreachable_reason"):
                messages.warning(request, urls["base_unreachable_reason"])
            return redirect("core:mikrotik_hotspot_settings", router_id=router.pk)

        form = HotspotSettingsForm(request.POST, instance=org)
        if form.is_valid():
            org = form.save(commit=False)
            urls = _portal_urls_for(org)
            if org.hotspot_use_welcome_page:
                org.hotspot_redirect_url = urls["welcome_url"]
            org.save()
            enabled = bool(org.hotspot_enabled)
            router_pk = router.pk
            org_pk = org.pk
            push_urls = {
                "redirect_url": org.hotspot_redirect_url if enabled else "",
                "login_url": urls["login_url"] if enabled else "",
                "alogin_url": urls["alogin_url"] if enabled else "",
                "pay_url": urls["pay_url"] if enabled else "",
                "welcome_url": urls["welcome_url"] if enabled else "",
            }

            def _bg_hotspot_save(
                r_pk: int = router_pk,
                o_pk: int = org_pk,
                on: bool = enabled,
                portal: dict = push_urls,
            ):
                live_router = MikroTikRouter.objects.select_related(
                    "organization"
                ).get(pk=r_pk)
                live_org = Organization.objects.get(pk=o_pk)
                return apply_hotspot_on_router(
                    live_router,
                    enabled=on,
                    organization=live_org,
                    redirect_url=portal.get("redirect_url") or "",
                    login_url=portal.get("login_url") or "",
                    alogin_url=portal.get("alogin_url") or "",
                    pay_url=portal.get("pay_url") or "",
                    welcome_url=portal.get("welcome_url") or "",
                )

            set_job(router_pk, "hotspot_push", "pending")
            schedule_mikrotik_job(
                _bg_hotspot_save,
                name=f"hotspot-save-{router_pk}",
                router_id=router_pk,
                job_type="hotspot_push",
            )
            messages.success(
                request,
                (
                    f"Settings saved. {'Pushing Hotspot to' if enabled else 'Removing Hotspot from'} "
                    f"{router.name} in the background."
                ),
            )
            if enabled and org.pppoe_compulsory:
                messages.info(
                    request,
                    "PPPoE enforcement stays on: dialed PPPoE clients keep internet; "
                    "other devices must log in via Hotspot.",
                )
            if enabled and urls.get("base_is_loopback"):
                messages.warning(
                    request,
                    "PUBLIC_BASE_URL is localhost — phones on Hotspot Wi‑Fi cannot reach it. "
                    "Set PUBLIC_BASE_URL to this PC’s Hotspot LAN IP "
                    "(e.g. http://10.10.0.168:8000) and run: "
                    "python manage.py runserver 0.0.0.0:8000",
                )
            elif enabled and urls.get("base_unreachable_reason"):
                messages.warning(request, urls["base_unreachable_reason"])
            return redirect("core:mikrotik_hotspot_settings", router_id=router.pk)
    else:
        form = HotspotSettingsForm(instance=org) if can_edit else None

    if form is not None:
        hotspot_enabled = bool(form["hotspot_enabled"].value())
        use_welcome_page = bool(form["hotspot_use_welcome_page"].value())
    else:
        hotspot_enabled = bool(org.hotspot_enabled)
        use_welcome_page = bool(org.hotspot_use_welcome_page)

    urls = _portal_urls_for(org)
    hotspot_client_count = Customer.objects.filter(
        organization=org,
        service_type=Customer.ServiceType.HOTSPOT,
    ).count()

    detail_nav = build_mikrotik_detail_nav(
        router,
        clean_uplink_enabled=bool(router.clean_uplink_enabled),
        is_suspended=router.account_status == MikroTikRouter.AccountStatus.SUSPENDED,
        include_modals=False,
    )
    ctx = client_page_context(
        request,
        active_nav="mikrotik_detail",
        sidebar_active="pppoe_hotspot_settings",
        page_title=f"{router.name} — PPPoE & Hotspot",
        page_kicker="Access",
        page_subtitle=f"Hotspot portal, payment page, and voucher defaults for {router.name}.",
        form=form,
        can_edit=can_edit,
        organization=org,
        hotspot_enabled=hotspot_enabled,
        use_welcome_page=use_welcome_page,
        hotspot_client_count=hotspot_client_count,
        welcome_page_url=urls["welcome_url"],
        welcome_page_path=urls["welcome_path"],
        pay_page_url=urls["pay_url"],
        pay_page_path=urls["pay_path"],
        portal_base_is_loopback=bool(urls.get("base_is_loopback")),
        portal_base_unreachable=urls.get("base_unreachable_reason") or "",
        router_count=1,
        pppoe_compulsory=bool(org.pppoe_compulsory),
        access_settings_tab="hotspot",
    )
    return render(
        request,
        "core/hotspot_settings.html",
        apply_mikrotik_detail_sidebar(ctx, router, detail_nav=detail_nav),
    )


def _payment_phone_autofill(phone: str) -> str:
    """Format a stored phone for the M-Pesa input (prefer 07xxxxxxxx)."""
    from billing.services import normalize_kenya_msisdn

    raw = (phone or "").strip()
    msisdn = normalize_kenya_msisdn(raw)
    if msisdn.startswith("254") and len(msisdn) == 12:
        return f"0{msisdn[3:]}"
    return raw


def _find_hotspot_customer_for_mac(org, mac: str):
    from billing.devices import find_hotspot_customer_for_mac

    return find_hotspot_customer_for_mac(org, mac, active_only=True)


def _ensure_customer_plan_in_list(org, plans, customer):
    """
    Keep the customer's previous package selectable and first in the list.

    Returns the plan list only (callers that also need the selected id should
    use ``_plans_with_customer_default``).
    """
    plans, _selected = _plans_with_customer_default(org, plans, customer)
    return plans


_DURATION_ORDER = {
    value: index for index, (value, _label) in enumerate(BillingPlan.Duration.choices)
}


def _sort_plans_by_duration(plans):
    """Stable order for pay-page category rows (duration, then price, then name)."""
    return sorted(
        list(plans or []),
        key=lambda plan: (
            _DURATION_ORDER.get(getattr(plan, "duration", "") or "", 99),
            getattr(plan, "price", 0) or 0,
            (getattr(plan, "name", "") or "").lower(),
        ),
    )


def _plans_with_customer_default(org, plans, customer):
    """
    Resolve which previous package to pre-select.

    Inactive previous packages stay available for renew when no active twin
    exists; otherwise the matching active twin is preferred so payment works.
    Plans are returned sorted by duration for category rows on the pay page.
    """
    plans = list(plans or [])
    if customer is None:
        return _sort_plans_by_duration(plans), None
    current_plan_id = getattr(customer, "plan_id", None)
    if not current_plan_id:
        return _sort_plans_by_duration(plans), None

    def _ensure_present(plan_id: int) -> bool:
        return any(plan.pk == plan_id for plan in plans)

    if _ensure_present(current_plan_id):
        return _sort_plans_by_duration(plans), current_plan_id

    current = BillingPlan.objects.filter(
        pk=current_plan_id, organization=org
    ).first()
    if current is None:
        return _sort_plans_by_duration(plans), None

    chosen = current
    if not current.is_active:
        twin = (
            BillingPlan.objects.filter(
                organization=org,
                is_active=True,
                service_type=current.service_type,
                name=current.name,
            )
            .order_by("id")
            .first()
        )
        if twin is None:
            twin = (
                BillingPlan.objects.filter(
                    organization=org,
                    is_active=True,
                    service_type=current.service_type,
                    price=current.price,
                    download_speed_mbps=current.download_speed_mbps,
                    upload_speed_mbps=current.upload_speed_mbps,
                )
                .order_by("id")
                .first()
            )
        if twin is not None:
            chosen = twin

    if not _ensure_present(chosen.pk):
        plans.append(chosen)
    return _sort_plans_by_duration(plans), chosen.pk


def _attach_plan_portal_images(plans, request=None):
    """Expose a same-origin image URL on each plan for portal/pay cards."""
    for plan in plans or []:
        image_url = ""
        image = getattr(plan, "image", None)
        if image:
            try:
                rel = image.url or ""
            except Exception:
                rel = ""
            if rel:
                image_url = rel
                if request is not None:
                    try:
                        # Use the host the browser already opened (127.0.0.1 or
                        # LAN), not PUBLIC_BASE_URL which can point at an
                        # unbound auto-detected IP and break <img> loads.
                        image_url = request.build_absolute_uri(rel)
                    except Exception:
                        image_url = rel
        plan.portal_image_url = image_url
    return plans


def _attach_plan_offer_progress(plans, customer=None):
    from billing.package_offers import attach_offer_progress_to_plans

    return attach_offer_progress_to_plans(plans, customer)


def _resolve_payable_plan(org, *, plan_id, service_type: str, customer=None):
    """
    Load a plan the customer may pay for.

    Active packages are always allowed. The customer's own previous package is
    also allowed even if staff deactivated it, so renew keeps working.
    """
    try:
        plan_pk = int(plan_id)
    except (TypeError, ValueError):
        return None
    plan = (
        BillingPlan.objects.filter(
            pk=plan_pk,
            organization=org,
            service_type=service_type,
        )
        .first()
    )
    if plan is None:
        return None
    if plan.is_active:
        return plan
    if customer is not None and getattr(customer, "plan_id", None) == plan.pk:
        return plan
    return None


def _hotspot_portal_context(org, *, mikrotik_login: bool = False, request=None):
    from core.hotspot_portal import hotspot_portal_urls, public_absolute_url

    urls = hotspot_portal_urls(org.join_code, request)
    title = (org.hotspot_portal_title or "").strip() or f"{org.name} Wi‑Fi"
    message = (org.hotspot_login_message or "").strip() or (
        "Choose a package and pay with M-Pesa. This device will connect automatically."
    )
    has_mpesa = bool(org.mpesa_payment_type and org.mpesa_number)
    stk_ready = bool(org.effective_daraja_credentials().get("ready"))

    link_login = ""
    link_orig = ""
    hotspot_mac = ""
    error = ""
    if request is not None:
        link_login = (request.GET.get("link-login-only") or request.GET.get("link_login_only") or "").strip()
        link_orig = (request.GET.get("dst") or request.GET.get("link-orig") or "").strip()
        hotspot_mac = _resolve_request_hotspot_mac(org, request)
        error = (request.GET.get("error") or "").strip()
        if link_login:
            mikrotik_login = True

    from billing.services import plans_for_router
    from core.mikrotik_connect import find_hotspot_router_for_mac

    # Customer + bound router first (DB only). Live NAS MAC→router scan is a
    # last resort — it was the main multi-second cost on every pay-page open.
    hotspot_customer = _find_hotspot_customer_for_mac(org, hotspot_mac)
    portal_router = getattr(hotspot_customer, "router", None)
    if hotspot_mac and portal_router is None:
        portal_router = find_hotspot_router_for_mac(org, hotspot_mac)
    hotspot_plans = list(
        plans_for_router(
            org, portal_router, service_type=BillingPlan.ServiceType.HOTSPOT
        )[:40]
    )
    hotspot_plans, hotspot_selected_plan_id = _plans_with_customer_default(
        org, hotspot_plans, hotspot_customer
    )
    plans = hotspot_plans
    has_payable_plans = bool(hotspot_plans)

    hotspot_start = public_absolute_url(
        reverse("core:hotspot_payment_start", kwargs={"join_code": org.join_code}),
        request,
    )
    # Hotspot pay URL is Hotspot-only. PPPoE renew uses /pppoe/<join>/pay/?t=…
    portal_mode = "hotspot"
    hotspot_phone = _payment_phone_autofill(
        getattr(hotspot_customer, "phone", "") if hotspot_customer else ""
    )
    _attach_plan_portal_images(hotspot_plans, request)
    _attach_plan_offer_progress(hotspot_plans, hotspot_customer)
    preview_mode = ""
    if request is not None:
        preview_mode = (request.GET.get("preview") or "").strip().lower()
    # Staff Wi‑Fi preview can force FRANCIS-style account even without a MAC.
    if preview_mode and hotspot_customer is None and request is not None:
        account = (request.GET.get("account") or "").strip()
        if account:
            hotspot_customer = (
                Customer.objects.filter(
                    organization=org,
                    account_number__iexact=account,
                )
                .select_related("plan", "router")
                .first()
            )
    access_ctx = customer_portal_access_context(
        hotspot_customer, preview=preview_mode
    )
    if access_ctx["subscription_paused"]:
        title = f"{org.name} — Internet paused"
        message = access_ctx["access_banner_message"]
    setup_hint = ""
    if not has_payable_plans:
        if not bool(getattr(org, "hotspot_enabled", True)):
            setup_hint = (
                f"{org.name} has Hotspot turned off in System settings. "
                "Turn it on and add Hotspot packages so clients can pay here."
            )
        else:
            setup_hint = (
                f"No Hotspot packages are available yet. Ask {org.name}"
                + (
                    f" ({org.phone})"
                    if getattr(org, "phone", None)
                    else ""
                )
                + " to add packages, or open Billing → Plans."
            )
    elif not stk_ready and not has_mpesa:
        setup_hint = (
            f"M-Pesa is not set up for {org.name} yet. "
            "Configure Paybill/Till or Daraja STK under System settings."
        )
    return {
        "organization": org,
        "org_name": org.name,
        "page_title": title,
        "page_message": message,
        "has_mpesa": has_mpesa,
        "stk_ready": stk_ready,
        "mpesa_type": org.mpesa_payment_type,
        "mpesa_number": org.mpesa_number,
        "mpesa_account": org.mpesa_account,
        "plans": plans,
        "hotspot_plans": hotspot_plans,
        "pppoe_plans": [],
        "has_payable_plans": has_payable_plans,
        "portal_mode": portal_mode,
        "portal_setup_hint": setup_hint,
        "show_payment_form": (
            (bool(hotspot_mac) or (stk_ready and bool(hotspot_plans)))
            and access_ctx["show_renew_payment"]
        ),
        "mikrotik_login": mikrotik_login,
        "link_login": link_login,
        "link_orig": link_orig or urls["welcome_url"],
        "hotspot_mac": hotspot_mac,
        "payment_start_url": hotspot_start,
        "hotspot_payment_start_url": hotspot_start,
        "voucher_redeem_url": public_absolute_url(
            reverse("core:hotspot_voucher_redeem", kwargs={"join_code": org.join_code}),
            request,
        ),
        "welcome_url": urls["welcome_url"],
        "error": error,
        "pppoe_option_available": False,
        "pppoe_pay_url": "",
        "pppoe_payment_start_url": "",
        "pppoe_require_account_lookup": False,
        "pppoe_account_locked": False,
        "pppoe_customer_token": "",
        "pppoe_customer_name": "",
        "pppoe_account_number": "",
        "pppoe_phone_value": "",
        "pppoe_selected_plan_id": None,
        "pppoe_package_end": None,
        "pppoe_identify_error": "",
        "hotspot_option_available": True,
        "hotspot_ssids": [],
        "require_account_lookup": False,
        "customer_token": "",
        "customer_name": (
            getattr(hotspot_customer, "full_name", "") if hotspot_customer else ""
        ),
        "account_number": (
            getattr(hotspot_customer, "account_number", "") if hotspot_customer else ""
        ),
        "phone_value": hotspot_phone,
        "selected_plan_id": hotspot_selected_plan_id,
        "package_end": (
            getattr(hotspot_customer, "package_end", None) if hotspot_customer else None
        ),
        "identify_error": "",
        "dual_access_tabs": False,
        "hotspot_phone_value": hotspot_phone,
        "hotspot_selected_plan_id": hotspot_selected_plan_id,
        **access_ctx,
    }


def _normalize_hotspot_mac(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if len(compact) != 12:
        return ""
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).upper()


def _resolve_request_hotspot_mac(org, request) -> str:
    """
    Best-effort device MAC for captive Hotspot payment.

    Prefer query/cookie values from RouterOS redirects; fall back to looking the
    client IP up on the organization's Hotspot NAS tables.
    """
    if request is None:
        return ""
    candidates = [
        request.GET.get("mac") or "",
        request.POST.get("mac") or "",
        request.COOKIES.get("hs_mac") or "",
    ]
    for raw in candidates:
        mac = _normalize_hotspot_mac(raw)
        if mac:
            remote = (request.META.get("REMOTE_ADDR") or "").strip()
            if remote:
                try:
                    from core.mikrotik_connect import remember_hotspot_mac_for_ip

                    remember_hotspot_mac_for_ip(org, remote, mac)
                except Exception:
                    pass
            return mac
    remote = (request.META.get("REMOTE_ADDR") or "").strip()
    if not remote:
        return ""
    try:
        from core.mikrotik_connect import find_hotspot_mac_for_ip

        return _normalize_hotspot_mac(find_hotspot_mac_for_ip(org, remote) or "")
    except Exception:
        return ""


def _prefetch_daraja_oauth(organization) -> None:
    """Warm Daraja OAuth off the request so Pay click skips a cold token fetch."""
    org_pk = getattr(organization, "pk", None)
    if not org_pk:
        return

    def _warm(pk: int = org_pk) -> None:
        try:
            from accounts.models import Organization
            from accounts.mpesa_daraja import get_access_token

            org = Organization.objects.filter(pk=pk).first()
            if org is None:
                return
            creds = org.effective_daraja_credentials()
            if not creds.get("ready"):
                return
            get_access_token(
                consumer_key=creds["consumer_key"],
                consumer_secret=creds["consumer_secret"],
                environment=creds.get("environment") or "sandbox",
            )
        except Exception:
            pass

    schedule_mikrotik_job(_warm, name=f"prefetch-daraja-{org_pk}")


def _set_hotspot_mac_cookie(response, mac: str):
    mac = _normalize_hotspot_mac(mac)
    if not mac or response is None:
        return response
    response.set_cookie(
        "hs_mac",
        mac,
        max_age=60 * 60 * 24,
        samesite="Lax",
        httponly=False,
    )
    return response


def _set_pppoe_account_cookie(response, token: str):
    token = (token or "").strip()
    if not token or response is None:
        return response
    response.set_cookie(
        "pppoe_pay",
        token,
        max_age=60 * 60 * 24 * 30,
        samesite="Lax",
        httponly=True,
    )
    return response


def _set_pppoe_account_hint_cookie(response, account_number: str):
    """
    Remember the account number on this browser for the next renew visit.

    Readable by the page so the field can autofill even when the signed token
    cookie is missing and the PPP IP could not be matched yet.
    """
    account_number = (account_number or "").strip()
    if not account_number or response is None:
        return response
    response.set_cookie(
        "pppoe_acct",
        account_number[:64],
        max_age=60 * 60 * 24 * 30,
        samesite="Lax",
        httponly=False,
    )
    return response


def _make_pppoe_customer_token(org, customer) -> str:
    if customer is None or org is None:
        return ""
    return signing.dumps(
        {"cid": customer.pk, "org": org.pk, "mode": "pppoe"},
        salt="pppoe-payment",
        compress=True,
    )


@require_POST
def hotspot_voucher_redeem(request, join_code: str):
    """Redeem a paid Hotspot voucher and authorize this device."""
    from billing.vouchers import redeem_access_voucher

    org = get_object_or_404(Organization, join_code=join_code)
    mac = _resolve_request_hotspot_mac(org, request)
    code = (request.POST.get("voucher_code") or request.POST.get("code") or "").strip()
    customer = _find_hotspot_customer_for_mac(org, mac) if mac else None
    result = redeem_access_voucher(
        organization=org,
        code=code,
        customer=customer,
        mac=mac,
    )
    if not result.get("ok"):
        return JsonResponse(result, status=400)
    remote = (request.META.get("REMOTE_ADDR") or "").strip()
    if remote:
        try:
            from core.mikrotik_connect import invalidate_captive_redirect_cache

            invalidate_captive_redirect_cache(remote)
        except Exception:
            pass
    if result.get("stk_id"):
        access_token = signing.dumps(
            {
                "stk": result["stk_id"],
                "org": org.pk,
                "mac": mac or "",
            },
            salt="hotspot-payment-status",
            compress=True,
        )
        result["status_token"] = access_token
        result["welcome_url"] = reverse(
            "core:hotspot_welcome", kwargs={"join_code": join_code}
        )
    return JsonResponse(result)


@require_POST
def pppoe_voucher_redeem(request, join_code: str):
    """Redeem a paid PPPoE voucher and restore the subscription."""
    from billing.vouchers import redeem_access_voucher

    org = get_object_or_404(Organization, join_code=join_code)
    code = (request.POST.get("voucher_code") or request.POST.get("code") or "").strip()
    customer = None
    token = (request.POST.get("customer_token") or "").strip()
    if token:
        customer = _find_pppoe_customer_from_token(org, token)
    if customer is None:
        customer = _find_pppoe_customer_for_pay(
            org,
            account_number=request.POST.get("account_number") or "",
            phone=request.POST.get("phone") or "",
        )
    if customer is None:
        remote = (request.META.get("REMOTE_ADDR") or "").strip()
        if remote:
            customer = find_pppoe_customer_for_ip(org, remote)
    result = redeem_access_voucher(
        organization=org,
        code=code,
        customer=customer,
    )
    if not result.get("ok"):
        return JsonResponse(result, status=400)
    remote = (request.META.get("REMOTE_ADDR") or "").strip()
    if remote:
        try:
            from core.mikrotik_connect import invalidate_captive_redirect_cache

            invalidate_captive_redirect_cache(remote)
        except Exception:
            pass
    return JsonResponse(result)


@require_POST
def hotspot_payment_start(request, join_code: str):
    """Start public M-Pesa payment for a captive device; no Hotspot password."""
    from accounts.security import AuthRateLimitExceeded, assert_public_pay_allowed, record_auth_failure
    from billing.devices import resolve_or_create_hotspot_customer
    from billing.stk import start_subscription_stk_payment

    try:
        assert_public_pay_allowed(request, join_code)
    except AuthRateLimitExceeded as exc:
        from accounts.audit import record_audit

        record_audit(
            action="stk_rate_limit",
            request=request,
            target=f"hotspot:{join_code}",
            detail={"retry_after": exc.retry_after},
        )
        return JsonResponse(
            {"ok": False, "error": "Too many payment attempts. Try again later."},
            status=429,
        )
    record_auth_failure("stk_start_ip", request, limit=12, window=900)
    if join_code:
        record_auth_failure(
            "stk_start_code", request, identifier=join_code, limit=20, window=900
        )

    org = get_object_or_404(Organization, join_code=join_code)
    mac = _resolve_request_hotspot_mac(org, request)
    if not mac:
        return JsonResponse(
            {"ok": False, "error": "Could not identify this device. Rejoin the Hotspot and try again."},
            status=400,
        )

    existing_hotspot = _find_hotspot_customer_for_mac(org, mac)
    phone = (request.POST.get("phone") or "").strip()
    if existing_hotspot is None and phone:
        from billing.devices import find_hotspot_customer_by_phone

        existing_hotspot = find_hotspot_customer_by_phone(org, phone)
    plan = _resolve_payable_plan(
        org,
        plan_id=request.POST.get("plan_id"),
        service_type=BillingPlan.ServiceType.HOTSPOT,
        customer=existing_hotspot,
    )
    if plan is None:
        return JsonResponse(
            {"ok": False, "error": "That package is not available."},
            status=404,
        )
    active_routers = MikroTikRouter.objects.filter(
        organization=org,
        account_status=MikroTikRouter.AccountStatus.ACTIVE,
    ).order_by("id")
    from core.mikrotik_connect import find_hotspot_router_for_mac

    # Bind the payment to the NAS that actually intercepted this MAC. Using the
    # first organization router attached paid clients to stale router records.
    router = find_hotspot_router_for_mac(org, mac) or active_routers.first()
    if router is None:
        return JsonResponse(
            {"ok": False, "error": "No active Hotspot router is available."},
            status=400,
        )
    if not plan.is_available_on_router(router):
        return JsonResponse(
            {
                "ok": False,
                "error": "That package is not available on this Hotspot router.",
            },
            status=400,
        )

    resolved = resolve_or_create_hotspot_customer(
        org, mac=mac, phone=phone, plan=plan, router=router
    )
    if not resolved.get("ok"):
        return JsonResponse(
            {"ok": False, "error": resolved.get("error") or "Could not start payment."},
            status=int(resolved.get("status") or 400),
        )
    customer = resolved["customer"]

    if customer_package_is_paused(customer):
        return JsonResponse(
            {
                "ok": False,
                "error": (
                    "This subscription is paused. Contact your internet provider "
                    "to resume service before paying."
                ),
            },
            status=403,
        )

    from billing.devices import customer_owns_hotspot_mac
    from billing.vouchers import customer_unused_voucher_count

    unused_vouchers = customer_unused_voucher_count(customer)
    extra_device = not customer_owns_hotspot_mac(customer, mac)
    if (
        resolved.get("already_paid")
        and extra_device
        and (resolved.get("needs_voucher") or unused_vouchers > 0)
    ):
        return JsonResponse(
            {
                "ok": True,
                "already_paid": True,
                "needs_voucher": True,
                "attached": False,
                "authorized": False,
                "remaining_vouchers": unused_vouchers,
                "message": (
                    "This package is already paid. Enter a voucher code for this "
                    "device to connect. A used voucher cannot be reused."
                ),
            }
        )

    # Extra device joining a live package (cash / unlimited): authorize without charging again.
    if resolved.get("attached") and resolved.get("already_paid"):
        provision = {"ok": False, "allowed": False}
        try:
            from core.subscription_sync import enqueue_customer_subscription_sync

            provision = (
                enqueue_customer_subscription_sync(
                    customer.pk,
                    True,
                    wait_first=True,
                    quick=True,
                    reauthenticate=False,
                )
                or provision
            )
        except Exception:
            pass
        return JsonResponse(
            {
                "ok": True,
                "already_paid": True,
                "attached": True,
                "authorized": bool(provision.get("ok") and provision.get("allowed")),
                "message": "This device was added to your package.",
                "welcome_url": reverse(
                    "core:hotspot_welcome", kwargs={"join_code": join_code}
                ),
            }
        )

    result = start_subscription_stk_payment(
        organization=org,
        customer=customer,
        phone=phone,
        plan=plan,
        request=request,
    )
    if not result.get("ok"):
        return JsonResponse(result, status=400)

    access_token = signing.dumps(
        {"stk": result["stk_id"], "org": org.pk, "mac": mac},
        salt="hotspot-payment-status",
        compress=True,
    )
    result["status_url"] = reverse(
        "core:hotspot_payment_status",
        kwargs={"join_code": join_code, "stk_id": result["stk_id"]},
    )
    result["status_token"] = access_token
    return JsonResponse(result)


@require_GET
def hotspot_payment_status(request, join_code: str, stk_id: int):
    """Return payment state and provision MAC access when payment succeeds."""
    from billing.models import StkPushRequest
    from billing.stk import refresh_stk_status

    org = get_object_or_404(Organization, join_code=join_code)
    try:
        payload = signing.loads(
            request.GET.get("token") or "",
            salt="hotspot-payment-status",
            max_age=60 * 60 * 24,
        )
    except signing.BadSignature:
        return JsonResponse({"ok": False, "error": "Invalid payment session."}, status=403)
    if payload.get("stk") != stk_id or payload.get("org") != org.pk:
        return JsonResponse({"ok": False, "error": "Invalid payment session."}, status=403)

    stk = get_object_or_404(
        StkPushRequest.objects.select_related(
            "customer",
            "customer__organization",
            "customer__router",
            "customer__plan",
        ),
        pk=stk_id,
        organization=org,
    )
    from billing.devices import customer_owns_hotspot_mac

    if not customer_owns_hotspot_mac(stk.customer, payload.get("mac") or ""):
        return JsonResponse({"ok": False, "error": "Invalid payment session."}, status=403)
    wait_for_nas = (request.GET.get("nas") or "1").strip().lower() not in {
        "0",
        "false",
        "no",
    }
    result = refresh_stk_status(stk, wait_for_nas=wait_for_nas)
    return JsonResponse(result)


def hotspot_welcome(request, join_code: str):
    """Public post-login landing page shown after Hotspot authentication."""
    org = get_object_or_404(Organization, join_code=join_code)
    title = (org.hotspot_welcome_title or "").strip() or "You're online"
    message = (org.hotspot_welcome_message or "").strip() or (
        f"Welcome to {org.name}. Your internet session is active — continue browsing."
    )
    button_label = (org.hotspot_welcome_button_label or "").strip() or "Continue browsing"
    # Prefer the org's configured link; otherwise use an HTTP connectivity check
    # so captive browsers can leave the portal and start surfing immediately.
    button_url = (org.hotspot_welcome_button_url or "").strip() or "http://neverssl.com/"
    logo_url = ""
    if org.profile_photo:
        from core.hotspot_portal import public_absolute_url

        logo_url = public_absolute_url(org.profile_photo.url, request)

    activation_url = ""
    stk_id = (request.GET.get("stk") or "").strip()
    token = (request.GET.get("token") or "").strip()
    if stk_id.isdigit() and token:
        activation_url = (
            reverse(
                "core:hotspot_payment_activate",
                kwargs={"join_code": join_code, "stk_id": int(stk_id)},
            )
            + "?"
            + urlencode({"token": token})
        )

    return render(
        request,
        "core/hotspot_welcome.html",
        {
            "organization": org,
            "org_name": org.name,
            "org_initial": (org.name[:1] or "H").upper(),
            "page_title": title,
            "page_message": message,
            "button_label": button_label,
            "button_url": button_url,
            "logo_url": logo_url,
            "activation_url": activation_url,
            "paid": bool(stk_id and token),
        },
    )


@csrf_exempt
@require_POST
def hotspot_payment_activate(request, join_code: str, stk_id: int):
    """
    Authorize / reauthenticate a paid MAC after payment success.

    Waits for one quick MikroTik restore so the welcome page can show Connected
    only after the NAS allows surfing. A background follow-up finishes CPE work.
    """
    from billing.models import StkPushRequest
    from core.subscription_sync import (
        enqueue_customer_subscription_sync,
        nas_access_ready,
    )

    org = get_object_or_404(Organization, join_code=join_code)
    try:
        payload = signing.loads(
            request.GET.get("token") or "",
            salt="hotspot-payment-status",
            max_age=60 * 60 * 24,
        )
    except signing.BadSignature:
        return JsonResponse({"ok": False, "error": "Invalid payment session."}, status=403)
    if payload.get("stk") != stk_id or payload.get("org") != org.pk:
        return JsonResponse({"ok": False, "error": "Invalid payment session."}, status=403)

    stk = get_object_or_404(
        StkPushRequest.objects.select_related("customer", "customer__organization"),
        pk=stk_id,
        organization=org,
        status=StkPushRequest.Status.SUCCESS,
        subscription_applied=True,
    )
    from billing.devices import customer_owns_hotspot_mac

    if not customer_owns_hotspot_mac(stk.customer, payload.get("mac") or ""):
        return JsonResponse({"ok": False, "error": "Invalid payment session."}, status=403)

    nas = (
        enqueue_customer_subscription_sync(
            stk.customer_id,
            True,
            wait_first=True,
            quick=True,
            reauthenticate=True,
        )
        or {}
    )
    authorized = nas_access_ready(nas)
    return JsonResponse(
        {
            "ok": True,
            "authorized": authorized,
            "queued": False,
            "can_retry_authorize": not authorized,
            "offline": bool(nas.get("offline")),
            "message": (
                "Surfing allowed on MikroTik."
                if authorized
                else (nas.get("message") or "Waiting for MikroTik to allow surfing.")
            ),
        }
    )


def _pppoe_pay_url_for_customer(customer, request=None) -> str:
    """Canonical PPPoE pay URL with signed account token."""
    from core.hotspot_portal import public_absolute_url
    from core.mikrotik_connect import _pppoe_pay_portal_url

    org = getattr(customer, "organization", None)
    if org is None or not getattr(org, "join_code", None):
        return ""
    # Prefer absolute public URL (same as CPE / captive redirects).
    url = _pppoe_pay_portal_url(org, customer=customer)
    if url and url.startswith("http"):
        return url
    path = reverse("core:pppoe_pay", kwargs={"join_code": org.join_code})
    token = _make_pppoe_customer_token(org, customer)
    if token:
        from urllib.parse import urlencode

        path = f"{path}?{urlencode({'t': token})}"
    if request is not None:
        return public_absolute_url(path, request)
    return path


def _hotspot_pay_url_for_org(org, request=None) -> str:
    """Canonical Hotspot pay URL for an organization."""
    from core.hotspot_portal import public_absolute_url

    if org is None or not getattr(org, "join_code", None):
        return ""
    path = reverse("core:hotspot_pay", kwargs={"join_code": org.join_code})
    if request is not None:
        return public_absolute_url(path, request)
    return path


def _redirect_pay_preserving_query(request, view_name: str, join_code: str):
    """302 to the other pay UI while keeping query (mac, t, account, …)."""
    path = reverse(view_name, kwargs={"join_code": join_code})
    qs = (request.META.get("QUERY_STRING") or "").strip()
    if qs:
        path = f"{path}?{qs}"
    return redirect(path)


def hotspot_pay(request, join_code: str):
    """Public Hotspot payment page (captive redirect target + preview)."""
    org = get_object_or_404(Organization, join_code=join_code)
    remote = (request.META.get("REMOTE_ADDR") or "").strip()
    # Pool mismatch guard: PPPoE / CPE-renew clients must not stick on Hotspot UI.
    try:
        from core.mikrotik_connect import is_cpe_renew_pool_ip, is_pppoe_pool_ip

        if is_pppoe_pool_ip(remote) or is_cpe_renew_pool_ip(remote):
            return _redirect_pay_preserving_query(
                request, "core:pppoe_pay", join_code
            )
    except Exception:
        pass
    context = _hotspot_portal_context(org, mikrotik_login=False, request=request)
    hotspot_mac = (context.get("hotspot_mac") or "").strip().upper()
    hotspot_customer = (
        _find_hotspot_customer_for_mac(org, hotspot_mac) if hotspot_mac else None
    )
    if hotspot_mac:
        from billing.services import customer_can_surf_via_hotspot

        if not (
            hotspot_customer is not None
            and customer_can_surf_via_hotspot(hotspot_customer)
        ):
            mac_for_job = hotspot_mac
            customer_pk = getattr(hotspot_customer, "pk", None)

            def _block_unpaid_mac(
                org_pk=org.pk,
                mac=mac_for_job,
                customer_id=customer_pk,
            ) -> None:
                from accounts.models import Organization
                from billing.models import Customer
                from core.mikrotik_connect import block_hotspot_mac_until_paid

                organization = Organization.objects.filter(pk=org_pk).first()
                if organization is None:
                    return
                customer = None
                if customer_id:
                    customer = Customer.objects.filter(pk=customer_id).first()
                block_hotspot_mac_until_paid(organization, mac, customer=customer)

            schedule_mikrotik_job(
                _block_unpaid_mac,
                name=f"hotspot-block-{hotspot_mac[-8:]}",
            )
    _prefetch_daraja_oauth(org)
    response = render(request, "core/hotspot_pay.html", context)
    response = _set_hotspot_mac_cookie(response, context.get("hotspot_mac") or "")
    token = (context.get("pppoe_customer_token") or context.get("customer_token") or "").strip()
    account = (
        context.get("pppoe_account_number") or context.get("account_number") or ""
    ).strip()
    if token:
        response = _set_pppoe_account_cookie(response, token)
    if account and context.get("portal_mode") == "pppoe":
        response = _set_pppoe_account_hint_cookie(response, account)
    return response


def _pppoe_portal_context(org, request, customer=None, identify_error: str = ""):
    from core.hotspot_portal import hotspot_portal_urls, public_absolute_url

    urls = hotspot_portal_urls(org.join_code, request)
    from billing.services import plans_for_router

    customer_router = getattr(customer, "router", None) if customer else None
    pppoe_plans = list(
        plans_for_router(
            org, customer_router, service_type=BillingPlan.ServiceType.PPPOE
        )[:40]
    )
    # Router-scoped plans with no links match every NAS; when a customer is tied
    # to one router but every plan is scoped elsewhere, still show org packages.
    if not pppoe_plans and customer_router is not None:
        pppoe_plans = list(
            plans_for_router(
                org, None, service_type=BillingPlan.ServiceType.PPPOE
            )[:40]
        )
    pppoe_plans, pppoe_selected_plan_id = _plans_with_customer_default(
        org, pppoe_plans, customer
    )
    _attach_plan_portal_images(pppoe_plans, request)
    _attach_plan_offer_progress(pppoe_plans, customer)
    hotspot_enabled = bool(getattr(org, "hotspot_enabled", False))
    hotspot_plans: list = []
    if hotspot_enabled:
        hotspot_plans = list(
            plans_for_router(
                org, customer_router, service_type=BillingPlan.ServiceType.HOTSPOT
            )[:40]
        )
        if not hotspot_plans and customer_router is not None:
            hotspot_plans = list(
                plans_for_router(
                    org, None, service_type=BillingPlan.ServiceType.HOTSPOT
                )[:40]
            )
        hotspot_plans = _sort_plans_by_duration(hotspot_plans)
        _attach_plan_portal_images(hotspot_plans, request)
        _attach_plan_offer_progress(hotspot_plans, customer)
    # Identified home customers renew PPPoE only; unidentified CPE visitors
    # also see Hotspot packages on this page.
    show_inline_hotspot = hotspot_enabled and bool(hotspot_plans) and customer is None
    plans = pppoe_plans or hotspot_plans
    has_payable_plans = bool(pppoe_plans or hotspot_plans)
    has_mpesa = bool(org.mpesa_payment_type and org.mpesa_number)
    stk_ready = bool(org.effective_daraja_credentials().get("ready"))
    customer_token = ""
    if customer is not None:
        customer_token = _make_pppoe_customer_token(org, customer)
    preview_mode = ""
    if request is not None:
        preview_mode = (request.GET.get("preview") or "").strip().lower()
    access_ctx = customer_portal_access_context(customer, preview=preview_mode)
    page_title = f"{org.name} renew"
    page_message = (
        "Your subscription has ended. Choose a package and pay with M-Pesa "
        "to restore internet on this connection."
    )
    if access_ctx["subscription_paused"]:
        page_title = f"{org.name} — Internet paused"
        page_message = access_ctx["access_banner_message"]
    show_payment_form = has_payable_plans and access_ctx["show_renew_payment"]
    stk_payment_available = stk_ready and access_ctx["show_renew_payment"]
    # Prefer a clear ISP-setup hint over a look-up error when nothing is payable.
    setup_hint = ""
    if not pppoe_plans and not show_inline_hotspot:
        setup_hint = (
            f"No PPPoE packages are available yet. Ask {org.name}"
            + (f" ({org.phone})" if getattr(org, "phone", None) else "")
            + " to add packages under Billing → Plans."
        )
        if not stk_ready and not has_mpesa:
            setup_hint += (
                " M-Pesa / Daraja STK is also not set up for this ISP yet."
            )
    elif pppoe_plans and not stk_ready and not has_mpesa:
        setup_hint = (
            f"M-Pesa is not set up for {org.name} yet. "
            "Configure Paybill/Till or Daraja STK under System settings."
        )
    # Don't scold the client for a missing match when the ISP has nothing to sell.
    if setup_hint and not pppoe_plans:
        identify_error = ""
    pppoe_start = public_absolute_url(
        reverse("core:pppoe_payment_start", kwargs={"join_code": org.join_code}),
        request,
    )
    hotspot_start = public_absolute_url(
        reverse("core:hotspot_payment_start", kwargs={"join_code": org.join_code}),
        request,
    )
    # PPPoE renew by default; Hotspot packages follow on the same page when enabled.
    portal_mode = "pppoe"
    phone_value = _payment_phone_autofill(
        getattr(customer, "phone", "") if customer else ""
    )
    hotspot_mac = ""
    if request is not None and show_inline_hotspot:
        hotspot_mac = _resolve_request_hotspot_mac(org, request) or ""
    hotspot_pay_url = urls.get("pay_url") or "" if hotspot_enabled else ""
    return {
        "organization": org,
        "org_name": org.name,
        "page_title": page_title,
        "page_message": page_message,
        "has_mpesa": has_mpesa,
        "stk_ready": stk_ready,
        "mpesa_type": org.mpesa_payment_type,
        "mpesa_number": org.mpesa_number,
        "mpesa_account": org.mpesa_account,
        "plans": plans,
        "hotspot_plans": hotspot_plans,
        "pppoe_plans": pppoe_plans,
        "has_payable_plans": has_payable_plans,
        "show_inline_hotspot": show_inline_hotspot,
        "portal_mode": portal_mode,
        "portal_setup_hint": setup_hint,
        "show_payment_form": show_payment_form,
        "stk_payment_available": stk_payment_available,
        "require_account_lookup": customer is None,
        "customer_token": customer_token,
        "customer_name": getattr(customer, "full_name", "") if customer else "",
        "account_number": getattr(customer, "account_number", "") if customer else "",
        "package_end": getattr(customer, "package_end", None) if customer else None,
        "phone_value": phone_value,
        "selected_plan_id": pppoe_selected_plan_id,
        "payment_start_url": pppoe_start,
        "pppoe_payment_start_url": pppoe_start,
        "hotspot_payment_start_url": hotspot_start,
        "voucher_redeem_url": public_absolute_url(
            reverse("core:pppoe_voucher_redeem", kwargs={"join_code": org.join_code}),
            request,
        ),
        "hotspot_voucher_redeem_url": public_absolute_url(
            reverse("core:hotspot_voucher_redeem", kwargs={"join_code": org.join_code}),
            request,
        ),
        "welcome_url": urls["welcome_url"],
        "identify_error": identify_error,
        "error": "",
        "hotspot_mac": hotspot_mac,
        "mikrotik_login": False,
        "hotspot_option_available": hotspot_enabled and bool(hotspot_pay_url or show_inline_hotspot),
        "hotspot_pay_url": hotspot_pay_url if not show_inline_hotspot else "",
        "hotspot_ssids": [],
        "pppoe_option_available": True,
        "pppoe_pay_url": "",
        "pppoe_require_account_lookup": customer is None,
        "pppoe_account_locked": customer is not None,
        "pppoe_customer_token": customer_token,
        "pppoe_customer_name": getattr(customer, "full_name", "") if customer else "",
        "pppoe_account_number": getattr(customer, "account_number", "") if customer else "",
        "pppoe_phone_value": phone_value,
        "pppoe_selected_plan_id": pppoe_selected_plan_id,
        "pppoe_package_end": getattr(customer, "package_end", None) if customer else None,
        "pppoe_identify_error": identify_error,
        "dual_access_tabs": False,
        "hotspot_phone_value": phone_value,
        "hotspot_selected_plan_id": None,
        **access_ctx,
    }


def _find_pppoe_customer_from_token(org, token: str):
    """Resolve a PPPoE customer from a signed renew-page token (CPE Wi‑Fi URL)."""
    token = (token or "").strip()
    if not token:
        return None
    try:
        payload = signing.loads(
            token,
            salt="pppoe-payment",
            max_age=60 * 60 * 24 * 30,
        )
    except signing.BadSignature:
        return None
    if payload.get("org") != org.pk or payload.get("mode") != "pppoe":
        return None
    customer_id = payload.get("cid")
    if not customer_id:
        return None
    return (
        Customer.objects.filter(
            pk=customer_id,
            organization=org,
            service_type=Customer.ServiceType.PPPOE,
        )
        .select_related("plan", "organization", "router")
        .first()
    )


def _find_pppoe_customer_for_pay(org, *, account_number: str = "", phone: str = ""):
    """Resolve a PPPoE customer by account number, username, or phone when IP match fails."""
    from billing.services import normalize_kenya_msisdn

    account_number = (account_number or "").strip()
    phone = (phone or "").strip()
    if not account_number and not phone:
        return None
    qs = Customer.objects.filter(
        organization=org,
        service_type=Customer.ServiceType.PPPOE,
        status=Customer.Status.ACTIVE,
    ).select_related("plan", "organization", "router")

    def match_by_phone(raw: str):
        raw = (raw or "").strip()
        if not raw:
            return None
        msisdn = normalize_kenya_msisdn(raw)
        candidates = list(qs.exclude(phone="").order_by("id")[:500])
        for row in candidates:
            if normalize_kenya_msisdn(row.phone or "") == msisdn:
                return row
            stored = (row.phone or "").strip()
            if stored and stored == raw:
                return row
        return None

    if account_number:
        match = qs.filter(account_number__iexact=account_number).order_by("id").first()
        if match is not None:
            return match
        # PPPoE username is often the same as the account / phone on the CPE.
        match = (
            qs.filter(pppoe_username__iexact=account_number).order_by("id").first()
        )
        if match is not None:
            return match
        # Allow phone typed into the account field.
        match = match_by_phone(account_number)
        if match is not None:
            return match
    if phone:
        return match_by_phone(phone)
    return None


def pppoe_pay(request, join_code: str):
    """Public renew page for expired PPPoE sessions (dst-nat captive target)."""
    org = get_object_or_404(Organization, join_code=join_code)
    remote = (request.META.get("REMOTE_ADDR") or "").strip()
    # Pool mismatch guard: dedicated Hotspot clients must not stick on PPPoE UI.
    try:
        from core.mikrotik_connect import is_hotspot_pool_ip

        if is_hotspot_pool_ip(remote):
            return _redirect_pay_preserving_query(
                request, "core:hotspot_pay", join_code
            )
    except Exception:
        pass
    customer = find_pppoe_customer_for_ip(org, remote)
    identify_error = ""
    if customer is None:
        # CPE Wi‑Fi renew popup installs a signed token so the account for the
        # connected router is filled without needing a 10.20.0.x pool IP.
        customer = _find_pppoe_customer_from_token(org, request.GET.get("t") or "")
    if customer is None:
        # Same browser returning to renew — reuse the last matched account.
        customer = _find_pppoe_customer_from_token(
            org, request.COOKIES.get("pppoe_pay") or ""
        )
    if customer is None:
        # Soft account hint cookie (set on a previous successful match).
        customer = _find_pppoe_customer_for_pay(
            org,
            account_number=request.COOKIES.get("pppoe_acct") or "",
        )
    if customer is None:
        # Staff / shared renew links can pass account or phone in the query.
        customer = _find_pppoe_customer_for_pay(
            org,
            account_number=request.GET.get("account") or "",
            phone=request.GET.get("phone") or "",
        )
    if customer is None:
        identify_error = (
            "Could not auto-match this connection. Enter your account number "
            "or phone number to pay and restore internet."
        )
    context = _pppoe_portal_context(
        org, request, customer=customer, identify_error=identify_error
    )
    _prefetch_daraja_oauth(org)
    response = render(request, "core/pppoe_pay.html", context)
    response = _set_hotspot_mac_cookie(response, context.get("hotspot_mac") or "")
    if customer is not None:
        response = _set_pppoe_account_cookie(
            response, context.get("customer_token") or ""
        )
        response = _set_pppoe_account_hint_cookie(
            response, getattr(customer, "account_number", "") or ""
        )
        if remote:
            try:
                from core.mikrotik_connect import remember_pppoe_customer_session_ip

                remember_pppoe_customer_session_ip(customer, remote)
            except Exception:
                pass
    return response


@require_POST
def pppoe_payment_start(request, join_code: str):
    """Start M-Pesa STK Push for an identified PPPoE customer."""
    from accounts.security import AuthRateLimitExceeded, assert_public_pay_allowed, record_auth_failure
    from billing.stk import start_subscription_stk_payment

    try:
        assert_public_pay_allowed(request, join_code)
    except AuthRateLimitExceeded as exc:
        from accounts.audit import record_audit

        record_audit(
            action="stk_rate_limit",
            request=request,
            target=f"pppoe:{join_code}",
            detail={"retry_after": getattr(exc, "retry_after", 900)},
        )
        return JsonResponse(
            {"ok": False, "error": "Too many payment attempts. Try again later."},
            status=429,
        )
    record_auth_failure("stk_start_ip", request, limit=12, window=900)
    if join_code:
        record_auth_failure(
            "stk_start_code", request, identifier=join_code, limit=20, window=900
        )

    org = get_object_or_404(Organization, join_code=join_code)
    customer = None
    token = (request.POST.get("customer_token") or "").strip()
    if token:
        try:
            payload = signing.loads(
                token,
                salt="pppoe-payment",
                max_age=60 * 60 * 24 * 30,
            )
        except signing.BadSignature:
            return JsonResponse(
                {
                    "ok": False,
                    "error": "Payment session expired. Reload the page and try again.",
                },
                status=400,
            )
        if payload.get("org") != org.pk or payload.get("mode") != "pppoe":
            return JsonResponse(
                {"ok": False, "error": "Invalid payment session."}, status=400
            )
        customer = get_object_or_404(
            Customer.objects.select_related("plan", "organization", "router"),
            pk=payload.get("cid"),
            organization=org,
            service_type=Customer.ServiceType.PPPOE,
        )
    else:
        customer = _find_pppoe_customer_for_pay(
            org,
            account_number=request.POST.get("account_number") or "",
            phone=request.POST.get("phone") or "",
        )
        if customer is None:
            return JsonResponse(
                {
                    "ok": False,
                    "error": (
                        "Could not find this PPPoE account. Check the account "
                        "number or phone number on the account."
                    ),
                },
                status=404,
            )

    if customer.status != Customer.Status.ACTIVE:
        return JsonResponse(
            {
                "ok": False,
                "error": (
                    "This PPPoE account is suspended. Contact your internet "
                    "provider before making a payment."
                ),
            },
            status=403,
        )
    if customer_package_is_paused(customer):
        return JsonResponse(
            {
                "ok": False,
                "error": (
                    "This subscription is paused. Contact your internet provider "
                    "to resume service before paying."
                ),
            },
            status=403,
        )
    plan = _resolve_payable_plan(
        org,
        plan_id=request.POST.get("plan_id"),
        service_type=BillingPlan.ServiceType.PPPOE,
        customer=customer,
    )
    if plan is None:
        return JsonResponse(
            {"ok": False, "error": "That package is not available."},
            status=404,
        )
    if customer.router_id and not plan.is_available_on_router(customer.router):
        return JsonResponse(
            {
                "ok": False,
                "error": "That package is not available on this client’s MikroTik.",
            },
            status=400,
        )
    phone = (request.POST.get("phone") or "").strip() or (customer.phone or "")

    result = start_subscription_stk_payment(
        organization=org,
        customer=customer,
        phone=phone,
        plan=plan,
        request=request,
    )
    if not result.get("ok"):
        return JsonResponse(result, status=400)

    access_token = signing.dumps(
        {"stk": result["stk_id"], "org": org.pk, "cid": customer.pk, "mode": "pppoe"},
        salt="pppoe-payment-status",
        compress=True,
    )
    result["status_url"] = reverse(
        "core:pppoe_payment_status",
        kwargs={"join_code": join_code, "stk_id": result["stk_id"]},
    )
    result["status_token"] = access_token
    # Some Android captive WebViews ignore or abort the page's submit
    # listener and perform a normal HTML form POST. Returning JSON in that
    # case leaves the customer staring at the raw STK response. Keep JSON for
    # fetch(), but send a normal form submission to an HTML polling page.
    if "application/json" not in (request.headers.get("Accept") or ""):
        return redirect(
            result["status_url"]
            + "?"
            + urlencode({"token": access_token, "view": "page"})
        )
    return JsonResponse(result)


@require_GET
def pppoe_payment_status(request, join_code: str, stk_id: int):
    """Return PPPoE renewal state and restore surfing when payment succeeds."""
    from billing.models import StkPushRequest
    from billing.stk import refresh_stk_status

    org = get_object_or_404(Organization, join_code=join_code)
    try:
        payload = signing.loads(
            request.GET.get("token") or "",
            salt="pppoe-payment-status",
            max_age=60 * 60 * 24,
        )
    except signing.BadSignature:
        return JsonResponse({"ok": False, "error": "Invalid payment session."}, status=403)
    if (
        payload.get("stk") != stk_id
        or payload.get("org") != org.pk
        or payload.get("mode") != "pppoe"
    ):
        return JsonResponse({"ok": False, "error": "Invalid payment session."}, status=403)

    stk = get_object_or_404(
        StkPushRequest.objects.select_related(
            "customer",
            "customer__organization",
            "customer__router",
        ),
        pk=stk_id,
        organization=org,
        customer_id=payload.get("cid"),
    )
    wait_for_nas = (request.GET.get("nas") or "1").strip().lower() not in {
        "0",
        "false",
        "no",
    }
    result = refresh_stk_status(stk, wait_for_nas=wait_for_nas)
    if request.GET.get("view") == "page":
        customer = stk.customer
        customer.refresh_from_db()
        try:
            tries = int(request.GET.get("tries") or 0)
        except (TypeError, ValueError):
            tries = 0
        waiting = bool(result.get("pending"))
        authorizing = bool(result.get("success") and not result.get("authorized"))
        voucher_fallback = bool(
            result.get("success")
            and not result.get("authorized")
            and not result.get("surfing")
            and (result.get("voucher_code") or result.get("voucher_redeemable"))
            and tries >= 2
        )
        if voucher_fallback:
            authorizing = False
        params = request.GET.copy()
        params["tries"] = str(tries + 1)
        refresh_url = request.path + "?" + params.urlencode()
        return render(
            request,
            "core/pppoe_payment_result.html",
            {
                "organization": org,
                "result": result,
                "customer": customer,
                "plan_name": getattr(getattr(customer, "plan", None), "name", ""),
                "waiting": waiting,
                "authorizing": authorizing,
                "voucher_fallback": voucher_fallback,
                "auto_refresh": waiting or authorizing,
                "refresh_url": refresh_url,
                "retry_url": reverse(
                    "core:pppoe_pay", kwargs={"join_code": org.join_code}
                ),
                "voucher_url": reverse(
                    "core:pppoe_pay", kwargs={"join_code": org.join_code}
                ),
                "continue_url": (
                    (org.hotspot_welcome_button_url or "").strip()
                    or "http://neverssl.com/"
                ),
                "continue_label": (
                    (org.hotspot_welcome_button_label or "").strip()
                    or "Continue browsing"
                ),
            },
        )
    return JsonResponse(result)


def hotspot_portal_login_page(request, join_code: str):
    """
    Legacy MikroTik login.html preview — use the Hotspot pay page.

    Captive clients and new installs should target hotspot_pay directly.
    """
    return redirect("core:hotspot_pay", join_code=join_code)


def hotspot_alogin_page(request, join_code: str):
    """
    HTML fetched onto MikroTik hotspot/alogin.html after login.

    Redirects the client browser to the organization welcome page.
    """
    org = get_object_or_404(Organization, join_code=join_code)
    from core.hotspot_portal import hotspot_portal_urls

    urls = hotspot_portal_urls(org.join_code, request)
    return render(
        request,
        "core/hotspot_alogin.html",
        {
            "organization": org,
            "org_name": org.name,
            "welcome_url": urls["welcome_url"],
        },
        content_type="text/html; charset=utf-8",
    )


@client_workspace_required
@require_POST
def save_owner_profile(request):
    """Save login profile from the Edit profile popup (available on any /app page)."""
    org = resolve_organization(request.user, request)
    next_url = (request.POST.get("next") or "").strip() or reverse("core:my_account")
    if not next_url.startswith("/"):
        next_url = reverse("core:my_account")

    if not org or org.owner_id != request.user.id:
        messages.error(request, "You can only edit your own login profile here.")
        return redirect(next_url)

    form = OwnerProfileForm(request.POST, user=request.user, organization=org)
    if form.is_valid():
        form.save()
        if form.cleaned_data.get("password1"):
            update_session_auth_hash(request, request.user)
            messages.success(request, "Profile and password updated.")
        else:
            messages.success(request, "Profile details updated.")
        return redirect(next_url)

    messages.error(request, "Could not save profile. Check the highlighted fields.")
    gateway = PaymentGateway.get_solo() if org else None
    return render(
        request,
        "core/my_account.html",
        client_page_context(
            request,
            active_nav="account",
            sidebar_active="account_profile",
            page_title="Company profile",
            page_kicker="My account",
            page_subtitle="Update your login profile and company details.",
            form=OrganizationEditForm(
                instance=org, section=OrganizationEditForm.SECTION_PROFILE
            )
            if org
            else None,
            can_edit=bool(org and org.owner_id == request.user.id),
            can_edit_profile=True,
            owner_profile_form=form,
            open_owner_profile_modal=True,
            platform_gateway=gateway,
            platform_gateway_ready=bool(gateway and gateway.is_stk_ready()),
            daraja_status=org.effective_daraja_credentials() if org else None,
            receive_type=(org.mpesa_payment_type if org else "") or "",
        ),
    )


def _owner_profile_form(user, organization, data=None, *, id_prefix="owner"):
    kwargs = {
        "user": user,
        "organization": organization,
        "id_prefix": id_prefix,
        "initial": {
            "username": organization.login_code if organization else "",
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
        },
    }
    if data is not None:
        return OwnerProfileForm(data, **kwargs)
    return OwnerProfileForm(**kwargs)


def _account_profile_user(request, org):
    """User whose login code and password are edited on the account page."""
    if not org:
        return None
    if org.owner_id == request.user.id:
        return request.user
    employee = getattr(request.user, "employee_profile", None)
    if employee and is_viewing_as_client(request, employee):
        return org.owner
    return None


def _account_org_context(request, org):
    employee = getattr(request.user, "employee_profile", None)
    viewing_client = bool(employee and is_viewing_as_client(request, employee))
    can_edit = bool(org and (org.owner_id == request.user.id or viewing_client))
    profile_user = _account_profile_user(request, org)
    can_edit_profile = profile_user is not None
    platform_gateway = PaymentGateway.get_solo() if org else None
    return {
        "can_edit": can_edit,
        "can_edit_profile": can_edit_profile,
        "platform_gateway": platform_gateway,
        "platform_gateway_ready": bool(
            platform_gateway and platform_gateway.is_stk_ready()
        ),
        "daraja_status": org.effective_daraja_credentials() if org else None,
        "receive_type": (org.mpesa_payment_type if org else "") or "",
        "open_owner_profile_modal": (request.GET.get("edit") or "").strip().lower()
        in {"1", "profile", "true"},
    }


def _save_account_section(request, org, *, section, success_url_name, success_messages=None):
    """Validate and save one OrganizationEditForm section. Returns (form, redirect_or_none)."""
    form = OrganizationEditForm(
        request.POST, request.FILES, instance=org, section=section
    )
    if not form.is_valid():
        return form, None
    org = form.save()
    if success_messages:
        for message in success_messages(org):
            messages.success(request, message)
    else:
        messages.success(request, "Account details updated.")
    return form, redirect(success_url_name)


@client_workspace_required
def my_account(request):
    """Company profile page — login + company details in one form."""
    org = resolve_organization(request.user, request)
    extra = _account_org_context(request, org)
    can_edit = extra["can_edit"]
    can_edit_profile = extra["can_edit_profile"]
    profile_user = _account_profile_user(request, org)
    form = (
        OrganizationEditForm(instance=org, section=OrganizationEditForm.SECTION_PROFILE)
        if org and can_edit
        else None
    )
    account_profile_form = (
        _owner_profile_form(profile_user, org, id_prefix="account")
        if can_edit_profile and profile_user
        else None
    )
    account_editing = False

    if request.method == "POST" and org and (can_edit or can_edit_profile):
        action = (request.POST.get("action") or "").strip()
        if action == "save_account":
            account_editing = True
            org_ok = True
            profile_ok = True
            if can_edit:
                form = OrganizationEditForm(
                    request.POST,
                    request.FILES,
                    instance=org,
                    section=OrganizationEditForm.SECTION_PROFILE,
                )
                org_ok = form.is_valid()
            if can_edit_profile and profile_user:
                account_profile_form = _owner_profile_form(
                    profile_user, org, request.POST, id_prefix="account"
                )
                profile_ok = account_profile_form.is_valid()

            if org_ok and profile_ok:
                saved_profile = False
                saved_password = False
                saved_company = False
                if can_edit and form is not None:
                    form.save()
                    saved_company = True
                if can_edit_profile and account_profile_form is not None:
                    account_profile_form.save()
                    saved_profile = True
                    if (
                        account_profile_form.cleaned_data.get("password1")
                        and profile_user
                        and profile_user.pk == request.user.pk
                    ):
                        update_session_auth_hash(request, request.user)
                        saved_password = True
                if saved_profile and saved_company and saved_password:
                    messages.success(
                        request, "Profile, password, and company details saved."
                    )
                elif saved_profile and saved_company:
                    messages.success(request, "Profile and company details saved.")
                elif saved_profile and saved_password:
                    messages.success(request, "Profile and password updated.")
                elif saved_profile:
                    messages.success(request, "Profile details updated.")
                else:
                    messages.success(request, "Company profile updated.")
                return redirect("core:my_account")
    elif (request.GET.get("edit") or "").strip().lower() in {
        "1",
        "profile",
        "true",
        "edit",
    }:
        account_editing = bool(can_edit or can_edit_profile)

    # Page uses inline edit mode; keep the topbar modal closed here.
    extra["open_owner_profile_modal"] = False

    return render(
        request,
        "core/my_account.html",
        client_page_context(
            request,
            active_nav="account",
            sidebar_active="account_profile",
            page_title="Company profile",
            page_kicker="My account",
            page_subtitle="Update your login profile and company details shown across your workspace.",
            form=form,
            account_profile_form=account_profile_form,
            account_editing=account_editing,
            **extra,
        ),
    )


@client_workspace_required
def my_account_payments(request):
    """Packages and payment status overview."""
    # Lazy import avoids circular dependency with billing.views.
    from billing.views import (
        _handle_delete_package,
        _handle_edit_package,
        _handle_package_offer,
        _handle_register_package,
        _handle_suspend_package,
    )

    org = resolve_organization(request.user, request)
    extra = _account_org_context(request, org)
    success_url = "core:my_account_payments"

    package_form, open_modal, early = _handle_register_package(
        request, org, success_url_name=success_url
    )
    if early:
        return early

    edit_form, edit_modal, early = _handle_edit_package(
        request, org, success_url_name=success_url
    )
    if early:
        return early
    if edit_modal:
        open_modal = edit_modal

    early = _handle_package_offer(request, org, success_url_name=success_url)
    if early:
        return early

    early = _handle_suspend_package(request, org, success_url_name=success_url)
    if early:
        return early

    early = _handle_delete_package(request, org, success_url_name=success_url)
    if early:
        return early

    package_list = list(
        BillingPlan.objects.filter(organization=org)
        .annotate(
            customer_count=Count("customers"),
            stk_count=Count("stk_push_requests"),
        )
        .prefetch_related("routers")
        .order_by("service_type", "price", "name")
        if org
        else BillingPlan.objects.none()
    )
    pppoe_packages = [p for p in package_list if p.service_type == BillingPlan.ServiceType.PPPOE]
    hotspot_packages = [
        p for p in package_list if p.service_type == BillingPlan.ServiceType.HOTSPOT
    ]

    return render(
        request,
        "core/my_account_payments.html",
        client_page_context(
            request,
            active_nav="account",
            sidebar_active="account_payments",
            page_title="Packages",
            page_kicker="My account",
            page_subtitle="Manage internet packages for this organization.",
            packages=package_list,
            pppoe_packages=pppoe_packages,
            hotspot_packages=hotspot_packages,
            package_count=len(package_list),
            pppoe_package_count=len(pppoe_packages),
            hotspot_package_count=len(hotspot_packages),
            package_form=package_form,
            package_edit_form=edit_form,
            open_billing_modal=open_modal,
            **extra,
        ),
    )


@client_workspace_required
def leads(request):
    org = resolve_organization(request.user, request)
    # Open = NEW with no ISP yet (visible to every company).
    # Allocated open/closed = assigned to THIS company only after successful payment.
    customer_qs = (
        Customer.objects.select_related(
            "organization",
            "plan",
            "registered_by",
            "assigned_technician",
            "assigned_technician__user",
        )
        .filter(
            Q(status=Customer.Status.NEW, organization__isnull=True)
            | Q(status__in=Customer.ALLOCATED_STATUSES, organization=org)
        )
        .order_by("-created_at")
        if org
        else Customer.objects.none()
    )
    customers = list(customer_qs[:200])
    pay_phone = (org.phone if org else "") or ""
    for customer in customers:
        if customer.status != Customer.Status.NEW:
            customer.allocation_amount_display = ""
            continue
        fee = resolve_lead_allocation_fee(organization=org, customer=customer)
        customer.allocation_amount_display = (
            fee.get("amount_display") if fee.get("ok") else ""
        )
        customer.allocation_fee_error = "" if fee.get("ok") else (fee.get("error") or "")

    technicians = []
    if org:
        technicians = list(
            Employee.objects.filter(
                role=Employee.Role.TECHNICIAN,
                status=Employee.Status.ACTIVE,
            )
            .filter(Q(organization=org) | Q(organization__isnull=True))
            .select_related("user", "organization")
            .order_by(
                "organization_id",
                "user__first_name",
                "user__last_name",
                "user__username",
            )
        )
        # If this ISP has no linked/unassigned techs, fall back to all active technicians.
        if not technicians:
            technicians = list(
                Employee.objects.filter(
                    role=Employee.Role.TECHNICIAN,
                    status=Employee.Status.ACTIVE,
                )
                .select_related("user", "organization")
                .order_by("user__first_name", "user__last_name", "user__username")
            )
    return render(
        request,
        "core/leads.html",
        client_page_context(
            request,
            active_nav="leads",
            page_title="Leads",
            page_kicker="Sales",
            page_subtitle="Open clients and clients allocated to your ISP.",
            customers=customers,
            allocation_phone=pay_phone,
            technicians=technicians,
        ),
    )


def _lead_action_customer(request, customer_id):
    """Return a lead the active ISP may act on, or None."""
    org = resolve_organization(request.user, request)
    if not org:
        return None, None
    customer = (
        Customer.objects.filter(pk=customer_id)
        .filter(
            Q(status=Customer.Status.NEW, organization__isnull=True)
            | Q(status__in=Customer.ALLOCATED_STATUSES, organization=org)
        )
        .select_related("organization", "plan", "assigned_technician")
        .first()
    )
    return org, customer


@client_workspace_required
@require_POST
def lead_allocation_stk_pay(request, customer_id):
    """Send STK Push to pay for allocating an open lead to this ISP."""
    org, customer = _lead_action_customer(request, customer_id)
    if org is None:
        return JsonResponse({"ok": False, "error": "No organization linked."}, status=400)
    if customer is None or customer.status != Customer.Status.NEW:
        return JsonResponse(
            {"ok": False, "error": "That lead is no longer available."},
            status=400,
        )

    phone = (request.POST.get("phone") or "").strip()
    request_technician = (request.POST.get("request_technician") or "").strip().lower() in {
        "1",
        "true",
        "on",
        "yes",
    }
    technician_mode = (request.POST.get("technician_mode") or "").strip()
    technician_id = request.POST.get("technician_id")
    result = start_lead_allocation_stk_payment(
        organization=org,
        customer=customer,
        phone=phone,
        user=request.user,
        request=request,
        request_technician=request_technician,
        technician_mode=technician_mode,
        technician_id=technician_id,
    )
    status = 200 if result.get("ok") else 400
    return JsonResponse(result, status=status)


@client_workspace_required
@require_GET
def lead_allocation_stk_status(request, stk_id: int):
    """Poll lead-allocation STK status for the active ISP."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization linked."}, status=400)

    stk = get_object_or_404(
        StkPushRequest.objects.select_related("customer", "organization"),
        pk=stk_id,
        organization=org,
        purpose=StkPushRequest.Purpose.LEAD_ALLOCATION,
    )
    payload = refresh_stk_status(stk)
    if payload.get("success"):
        customer = stk.customer
        customer.refresh_from_db(fields=["status", "phone", "organization_id"])
        payload["customer_status"] = customer.status
        payload["allocated"] = customer.status in Customer.ALLOCATED_STATUSES
        payload["customer_phone"] = customer.phone or ""
    return JsonResponse(payload)


@client_workspace_required
@require_POST
def lead_reverse(request, customer_id):
    """Reverse allocation payment record and return the ticket to New."""
    org, customer = _lead_action_customer(request, customer_id)
    if customer is None or customer.status not in Customer.ALLOCATED_STATUSES:
        messages.error(request, "That allocated lead is no longer available.")
        return redirect("core:leads")

    reason_labels = {
        "wrong_location": "Wrong location",
        "full_capacity": "Full capacity",
        "not_fibre_ready": "Not fibre ready",
        "technician": "Technician",
        "client": "Client",
        "other": "Other reason",
    }
    detail_required = {"technician", "client", "other"}
    category = (request.POST.get("reason_category") or "").strip()
    detail = (request.POST.get("reason_detail") or "").strip()
    reason = (request.POST.get("reason") or "").strip()

    label = reason_labels.get(category)
    if not label:
        messages.error(request, "Choose a reason for this reversal.")
        return redirect("core:leads")
    if category in detail_required and not detail:
        messages.error(request, f"Enter details for “{label}”.")
        return redirect("core:leads")

    if category in detail_required:
        reason = f"{label}: {detail}"
    else:
        reason = label

    result = reverse_lead_allocation(
        organization=org,
        customer=customer,
        user=request.user,
        reason=reason,
    )
    ticket = customer.sales_ticket_number or customer.account_number
    if result.get("ok"):
        messages.success(
            request,
            result.get("message")
            or f"Reversed allocation for {customer.full_name} ({ticket}). Ticket is New again.",
        )
    else:
        messages.error(request, result.get("error") or "Could not reverse this allocation.")
    return redirect("core:leads")


@client_workspace_required
@require_POST
def lead_not_interested(request, customer_id):
    org, customer = _lead_action_customer(request, customer_id)
    if customer is None:
        messages.error(request, "That lead is no longer available.")
        return redirect("core:leads")
    if customer.status != Customer.Status.NEW:
        messages.error(request, "Only open tickets can be marked not interested.")
        return redirect("core:leads")

    # Leave open-pool ownership empty but mark disposition so it leaves every leads queue.
    customer.organization = org
    customer.status = Customer.Status.NOT_INTERESTED
    customer.save(update_fields=["organization", "status"])
    ticket = customer.sales_ticket_number or customer.account_number
    messages.success(
        request,
        f"Marked {customer.full_name} ({ticket}) as not interested. Ticket hidden.",
    )
    return redirect("core:leads")


@client_workspace_required
def technicians(request):
    org = resolve_organization(request.user, request)
    members = (
        Employee.objects.filter(organization=org, role=Employee.Role.TECHNICIAN)
        .select_related("user")
        .order_by("user__first_name", "user__username")
        if org
        else Employee.objects.none()
    )
    return render(
        request,
        "core/staff_role_list.html",
        client_page_context(
            request,
            active_nav="technicians",
            page_title="Technicians",
            page_kicker="Team",
            page_subtitle="Field technicians and installers for this organization.",
            members=members,
            empty_text="No technicians are assigned to this company yet.",
        ),
    )


@client_workspace_required
def shop(request):
    """Ecommerce-style catalog of active network equipment."""
    q = (request.GET.get("q") or "").strip()
    category = (request.GET.get("type") or "all").strip().lower()
    valid_types = {choice[0] for choice in NetworkEquipment.EquipmentType.choices}
    if category not in valid_types and category != "all":
        category = "all"

    equipment_qs = NetworkEquipment.objects.filter(
        status=NetworkEquipment.Status.ACTIVE,
    ).order_by("equipment_type", "name", "id")
    if q:
        equipment_qs = equipment_qs.filter(
            Q(name__icontains=q) | Q(equipment_type__icontains=q)
        )

    equipment_list = list(equipment_qs[:300])
    grouped = {key: [] for key, _label in NetworkEquipment.EquipmentType.choices}
    for item in equipment_list:
        grouped.setdefault(item.equipment_type, []).append(item)

    category_rows = []
    for key, label in NetworkEquipment.EquipmentType.choices:
        items = grouped.get(key) or []
        if not items:
            continue
        if category != "all" and key != category:
            continue
        category_rows.append(
            {
                "key": key,
                "label": label,
                "items": items,
                "count": len(items),
            }
        )

    type_counts = {
        row["equipment_type"]: row["total"]
        for row in (
            NetworkEquipment.objects.filter(status=NetworkEquipment.Status.ACTIVE)
            .values("equipment_type")
            .annotate(total=Count("id"))
        )
    }
    categories = [
        {
            "key": key,
            "label": label,
            "count": type_counts.get(key, 0),
        }
        for key, label in NetworkEquipment.EquipmentType.choices
        if type_counts.get(key, 0)
    ]
    catalog_stats = NetworkEquipment.objects.filter(
        status=NetworkEquipment.Status.ACTIVE
    ).aggregate(
        total=Count("id"),
        in_stock=Count("id", filter=Q(quantity__gt=0)),
        on_sale=Count(
            "id",
            filter=Q(discount_enabled=True, discount_price__gt=0),
        ),
    )

    return render(
        request,
        "core/shop.html",
        client_page_context(
            request,
            active_nav="shop",
            page_title="Shop",
            page_kicker="Shop",
            page_subtitle="Browse network equipment for installs and upgrades.",
            category_rows=category_rows,
            equipment_count=sum(row["count"] for row in category_rows),
            categories=categories,
            active_category=category,
            shop_query=q,
            in_stock_count=catalog_stats["in_stock"] or 0,
            on_sale_count=catalog_stats["on_sale"] or 0,
            total_active=catalog_stats["total"] or 0,
        ),
    )


@client_workspace_required
def referrals(request):
    if not ClientSettings.get_solo().referral_enabled:
        messages.info(request, "Referrals are not enabled on this platform.")
        return redirect("core:workspace")

    org = resolve_organization(request.user, request)
    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect("core:workspace")

    referral_code = org.ensure_referral_code()
    referral_path = reverse("accounts:register")
    referral_url = request.build_absolute_uri(f"{referral_path}?ref={referral_code}")
    org_label = org.name or "an ISPCENTRIC partner"
    share_text = (
        f"Join ISPCENTRIC — referred by {org_label}. "
        f"Open this link to register (referral code is their phone {referral_code}):"
    )
    from urllib.parse import quote

    whatsapp_share_url = (
        "https://wa.me/?text=" + quote(f"{share_text}\n{referral_url}")
    )
    sms_share_url = "sms:?body=" + quote(f"{share_text} {referral_url}")
    email_share_url = (
        "mailto:?subject="
        + quote(f"Join ISPCENTRIC — referral from {org_label}")
        + "&body="
        + quote(f"{share_text}\n\n{referral_url}")
    )
    referred = (
        Organization.objects.filter(referred_by=org)
        .select_related("owner")
        .order_by("-created_at")
    )
    pending_count = referred.filter(
        referral_status=Organization.ReferralStatus.PENDING
    ).count()
    active_count = referred.filter(
        referral_status=Organization.ReferralStatus.ACTIVE
    ).count()
    return render(
        request,
        "core/referrals.html",
        client_page_context(
            request,
            active_nav="referral",
            page_title="Referrals",
            page_kicker="Grow",
            page_subtitle=(
                f"Share {org_label}'s referral link. New signups stay pending "
                "until they onboard their first MikroTik."
            ),
            referral_code=referral_code,
            referral_company_name=org_label,
            referral_url=referral_url,
            share_text=share_text,
            whatsapp_share_url=whatsapp_share_url,
            sms_share_url=sms_share_url,
            email_share_url=email_share_url,
            referral_count=referred.count(),
            referral_pending_count=pending_count,
            referral_active_count=active_count,
            referred_organizations=referred,
        ),
    )


@client_workspace_required
def system_settings(request):
    return render(
        request,
        "core/system_settings.html",
        client_page_context(
            request,
            active_nav="settings",
            sidebar_active="company_settings",
            page_title="ISP Acc. Settings",
            page_kicker="Settings",
            page_subtitle="ISP account status, staff join code, and workspace identity.",
        ),
    )


def _isp_communications_page(request, *, variant):
    """Settings = credential config only; My account = when messages are sent."""
    org = resolve_organization(request.user, request)
    employee = getattr(request.user, "employee_profile", None)
    viewing_client = bool(employee and is_viewing_as_client(request, employee))
    can_edit = bool(org and (org.owner_id == request.user.id or viewing_client))
    comms = CommunicationSettings.for_organization(org) if org else None
    is_settings = variant == "settings"
    form = (
        CommunicationSettingsForm(instance=comms)
        if is_settings and comms and can_edit
        else None
    )

    if is_settings and request.method == "POST" and can_edit and comms:
        form = CommunicationSettingsForm(request.POST, instance=comms)
        if form.is_valid():
            comms = form.save()
            statuses = comms.channel_statuses()
            parts = []
            for key, label in (("sms", "SMS"), ("email", "Email"), ("whatsapp", "WhatsApp")):
                status = statuses[key]
                if status["ready"]:
                    parts.append(f"{label} ready")
                elif status["enabled"]:
                    parts.append(f"{label} needs setup")
                else:
                    parts.append(f"{label} off")
            messages.success(
                request,
                "Communication settings saved. " + " · ".join(parts) + ".",
            )
            return redirect("core:settings_communications")
    elif not is_settings and request.method == "POST":
        return redirect("core:settings_communications")

    statuses = comms.channel_statuses() if comms else None
    context = {
        "form": form,
        "can_edit": can_edit,
        "comms": comms,
        "sms_status": statuses["sms"] if statuses else None,
        "email_status": statuses["email"] if statuses else None,
        "whatsapp_status": statuses["whatsapp"] if statuses else None,
        "show_events": not is_settings,
        "show_config": is_settings,
        "save_label": "Save communication settings",
    }
    if is_settings:
        return render(
            request,
            "core/settings_communications.html",
            client_page_context(
                request,
                active_nav="settings",
                sidebar_active="communications",
                page_title="Communication settings",
                page_kicker="Settings",
                page_subtitle=(
                    "Configure SMS, email, and WhatsApp credentials used to message "
                    "your clients and this ISP account."
                ),
                comms_fetch_url=reverse("core:settings_communications_fetch"),
                **context,
            ),
        )
    return render(
        request,
        "core/settings_communications.html",
        client_page_context(
            request,
            active_nav="account",
            sidebar_active="account_communications",
            page_title="Communications",
            page_kicker="My account",
            page_subtitle=(
                "When this ISP sends messages to clients and to this account. "
                "Gateway credentials are configured under Communication settings."
            ),
            client_events=CLIENT_COMMUNICATION_EVENTS,
            isp_events=ISP_COMMUNICATION_EVENTS,
            **context,
        ),
    )


def _comms_fetch_payload(request):
    if "application/json" in (request.content_type or ""):
        try:
            return json.loads(request.body.decode() or "{}")
        except json.JSONDecodeError:
            return {}
    return {key: request.POST.get(key, "") for key in request.POST}


@client_workspace_required
@require_POST
def settings_communications_fetch(request):
    org = resolve_organization(request.user, request)
    employee = getattr(request.user, "employee_profile", None)
    viewing_client = bool(employee and is_viewing_as_client(request, employee))
    can_edit = bool(org and (org.owner_id == request.user.id or viewing_client))
    if not can_edit:
        return JsonResponse({"ok": False, "error": "Only the organization owner can fetch providers."}, status=403)
    result = fetch_provider_options(_comms_fetch_payload(request))
    return JsonResponse(result, status=200 if result.get("ok") else 400)


@client_workspace_required
def settings_communications(request):
    return _isp_communications_page(request, variant="settings")


@client_workspace_required
def my_account_communications(request):
    return _isp_communications_page(request, variant="account")


@client_workspace_required
def settings_payments(request):
    """STK Payment Settings: receive money + Daraja STK Push."""
    org = resolve_organization(request.user, request)
    extra = _account_org_context(request, org)
    can_edit = extra["can_edit"]
    form = (
        OrganizationEditForm(instance=org, section=OrganizationEditForm.SECTION_DARAJA)
        if org and can_edit
        else None
    )

    if request.method == "POST" and can_edit and org:
        def _daraja_messages(saved_org):
            creds = saved_org.effective_daraja_credentials()
            if saved_org.daraja_enabled and creds.get("ready"):
                return [
                    "Payment settings saved. Daraja STK Push is ready "
                    f"({creds.get('source_label')}).",
                ]
            if saved_org.daraja_enabled:
                return [
                    "Payment settings saved. Daraja is enabled but not fully ready yet — "
                    f"{creds.get('message')}"
                ]
            return ["Receive money and Daraja settings updated."]

        form, early = _save_account_section(
            request,
            org,
            section=OrganizationEditForm.SECTION_DARAJA,
            success_url_name="core:settings_payments",
            success_messages=_daraja_messages,
        )
        if early:
            return early

    return render(
        request,
        "core/settings_payments.html",
        client_page_context(
            request,
            active_nav="settings",
            sidebar_active="stk_payment_settings",
            page_title="STK Payment Settings",
            page_kicker="Settings",
            page_subtitle=(
                "Set this ISP's Paybill or Till for manual collections, then choose "
                "Company Payment Gateway (default) or this ISP's own Daraja app for STK Push."
            ),
            form=form,
            **extra,
        ),
    )
