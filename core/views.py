"""Client (organization owner) workspace helpers and module pages."""

import gzip
import hashlib
import http.client
import json
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
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from accounts.forms import HotspotSettingsForm, OrganizationEditForm, OwnerProfileForm, PppoeSettingsForm
from accounts.models import ClientSettings, Employee, Organization, PaymentGateway
from accounts.routing import (
    can_access_client_portal,
    can_switch_roles,
    get_client_view_organization,
    home_url_for_user,
    is_viewing_as_client,
)
from billing.forms import (
    CustomerDetailsEditForm,
    CustomerPackagePeriodForm,
    PppoeClientRegisterForm,
)
from billing.models import BillingPlan, Customer, Invoice, Payment, StkPushRequest
from billing.services import (
    customer_receives_internet,
    customer_subscription_expired,
    customers_needing_renewal_attention,
    make_renew_token,
    plan_uses_clock_time,
    plans_for_router,
    resolve_lead_allocation_fee,
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
    apply_mikrotik_uplink_bond,
    apply_mikrotik_uplink_failover,
    apply_mikrotik_single_wan,
    apply_pppoe_enforcement_on_router,
    apply_hotspot_on_router,
    check_mikrotik_reachable,
    clear_mikrotik_uplink_multi,
    customer_cpe_web_proxy,
    probe_customer_cpe_web,
    CPE_WEB_PORTS,
    PPPOE_LOCAL_ADDRESS as MK_PPPOE_LOCAL_ADDRESS,
    configure_customer_cpe_web_wifi,
    configure_mikrotik_wifi,
    fetch_active_pppoe_usernames,
    fetch_customer_cpe_web_data,
    fetch_customer_cpe_live_usage,
    fetch_customer_hotspot_usage,
    fetch_customer_pppoe_usage,
    fetch_hotspot_client_macs,
    fetch_mikrotik_live_snapshot,
    find_hotspot_router_for_mac,
    find_pppoe_customer_for_ip,
    list_mikrotik_ports,
    cpe_firewall_unlock_script,
    prepare_customer_cpe_access,
    provision_customer_pppoe,
    read_mikrotik_uplink_multi,
    read_mikrotik_wifi,
    recover_mikrotik_connection,
    set_mikrotik_clean_uplink,
    set_mikrotik_port_enabled,
    set_mikrotik_wifi_enabled,
    sync_customer_subscription_access,
    test_mikrotik_api_login,
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
                "key": "change_credentials",
                "label": "Login credentials",
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
                "key": "general_usage",
                "label": "General usage",
                "url_name": "core:clients_general_usage",
            },
            {"key": "clients", "label": "All clients", "url_name": "core:my_clients"},
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
                "label": "Update package",
                "action": "open_modal",
                "modal": "client-package-modal",
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
                "key": "account_daraja",
                "label": "Daraja STK Push",
                "url_name": "core:my_account_daraja",
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
        "items": [],
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


def _schedule_mikrotik_job(target, *, name: str = "mikrotik-bg") -> None:
    """Run RouterOS work off the request thread so nginx does not 504."""

    def _runner():
        from django.db import connection

        try:
            target()
        except Exception:
            pass
        finally:
            connection.close()

    threading.Thread(target=_runner, name=name, daemon=True).start()


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
        if row.get("url_name") and row.get("anchor") and not row.get("href"):
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
    access_url = reverse("core:mikrotik_pppoe_settings", kwargs={"router_id": router.pk})
    clean_url = reverse("core:mikrotik_clean_uplink", kwargs={"router_id": router.pk})
    nav: list[dict] = [
        {"key": "overview", "label": "Router overview", "href": detail_url},
        {"key": "ports", "label": "Ports", "href": ports_url},
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
        return bool((customer.hotspot_mac or "").strip())
    return False


def resolve_client_usage_router(customer, org=None):
    """MikroTik to query for this client's live usage."""
    router = getattr(customer, "router", None)
    if router is not None and router.account_status != MikroTikRouter.AccountStatus.SUSPENDED:
        return router
    if customer.service_type != Customer.ServiceType.HOTSPOT:
        return None
    mac = (customer.hotspot_mac or "").strip()
    if not mac:
        return None
    organization = org or getattr(customer, "organization", None)
    found = find_hotspot_router_for_mac(organization, mac)
    if found is not None and found.account_status != MikroTikRouter.AccountStatus.SUSPENDED:
        return found
    return (
        MikroTikRouter.objects.filter(
            organization=organization,
            account_status=MikroTikRouter.AccountStatus.ACTIVE,
        )
        .order_by("id")
        .first()
    )


def build_client_detail_nav(customer, *, can_access_wifi: bool = False) -> list[dict]:
    """Sidebar items for a single client (sections + update package)."""
    nav: list[dict] = [
        {
            "key": "package",
            "label": "Update package",
            "action": "open_modal",
            "modal": "client-package-modal",
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
    nav.append(
        {
            "key": "billing",
            "label": "Client billing",
            "href": reverse(
                "core:client_billing",
                kwargs={"customer_id": customer.pk},
            ),
        }
    )
    if can_access_wifi:
        nav.append(
            {
                "key": "wifi",
                "label": "Wi‑Fi settings",
                "href": reverse(
                    "core:client_wifi_settings",
                    kwargs={"customer_id": customer.pk},
                ),
            }
        )
    return nav


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
    if mode == MikroTikRouter.UplinkMode.FAILOVER and uplink_ports:
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
    if mode == MikroTikRouter.UplinkMode.FAILOVER and uplink_ports:
        primary = uplink_ports[0]
        if len(uplink_ports) > 1:
            secondary = uplink_ports[1]
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
                "label": f"Primary WAN · {primary}",
            }
        )
    if secondary and secondary != primary:
        ports.append(
            {
                "role": "secondary",
                "interface": secondary,
                "label": f"Secondary WAN · {secondary}",
            }
        )
    return ports


def _port_role_choices_for_ui() -> list[tuple[str, str]]:
    """Roles shown in the ports UI (WAN primary is merged into WAN)."""
    labels = {
        MikroTikRouter.PortRole.NONE: "Unassigned",
        MikroTikRouter.PortRole.WAN: "Internet",
        MikroTikRouter.PortRole.WAN_BACKUP: "Backup internet",
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


def _friendly_role_label(role: str) -> str:
    labels = dict(_port_role_choices_for_ui())
    return labels.get((role or "").strip().lower(), "Unassigned")


def _is_bond_port_row(row: dict) -> bool:
    name = (row.get("name") or "").strip().lower()
    iface_type = (row.get("type") or "").strip().lower()
    return iface_type == "bond" or name.startswith("bond")


def _pick_auto_wan(ports: list[dict], *, suggested_wan: str, saved_wan: str) -> str:
    """Choose the best Internet port from live data (DHCP, PPPoE, or ether)."""
    physical = [p for p in ports if not _is_bond_port_row(p)]
    by_name = {(p.get("name") or "").strip(): p for p in physical}

    for candidate in (suggested_wan, saved_wan, "ether1"):
        name = (candidate or "").strip()
        row = by_name.get(name)
        if not row:
            continue
        if row.get("disabled") or row.get("is_wireless"):
            continue
        return name

    # Prefer a port that already has PPPoE or DHCP uplink configured.
    for kind in ("pppoe", "dhcp"):
        for p in physical:
            if p.get("disabled") or p.get("is_wireless"):
                continue
            if (p.get("uplink_kind") or "") != kind:
                continue
            name = (p.get("name") or "").strip()
            if name:
                return name

    running_ether = [
        p
        for p in physical
        if p.get("running")
        and not p.get("is_wireless")
        and not p.get("disabled")
        and not (p.get("is_bridged") and (p.get("name") or "").lower() != "ether1")
    ]
    if running_ether:
        # Prefer non-bridged running ether (typical WAN), else first running.
        unbridged = [p for p in running_ether if not p.get("is_bridged")]
        pick = (unbridged or running_ether)[0]
        return (pick.get("name") or "").strip()

    any_ether = [
        p
        for p in physical
        if not p.get("is_wireless") and not p.get("disabled")
    ]
    if any_ether:
        return (any_ether[0].get("name") or "").strip()
    return ""


def suggest_port_roles(
    ports: list[dict],
    *,
    suggested_wan: str = "",
    saved_wan: str = "",
) -> dict[str, str]:
    """
    Auto map ports for any ISP uplink:
    - one Internet (WAN) from default route / PPPoE parent / ether1 / first live uplink
    - running customer ports → Customers (LAN)
    - disabled / link-down → Unused
    """
    roles: dict[str, str] = {}
    wan = _pick_auto_wan(ports, suggested_wan=suggested_wan, saved_wan=saved_wan)

    for row in ports:
        name = (row.get("name") or "").strip()
        if not name or _is_bond_port_row(row):
            continue
        if name == wan:
            roles[name] = MikroTikRouter.PortRole.WAN
            continue
        if row.get("disabled"):
            roles[name] = MikroTikRouter.PortRole.UNUSED
            continue
        # Bridged / Wi‑Fi ports are customer-facing even if the link is currently down.
        # Ports that already carry DHCP/PPPoE but are not the chosen WAN stay unassigned
        # so the operator can mark them as backup deliberately.
        if (row.get("uplink_kind") or "") in {"pppoe", "dhcp"} and name != wan:
            roles[name] = MikroTikRouter.PortRole.NONE
            continue
        if row.get("is_bridged") or row.get("is_wireless") or row.get("running"):
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
    elif mode == MikroTikRouter.UplinkMode.FAILOVER and ports:
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
    # Anyone in the client workspace can edit their own login via the popup.
    can_edit_owner_profile = True
    sidebar = CLIENT_SIDEBARS.get(active_nav, CLIENT_SIDEBARS["workspace"])
    referral_enabled = bool(ClientSettings.get_solo().referral_enabled)
    nav = build_client_nav(active_nav, referral_enabled=referral_enabled)

    owner_profile_form = extra.pop("owner_profile_form", None)
    open_owner_profile_modal = bool(extra.pop("open_owner_profile_modal", False))
    if owner_profile_form is None:
        owner_profile_form = OwnerProfileForm(
            user=request.user,
            initial={
                "username": request.user.username,
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
        "can_edit_owner_profile": can_edit_owner_profile,
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
    try:
        from core.mikrotik_status_samples import mikrotik_performance_trend

        snapshot["mikrotik_trend"] = mikrotik_performance_trend(org, hours=24)
    except Exception:
        snapshot["mikrotik_trend"] = {
            "ok": False,
            "labels": [],
            "datasets": [],
            "routers": [],
        }
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

    score_map = {
        "connected": 100,
        "reachable": 70,
        "limited": 55,
        "auth_failed": 25,
        "wrong_host": 10,
        "disconnected": 0,
    }
    scores = []
    connected = 0
    outages = []
    for row in routers:
        status = (row.get("status") or "disconnected").strip().lower()
        scores.append(score_map.get(status, 0))
        if status == "connected":
            connected += 1
        if status in {"disconnected", "auth_failed", "wrong_host", "limited"}:
            outages.append(
                {
                    "id": row.get("id"),
                    "name": row.get("name") or "MikroTik",
                    "host": row.get("host") or "",
                    "status": status,
                    "error": row.get("error") or "",
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
    try:
        from core.mikrotik_status_samples import mikrotik_performance_trend

        hours = 24
        try:
            hours = max(1, min(int(request.GET.get("hours") or 24), 168))
        except (TypeError, ValueError):
            hours = 24
        snapshot["mikrotik_trend"] = mikrotik_performance_trend(
            org, hours=hours, live_routers=routers or []
        )
    except Exception:
        snapshot["mikrotik_trend"] = {
            "ok": False,
            "labels": [],
            "datasets": [],
            "routers": [],
        }

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
    return render(
        request,
        "core/mikrotik.html",
        client_page_context(
            request,
            active_nav="mikrotik",
            page_title="MikroTik",
            page_subtitle="Manage MikroTik routers, interfaces, and device health for this ISP.",
            routers=routers if routers is not None else _mikrotik_list_routers(org),
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

            # Read hardware IDs so we can detect the same physical MikroTik.
            hardware = test_mikrotik_api_login(
                router.host,
                router.username,
                router.password,
                timeout=5.0,
            )
            serial_number = ""
            software_id = ""
            if not hardware.get("ok"):
                form.add_error(
                    "host",
                    hardware.get("error")
                    or "Could not reach this MikroTik to read its serial number.",
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
                    wifi_result = configure_mikrotik_wifi(
                        router.host,
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
            if org and getattr(org, "pppoe_compulsory", False):
                router_pk = router.pk

                def _bg_enforce(pk: int = router_pk) -> None:
                    try:
                        live = MikroTikRouter.objects.select_related("organization").get(
                            pk=pk
                        )
                        apply_pppoe_enforcement_on_router(live, compulsory=True)
                    except Exception:
                        pass

                _schedule_mikrotik_job(_bg_enforce, name=f"pppoe-enforce-{router_pk}")
                messages.info(
                    request,
                    "PPPoE enforcement is being applied on this MikroTik in the background — "
                    "paid PPPoE clients will surf automatically; other devices use Hotspot.",
                )
            # Drop stale discovery/status caches for this org after onboard.
            if org:
                cache.delete_many(
                    [
                        f"mikrotik_discover:{org.pk}:quick",
                        f"mikrotik_discover:{org.pk}:full",
                        f"mikrotik_status:{org.pk}",
                    ]
                )
            return redirect("core:mikrotik")
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
    """Edit name, model, location, and internet company from the routers list."""
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
                edit_form.save()
                cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
                messages.success(request, "MikroTik details updated.")
                return redirect("core:mikrotik_detail", router_id=router.pk)
            open_modal = "mikrotik-edit-modal"
        elif action == "change_credentials":
            if is_suspended:
                messages.error(
                    request,
                    "Activate this MikroTik account before changing credentials.",
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
                apply_result = apply_mikrotik_access_changes(
                    current_host=current_host,
                    current_username=current_username,
                    current_password=current_password,
                    current_wifi_ssid=current_wifi_ssid,
                    current_wifi_password=current_wifi_password,
                    new_host=cleaned.get("host") or "",
                    new_username=cleaned.get("username") or "",
                    new_password=cleaned.get("password") or "",
                    new_wifi_ssid=cleaned.get("wifi_ssid") or "",
                    new_wifi_password=cleaned.get("wifi_password") or "",
                )
                if not apply_result.get("ok"):
                    credentials_form.add_error(
                        None,
                        apply_result.get("error")
                        or "Could not update credentials on the MikroTik.",
                    )
                    open_modal = "mikrotik-credentials-modal"
                else:
                    credentials_form.save()
                    cache.delete_many(
                        [
                            f"mikrotik_status:{org.pk}",
                            f"mikrotik_live:{org.pk}:{router.pk}",
                            _wifi_fields_cache_key(org.pk, router.pk),
                            f"mikrotik_discover:{org.pk}:quick",
                            f"mikrotik_discover:{org.pk}:full",
                        ]
                    )
                    messages.success(
                        request,
                        apply_result.get("message")
                        or "Login credentials updated on the MikroTik.",
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
                # Re-read live state so we toggle the real radio, not a stale cache.
                live_now = read_mikrotik_wifi(
                    router.host,
                    router.username,
                    router.password or "",
                    timeout=5.0,
                )
                currently_on = bool(live_now.get("wifi_enabled"))
                turn_on = not currently_on
                result = set_mikrotik_wifi_enabled(
                    router.host,
                    router.username,
                    router.password or "",
                    enabled=turn_on,
                    wifi_ssid=router.wifi_ssid or "",
                    wifi_password=router.wifi_password or "",
                )
                cache.delete_many(
                    [
                        f"mikrotik_live:{org.pk}:{router.pk}",
                        _wifi_fields_cache_key(org.pk, router.pk),
                    ]
                )
                if not result.get("ok"):
                    wifi_form.add_error(
                        None,
                        result.get("error") or "Could not update Wi‑Fi on the MikroTik.",
                    )
                    wifi_enabled = currently_on
                    open_modal = "mikrotik-wifi-modal"
                else:
                    ssid = (result.get("wifi_ssid") or "").strip()
                    password = result.get("wifi_password") or ""
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
                    messages.success(
                        request,
                        result.get("message")
                        or (
                            "Wi‑Fi activated on the MikroTik."
                            if turn_on
                            else "Wi‑Fi deactivated on the MikroTik."
                        ),
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
    role_choices = _port_role_choices_for_ui()
    bond_mode_choices = [
        ("balance-xor", "Balance XOR (same provider)"),
        ("802.3ad", "LACP 802.3ad (if provider/switch supports it)"),
        ("active-backup", "Active-backup (same provider redundancy)"),
        ("balance-rr", "Balance round-robin"),
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
                router.host,
                router.username,
                router.password or "",
                timeout=6.0,
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
            if wan_name:
                apply_mikrotik_single_wan(
                    router.host,
                    router.username,
                    router.password or "",
                    wan_interface=wan_name,
                )
            cache.delete_many(
                [
                    f"mikrotik_live:{org.pk}:{router.pk}",
                    f"mikrotik_ports_live:{org.pk}:{router.pk}",
                ]
            )
            messages.success(request, result.get("message") or "Ports auto-assigned.")
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action in {"toggle_port", "set_port_role"}:
            port_name = (request.POST.get("port_name") or "").strip()
            if not port_name:
                messages.error(request, "Select a port to update.")
                return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "toggle_port":
            port_name = (request.POST.get("port_name") or "").strip()
            listed = list_mikrotik_ports(
                router.host,
                router.username,
                router.password or "",
                timeout=6.0,
            )
            current = None
            for row in listed.get("ports") or []:
                if row.get("name") == port_name:
                    current = row
                    break
            if not listed.get("ok"):
                messages.error(
                    request,
                    listed.get("error") or "Could not read ports from the MikroTik.",
                )
            elif not current:
                messages.error(request, f"Port “{port_name}” was not found on the router.")
            else:
                turn_on = bool(current.get("disabled"))
                result = set_mikrotik_port_enabled(
                    router.host,
                    router.username,
                    router.password or "",
                    interface_name=port_name,
                    enabled=turn_on,
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
                        or (
                            f"Port {port_name} enabled."
                            if turn_on
                            else f"Port {port_name} disabled."
                        ),
                    )
                else:
                    messages.error(
                        request,
                        result.get("error") or f"Could not update port {port_name}.",
                    )
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

            roles = dict(router.port_roles) if isinstance(router.port_roles, dict) else {}
            update_fields = ["port_roles", "updated_at"]
            uplink_roles = {
                MikroTikRouter.PortRole.WAN,
                MikroTikRouter.PortRole.WAN_PRIMARY,
                MikroTikRouter.PortRole.WAN_BACKUP,
                MikroTikRouter.PortRole.BOND,
            }

            if role == MikroTikRouter.PortRole.WAN:
                for name, existing in list(roles.items()):
                    if name == port_name:
                        continue
                    if _is_primary_wan_role(existing) or existing == MikroTikRouter.PortRole.BOND:
                        roles[name] = MikroTikRouter.PortRole.NONE
                roles[port_name] = MikroTikRouter.PortRole.WAN
                router.wan_interface = port_name
                has_backups = any(
                    (value or "").strip().lower() == MikroTikRouter.PortRole.WAN_BACKUP
                    for key, value in roles.items()
                    if key != port_name
                )
                if has_backups:
                    router.uplink_mode = MikroTikRouter.UplinkMode.FAILOVER
                    backup_ports = [
                        key
                        for key, value in roles.items()
                        if (value or "").strip().lower() == MikroTikRouter.PortRole.WAN_BACKUP
                    ]
                    router.uplink_ports = [port_name, *backup_ports]
                else:
                    router.uplink_mode = MikroTikRouter.UplinkMode.SINGLE
                    router.uplink_ports = [port_name]
                update_fields.extend(["wan_interface", "uplink_mode", "uplink_ports"])
                # Best-effort push so RouterOS WAN list matches the chosen Internet port.
                sync = apply_mikrotik_single_wan(
                    router.host,
                    router.username,
                    router.password or "",
                    wan_interface=port_name,
                )
                if not sync.get("ok"):
                    messages.warning(
                        request,
                        sync.get("error")
                        or f"Saved {port_name} as Internet, but could not sync the WAN list on the router.",
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
                if primary:
                    router.uplink_mode = MikroTikRouter.UplinkMode.FAILOVER
                    router.wan_interface = primary
                    backup_ports = [
                        name
                        for name, existing in roles.items()
                        if (existing or "").strip().lower() == MikroTikRouter.PortRole.WAN_BACKUP
                    ]
                    router.uplink_ports = [primary, *backup_ports]
                    update_fields.extend(["uplink_mode", "wan_interface", "uplink_ports"])
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
            label = dict(MikroTikRouter.PortRole.choices).get(role, role)
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

            result = apply_mikrotik_uplink_bond(
                router.host,
                router.username,
                router.password or "",
                member_ports=member_ports,
                bond_name=bond_name,
                bond_mode=bond_mode,
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

            result = apply_mikrotik_uplink_failover(
                router.host,
                router.username,
                router.password or "",
                primary_port=primary,
                backup_ports=backups,
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
            return redirect("core:mikrotik_ports", router_id=router.pk)

        if action == "clear_multi_uplink":
            restore = (
                list(router.uplink_unbridged)
                if isinstance(router.uplink_unbridged, list)
                else []
            )
            result = clear_mikrotik_uplink_multi(
                router.host,
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
                    "wan_interface",
                    "uplink_unbridged",
                    "port_roles",
                    "updated_at",
                ]
            )
            messages.success(
                request,
                result.get("message") or "Bonded / failover uplink settings cleared.",
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

    detail_nav = build_mikrotik_detail_nav(router, include_modals=False)
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
        bond_member_ports=bond_member_ports,
        primary_wan_ports=primary_wan_ports,
        backup_wan_ports=backup_wan_ports,
        lan_ports=lan_ports,
        unused_ports=unused_ports,
        unassigned_ports=unassigned_ports,
        can_apply_bond=can_apply_bond,
        can_apply_failover=can_apply_failover,
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
    )
    ctx["client_nav_main"] = [
        *CLIENT_COMMON_NAV_START,
        *detail_nav,
    ]
    ctx["sidebar_label"] = "MikroTik"
    return render(request, "core/mikrotik_ports.html", ctx)


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
            result = set_mikrotik_clean_uplink(
                router.host,
                router.username,
                router.password or "",
                enabled=turn_on,
                mode=cleaned.get("mode") or MikroTikRouter.CleanUplinkMode.BYPASS,
                wan_interface=cleaned.get("wan_interface") or "ether1",
                lan_bridge=cleaned.get("lan_bridge") or "bridgeLocal",
                provider_gateway=cleaned.get("provider_gateway") or "",
                separate_wan=bool(cleaned.get("separate_wan")),
                restore_wan_to_bridge=bool(router.clean_uplink_wan_was_bridged),
            )
            cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
            if not result.get("ok"):
                form.add_error(
                    None,
                    result.get("error")
                    or "Could not update clean uplink on the MikroTik.",
                )
            else:
                router.clean_uplink_enabled = bool(result.get("enabled"))
                router.clean_uplink_mode = (
                    cleaned.get("mode") or MikroTikRouter.CleanUplinkMode.BYPASS
                )
                router.wan_interface = cleaned.get("wan_interface") or "ether1"
                router.lan_bridge = cleaned.get("lan_bridge") or "bridgeLocal"
                router.provider_gateway = cleaned.get("provider_gateway") or ""
                router.clean_uplink_separate_wan = bool(cleaned.get("separate_wan"))
                if turn_on:
                    router.clean_uplink_wan_was_bridged = bool(
                        result.get("wan_was_bridged")
                    )
                else:
                    router.clean_uplink_wan_was_bridged = False
                router.save(
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
    with ThreadPoolExecutor(max_workers=2) as pool:
        ports_future = pool.submit(
            list_mikrotik_ports,
            router.host,
            router.username,
            router.password or "",
            timeout=6.0,
        )
        uplink_future = pool.submit(
            read_mikrotik_uplink_multi,
            router.host,
            router.username,
            router.password or "",
            timeout=5.0,
        )
        listed = ports_future.result()
        try:
            uplink_live = uplink_future.result()
        except Exception:
            uplink_live = {"ok": False}

    if not listed.get("ok"):
        return {
            "ok": False,
            "error": listed.get("error") or "Could not read ports from the MikroTik.",
            "ports": [],
            "auto_assigned": False,
        }

    suggested_wan = (listed.get("suggested_wan") or "").strip()
    live_ports = listed.get("ports") or []
    auto_assigned = False

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

    ports: list[dict] = []
    for row in live_ports:
        name = row.get("name") or ""
        role = resolve_port_role(router, name)
        ports.append(
            {
                **row,
                "role": role,
                "role_label": _friendly_role_label(role),
                "is_bond_iface": _is_bond_port_row(row),
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
    uplink_mode = router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE

    return {
        "ok": True,
        "ports": ports,
        "physical_ports": physical_ports,
        "suggested_wan": suggested_wan,
        "auto_assigned": auto_assigned,
        "auto_assigned_message": (
            "Ports were auto-assigned from live links. Change any role with one tap, or run Auto-assign again."
            if auto_assigned
            else ""
        ),
        "uplink_live": uplink_live if uplink_live.get("ok") else {},
        "bond_member_ports": bond_member_ports,
        "primary_wan_ports": primary_wan_ports,
        "backup_wan_ports": backup_wan_ports,
        "lan_ports": lan_ports,
        "unused_ports": unused_ports,
        "unassigned_ports": unassigned_ports,
        "can_apply_bond": len(bond_member_ports) >= 2,
        "can_apply_failover": len(primary_wan_ports) == 1 and len(backup_wan_ports) >= 1,
        "uplink_mode": uplink_mode,
        "uplink_mode_label": dict(MikroTikRouter.UplinkMode.choices).get(
            uplink_mode, "Single WAN"
        ),
        "wan_interface": router.wan_interface or "",
        "bond_interface": router.bond_interface or "",
        "bond_mode": router.bond_mode or "",
        "uplink_ports": list(router.uplink_ports or []),
        "failover_backup_label": ", ".join(
            str(p).strip() for p in (router.uplink_ports or [])[1:] if str(p).strip()
        ),
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
    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            return JsonResponse(cached)

    payload = _ports_live_payload(router)
    payload["router_id"] = router.pk
    # Auto-assign mutates DB — do not serve a stale empty role map.
    ttl = 3 if payload.get("auto_assigned") else (8 if payload.get("ok") else 4)
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

    candidate_hosts: list[str] = []
    try:
        devices = discover_mikrotik_devices(timeout=2.5, full_scan=False)
        for device in devices or []:
            ip = (device.get("ip") or device.get("host") or "").strip()
            if ip:
                candidate_hosts.append(ip)
    except Exception:
        candidate_hosts = []

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
                "api_disabled": bool(result.get("api_disabled")),
                "auth_error": bool(result.get("auth_error")),
                "pingable_hosts": result.get("pingable_hosts") or [],
                "username": use_username,
                "host": router.host,
                "name": router.name,
            },
            status=400,
        )

    update_fields = ["updated_at"]
    new_host = (result.get("host") or "").strip()
    if new_host and new_host != (router.host or "").strip():
        router.host = new_host
        update_fields.append("host")

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
            "host",
            "username",
            "password",
            "account_status",
            "organization_id",
            "internet_provider",
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

    cache_key = f"mikrotik_live:{org.pk}:{router.pk}"
    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            return JsonResponse(cached)

    # Dial the same address status probes use (tunnel when present).
    dial = (router.api_host or router.host or "").strip()
    snapshot = fetch_mikrotik_live_snapshot(
        dial,
        router.username,
        router.password,
        timeout=5.0,
    )
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

    saved_provider = (router.internet_provider or "").strip()
    detected_provider = (snapshot.get("wan_provider_detected") or "").strip()
    provider = saved_provider or detected_provider
    snapshot["wan_provider"] = provider
    snapshot["wan_provider_label"] = provider or "—"
    snapshot["wan_provider_saved"] = saved_provider
    if saved_provider:
        snapshot["wan_provider_hint"] = "Saved internet company"
        if snapshot.get("wan_port"):
            snapshot["wan_summary"] = (
                f"{saved_provider} internet entering on {snapshot['wan_port']}"
            )
        else:
            snapshot["wan_summary"] = f"Internet from {saved_provider}"
    elif detected_provider and snapshot.get("wan_port"):
        snapshot["wan_summary"] = (
            f"{detected_provider} internet entering on {snapshot['wan_port']}"
        )

    # Cache successes a bit longer; failures briefly so recovery shows soon.
    cache.set(cache_key, snapshot, 5 if snapshot.get("ok") else 3)
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
        reservation = wireguard.reserve_peer(label)
        payload = wireguard.peer_payload(
            reservation.label,
            reservation.address,
            reservation.private_key,
            reservation.public_key,
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

    return JsonResponse(
        {
            "ok": True,
            "configured": True,
            "label": payload["label"],
            "address": payload["address"],
            "script": payload["script"],
            "server_peer": payload["server_peer"],
            "endpoint": payload["endpoint"],
            "status_token": signing.dumps(
                {"address": payload["address"], "user_id": request.user.pk},
                salt="mikrotik-tunnel-status",
                compress=True,
            ),
            "hint": (
                "Script ready. Copy it and paste it into Winbox → New Terminal. "
                "ISPCENTRIC will check the tunnel and API automatically."
            ),
        }
    )


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
@require_GET
def mikrotik_tunnel_status(request):
    """Check whether a newly reserved tunnel reaches RouterOS API port 8728."""
    token = (request.GET.get("token") or "").strip()
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
    # discovery instead; the generated script places RFC1918 API accepts before
    # Hotspot/drop rules so this same onboarding flow works on localhost.
    if not wireguard.server_on_tunnel():
        org = resolve_organization(request.user, request)
        cache_key = f"mikrotik_tunnel_local_devices:{org.pk if org else 0}"
        devices = cache.get(cache_key)
        if devices is None:
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
        requested_lan = (request.GET.get("lan_host") or "").strip()
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

        lan_address = (candidate or {}).get("host") or ""
        probe = (
            check_mikrotik_reachable(lan_address, timeout=0.8)
            if lan_address
            else {}
        )
        via = probe.get("via") or ""
        api_enabled = bool(probe.get("online") and via == "api")
        if api_enabled:
            message = (
                f"Local mode ready — MikroTik API is available at {lan_address}:8728. "
                "Enter the router username and password, then press Connect."
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

        return JsonResponse(
            {
                "ok": True,
                "address": address,
                "tunnel_reachable": False,
                "api_enabled": api_enabled,
                "ready": api_enabled,
                "no_tunnel_route": True,
                "local_mode": True,
                "lan_address": lan_address,
                "local_devices": [
                    {
                        "host": device.get("host") or "",
                        "name": device.get("identity") or device.get("name") or "",
                    }
                    for device in candidates
                ],
                "via": via,
                "message": message,
            }
        )

    probe = check_mikrotik_reachable(address, timeout=0.8)
    via = probe.get("via") or ""
    api_enabled = bool(probe.get("online") and via == "api")
    tunnel_reachable = bool(probe.get("online"))

    if api_enabled:
        message = "Success — tunnel is online and RouterOS API is enabled on port 8728."
    elif tunnel_reachable:
        message = (
            "Tunnel is reachable, but RouterOS API port 8728 is not available. "
            "Wait for the script to finish or paste it again."
        )
    else:
        message = "Waiting for MikroTik… paste the script in Winbox → New Terminal."

    return JsonResponse(
        {
            "ok": True,
            "address": address,
            "tunnel_reachable": tunnel_reachable,
            "api_enabled": api_enabled,
            "ready": api_enabled,
            "no_tunnel_route": False,
            "via": via,
            "message": message,
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

    result = test_mikrotik_api_login(host, username, password)
    if not result.get("ok"):
        return JsonResponse(
            {"ok": False, "error": result.get("error") or "Connection failed."},
            status=400,
        )

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

    return JsonResponse(
        {
            "ok": True,
            "host": result.get("host") or host,
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
        }
    )


@client_workspace_required
@require_GET
def mikrotik_status(request):
    """Live online/offline status for onboarded MikroTik routers."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

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
            )
        )
        if org
        else []
    )
    if not routers:
        return JsonResponse({"ok": True, "routers": []})

    force_refresh = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    cache_key = f"mikrotik_status:{org.pk if org else 0}"
    if not force_refresh:
        cached = cache.get(cache_key)
        if cached is not None:
            # Never persist cached rows as samples — that froze "Connected" in
            # analytics after a router had already gone offline.
            return JsonResponse({"ok": True, "routers": cached})

    results = {}

    # Probe each unique host once so duplicate onboardings of the same IP
    # cannot race to different via channels (Connected vs Reachable).
    # api_host prefers the management tunnel, which is the address every other
    # router call dials; probing the raw LAN default instead reported remote
    # sites on whatever device now owns 192.168.88.1.
    unique_hosts = list(
        dict.fromkeys(
            router.api_host for router in routers if (router.api_host or "").strip()
        )
    )
    probe_by_host: dict[str, dict] = {}

    def _probe_host(host: str):
        return host, check_mikrotik_reachable(host, timeout=1.2)

    probe_workers = min(8, max(1, len(unique_hosts)))
    with ThreadPoolExecutor(max_workers=probe_workers) as pool:
        futures = [pool.submit(_probe_host, host) for host in unique_hosts]
        for future in as_completed(futures):
            try:
                host, probe = future.result()
                probe_by_host[host] = probe
            except Exception:
                continue

    def _check(router):
        host = (router.api_host or "").strip()
        probe = probe_by_host.get(host) or {"online": False, "via": "", "error": "Unreachable."}
        via = probe.get("via") or ""
        online = bool(probe.get("online"))
        auth_ok = None
        status = "disconnected"
        error = ""
        serial_number = (router.serial_number or "").strip()
        software_id = (router.software_id or "").strip()
        backfill = {}
        if online and via == "api":
            # Port 8728 is open — verify saved credentials so "Connected" means usable.
            # Skip Wi‑Fi reads: status only needs auth + hardware IDs.
            login = test_mikrotik_api_login(
                host,
                router.username,
                router.password or "",
                timeout=2.0,
                include_wifi=False,
            )
            if login.get("ok"):
                auth_ok = True
                status = "connected"
                live_serial = (login.get("serial_number") or "").strip()
                live_soft = (login.get("software_id") or "").strip()
                if live_serial:
                    serial_number = live_serial
                    if live_serial != (router.serial_number or "").strip():
                        backfill["serial_number"] = live_serial
                if live_soft:
                    software_id = live_soft
                    if live_soft != (router.software_id or "").strip():
                        backfill["software_id"] = live_soft
            else:
                auth_ok = False
                status = "auth_failed"
                error = login.get("error") or "Login failed"
        elif online and via == "ping":
            status = "limited"
        elif online:
            # Winbox/HTTP up, but don't claim API credentials work.
            status = "reachable"
        elif probe.get("foreign_http"):
            # Saved address now belongs to a different device entirely.
            status = "wrong_host"
            error = probe.get("error") or "Another device answers on this address."
        elif probe.get("error"):
            error = probe["error"]

        return router.id, {
            "id": router.id,
            "host": router.host,
            "name": router.name,
            "online": bool(auth_ok) if via == "api" else online and via != "ping",
            "reachable": online,
            "auth_ok": auth_ok,
            "manageable": bool(auth_ok),
            "status": status,
            "via": via,
            "error": error,
            "serial_number": serial_number,
            "software_id": software_id,
            "_backfill": backfill,
        }

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
    # Keep the org-wide cache short. A 15s "any peer online" TTL left powered-off
    # routers showing Connected for a full dashboard poll cycle.
    all_connected = bool(payload) and all(
        (item.get("status") or "") == "connected" for item in payload
    )
    cache.set(cache_key, payload, 5 if all_connected else 3)
    # Drop stale live snapshots so the detail page cannot keep showing Online
    # after status has already marked the router down.
    for item in payload:
        if (item.get("status") or "") != "connected" and item.get("id") is not None:
            cache.delete(f"mikrotik_live:{org.pk}:{item['id']}")
    try:
        from core.mikrotik_status_samples import record_mikrotik_status_samples

        record_mikrotik_status_samples(org, payload)
    except Exception:
        pass
    return JsonResponse({"ok": True, "routers": payload})


@client_workspace_required
def my_clients(request):
    org = resolve_organization(request.user, request)

    open_modal = ""
    pppoe_form = PppoeClientRegisterForm(organization=org)

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action == "register_pppoe":
            if not org:
                messages.error(request, "No organization is linked to this workspace.")
                return redirect("core:my_clients")
            pppoe_form = PppoeClientRegisterForm(request.POST, organization=org)
            if pppoe_form.is_valid():
                customer = pppoe_form.save()
                customer_pk = customer.pk
                account_number = customer.account_number
                full_name = customer.full_name

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
                messages.success(
                    request,
                    (
                        f"PPPoE client “{full_name}” registered "
                        f"({account_number}). "
                        "Installing the login on MikroTik in the background — "
                        "the CPE can dial once the push finishes."
                    ),
                )
                return redirect(f"{reverse('core:my_clients')}?tab=pppoe")
            open_modal = "pppoe-register-modal"
            tab = "pppoe"
        else:
            tab = (request.GET.get("tab") or "pppoe").strip().lower()
    else:
        tab = (request.GET.get("tab") or "pppoe").strip().lower()

    valid_tabs = {"pppoe", "static", "hotspot"}
    if tab not in valid_tabs:
        tab = "pppoe"

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
    if org:
        client_routers = list(
            MikroTikRouter.objects.filter(organization=org)
            .order_by("name", "host")
            .only("id", "name", "host")
        )
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

    ctx = client_page_context(
        request,
        active_nav="clients",
        page_title="My clients",
        page_kicker="Subscribers",
        page_subtitle="Browse subscribers by connection type and open a client for details.",
        active_tab=tab,
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
        open_client_modal=open_modal,
        billing_plans_exist=bool(
            org
            and BillingPlan.objects.filter(organization=org, is_active=True).exists()
        ),
    )
    # Already on All clients — hide the redundant sidebar link on this page only.
    ctx["client_nav_main"] = [
        item for item in ctx["client_nav_main"] if item.get("key") != "clients"
    ]
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
    can_access_wifi = bool(
        org
        and customer.service_type == Customer.ServiceType.PPPOE
        and customer.pppoe_username
        and nas
        and nas.account_status != MikroTikRouter.AccountStatus.SUSPENDED
    )

    wifi_ssid_display = (customer.cpe_wifi_ssid or "").strip()
    wifi_password_display = customer.cpe_wifi_password or ""
    package_form = CustomerPackagePeriodForm(instance=customer, organization=org)
    details_form = CustomerDetailsEditForm(instance=customer, organization=org)
    open_client_modal = ""

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    def _enqueue_subscription_sync(customer_pk: int, provision: bool) -> None:
        def _bg_sync():
            from django.db import connection
            try:
                _cust = Customer.objects.select_related(
                    "plan", "router", "organization"
                ).get(pk=customer_pk)
                sync_customer_subscription_access(
                    _cust,
                    provision=provision,
                )
            except Exception:
                pass
            finally:
                connection.close()

        threading.Thread(target=_bg_sync, daemon=True).start()

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

    def _package_json_response(customer, *, message: str, provision: bool) -> JsonResponse:
        from django.utils import timezone as dj_tz

        allowed = customer_receives_internet(customer)
        expired = customer_subscription_expired(customer)
        is_hourly = bool(
            customer.plan_id
            and getattr(customer.plan, "duration", "") in ("hourly", "six_hours")
        )

        def _fmt(value):
            if not value:
                return ""
            local = dj_tz.localtime(value)
            return local.strftime("%H:%M") if is_hourly else local.strftime("%Y-%m-%d")

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
            "syncing": provision,
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
                customer = details_form.save()
                creds_changed = (
                    customer.service_type == Customer.ServiceType.PPPOE
                    and customer.router_id
                    and (
                        (customer.pppoe_username or "").strip() != old_username
                        or (customer.pppoe_password or "") != old_password
                    )
                )
                if creds_changed:
                    _enqueue_pppoe_provision(customer.pk)

                if is_ajax:
                    return JsonResponse(
                        {
                            "ok": True,
                            "message": (
                                "Client details saved."
                                + (
                                    " Syncing PPPoE login to MikroTik…"
                                    if creds_changed
                                    else ""
                                )
                            ),
                            "full_name": customer.full_name,
                            "pppoe_username": customer.pppoe_username or "",
                            "pppoe_password": customer.pppoe_password or "",
                            "initial": (customer.full_name[:1].upper() if customer.full_name else "C"),
                            "syncing": creds_changed,
                        }
                    )
                messages.success(request, "Client details saved.")
                return redirect("core:client_detail", customer_id=customer.pk)

            if is_ajax:
                errors = json.loads(details_form.errors.as_json())
                return JsonResponse({"ok": False, "errors": errors}, status=400)
            open_client_modal = "client-details-modal"

        if action in ("update_package", "update_package_period", "update_package_and_period"):
            package_form = CustomerPackagePeriodForm(
                request.POST, instance=customer, organization=org
            )
            if package_form.is_valid():
                customer = package_form.save()
                provision = bool(customer.pppoe_username and customer.router_id)
                _enqueue_subscription_sync(customer.pk, provision)

                if is_ajax:
                    if customer.plan_id and customer.package_start and customer.package_end:
                        msg = (
                            f"Package set to {customer.plan.name} "
                            f"({customer.package_start.isoformat()} → {customer.package_end.isoformat()})."
                        )
                    elif customer.plan_id:
                        msg = f"Package set to {customer.plan.name}."
                    else:
                        msg = "Package updated."
                    return _package_json_response(
                        customer,
                        message=msg,
                        provision=provision,
                    )

                if customer.plan_id and customer.package_start and customer.package_end:
                    messages.success(
                        request,
                        f"Package set to {customer.plan.name} "
                        f"({customer.package_start.isoformat()} → {customer.package_end.isoformat()}).",
                    )
                elif customer.plan_id:
                    messages.success(request, f"Package set to {customer.plan.name}.")
                else:
                    messages.success(request, "Package updated.")
                return redirect("core:client_detail", customer_id=customer.pk)

            if is_ajax:
                errors = json.loads(package_form.errors.as_json())
                return JsonResponse({"ok": False, "errors": errors}, status=400)
            open_client_modal = "client-package-modal"


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
        package_form=package_form,
        details_form=details_form,
        package_duration=getattr(customer.plan, "duration", "") or "",
        package_duration_label=(
            customer.plan.get_duration_display() if customer.plan_id else ""
        ),
        plan_durations_json=json.dumps(
            {
                str(p.pk): p.duration
                for p in (
                    plans_for_router(
                        org,
                        customer.router,
                        service_type=getattr(customer, "service_type", None) or None,
                    )
                    if org
                    else []
                )
            }
        ),
        subscription_active=customer_receives_internet(customer),
        subscription_expired=customer_subscription_expired(customer),
        renew_url=(
            request.build_absolute_uri(
                reverse("billing:subscription_renew", args=[make_renew_token(customer)])
            )
            if customer.pk
            else ""
        ),
        open_client_modal=open_client_modal,
    )
    ctx["client_nav_main"] = [
        *CLIENT_COMMON_NAV_START,
        *build_client_detail_nav(customer, can_access_wifi=can_access_wifi),
    ]
    ctx["sidebar_label"] = "Client"
    return render(request, "core/client_detail.html", ctx)


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


def _cpe_proxy_token(request, customer: Customer, cpe_port: int = 80) -> str:
    return signing.dumps(
        {
            "customer_id": customer.pk,
            "user_id": request.user.pk,
            "cpe_port": int(cpe_port or 80),
        },
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


@client_workspace_required
@require_GET
def client_router_login(request, customer_id: int):
    """Start a short-lived, user-bound browser session to a live PPPoE CPE."""
    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("router"),
        pk=customer_id,
        organization=org,
    )
    if (
        customer.service_type != Customer.ServiceType.PPPOE
        or not customer.pppoe_username
        or not customer.router_id
        or customer.router.account_status == MikroTikRouter.AccountStatus.SUSPENDED
    ):
        messages.error(request, "Router login requires an active PPPoE client and NAS.")
        return redirect("core:client_detail", customer_id=customer.pk)

    nas = customer.router
    probe = probe_customer_cpe_web(
        nas.host,
        nas.username,
        nas.password or "",
        pppoe_username=customer.pppoe_username,
        timeout=8.0,
    )
    if not probe.get("ok"):
        return render(
            request,
            "core/client_router_unavailable.html",
            {
                "customer": customer,
                "router": nas,
                "cpe_host": probe.get("cpe_host") or "",
                "session_active": bool(probe.get("session_active")),
                "ping_ok": bool(probe.get("ping_ok")),
                "gateway": MK_PPPOE_LOCAL_ADDRESS,
                "detail": probe.get("hint") or probe.get("error") or "",
                "checked_ports": ", ".join(str(p) for p in CPE_WEB_PORTS),
                "detail_url": reverse("core:client_detail", args=[customer.pk]),
            },
            status=200,
        )

    token = _cpe_proxy_token(request, customer, probe.get("port") or 80)
    return redirect(
        "core:client_router_proxy_root",
        customer_id=customer.pk,
        token=token,
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
    if (
        customer.service_type != Customer.ServiceType.PPPOE
        or not customer.pppoe_username
        or not customer.router_id
        or customer.router.account_status == MikroTikRouter.AccountStatus.SUSPENDED
    ):
        return HttpResponse(
            "Router login is unavailable for this client.",
            status=409,
            content_type="text/plain",
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

    try:
        with customer_cpe_web_proxy(
            customer.router.host,
            customer.router.username,
            customer.router.password or "",
            pppoe_username=customer.pppoe_username,
            cpe_port=cpe_port,
            timeout=10.0,
        ) as proxy:
            headers = {}
            for name, value in request.headers.items():
                lower = name.lower()
                if lower in _CPE_HOP_HEADERS or lower in {
                    "cookie",
                    "origin",
                    "referer",
                    "x-csrftoken",
                }:
                    continue
                headers[name] = value
            headers["Host"] = proxy["cpe_host"]
            headers["Accept-Encoding"] = "identity"
            if router_cookies:
                headers["Cookie"] = "; ".join(
                    f"{name}={value}" for name, value in router_cookies.items()
                )

            if cpe_is_tls:
                connection = http.client.HTTPSConnection(
                    proxy["host"],
                    proxy["port"],
                    timeout=10.0,
                    context=ssl._create_unverified_context(),
                )
            else:
                connection = http.client.HTTPConnection(
                    proxy["host"],
                    proxy["port"],
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
                body = upstream.read(_CPE_PROXY_MAX_BODY + 1)
                upstream_headers = upstream.getheaders()
                status = upstream.status
            finally:
                connection.close()
    except (ConnectionError, OSError, TimeoutError, http.client.HTTPException) as exc:
        detail = str(exc) or exc.__class__.__name__
        timed_out = "timed out" in detail.lower() or isinstance(exc, TimeoutError)
        hint = (
            f" The client router did not answer on port {cpe_port} through the ISP "
            "MikroTik. Enable Remote / WAN Web Management on the client's router "
            f"(limit it to the ISP gateway {MK_PPPOE_LOCAL_ADDRESS}), confirm the "
            "client is online on PPPoE, then try again."
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
    can_access_wifi = bool(
        customer.service_type == Customer.ServiceType.PPPOE
        and customer.pppoe_username
        and nas
        and nas.account_status != MikroTikRouter.AccountStatus.SUSPENDED
    )
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
    probe = probe_customer_cpe_web(
        nas.host,
        nas.username,
        nas.password or "",
        pppoe_username=customer.pppoe_username,
        timeout=6.0,
    )
    session_active = bool(probe.get("session_active"))
    cpe_host = (probe.get("cpe_host") or "").strip()
    if probe.get("reachable") and probe.get("port"):
        web = fetch_customer_cpe_web_data(
            nas.host,
            nas.username,
            nas.password or "",
            pppoe_username=customer.pppoe_username,
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
            nas.host,
            nas.username,
            nas.password or "",
            pppoe_username=customer.pppoe_username,
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
        else:
            error = error or live.get("error") or ""
            hint = hint or live.get("hint") or ""
            working_user = (live.get("cpe_username") or "").strip()
            working_pass = live.get("cpe_password")
            update_fields: list[str] = []
            if working_user and working_user != (customer.cpe_username or ""):
                customer.cpe_username = working_user
                update_fields.append("cpe_username")
            if working_pass is not None and working_pass != (customer.cpe_password or ""):
                customer.cpe_password = working_pass
                update_fields.append("cpe_password")
            if update_fields:
                customer.save(update_fields=update_fields)

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
        "needs_password": needs_password and not auth_ok,
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
    can_access_wifi = bool(
        org
        and customer.service_type == Customer.ServiceType.PPPOE
        and customer.pppoe_username
        and nas
        and nas.account_status != MikroTikRouter.AccountStatus.SUSPENDED
    )
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

            probe = probe_customer_cpe_web(
                nas.host,
                nas.username,
                nas.password or "",
                pppoe_username=customer.pppoe_username,
                timeout=8.0,
            )
            if probe.get("reachable") and probe.get("port"):
                result = configure_customer_cpe_web_wifi(
                    nas.host,
                    nas.username,
                    nas.password or "",
                    pppoe_username=customer.pppoe_username,
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
                    nas.host,
                    nas.username,
                    nas.password or "",
                    pppoe_username=customer.pppoe_username,
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
                        nas_host=nas.host,
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

    ctx = client_page_context(
        request,
        active_nav="client_detail",
        sidebar_active="wifi",
        page_title=f"Wi‑Fi · {customer.full_name}",
        customer=customer,
        can_access_wifi=can_access_wifi,
        wifi_form=wifi_form,
        wifi_ssid_display=(customer.cpe_wifi_ssid or "").strip(),
        wifi_password_display=customer.cpe_wifi_password or "",
        back_url=reverse("core:client_detail", kwargs={"customer_id": customer.pk}),
        wifi_url=reverse("core:client_cpe_wifi", kwargs={"customer_id": customer.pk}),
        router_data_url=reverse(
            "core:client_cpe_router_data", kwargs={"customer_id": customer.pk}
        ),
        router_login_url=reverse(
            "core:client_router_login", kwargs={"customer_id": customer.pk}
        ),
    )
    ctx["client_nav_main"] = [
        *CLIENT_COMMON_NAV_START,
        *build_client_detail_nav(customer, can_access_wifi=can_access_wifi),
    ]
    ctx["sidebar_label"] = "Client"
    return render(request, "core/client_wifi_settings.html", ctx)


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
    if (
        customer.service_type != Customer.ServiceType.PPPOE
        or not customer.pppoe_username
        or not customer.router_id
        or customer.router.account_status == MikroTikRouter.AccountStatus.SUSPENDED
    ):
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
    probe = probe_customer_cpe_web(
        nas.host,
        nas.username,
        nas.password or "",
        pppoe_username=customer.pppoe_username,
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
        nas.host,
        nas.username,
        nas.password or "",
        pppoe_username=customer.pppoe_username,
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
        customer_receives_internet,
        customer_subscription_expired,
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

    remaining_seconds = None
    remaining_label = ""
    if customer.package_end:
        end = dj_tz.localtime(customer.package_end)
        remaining_seconds = int((end - now).total_seconds())
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
            "remaining_seconds": remaining_seconds,
            "remaining_label": remaining_label,
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
    if is_hotspot and not (customer.hotspot_mac or "").strip():
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

    cache_key = f"client_usage:{org.pk}:{customer.pk}"
    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            return JsonResponse(cached)

    if is_hotspot:
        payload = fetch_customer_hotspot_usage(
            router.host,
            router.username,
            router.password or "",
            hotspot_mac=customer.hotspot_mac,
        )
        payload["devices_connected"] = 1 if payload.get("session_active") else 0
        payload["devices_label"] = "1 gadget" if payload.get("session_active") else "0"
        payload["devices_hint"] = "Hotspot gadget session"
        payload["speed_source"] = "nas"
        payload["cpe_host"] = (payload.get("address") or "").strip()
        payload["cpe_auth_ok"] = False
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

    try:
        from billing.usage_samples import record_customer_usage_sample

        record_customer_usage_sample(customer, payload)
    except Exception:
        pass

    # Short cache so live speeds stay useful without hammering the API.
    cache.set(cache_key, payload, 8 if payload.get("session_active") else 4)
    return JsonResponse(payload)


@client_workspace_required
def clients_general_usage(request):
    """Organization-wide usage analytics and highest-users ranking."""
    org = resolve_organization(request.user, request)
    from billing.usage_samples import (
        clamp_usage_hours,
        org_usage_payload,
        sample_organization_usage,
        usage_range_label,
    )

    hours = clamp_usage_hours(request.GET.get("hours") or 72, default=72)

    if org:
        try:
            sample_organization_usage(org, force=False)
        except Exception:
            pass
        trends = org_usage_payload(org, hours=hours, auto_widen=True)
    else:
        trends = {
            "ok": False,
            "hours": hours,
            "requested_hours": hours,
            "auto_widened": False,
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
            page_subtitle="Organization-wide usage trends and highest data users.",
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
    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}

    try:
        sample_organization_usage(org, force=force)
    except Exception:
        pass
    return JsonResponse(
        org_usage_payload(org, hours=hours, auto_widen=True, use_cache=not force)
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
    can_access_wifi = bool(
        org
        and customer.service_type == Customer.ServiceType.PPPOE
        and customer.pppoe_username
        and customer.router_id
        and customer.router.account_status != MikroTikRouter.AccountStatus.SUSPENDED
    )
    hours = 24
    try:
        hours = max(1, min(int(request.GET.get("hours") or 24), 168))
    except (TypeError, ValueError):
        hours = 24

    from billing.usage_samples import usage_trend_payload

    if can_live:
        trends = usage_trend_payload(customer, hours=hours)
    else:
        if customer.service_type == Customer.ServiceType.HOTSPOT:
            error = (
                "No active MikroTik is available to collect Hotspot gadget usage."
                if not (customer.hotspot_mac or "").strip()
                else "No MikroTik router is available for this Hotspot gadget."
            )
        else:
            error = "Live usage trends are available for PPPoE clients with an assigned router."
        trends = {
            "ok": False,
            "hours": hours,
            "sample_count": 0,
            "labels": [],
            "series": {
                "uptime_minutes": [],
                "download_kbps": [],
                "upload_kbps": [],
                "data_used_mb": [],
            },
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
    return render(request, "core/client_usage_analysis.html", ctx)


@client_workspace_required
def client_billing(request, customer_id: int):
    """Dedicated page listing successful payments for one client."""
    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("plan", "router", "organization"),
        pk=customer_id,
        organization=org,
    )
    can_access_wifi = bool(
        org
        and customer.service_type == Customer.ServiceType.PPPOE
        and customer.pppoe_username
        and customer.router_id
        and customer.router.account_status != MikroTikRouter.AccountStatus.SUSPENDED
    )
    payments = (
        list(
            Payment.objects.filter(invoice__customer=customer, organization=org)
            .select_related("invoice")
            .order_by("-received_at")[:100]
        )
        if org
        else []
    )
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
        back_url=reverse("core:client_detail", kwargs={"customer_id": customer.pk}),
    )
    ctx["client_nav_main"] = [
        *CLIENT_COMMON_NAV_START,
        *build_client_detail_nav(customer, can_access_wifi=can_access_wifi),
    ]
    ctx["sidebar_label"] = "Client"
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
    try:
        hours = max(1, min(int(request.GET.get("hours") or 24), 168))
    except (TypeError, ValueError):
        hours = 24
    from billing.usage_samples import usage_trend_payload

    return JsonResponse(usage_trend_payload(customer, hours=hours))


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
    cache_key = f"clients_surfing:{org.pk}:{service}:v2"
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
        elif router_unreachable and not session_online:
            reason = router_error or "Router disconnected"
        else:
            internet_allowed = customer_receives_internet(customer)
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

        subscription_expired = False
        try:
            subscription_expired = customer_subscription_expired(customer)
        except Exception:
            subscription_expired = False

        if surfing:
            state = "surfing"
            label = "Surfing"
            surfing_count += 1
        elif subscription_expired:
            # Package ended — Internet column shows Expired (even if still dialed).
            state = "expired"
            label = "Expired"
            if not reason or "subscription" not in reason.lower():
                reason = _period_blocked_reason(customer)
        elif not session_online:
            # No live PPPoE/Hotspot session — show Disconnected in the Internet column.
            state = "disconnected"
            label = "Disconnected"
            if not reason:
                reason = (
                    router_error
                    or (
                        "Router not dialed — no active PPPoE session"
                        if service == "pppoe"
                        else "No active Hotspot session"
                    )
                )
        else:
            # Dialed/connected on the NAS but not getting internet (blocked, outside period, …).
            state = "not_surfing"
            label = "Not surfing"

        if connected:
            connected_count += 1
            connection_reason = (
                "Device connected to the Hotspot network"
                if service == "hotspot"
                else "Active PPPoE session"
            )
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
                "connection_label": "Connected" if connected else "Not connected",
                "connection_reason": connection_reason,
            }
        )

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

            def _bg_push(pk: int = router_pk, compulsory: bool = enabled) -> None:
                try:
                    live = MikroTikRouter.objects.select_related("organization").get(
                        pk=pk
                    )
                    apply_pppoe_enforcement_on_router(live, compulsory=compulsory)
                except Exception:
                    pass

            _schedule_mikrotik_job(_bg_push, name=f"pppoe-push-{router_pk}")
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

            def _bg_save_push(pk: int = router_pk, compulsory: bool = enabled) -> None:
                try:
                    live = MikroTikRouter.objects.select_related("organization").get(
                        pk=pk
                    )
                    apply_pppoe_enforcement_on_router(live, compulsory=compulsory)
                except Exception:
                    pass

            _schedule_mikrotik_job(_bg_save_push, name=f"pppoe-save-{router_pk}")
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
            ) -> None:
                try:
                    live_router = MikroTikRouter.objects.select_related(
                        "organization"
                    ).get(pk=r_pk)
                    live_org = Organization.objects.get(pk=o_pk)
                    apply_hotspot_on_router(
                        live_router,
                        enabled=on,
                        organization=live_org,
                        redirect_url=portal.get("redirect_url") or "",
                        login_url=portal.get("login_url") or "",
                        alogin_url=portal.get("alogin_url") or "",
                        pay_url=portal.get("pay_url") or "",
                        welcome_url=portal.get("welcome_url") or "",
                    )
                except Exception:
                    pass

            _schedule_mikrotik_job(_bg_hotspot_push, name=f"hotspot-push-{router_pk}")
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
            ) -> None:
                try:
                    live_router = MikroTikRouter.objects.select_related(
                        "organization"
                    ).get(pk=r_pk)
                    live_org = Organization.objects.get(pk=o_pk)
                    apply_hotspot_on_router(
                        live_router,
                        enabled=on,
                        organization=live_org,
                        redirect_url=portal.get("redirect_url") or "",
                        login_url=portal.get("login_url") or "",
                        alogin_url=portal.get("alogin_url") or "",
                        pay_url=portal.get("pay_url") or "",
                        welcome_url=portal.get("welcome_url") or "",
                    )
                except Exception:
                    pass

            _schedule_mikrotik_job(_bg_hotspot_save, name=f"hotspot-save-{router_pk}")
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
    mac = _normalize_hotspot_mac(mac)
    if not mac:
        return None
    return (
        Customer.objects.filter(
            organization=org,
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac=mac,
            status=Customer.Status.ACTIVE,
        )
        .select_related("plan", "organization", "router")
        .order_by("id")
        .first()
    )


def _ensure_customer_plan_in_list(org, plans, customer):
    """Keep the customer's current package selectable even if filtered out."""
    plans = list(plans or [])
    current_plan_id = getattr(customer, "plan_id", None) if customer else None
    if not current_plan_id or any(p.pk == current_plan_id for p in plans):
        return plans
    current_plan = (
        BillingPlan.objects.filter(
            pk=current_plan_id,
            organization=org,
            is_active=True,
        ).first()
    )
    if current_plan is not None:
        plans.insert(0, current_plan)
    return plans


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
    pppoe_customer = None
    if request is not None:
        link_login = (request.GET.get("link-login-only") or request.GET.get("link_login_only") or "").strip()
        link_orig = (request.GET.get("dst") or request.GET.get("link-orig") or "").strip()
        hotspot_mac = _resolve_request_hotspot_mac(org, request)
        error = (request.GET.get("error") or "").strip()
        if link_login:
            mikrotik_login = True
        # Returning PPPoE renewers may land on the Hotspot URL with a cookie/token.
        pppoe_customer = _find_pppoe_customer_from_token(
            org, request.GET.get("t") or ""
        )
        if pppoe_customer is None:
            pppoe_customer = _find_pppoe_customer_from_token(
                org, request.COOKIES.get("pppoe_pay") or ""
            )
        if pppoe_customer is None:
            account_q = (request.GET.get("account") or "").strip()
            phone_q = (request.GET.get("phone") or "").strip()
            if account_q or phone_q:
                pppoe_customer = _find_pppoe_customer_for_pay(
                    org,
                    account_number=account_q,
                    phone=phone_q,
                )

    from billing.services import plans_for_router
    from core.mikrotik_connect import find_hotspot_router_for_mac

    portal_router = None
    if hotspot_mac:
        portal_router = find_hotspot_router_for_mac(org, hotspot_mac)
    hotspot_customer = _find_hotspot_customer_for_mac(org, hotspot_mac)
    hotspot_plans = list(
        plans_for_router(
            org, portal_router, service_type=BillingPlan.ServiceType.HOTSPOT
        )[:8]
    )
    hotspot_plans = _ensure_customer_plan_in_list(org, hotspot_plans, hotspot_customer)
    pppoe_plans = list(
        plans_for_router(
            org, None, service_type=BillingPlan.ServiceType.PPPOE
        )[:8]
    )
    pppoe_plans = _ensure_customer_plan_in_list(org, pppoe_plans, pppoe_customer)
    plans = hotspot_plans
    has_payable_plans = bool(hotspot_plans or pppoe_plans)

    pppoe_option_available = bool(getattr(org, "pppoe_compulsory", False))
    pppoe_pay_url = ""
    pppoe_payment_start_url = ""
    if pppoe_option_available:
        pppoe_pay_url = public_absolute_url(
            reverse("core:pppoe_pay", kwargs={"join_code": org.join_code}),
            request,
        )
        pppoe_payment_start_url = public_absolute_url(
            reverse(
                "core:pppoe_payment_start", kwargs={"join_code": org.join_code}
            ),
            request,
        )

    hotspot_start = public_absolute_url(
        reverse("core:hotspot_payment_start", kwargs={"join_code": org.join_code}),
        request,
    )
    # Prefer PPPoE tab when this visitor is a known PPPoE client; otherwise Hotspot.
    portal_mode = "pppoe" if pppoe_customer is not None else "hotspot"
    pppoe_token = (
        _make_pppoe_customer_token(org, pppoe_customer) if pppoe_customer else ""
    )
    hotspot_phone = _payment_phone_autofill(
        getattr(hotspot_customer, "phone", "") if hotspot_customer else ""
    )
    pppoe_phone = _payment_phone_autofill(
        getattr(pppoe_customer, "phone", "") if pppoe_customer else ""
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
        "pppoe_plans": pppoe_plans,
        "has_payable_plans": has_payable_plans,
        "portal_mode": portal_mode,
        "show_payment_form": bool(hotspot_mac) or (
            pppoe_option_available and stk_ready and bool(pppoe_plans)
        ),
        "mikrotik_login": mikrotik_login,
        "link_login": link_login,
        "link_orig": link_orig or urls["welcome_url"],
        "hotspot_mac": hotspot_mac,
        "payment_start_url": hotspot_start,
        "hotspot_payment_start_url": hotspot_start,
        "welcome_url": urls["welcome_url"],
        "error": error,
        "pppoe_option_available": pppoe_option_available,
        "pppoe_pay_url": pppoe_pay_url,
        "pppoe_payment_start_url": pppoe_payment_start_url,
        "pppoe_require_account_lookup": pppoe_customer is None,
        "pppoe_account_locked": pppoe_customer is not None,
        "pppoe_customer_token": pppoe_token,
        "pppoe_customer_name": getattr(pppoe_customer, "full_name", "")
        if pppoe_customer
        else "",
        "pppoe_account_number": getattr(pppoe_customer, "account_number", "")
        if pppoe_customer
        else "",
        "pppoe_phone_value": pppoe_phone,
        "pppoe_selected_plan_id": getattr(pppoe_customer, "plan_id", None)
        if pppoe_customer
        else None,
        "pppoe_package_end": getattr(pppoe_customer, "package_end", None)
        if pppoe_customer
        else None,
        "pppoe_identify_error": (
            ""
            if pppoe_customer is not None
            else (
                "Enter the PPPoE account number or phone number for the router you want to renew."
                if pppoe_option_available
                else ""
            )
        ),
        "hotspot_option_available": True,
        "hotspot_ssids": [],
        "require_account_lookup": False,
        "customer_token": pppoe_token,
        "customer_name": getattr(pppoe_customer, "full_name", "")
        if pppoe_customer
        else (getattr(hotspot_customer, "full_name", "") if hotspot_customer else ""),
        "account_number": getattr(pppoe_customer, "account_number", "")
        if pppoe_customer
        else (getattr(hotspot_customer, "account_number", "") if hotspot_customer else ""),
        "phone_value": pppoe_phone or hotspot_phone,
        "selected_plan_id": (
            getattr(pppoe_customer, "plan_id", None)
            if pppoe_customer
            else getattr(hotspot_customer, "plan_id", None)
            if hotspot_customer
            else None
        ),
        "package_end": (
            getattr(pppoe_customer, "package_end", None)
            if pppoe_customer
            else getattr(hotspot_customer, "package_end", None)
            if hotspot_customer
            else None
        ),
        "identify_error": "",
        "dual_access_tabs": bool(pppoe_option_available),
        "hotspot_phone_value": hotspot_phone,
        "hotspot_selected_plan_id": getattr(hotspot_customer, "plan_id", None)
        if hotspot_customer
        else None,
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


def _make_pppoe_customer_token(org, customer) -> str:
    if customer is None or org is None:
        return ""
    return signing.dumps(
        {"cid": customer.pk, "org": org.pk, "mode": "pppoe"},
        salt="pppoe-payment",
        compress=True,
    )


@require_POST
def hotspot_payment_start(request, join_code: str):
    """Start public M-Pesa payment for a captive device; no Hotspot password."""
    from billing.stk import start_subscription_stk_payment

    org = get_object_or_404(Organization, join_code=join_code)
    mac = _resolve_request_hotspot_mac(org, request)
    if not mac:
        return JsonResponse(
            {"ok": False, "error": "Could not identify this device. Rejoin the Hotspot and try again."},
            status=400,
        )

    plan = get_object_or_404(
        BillingPlan,
        pk=request.POST.get("plan_id"),
        organization=org,
        is_active=True,
        service_type=BillingPlan.ServiceType.HOTSPOT,
    )
    phone = (request.POST.get("phone") or "").strip()
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

    account_number = f"HOT-{org.pk}-{mac.replace(':', '')}"[:40]
    from django.db import IntegrityError, transaction

    with transaction.atomic():
        customer = (
            Customer.objects.select_for_update()
            .filter(
                organization=org,
                service_type=Customer.ServiceType.HOTSPOT,
                hotspot_mac=mac,
            )
            .order_by("id")
            .first()
        )
        if customer is None:
            try:
                with transaction.atomic():
                    customer = Customer.objects.create(
                        organization=org,
                        full_name=f"Hotspot device {mac[-5:]}",
                        phone=phone,
                        account_number=account_number,
                        service_type=Customer.ServiceType.HOTSPOT,
                        hotspot_mac=mac,
                        status=Customer.Status.ACTIVE,
                        plan=plan,
                        router=router,
                    )
            except IntegrityError:
                customer = (
                    Customer.objects.filter(
                        organization=org,
                        service_type=Customer.ServiceType.HOTSPOT,
                        hotspot_mac=mac,
                    )
                    .order_by("id")
                    .first()
                )
                if customer is None:
                    raise
        if customer is not None:
            if customer.status != Customer.Status.ACTIVE:
                return JsonResponse(
                    {
                        "ok": False,
                        "error": (
                            "This device account is suspended. Contact your internet "
                            "provider before making a payment."
                        ),
                    },
                    status=403,
                )
            customer.phone = phone
            customer.router = router
            customer.save(update_fields=["phone", "router"])

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
        ),
        pk=stk_id,
        organization=org,
        customer__hotspot_mac=payload.get("mac"),
    )
    result = refresh_stk_status(stk)
    if result.get("success") and "authorized" not in result:
        stk.customer.refresh_from_db()
        provision = sync_customer_subscription_access(
            stk.customer,
            provision=True,
            reauthenticate=False,
        )
        result["authorized"] = bool(provision.get("ok") and provision.get("allowed"))
        if not result["authorized"]:
            result["authorization_error"] = (
                provision.get("message") or "Payment succeeded, but router authorization failed."
            )
            # The charge went through, so retrying payment would bill twice.
            # Authorization itself may be retried when the NAS comes back online.
            result["can_retry"] = False
            result["can_retry_authorize"] = True
            result["offline"] = bool(provision.get("offline"))
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
    Reauthenticate a paid MAC after its success page has loaded.

    Expiring the old RouterOS host during the status poll resets that client's
    network connection and can discard the success JSON before the captive
    browser redirects. This signed follow-up is intentionally fire-and-forget:
    the welcome page is already visible when RouterOS resets the connection.
    """
    from billing.models import StkPushRequest

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
        customer__hotspot_mac=payload.get("mac"),
        status=StkPushRequest.Status.SUCCESS,
        subscription_applied=True,
    )
    customer_pk = stk.customer_id

    def _bg_activate(pk: int = customer_pk) -> None:
        try:
            cust = Customer.objects.select_related(
                "plan", "router", "organization"
            ).get(pk=pk)
            sync_customer_subscription_access(
                cust,
                provision=True,
                reauthenticate=True,
            )
        except Exception:
            pass

    # Welcome page is already shown; reauth can reset the client's network.
    _schedule_mikrotik_job(_bg_activate, name=f"hotspot-activate-{customer_pk}")
    return JsonResponse(
        {
            "ok": True,
            "authorized": True,
            "queued": True,
            "can_retry_authorize": False,
            "offline": False,
            "message": "Reauthenticating on MikroTik in the background.",
        }
    )


def hotspot_pay(request, join_code: str):
    """Public Hotspot payment page (captive redirect target + preview)."""
    org = get_object_or_404(Organization, join_code=join_code)
    context = _hotspot_portal_context(org, mikrotik_login=False, request=request)
    response = render(request, "core/hotspot_portal_login.html", context)
    return _set_hotspot_mac_cookie(response, context.get("hotspot_mac") or "")


def _pppoe_portal_context(org, request, customer=None, identify_error: str = ""):
    from core.hotspot_portal import hotspot_portal_urls, public_absolute_url

    urls = hotspot_portal_urls(org.join_code, request)
    from billing.services import plans_for_router

    customer_router = getattr(customer, "router", None) if customer else None
    pppoe_plans = list(
        plans_for_router(
            org, customer_router, service_type=BillingPlan.ServiceType.PPPOE
        )[:8]
    )
    pppoe_plans = _ensure_customer_plan_in_list(org, pppoe_plans, customer)
    hotspot_plans = list(
        plans_for_router(
            org, None, service_type=BillingPlan.ServiceType.HOTSPOT
        )[:8]
    )
    # Prefer real MAC from the request / NAS IP lookup; otherwise keep MikroTik's
    # $(mac) so CPE / ISP Hotspot HTML files can substitute it when served by RouterOS.
    hotspot_mac = ""
    if request is not None:
        hotspot_mac = _resolve_request_hotspot_mac(org, request)
    hotspot_customer = _find_hotspot_customer_for_mac(org, hotspot_mac)
    hotspot_plans = _ensure_customer_plan_in_list(
        org, hotspot_plans, hotspot_customer
    )
    plans = pppoe_plans
    has_payable_plans = bool(pppoe_plans or hotspot_plans)
    has_mpesa = bool(org.mpesa_payment_type and org.mpesa_number)
    stk_ready = bool(org.effective_daraja_credentials().get("ready"))
    customer_token = ""
    if customer is not None:
        customer_token = _make_pppoe_customer_token(org, customer)
    hotspot_option_available = bool(getattr(org, "hotspot_enabled", False))
    hotspot_ssids = []
    if hotspot_option_available:
        hotspot_ssids = list(
            MikroTikRouter.objects.filter(
                organization=org,
                account_status=MikroTikRouter.AccountStatus.ACTIVE,
            )
            .exclude(wifi_ssid="")
            .values_list("wifi_ssid", flat=True)
            .distinct()[:8]
        )
    hotspot_mac_value = hotspot_mac or "$(mac)"
    show_payment_form = bool(stk_ready and pppoe_plans)
    pppoe_start = public_absolute_url(
        reverse("core:pppoe_payment_start", kwargs={"join_code": org.join_code}),
        request,
    )
    hotspot_start = public_absolute_url(
        reverse("core:hotspot_payment_start", kwargs={"join_code": org.join_code}),
        request,
    )
    # Known PPPoE client → PPPoE tab; otherwise start on Hotspot when available.
    if customer is not None:
        portal_mode = "pppoe"
    elif hotspot_option_available and hotspot_plans:
        portal_mode = "hotspot"
    else:
        portal_mode = "pppoe"
    phone_value = _payment_phone_autofill(
        getattr(customer, "phone", "") if customer else ""
    )
    hotspot_phone = _payment_phone_autofill(
        getattr(hotspot_customer, "phone", "") if hotspot_customer else ""
    )
    return {
        "organization": org,
        "org_name": org.name,
        "page_title": f"{org.name} Wi‑Fi",
        "page_message": (
            "Your subscription has ended. Choose a package and pay with M-Pesa "
            "to restore internet on this connection."
        ),
        "has_mpesa": has_mpesa,
        "stk_ready": stk_ready,
        "mpesa_type": org.mpesa_payment_type,
        "mpesa_number": org.mpesa_number,
        "mpesa_account": org.mpesa_account,
        "plans": plans,
        "hotspot_plans": hotspot_plans,
        "pppoe_plans": pppoe_plans,
        "has_payable_plans": has_payable_plans,
        "portal_mode": portal_mode,
        "show_payment_form": show_payment_form,
        "require_account_lookup": customer is None,
        "customer_token": customer_token,
        "customer_name": getattr(customer, "full_name", "") if customer else "",
        "account_number": getattr(customer, "account_number", "") if customer else "",
        "package_end": getattr(customer, "package_end", None) if customer else None,
        "phone_value": phone_value,
        "selected_plan_id": getattr(customer, "plan_id", None) if customer else None,
        "payment_start_url": pppoe_start,
        "pppoe_payment_start_url": pppoe_start,
        "hotspot_payment_start_url": hotspot_start,
        "welcome_url": urls["welcome_url"],
        "identify_error": identify_error,
        "error": "",
        "hotspot_mac": hotspot_mac_value,
        "mikrotik_login": False,
        "hotspot_option_available": hotspot_option_available,
        "hotspot_ssids": hotspot_ssids,
        "pppoe_option_available": False,
        "pppoe_pay_url": "",
        "pppoe_require_account_lookup": customer is None,
        "pppoe_account_locked": customer is not None,
        "pppoe_customer_token": customer_token,
        "pppoe_customer_name": getattr(customer, "full_name", "") if customer else "",
        "pppoe_account_number": getattr(customer, "account_number", "") if customer else "",
        "pppoe_phone_value": phone_value,
        "pppoe_selected_plan_id": getattr(customer, "plan_id", None) if customer else None,
        "pppoe_package_end": getattr(customer, "package_end", None) if customer else None,
        "pppoe_identify_error": identify_error,
        "dual_access_tabs": hotspot_option_available,
        "hotspot_phone_value": hotspot_phone,
        "hotspot_selected_plan_id": getattr(hotspot_customer, "plan_id", None)
        if hotspot_customer
        else None,
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
    """Resolve a PPPoE customer by account number or phone when IP match fails."""
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
    response = render(request, "core/hotspot_portal_login.html", context)
    response = _set_hotspot_mac_cookie(response, context.get("hotspot_mac") or "")
    if customer is not None:
        response = _set_pppoe_account_cookie(
            response, context.get("customer_token") or ""
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
    from billing.stk import start_subscription_stk_payment

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
    plan = get_object_or_404(
        BillingPlan,
        pk=request.POST.get("plan_id"),
        organization=org,
        is_active=True,
        service_type=BillingPlan.ServiceType.PPPOE,
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
    customer.phone = phone
    customer.save(update_fields=["phone"])

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
    result = refresh_stk_status(stk)
    if result.get("success") and "authorized" not in result:
        stk.customer.refresh_from_db()
        provision = sync_customer_subscription_access(
            stk.customer,
            provision=True,
            reauthenticate=False,
        )
        result["authorized"] = bool(provision.get("ok") and provision.get("allowed"))
        if not result["authorized"]:
            result["authorization_error"] = (
                provision.get("message")
                or "Payment succeeded, but the router could not restore this connection."
            )
            result["can_retry"] = False
            result["can_retry_authorize"] = True
            result["offline"] = bool(
                (provision.get("provision") or {}).get("timeout")
                or (provision.get("provision") or {}).get("skipped")
            )
    if request.GET.get("view") == "page":
        customer = stk.customer
        customer.refresh_from_db()
        waiting = bool(result.get("pending"))
        authorizing = bool(result.get("success") and not result.get("authorized"))
        refresh_url = request.get_full_path()
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
                "auto_refresh": waiting or authorizing,
                "refresh_url": refresh_url,
                "retry_url": reverse(
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
    HTML template for MikroTik hotspot/login.html (also usable as a direct preview).

    Captive clients are redirected to hotspot_pay; this page remains available for fetch.
    """
    org = get_object_or_404(Organization, join_code=join_code)
    ctx = _hotspot_portal_context(org, mikrotik_login=True, request=request)
    return render(
        request,
        "core/hotspot_portal_login.html",
        ctx,
        content_type="text/html; charset=utf-8",
    )


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
    employee = getattr(request.user, "employee_profile", None)
    viewing_client = bool(employee and is_viewing_as_client(request, employee))
    next_url = (request.POST.get("next") or "").strip() or reverse("core:my_account")
    if not next_url.startswith("/"):
        next_url = reverse("core:my_account")

    form = OwnerProfileForm(request.POST, user=request.user)
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
            can_edit=bool(org and (org.owner_id == request.user.id or viewing_client)),
            can_edit_profile=True,
            owner_profile_form=form,
            open_owner_profile_modal=True,
            platform_gateway=gateway,
            platform_gateway_ready=bool(gateway and gateway.is_stk_ready()),
            daraja_status=org.effective_daraja_credentials() if org else None,
            receive_type=(org.mpesa_payment_type if org else "") or "",
        ),
    )


def _owner_profile_form(user, data=None, *, id_prefix="owner"):
    kwargs = {
        "user": user,
        "id_prefix": id_prefix,
        "initial": {
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
        },
    }
    if data is not None:
        return OwnerProfileForm(data, **kwargs)
    return OwnerProfileForm(**kwargs)


def _account_org_context(request, org):
    employee = getattr(request.user, "employee_profile", None)
    viewing_client = bool(employee and is_viewing_as_client(request, employee))
    can_edit = bool(org and (org.owner_id == request.user.id or viewing_client))
    can_edit_profile = bool(
        not viewing_client
        and (
            (org and org.owner_id == request.user.id)
            or Organization.objects.filter(owner_id=request.user.id).exists()
        )
    )
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
    form = (
        OrganizationEditForm(instance=org, section=OrganizationEditForm.SECTION_PROFILE)
        if org and can_edit
        else None
    )
    account_profile_form = (
        _owner_profile_form(request.user, id_prefix="account")
        if can_edit_profile
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
            if can_edit_profile:
                account_profile_form = _owner_profile_form(
                    request.user, request.POST, id_prefix="account"
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
                    if account_profile_form.cleaned_data.get("password1"):
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
def my_account_daraja(request):
    """Receive subscription money + Daraja STK Push settings."""
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
            success_url_name="core:my_account_daraja",
            success_messages=_daraja_messages,
        )
        if early:
            return early

    return render(
        request,
        "core/my_account_daraja.html",
        client_page_context(
            request,
            active_nav="account",
            sidebar_active="account_daraja",
            page_title="Daraja STK Push",
            page_kicker="My account",
            page_subtitle=(
                "Set Paybill or Till for subscription collections, then configure Daraja STK Push."
            ),
            form=form,
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
    return render(
        request,
        "core/shop.html",
        client_page_context(
            request,
            active_nav="shop",
            page_title="Shop",
            page_kicker="Shop",
            page_subtitle="Browse and purchase products for your network.",
            empty_title="Shop",
            empty_text="No products available yet.",
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
            page_title="My system settings",
            page_kicker="Settings",
            page_subtitle="Organization status, join code, and workspace preferences.",
        ),
    )
