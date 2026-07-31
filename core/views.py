"""Client (organization owner) workspace helpers and module pages."""

import json
import re
import threading
from functools import wraps
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.core.cache import cache
from django.core import signing
from django.core.paginator import Paginator
from django.db.models import Count, Q, Sum
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from accounts.forms import HotspotSettingsForm, OrganizationEditForm, PppoeSettingsForm
from accounts.models import Employee, Organization, PaymentGateway
from accounts.routing import (
    can_switch_roles,
    get_client_view_organization,
    home_url_for_user,
    is_viewing_as_client,
)
from billing.forms import (
    CustomerPackageForm,
    CustomerPeriodForm,
    PppoeClientRegisterForm,
)
from billing.models import BillingPlan, Customer, Invoice, Payment
from billing.services import (
    customer_receives_internet,
    customer_subscription_expired,
    make_renew_token,
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
    apply_pppoe_enforcement_on_router,
    apply_hotspot_on_router,
    check_mikrotik_reachable,
    clear_mikrotik_uplink_multi,
    configure_mikrotik_wifi,
    fetch_active_pppoe_usernames,
    fetch_customer_cpe_live_usage,
    fetch_customer_pppoe_usage,
    fetch_mikrotik_live_snapshot,
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
from core.models import MikroTikRouter
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
            {"key": "sales", "label": "Sales representatives", "url_name": "core:sales_reps"},
            {"key": "technicians", "label": "Technicians", "url_name": "core:technicians"},
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
            {
                "key": "toggle_clean_uplink",
                "label": "Clean uplink",
                "action": "open_modal",
                "modal": "mikrotik-clean-uplink-modal",
            },
            {
                "key": "suspend_account",
                "label": "Suspend account",
                "action": "open_modal",
                "modal": "mikrotik-suspend-modal",
            },
        ],
    },
    "clients": {
        "label": "My clients",
        "items": [
            {"key": "clients", "label": "All clients", "url_name": "core:my_clients"},
            {
                "key": "register_pppoe",
                "label": "Register PPPoE client",
                "action": "open_modal",
                "modal": "pppoe-register-modal",
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
                "label": "Package period",
                "action": "open_modal",
                "modal": "client-package-period-modal",
            },
            {
                "key": "update_package",
                "label": "Update package",
                "action": "open_modal",
                "modal": "client-update-package-modal",
            },
            {"key": "billing", "label": "Billing analysis", "anchor": "client-billing"},
        ],
    },
    "billing": {
        "label": "Billings",
        "items": [
            {"key": "billing", "label": "Billing overview", "url_name": "billing:dashboard"},
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
            {"key": "account", "label": "Account details", "url_name": "core:my_account"},
        ],
    },
    "sales": {
        "label": "Sales representatives",
        "items": [
            {"key": "sales", "label": "Sales team", "url_name": "core:sales_reps"},
        ],
    },
    "technicians": {
        "label": "Technicians",
        "items": [
            {"key": "technicians", "label": "Technician team", "url_name": "core:technicians"},
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
    """Allow organization owners and IT Support client-view sessions."""

    @wraps(view_func)
    @login_required
    def _wrapped(request, *args, **kwargs):
        employee = getattr(request.user, "employee_profile", None)
        viewing_client = bool(employee and is_viewing_as_client(request, employee))
        if employee is not None and not viewing_client:
            return redirect(home_url_for_user(request.user, request))
        return view_func(request, *args, **kwargs)

    return _wrapped


def build_client_nav(active_nav: str) -> dict:
    """Dashboard at top, page links in the middle, settings + logout at the bottom."""
    sidebar = CLIENT_SIDEBARS.get(active_nav, CLIENT_SIDEBARS["workspace"])
    reserved = {"workspace", "settings", "logout"}
    page_items = [item for item in sidebar.get("items", []) if item.get("key") not in reserved]
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
    pppoe_url = reverse("core:mikrotik_pppoe_settings", kwargs={"router_id": router.pk})
    hotspot_url = reverse("core:mikrotik_hotspot_settings", kwargs={"router_id": router.pk})
    nav: list[dict] = [
        {"key": "overview", "label": "Router overview", "href": detail_url},
        {"key": "ports", "label": "Ports", "href": ports_url},
        {"key": "pppoe_settings", "label": "PPPoE settings", "href": pppoe_url},
        {"key": "hotspot_settings", "label": "Hotspot settings", "href": hotspot_url},
    ]
    if not include_modals:
        return nav

    for item in CLIENT_SIDEBARS["mikrotik_detail"]["items"]:
        if item.get("key") == "ports":
            continue
        row = dict(item)
        if row.get("key") == "suspend_account":
            row["label"] = "Activate account" if is_suspended else "Suspend account"
        elif row.get("key") == "toggle_wifi":
            row["label"] = "Deactivate Wi‑Fi" if wifi_enabled else "Activate Wi‑Fi"
        elif row.get("key") == "toggle_clean_uplink":
            row["label"] = (
                "Disable clean uplink" if clean_uplink_enabled else "Enable clean uplink"
            )
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


def build_client_detail_nav(customer, *, can_access_wifi: bool = False) -> list[dict]:
    """Sidebar items for a single client (sections + update package)."""
    base = reverse("core:client_detail", kwargs={"customer_id": customer.pk})
    nav: list[dict] = [
        {"key": "clients", "label": "All clients", "url_name": "core:my_clients"},
        {"key": "overview", "label": "Client details", "href": f"{base}#client-overview"},
    ]
    if (
        customer.service_type == Customer.ServiceType.PPPOE
        and customer.router_id
        and customer.pppoe_username
    ):
        nav.append({"key": "usage", "label": "Usage analysis", "href": f"{base}#client-usage"})
    if can_access_wifi:
        nav.append({"key": "wifi", "label": "Wi‑Fi settings", "href": f"{base}#client-wifi"})
    nav.extend(
        [
            {
                "key": "package",
                "label": "Package period",
                "action": "open_modal",
                "modal": "client-package-period-modal",
            },
            {
                "key": "update_package",
                "label": "Update package",
                "action": "open_modal",
                "modal": "client-update-package-modal",
            },
            {"key": "billing", "label": "Billing analysis", "href": f"{base}#client-billing"},
        ]
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
    """Choose the best Internet port from live data."""
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
    Auto map ports:
    - one Internet (WAN) from default route / ether1 / first live uplink
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
    return sorted(
        name for name, value in roles.items() if (value or "").strip().lower() == role
    )


def _bond_ports_from_roles(router: MikroTikRouter) -> list[str]:
    roles = router.port_roles if isinstance(router.port_roles, dict) else {}
    return _ports_by_role(roles, MikroTikRouter.PortRole.BOND)


def _failover_ports_from_roles(router: MikroTikRouter) -> tuple[str, list[str]]:
    roles = router.port_roles if isinstance(router.port_roles, dict) else {}
    primary = ""
    backups: list[str] = []
    for name, value in sorted(roles.items()):
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
    sidebar = CLIENT_SIDEBARS.get(active_nav, CLIENT_SIDEBARS["workspace"])
    nav = build_client_nav(active_nav)
    ctx = {
        "organization": org,
        "is_owner": is_owner,
        "active_nav": active_nav,
        "sidebar_label": sidebar["label"],
        "sidebar_active": sidebar_active or active_nav,
        "client_nav_main": nav["main"],
        "client_nav_end": nav["end"],
        "is_viewing_as_client": viewing_client,
        "can_switch_roles": can_switch_roles(employee) if employee else False,
    }
    ctx.update(extra)
    return ctx


@client_workspace_required
def workspace(request):
    """Main ISPCENTRIC workspace home — modules hub."""
    org = resolve_organization(request.user, request)
    if org:
        stats = {
            "employees": Employee.objects.filter(organization=org).aggregate(
                total=Count("id")
            )["total"]
            or 0,
            "customers": Customer.objects.filter(organization=org).aggregate(
                total=Count("id")
            )["total"]
            or 0,
            "revenue": Payment.objects.filter(organization=org).aggregate(
                total=Sum("amount")
            )["total"]
            or 0,
            "pending_invoices": Invoice.objects.filter(organization=org).aggregate(
                pending=Count("id", filter=Q(status="pending"))
            )["pending"]
            or 0,
        }
    else:
        stats = {
            "employees": 0,
            "customers": 0,
            "revenue": 0,
            "pending_invoices": 0,
        }

    return render(
        request,
        "core/workspace.html",
        client_page_context(
            request,
            active_nav="workspace",
            page_title="Workspace",
            stats=stats,
        ),
    )


@client_workspace_required
def mikrotik(request):
    org = resolve_organization(request.user, request)
    routers = (
        MikroTikRouter.objects.filter(organization=org)
        .only(
            "id",
            "name",
            "model",
            "location",
            "host",
            "username",
            "wifi_ssid",
            "account_status",
        )
        .order_by("name")
        if org
        else MikroTikRouter.objects.none()
    )
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
                    return render(
                        request,
                        "core/mikrotik.html",
                        client_page_context(
                            request,
                            active_nav="mikrotik",
                            page_title="MikroTik",
                            page_subtitle="Manage MikroTik routers, interfaces, and device health for this ISP.",
                            routers=routers,
                            onboard_form=form,
                            mikrotik_models=mikrotik_model_catalog(),
                            open_mikrotik_onboard=True,
                            wireguard_ready=wireguard.configured(),
                            hosted_server=bool(getattr(settings, "HOSTED", False)),
                        ),
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
            if org and getattr(org, "pppoe_compulsory", False):
                enforce = apply_pppoe_enforcement_on_router(router, compulsory=True)
                if enforce.get("ok"):
                    messages.info(
                        request,
                        "PPPoE enforcement applied on this router — unregistered devices cannot reach the internet.",
                    )
                else:
                    messages.warning(
                        request,
                        enforce.get("error")
                        or "Router onboarded, but PPPoE enforcement could not be applied yet.",
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

    return render(
        request,
        "core/mikrotik.html",
        client_page_context(
            request,
            active_nav="mikrotik",
            page_title="MikroTik",
            page_subtitle="Manage MikroTik routers, interfaces, and device health for this ISP.",
            routers=routers,
            onboard_form=form,
            mikrotik_models=mikrotik_model_catalog(),
            open_mikrotik_onboard=open_onboard,
            wireguard_ready=wireguard.configured(),
            hosted_server=bool(getattr(settings, "HOSTED", False)),
        ),
    )


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
    suspend_form = MikroTikSuspendForm()
    wifi_form = MikroTikWifiToggleForm()
    clean_uplink_enabled = bool(router.clean_uplink_enabled)
    clean_uplink_form = MikroTikCleanUplinkForm(
        initial={
            "mode": router.clean_uplink_mode or MikroTikRouter.CleanUplinkMode.BYPASS,
            "wan_interface": router.wan_interface or "ether1",
            "lan_bridge": router.lan_bridge or "bridgeLocal",
            "provider_gateway": router.provider_gateway or "192.168.1.1",
            "separate_wan": router.clean_uplink_separate_wan,
        }
    )
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
        elif action == "toggle_clean_uplink":
            if is_suspended:
                messages.error(
                    request,
                    "Activate this MikroTik account before changing clean uplink.",
                )
                return redirect("core:mikrotik_detail", router_id=router.pk)

            clean_uplink_form = MikroTikCleanUplinkForm(request.POST)
            if clean_uplink_form.is_valid():
                cleaned = clean_uplink_form.cleaned_data
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
                    clean_uplink_form.add_error(
                        None,
                        result.get("error")
                        or "Could not update clean uplink on the MikroTik.",
                    )
                    open_modal = "mikrotik-clean-uplink-modal"
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
                    clean_uplink_enabled = router.clean_uplink_enabled
                    messages.success(
                        request,
                        result.get("message")
                        or (
                            "Clean uplink enabled on the MikroTik."
                            if turn_on
                            else "Clean uplink disabled on the MikroTik."
                        ),
                    )
                    return redirect("core:mikrotik_detail", router_id=router.pk)
            else:
                open_modal = "mikrotik-clean-uplink-modal"
        elif action == "suspend_account":
            suspend_form = MikroTikSuspendForm(request.POST)
            if suspend_form.is_valid():
                if is_suspended:
                    router.account_status = MikroTikRouter.AccountStatus.ACTIVE
                    router.save(update_fields=["account_status", "updated_at"])
                    messages.success(request, f"“{router.name}” account activated.")
                else:
                    router.account_status = MikroTikRouter.AccountStatus.SUSPENDED
                    router.save(update_fields=["account_status", "updated_at"])
                    messages.success(request, f"“{router.name}” account suspended.")
                return redirect("core:mikrotik_detail", router_id=router.pk)
            open_modal = "mikrotik-suspend-modal"

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
        suspend_form=suspend_form,
        wifi_form=wifi_form,
        clean_uplink_form=clean_uplink_form,
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
                    backup_ports = sorted(
                        key
                        for key, value in roles.items()
                        if (value or "").strip().lower() == MikroTikRouter.PortRole.WAN_BACKUP
                    )
                    router.uplink_ports = [port_name, *backup_ports]
                else:
                    router.uplink_mode = MikroTikRouter.UplinkMode.SINGLE
                    router.uplink_ports = [port_name]
                update_fields.extend(["wan_interface", "uplink_mode", "uplink_ports"])
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
                    backup_ports = sorted(
                        name
                        for name, existing in roles.items()
                        if (existing or "").strip().lower() == MikroTikRouter.PortRole.WAN_BACKUP
                    )
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
            if single_wan == (router.bond_interface or "").strip() or single_wan.startswith(
                "bond"
            ):
                single_wan = "ether1"
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


def _ports_live_payload(router: MikroTikRouter) -> dict:
    """Read live ports/uplink and optionally auto-assign empty role maps."""
    listed = list_mikrotik_ports(
        router.host,
        router.username,
        router.password or "",
        timeout=6.0,
    )
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

    uplink_live = read_mikrotik_uplink_multi(
        router.host,
        router.username,
        router.password or "",
        timeout=5.0,
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

    snapshot = fetch_mikrotik_live_snapshot(
        router.host,
        router.username,
        router.password,
        timeout=5.0,
    )
    snapshot["router_id"] = router.pk
    snapshot["host"] = router.host

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

    return JsonResponse(
        {
            "ok": True,
            "configured": True,
            "label": payload["label"],
            "address": payload["address"],
            "script": payload["script"],
            "server_peer": payload["server_peer"],
            "endpoint": payload["endpoint"],
            "hint": (
                f"Paste into Winbox → New Terminal and wait for “ispcentric OK”. "
                f"Then Connect using MikroTik IP {payload['address']}."
            ),
        }
    )


@client_workspace_required
@require_POST
def mikrotik_connect(request):
    """Verify RouterOS API credentials before onboard step."""
    host = (request.POST.get("host") or "").strip()
    username = (request.POST.get("username") or "").strip()
    password = request.POST.get("password") or ""

    result = test_mikrotik_api_login(host, username, password)
    if not result.get("ok"):
        return JsonResponse(
            {"ok": False, "error": result.get("error") or "Connection failed."},
            status=400,
        )

    board = result.get("board") or ""
    return JsonResponse(
        {
            "ok": True,
            "host": result.get("host") or host,
            "name": result.get("name") or "",
            "identity": result.get("identity") or "",
            "version": result.get("version") or "",
            "board": board,
            "model": guess_model(board),
            "username": username,
            "wifi_ssid": result.get("wifi_ssid") or "",
            "wifi_password": result.get("wifi_password") or "",
            "wifi_mode": result.get("wifi_mode") or "",
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
                "id", "host", "name", "username", "password"
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
            return JsonResponse({"ok": True, "routers": cached})

    results = {}

    def _check(router):
        # Parallel multi-port probe; 1.2s is enough without false timeouts on LAN.
        probe = check_mikrotik_reachable(router.host, timeout=1.2)
        via = probe.get("via") or ""
        online = bool(probe.get("online"))
        auth_ok = None
        status = "disconnected"
        error = ""
        if online and via == "api":
            # Port 8728 is open — verify saved credentials so "Connected" means usable.
            login = test_mikrotik_api_login(
                router.host,
                router.username,
                router.password or "",
                timeout=2.5,
            )
            if login.get("ok"):
                auth_ok = True
                status = "connected"
            else:
                auth_ok = False
                status = "auth_failed"
                error = login.get("error") or "Login failed"
        elif online and via == "ping":
            status = "limited"
        elif online:
            # Winbox/HTTP up, but don't claim API credentials work.
            status = "reachable"

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

    payload = [
        results.get(
            router.id,
            {
                "id": router.id,
                "host": router.host,
                "name": router.name,
                "online": False,
                "status": "disconnected",
                "via": "",
            },
        )
        for router in routers
    ]
    # Cache online results longer; offline only briefly so recoveries show quickly.
    any_online = any(item.get("online") for item in payload)
    cache.set(cache_key, payload, 15 if any_online else 3)
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
                provision = provision_customer_pppoe(customer)
                if provision.get("ok"):
                    messages.success(
                        request,
                        (
                            f"PPPoE client “{customer.full_name}” registered "
                            f"({customer.account_number}). "
                            f"{provision.get('message') or 'Login installed on MikroTik.'}"
                        ),
                    )
                else:
                    messages.warning(
                        request,
                        (
                            f"PPPoE client “{customer.full_name}” saved "
                            f"({customer.account_number}), but the username/password "
                            f"was not installed on the MikroTik yet — "
                            f"{provision.get('error') or 'API unreachable'}. "
                            "Open MikroTik → Reconnect, then push PPPoE settings "
                            "(or re-save this client) before the CPE can dial in."
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

    tab_qs = (
        base_qs.filter(service_type=service_type)
        .select_related("plan", "router")
        .order_by("-created_at")
    )
    paginator = Paginator(tab_qs, 100)
    page_obj = paginator.get_page(request.GET.get("page") or 1)
    page_customers = list(page_obj)

    pppoe_customers = page_customers if tab == "pppoe" else []
    static_customers = page_customers if tab == "static" else []
    hotspot_customers = page_customers if tab == "hotspot" else []

    return render(
        request,
        "core/my_clients.html",
        client_page_context(
            request,
            active_nav="clients",
            page_title="My clients",
            page_kicker="Subscribers",
            page_subtitle="Internet customers linked to this organization, grouped by service type.",
            active_tab=tab,
            pppoe_customers=pppoe_customers,
            static_customers=static_customers,
            hotspot_customers=hotspot_customers,
            pppoe_count=pppoe_count,
            static_count=static_count,
            hotspot_count=hotspot_count,
            clients_page=page_obj,
            pppoe_form=pppoe_form,
            open_client_modal=open_modal,
            billing_plans_exist=bool(
                org
                and BillingPlan.objects.filter(organization=org, is_active=True).exists()
            ),
        ),
    )


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
    package_form = CustomerPackageForm(instance=customer, organization=org)
    package_period_form = CustomerPeriodForm(instance=customer, organization=org)
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

    def _package_json_response(customer, *, message: str, provision: bool) -> JsonResponse:
        from django.utils import timezone as dj_tz

        allowed = customer_receives_internet(customer)
        expired = customer_subscription_expired(customer)
        is_hourly = bool(
            customer.plan_id
            and getattr(customer.plan, "duration", "") == "hourly"
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
        if action == "update_package":
            package_form = CustomerPackageForm(request.POST, instance=customer, organization=org)
            if package_form.is_valid():
                customer = package_form.save()
                provision = bool(customer.pppoe_username and customer.router_id)
                _enqueue_subscription_sync(customer.pk, provision)

                if is_ajax:
                    return _package_json_response(
                        customer,
                        message=(
                            f"Package updated to {customer.plan.name}."
                            if customer.plan_id
                            else "Package updated."
                        ),
                        provision=provision,
                    )

                messages.success(
                    request,
                    f"Package updated to {customer.plan.name}." if customer.plan_id else "Package updated.",
                )
                return redirect("core:client_detail", customer_id=customer.pk)

            if is_ajax:
                errors = json.loads(package_form.errors.as_json())
                return JsonResponse({"ok": False, "errors": errors}, status=400)
            open_client_modal = "client-update-package-modal"

        elif action == "update_package_period":
            package_period_form = CustomerPeriodForm(request.POST, instance=customer, organization=org)
            if package_period_form.is_valid():
                customer = package_period_form.save()
                provision = bool(customer.pppoe_username and customer.router_id)
                _enqueue_subscription_sync(customer.pk, provision)

                if is_ajax:
                    return _package_json_response(
                        customer,
                        message=(
                            f"Package period updated "
                            f"({customer.package_start.isoformat()} → {customer.package_end.isoformat()})."
                            if customer.package_start and customer.package_end
                            else "Package period updated."
                        ),
                        provision=provision,
                    )

                if customer.package_start and customer.package_end:
                    messages.success(
                        request,
                        f"Package period updated "
                        f"({customer.package_start.isoformat()} → {customer.package_end.isoformat()}).",
                    )
                else:
                    messages.success(request, "Package period updated.")
                return redirect("core:client_detail", customer_id=customer.pk)

            if is_ajax:
                errors = json.loads(package_period_form.errors.as_json())
                return JsonResponse({"ok": False, "errors": errors}, status=400)
            open_client_modal = "client-package-period-modal"


    invoices = (
        list(
            Invoice.objects.filter(customer=customer, organization=org)
            .order_by("-issued_at")[:8]
        )
        if org
        else []
    )
    payments = (
        list(
            Payment.objects.filter(invoice__customer=customer, organization=org)
            .select_related("invoice")
            .order_by("-received_at")[:8]
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
            billed=Sum("amount"),
        )
        if org
        else {}
    )
    paid_total = (
        Payment.objects.filter(invoice__customer=customer, organization=org).aggregate(
            total=Sum("amount")
        )["total"]
        if org
        else None
    ) or 0

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
        invoices=invoices,
        payments=payments,
        invoice_total=invoice_stats.get("total") or 0,
        invoice_pending=invoice_stats.get("pending") or 0,
        invoice_paid=invoice_stats.get("paid") or 0,
        invoice_overdue=invoice_stats.get("overdue") or 0,
        amount_billed=invoice_stats.get("billed") or 0,
        amount_paid=paid_total,
        can_live_usage=bool(
            customer.router_id
            and customer.pppoe_username
            and customer.service_type == Customer.ServiceType.PPPOE
        ),
        can_access_wifi=can_access_wifi,
        wifi_ssid_display=wifi_ssid_display,
        wifi_password_display=wifi_password_display,
        package_form=package_form,
        package_period_form=package_period_form,
        package_duration=getattr(customer.plan, "duration", "") or "",
        package_duration_label=(
            customer.plan.get_duration_display() if customer.plan_id else ""
        ),
        plan_durations_json=json.dumps(
            {
                str(p.pk): p.duration
                for p in BillingPlan.objects.filter(organization=org, is_active=True)
            }
            if org
            else {}
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

    live = access_customer_cpe_wifi(
        nas.host,
        nas.username,
        nas.password or "",
        pppoe_username=customer.pppoe_username,
        cpe_username=customer.cpe_username or "admin",
        cpe_password=customer.cpe_password or "",
        pppoe_password=customer.pppoe_password or "",
        timeout=6.0,
        # Status polls must stay fast — SSH auto-enable is for POST / explicit setup.
        auto_enable=(request.GET.get("setup") or "").strip() in {"1", "true", "yes"},
    )

    wifi_ssid = (live.get("wifi_ssid") or "").strip() or (customer.cpe_wifi_ssid or "").strip()
    wifi_password = live.get("wifi_password") or customer.cpe_wifi_password or ""
    auth_ok = bool(live.get("auth_ok"))

    if auth_ok:
        update_fields: list[str] = []
        if wifi_ssid and wifi_ssid != (customer.cpe_wifi_ssid or ""):
            customer.cpe_wifi_ssid = wifi_ssid
            update_fields.append("cpe_wifi_ssid")
        if wifi_password and wifi_password != (customer.cpe_wifi_password or ""):
            customer.cpe_wifi_password = wifi_password
            update_fields.append("cpe_wifi_password")
        working_user = (live.get("cpe_username") or "").strip()
        working_pass = live.get("cpe_password")
        if working_user and working_user != (customer.cpe_username or ""):
            customer.cpe_username = working_user
            update_fields.append("cpe_username")
        if working_pass is not None and working_pass != (customer.cpe_password or ""):
            customer.cpe_password = working_pass
            update_fields.append("cpe_password")
        if update_fields:
            customer.save(update_fields=update_fields)

    payload = {
        "ok": True,
        "customer_id": customer.pk,
        "session_active": bool(live.get("session_active")),
        "auth_ok": auth_ok,
        "cpe_host": (live.get("cpe_host") or "").strip(),
        "wifi_enabled": bool(live.get("wifi_enabled")) if auth_ok else False,
        "wifi_ssid": wifi_ssid,
        "wifi_password": wifi_password if auth_ok else (customer.cpe_wifi_password or ""),
        "hint": live.get("hint") or "",
        "error": live.get("error") or "",
        "firewall_blocked": bool(live.get("firewall_blocked"))
        or ("firewall is blocking" in ((live.get("error") or "") + (live.get("hint") or "")).lower()),
        "prep_steps": list(live.get("prep_steps") or []),
        "cpe_username": (customer.cpe_username or "").strip() or "admin",
    }
    cache.set(cache_key, payload, 12 if auth_ok else 5)
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
    is_hourly = duration == "hourly"
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
    """JSON live PPPoE session / traffic usage for one client."""
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization."}, status=400)

    customer = get_object_or_404(
        Customer.objects.select_related("router"),
        pk=customer_id,
        organization=org,
    )
    router = customer.router
    if not router:
        return JsonResponse(
            {
                "ok": False,
                "session_active": False,
                "error": "No MikroTik router is assigned to this client.",
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
    if not customer.pppoe_username:
        return JsonResponse(
            {
                "ok": False,
                "session_active": False,
                "error": "This client has no PPPoE username.",
            }
        )

    cache_key = f"client_usage:{org.pk}:{customer.pk}"
    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            return JsonResponse(cached)

    payload = fetch_customer_pppoe_usage(
        router.host,
        router.username,
        router.password or "",
        pppoe_username=customer.pppoe_username,
    )
    payload["customer_id"] = customer.pk
    payload["router_id"] = router.pk
    payload["router_name"] = router.name
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

    # Short cache so live speeds stay useful without hammering the API.
    cache.set(cache_key, payload, 8 if payload.get("session_active") else 4)
    return JsonResponse(payload)


@client_workspace_required
@require_GET
def clients_surfing_status(request):
    """
    Live Surfing / Not surfing for PPPoE clients on this organization.

    Groups by assigned MikroTik and reads /ppp/active once per router.
    """
    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization.", "clients": []}, status=400)

    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    cache_key = f"clients_surfing:{org.pk}"
    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            return JsonResponse(cached)

    customers = list(
        Customer.objects.filter(
            organization=org,
            service_type=Customer.ServiceType.PPPOE,
        )
        .exclude(pppoe_username="")
        .select_related("router", "organization")
        .order_by("id")
    )

    by_router: dict[int, list] = {}
    for customer in customers:
        if not customer.router_id:
            continue
        by_router.setdefault(customer.router_id, []).append(customer)

    online_by_router: dict[int, set[str]] = {}
    router_errors: dict[int, str] = {}

    def _probe_router(router_id: int, group: list) -> tuple[int, set[str], str]:
        router = group[0].router
        if router is None:
            return router_id, set(), "No router"
        if router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
            return router_id, set(), "Router suspended"
        result = fetch_active_pppoe_usernames(
            router.host,
            router.username,
            router.password,
            timeout=4.0,
        )
        if result.get("ok"):
            return router_id, {n.lower() for n in (result.get("usernames") or [])}, ""
        return router_id, set(), result.get("error") or "Could not reach router"

    if by_router:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        workers = min(8, len(by_router))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(_probe_router, router_id, group)
                for router_id, group in by_router.items()
            ]
            for future in as_completed(futures):
                router_id, names, error = future.result()
                online_by_router[router_id] = names
                if error:
                    router_errors[router_id] = error

    clients_payload = []
    surfing_count = 0
    for customer in customers:
        username = (customer.pppoe_username or "").strip().lower()
        surfing = False
        reason = ""
        if customer.status != Customer.Status.ACTIVE:
            reason = customer.get_status_display()
        elif not customer_receives_internet(customer):
            if customer_subscription_expired(customer):
                reason = "Subscription expired"
            else:
                reason = "Outside package period"
        elif not customer.router_id:
            reason = "No router"
        else:
            active_names = online_by_router.get(customer.router_id) or set()
            surfing = bool(username and username in active_names)
            if not surfing:
                reason = router_errors.get(customer.router_id) or "Offline"
        if surfing:
            surfing_count += 1
            reason = "Online"
        clients_payload.append(
            {
                "id": customer.pk,
                "surfing": surfing,
                "label": "Surfing" if surfing else "Not surfing",
                "reason": reason,
            }
        )

    payload = {
        "ok": True,
        "clients": clients_payload,
        "surfing_count": surfing_count,
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
            f"{prefix}PPPoE enforcement pushed to {name}.{secret_bit}",
        )
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
            result = apply_pppoe_enforcement_on_router(router, compulsory=enabled)
            _pppoe_push_messages(request, result, enabled=enabled)
            return redirect("core:mikrotik_pppoe_settings", router_id=router.pk)

        form = PppoeSettingsForm(request.POST, instance=org)
        if form.is_valid():
            form.save()
            enabled = bool(form.cleaned_data.get("pppoe_compulsory"))
            result = apply_pppoe_enforcement_on_router(router, compulsory=enabled)
            if enabled:
                messages.success(
                    request,
                    "PPPoE enforcement enabled. Free LAN browsing is blocked on this router; "
                    "dialed PPPoE clients and Hotspot logins (if enabled) can reach the internet.",
                )
            else:
                messages.success(request, "PPPoE enforcement disabled.")
            _pppoe_push_messages(request, result, enabled=enabled, saved=True)
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
        sidebar_active="pppoe_settings",
        page_title=f"{router.name} — PPPoE",
        page_kicker="Access",
        page_subtitle=f"PPPoE enforcement and client logins for {router.name}.",
        form=form,
        can_edit=can_edit,
        organization=org,
        pppoe_compulsory=pppoe_compulsory,
        pppoe_eligible_count=pppoe_eligible_count,
        blocked_count=blocked_count,
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
            result = apply_hotspot_on_router(
                router,
                enabled=enabled,
                organization=org,
                redirect_url=redirect_url if enabled else "",
                login_url=urls["login_url"] if enabled else "",
                alogin_url=urls["alogin_url"] if enabled else "",
                pay_url=urls["pay_url"] if enabled else "",
                welcome_url=urls["welcome_url"] if enabled else "",
            )
            _push_one(result, enabled=enabled)
            if enabled and org.pppoe_compulsory and result.get("ok") and not result.get("skipped"):
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
            return redirect("core:mikrotik_hotspot_settings", router_id=router.pk)

        form = HotspotSettingsForm(request.POST, instance=org)
        if form.is_valid():
            org = form.save(commit=False)
            urls = _portal_urls_for(org)
            if org.hotspot_use_welcome_page:
                org.hotspot_redirect_url = urls["welcome_url"]
            org.save()
            enabled = bool(org.hotspot_enabled)
            result = apply_hotspot_on_router(
                router,
                enabled=enabled,
                organization=org,
                redirect_url=org.hotspot_redirect_url if enabled else "",
                login_url=urls["login_url"] if enabled else "",
                alogin_url=urls["alogin_url"] if enabled else "",
                pay_url=urls["pay_url"] if enabled else "",
                welcome_url=urls["welcome_url"] if enabled else "",
            )
            _push_one(result, enabled=enabled, saved=True)
            if enabled and org.pppoe_compulsory and result.get("ok") and not result.get("skipped"):
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
        sidebar_active="hotspot_settings",
        page_title=f"{router.name} — Hotspot",
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
        router_count=1,
        pppoe_compulsory=bool(org.pppoe_compulsory),
    )
    return render(
        request,
        "core/hotspot_settings.html",
        apply_mikrotik_detail_sidebar(ctx, router, detail_nav=detail_nav),
    )


def _hotspot_portal_context(org, *, mikrotik_login: bool = False, request=None):
    from core.hotspot_portal import hotspot_portal_urls

    urls = hotspot_portal_urls(org.join_code, request)
    title = (org.hotspot_portal_title or "").strip() or f"{org.name} Wi‑Fi"
    message = (org.hotspot_login_message or "").strip() or (
        "Choose a package and pay with M-Pesa. This device will connect automatically."
    )
    plans = list(
        BillingPlan.objects.filter(organization=org, is_active=True).order_by("price")[:8]
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
        hotspot_mac = _normalize_hotspot_mac(request.GET.get("mac") or "")
        error = (request.GET.get("error") or "").strip()
        if link_login:
            mikrotik_login = True

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
        "portal_mode": "hotspot",
        "show_payment_form": bool(mikrotik_login and hotspot_mac),
        "mikrotik_login": mikrotik_login,
        "link_login": link_login,
        "link_orig": link_orig or urls["welcome_url"],
        "hotspot_mac": hotspot_mac,
        "payment_start_url": reverse(
            "core:hotspot_payment_start", kwargs={"join_code": org.join_code}
        ),
        "welcome_url": urls["welcome_url"],
        "error": error,
    }


def _normalize_hotspot_mac(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if len(compact) != 12:
        return ""
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).upper()


@require_POST
def hotspot_payment_start(request, join_code: str):
    """Start public M-Pesa payment for a captive device; no Hotspot password."""
    from billing.stk import start_subscription_stk_payment

    org = get_object_or_404(Organization, join_code=join_code)
    mac = _normalize_hotspot_mac(request.POST.get("mac") or "")
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

    account_number = f"HOT-{org.pk}-{mac.replace(':', '')}"[:40]
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
    else:
        customer.phone = phone
        customer.plan = plan
        customer.router = router
        customer.status = Customer.Status.ACTIVE
        customer.save(update_fields=["phone", "plan", "router", "status"])

    result = start_subscription_stk_payment(
        organization=org,
        customer=customer,
        phone=phone,
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
    if result.get("success"):
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
            # The charge went through, so retrying would bill the customer twice.
            result["can_retry"] = False
    return JsonResponse(result)


def hotspot_welcome(request, join_code: str):
    """Public post-login landing page shown after Hotspot authentication."""
    org = get_object_or_404(Organization, join_code=join_code)
    title = (org.hotspot_welcome_title or "").strip() or "You're online"
    message = (org.hotspot_welcome_message or "").strip() or (
        f"Welcome to {org.name}. Your internet session is active — continue browsing."
    )
    button_label = (org.hotspot_welcome_button_label or "").strip() or "Continue browsing"
    button_url = (org.hotspot_welcome_button_url or "").strip()
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
    provision = sync_customer_subscription_access(
        stk.customer,
        provision=True,
        reauthenticate=True,
    )
    return JsonResponse(
        {
            "ok": bool(provision.get("ok") and provision.get("allowed")),
            "authorized": bool(provision.get("ok") and provision.get("allowed")),
        }
    )


def hotspot_pay(request, join_code: str):
    """Public Hotspot payment page (captive redirect target + preview)."""
    org = get_object_or_404(Organization, join_code=join_code)
    return render(
        request,
        "core/hotspot_portal_login.html",
        _hotspot_portal_context(org, mikrotik_login=False, request=request),
    )


def _pppoe_portal_context(org, request, customer=None, identify_error: str = ""):
    from core.hotspot_portal import hotspot_portal_urls

    urls = hotspot_portal_urls(org.join_code, request)
    plans = list(
        BillingPlan.objects.filter(organization=org, is_active=True).order_by("price")[:8]
    )
    has_mpesa = bool(org.mpesa_payment_type and org.mpesa_number)
    stk_ready = bool(org.effective_daraja_credentials().get("ready"))
    customer_token = ""
    if customer is not None:
        customer_token = signing.dumps(
            {"cid": customer.pk, "org": org.pk, "mode": "pppoe"},
            salt="pppoe-payment",
            compress=True,
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
        "portal_mode": "pppoe",
        "show_payment_form": customer is not None,
        "customer_token": customer_token,
        "customer_name": getattr(customer, "full_name", "") if customer else "",
        "account_number": getattr(customer, "account_number", "") if customer else "",
        "package_end": getattr(customer, "package_end", None) if customer else None,
        "phone_value": (getattr(customer, "phone", "") or "") if customer else "",
        "selected_plan_id": getattr(customer, "plan_id", None) if customer else None,
        "payment_start_url": reverse(
            "core:pppoe_payment_start", kwargs={"join_code": org.join_code}
        ),
        "welcome_url": urls["welcome_url"],
        "identify_error": identify_error,
        "error": "",
        "hotspot_mac": "",
        "mikrotik_login": False,
    }


def pppoe_pay(request, join_code: str):
    """Public renew page for expired PPPoE sessions (dst-nat captive target)."""
    org = get_object_or_404(Organization, join_code=join_code)
    remote = (request.META.get("REMOTE_ADDR") or "").strip()
    customer = find_pppoe_customer_for_ip(org, remote)
    identify_error = ""
    if customer is None:
        identify_error = (
            "Could not match this connection to a PPPoE account. "
            "Confirm the client router is dialed, then open any http:// page again."
        )
    return render(
        request,
        "core/hotspot_portal_login.html",
        _pppoe_portal_context(
            org, request, customer=customer, identify_error=identify_error
        ),
    )


@require_POST
def pppoe_payment_start(request, join_code: str):
    """Start M-Pesa STK Push for an identified PPPoE customer."""
    from billing.stk import start_subscription_stk_payment

    org = get_object_or_404(Organization, join_code=join_code)
    try:
        payload = signing.loads(
            request.POST.get("customer_token") or "",
            salt="pppoe-payment",
            max_age=60 * 60 * 6,
        )
    except signing.BadSignature:
        return JsonResponse(
            {"ok": False, "error": "Payment session expired. Reload the page and try again."},
            status=400,
        )
    if payload.get("org") != org.pk or payload.get("mode") != "pppoe":
        return JsonResponse({"ok": False, "error": "Invalid payment session."}, status=400)

    customer = get_object_or_404(
        Customer.objects.select_related("plan", "organization", "router"),
        pk=payload.get("cid"),
        organization=org,
        service_type=Customer.ServiceType.PPPOE,
    )
    plan = get_object_or_404(
        BillingPlan,
        pk=request.POST.get("plan_id"),
        organization=org,
        is_active=True,
    )
    phone = (request.POST.get("phone") or "").strip() or (customer.phone or "")
    customer.phone = phone
    customer.plan = plan
    if customer.status != Customer.Status.ACTIVE:
        # Payment is the path back online; an inactive account that can still
        # dial (blocked profile) is reactivated when they renew.
        customer.status = Customer.Status.ACTIVE
    customer.save(update_fields=["phone", "plan", "status"])

    result = start_subscription_stk_payment(
        organization=org,
        customer=customer,
        phone=phone,
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
    if result.get("success"):
        stk.customer.refresh_from_db()
        # PPPoE provision already kicks the live session when the profile flips
        # from blocked → normal, so the CPE redials onto a surfing profile.
        provision = sync_customer_subscription_access(
            stk.customer,
            provision=True,
        )
        result["authorized"] = bool(provision.get("ok") and provision.get("allowed"))
        if not result["authorized"]:
            result["authorization_error"] = (
                provision.get("message")
                or "Payment succeeded, but the router could not restore this connection."
            )
            result["can_retry"] = False
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
def my_account(request):
    org = resolve_organization(request.user, request)
    employee = getattr(request.user, "employee_profile", None)
    viewing_client = bool(employee and is_viewing_as_client(request, employee))
    can_edit = bool(org and (org.owner_id == request.user.id or viewing_client))
    platform_gateway = PaymentGateway.get_solo() if org else None

    if request.method == "POST" and can_edit and org:
        form = OrganizationEditForm(request.POST, request.FILES, instance=org)
        if form.is_valid():
            org = form.save()
            creds = org.effective_daraja_credentials()
            if org.daraja_enabled and creds.get("ready"):
                messages.success(
                    request,
                    "Account saved. Daraja STK Push is ready "
                    f"({creds.get('source_label')}).",
                )
            elif org.daraja_enabled:
                messages.success(
                    request,
                    "Account saved. Daraja is enabled but not fully ready yet — "
                    f"{creds.get('message')}",
                )
            else:
                messages.success(request, "Account details updated.")
            return redirect("core:my_account")
    else:
        form = OrganizationEditForm(instance=org) if org and can_edit else None

    daraja_status = org.effective_daraja_credentials() if org else None

    return render(
        request,
        "core/my_account.html",
        client_page_context(
            request,
            active_nav="account",
            page_title="My account",
            page_kicker="Company",
            page_subtitle=(
                "Update company details, choose Paybill or Till, "
                "and enable Daraja STK Push for subscription payments."
            ),
            form=form,
            can_edit=can_edit,
            platform_gateway=platform_gateway,
            platform_gateway_ready=bool(
                platform_gateway and platform_gateway.is_stk_ready()
            ),
            daraja_status=daraja_status,
            receive_type=(org.mpesa_payment_type if org else "") or "",
        ),
    )


@client_workspace_required
def sales_reps(request):
    org = resolve_organization(request.user, request)
    members = (
        Employee.objects.filter(organization=org, role=Employee.Role.SALES)
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
            active_nav="sales",
            page_title="Sales representatives",
            page_kicker="Team",
            page_subtitle="Sales staff assigned to this organization.",
            members=members,
            empty_text="No sales representatives are assigned to this company yet.",
        ),
    )


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
