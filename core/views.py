"""Client (organization owner) workspace helpers and module pages."""

from functools import wraps
from datetime import date

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db.models import Count, Q, Sum
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from accounts.forms import OrganizationEditForm, ClientSettingsForm
from accounts.models import Employee, Organization
from accounts.routing import (
    can_switch_roles,
    get_client_view_organization,
    home_url_for_user,
    is_viewing_as_client,
)
from billing.forms import ClientDeleteForm, ClientEditForm, PppoeClientRegisterForm
from billing.models import BillingPlan, Customer, Invoice, Payment
from billing.services import (
    build_customer_billing_cycles,
    calculate_service_end,
    customer_receives_internet,
    ensure_period_invoice,
    service_days_remaining,
    service_end_from_remaining_days,
)
from core.forms import (
    MikroTikCleanUplinkForm,
    MikroTikCredentialsForm,
    MikroTikDeleteForm,
    MikroTikEditDetailsForm,
    MikroTikOnboardForm,
    MikroTikSuspendForm,
    MikroTikWifiToggleForm,
)
from core.mikrotik_catalog import mikrotik_model_catalog, mikrotik_model_image
from core.mikrotik_connect import (
    BOND_MODES,
    DEFAULT_BOND_NAME,
    apply_mikrotik_access_changes,
    apply_mikrotik_uplink_bond,
    apply_mikrotik_uplink_failover,
    check_mikrotik_reachable,
    clear_mikrotik_uplink_multi,
    configure_mikrotik_wifi,
    disconnect_pppoe_active_session,
    fetch_customer_pppoe_usage,
    fetch_mikrotik_live_snapshot,
    fetch_pppoe_active_usernames,
    list_mikrotik_ports,
    read_mikrotik_uplink_multi,
    read_mikrotik_wifi,
    recover_mikrotik_connection,
    resolve_mikrotik_api_login,
    set_mikrotik_clean_uplink,
    set_mikrotik_port_enabled,
    set_mikrotik_wifi_enabled,
    sync_customer_pppoe_to_router,
    sync_pppoe_customers_on_router,
    test_mikrotik_api_login,
)
from core.mikrotik_discovery import annotate_onboarded, discover_mikrotik_devices, guess_model, rank_mikrotik_hosts
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
            {"key": "pppoe_hotspot", "label": "PPPoE & Hotspot", "url_name": "core:pppoe_hotspot"},
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
            {
                "key": "edit_client",
                "label": "Edit account",
                "action": "open_modal",
                "modal": "client-edit-modal",
            },
            {
                "key": "delete_client",
                "label": "Delete account",
                "action": "open_modal",
                "modal": "client-delete-modal",
            },
        ],
    },
    "pppoe_hotspot": {
        "label": "PPPoE & Hotspot",
        "items": [],
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
        "items": [
            {"key": "client_settings", "label": "Client settings", "url_name": "core:client_settings"},
            {"key": "hotspot_settings", "label": "Hotspot settings", "url_name": "core:hotspot_settings"},
            {"key": "billing_settings", "label": "Billing settings", "url_name": "core:billing_settings"},
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
    """Sidebar items for a single router (overview + ports + optional modal actions)."""
    detail_url = reverse("core:mikrotik_detail", kwargs={"router_id": router.pk})
    ports_url = reverse("core:mikrotik_ports", kwargs={"router_id": router.pk})
    nav: list[dict] = [
        {"key": "overview", "label": "Router overview", "href": detail_url},
        {"key": "ports", "label": "Ports", "href": ports_url},
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
    """Roles shown in the ports dropdown (WAN primary is merged into WAN)."""
    hidden = {MikroTikRouter.PortRole.WAN_PRIMARY}
    return [
        (value, label)
        for value, label in MikroTikRouter.PortRole.choices
        if value not in hidden
    ]


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
        .annotate(customer_count=Count("customers"))
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
            wifi_activate = (request.POST.get("wifi_activate") or "").strip() in {
                "1",
                "true",
                "on",
                "yes",
            }
            apply_ssid = wifi_ssid != original_ssid
            apply_password = bool(wifi_password) and wifi_password != original_password
            wifi_result = None

            # Toggle on: activate Wi‑Fi and optionally update name/password before saving.
            if wifi_activate:
                if not wifi_ssid:
                    form.add_error("wifi_ssid", "Enter a Wi‑Fi name to activate Wi‑Fi.")
                elif apply_password and len(wifi_password) < 8:
                    form.add_error(
                        "wifi_password",
                        "Wi‑Fi password must be at least 8 characters.",
                    )
                elif not wifi_password and not original_password:
                    form.add_error(
                        "wifi_password",
                        "Enter a Wi‑Fi password (at least 8 characters) to activate Wi‑Fi.",
                    )
                else:
                    wifi_result = set_mikrotik_wifi_enabled(
                        router.host,
                        router.username,
                        router.password,
                        enabled=True,
                        wifi_ssid=wifi_ssid,
                        wifi_password=wifi_password if apply_password or not original_password else "",
                    )
                    if not wifi_result.get("ok"):
                        form.add_error(
                            "wifi_ssid",
                            wifi_result.get("error") or "Could not activate Wi‑Fi on the router.",
                        )
                    elif apply_ssid or apply_password:
                        configure_result = configure_mikrotik_wifi(
                            router.host,
                            router.username,
                            router.password,
                            wifi_ssid=wifi_ssid,
                            wifi_password=wifi_password,
                            wifi_mode=wifi_mode,
                            apply_ssid=apply_ssid and bool(wifi_ssid),
                            apply_password=apply_password and bool(wifi_password),
                        )
                        if not configure_result.get("ok"):
                            form.add_error(
                                "wifi_ssid",
                                configure_result.get("error")
                                or "Could not apply Wi‑Fi settings on the router.",
                            )
                        else:
                            wifi_result = configure_result

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
                        ),
                    )
                if wifi_result and (wifi_result.get("updated") or wifi_result.get("ok")):
                    messages.success(
                        request,
                        f"MikroTik “{router.name}” onboarded and Wi‑Fi activated.",
                    )
                else:
                    messages.success(request, f"MikroTik “{router.name}” onboarded.")
            else:
                messages.success(request, f"MikroTik “{router.name}” onboarded.")

            router.save()
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
    wifi_live: dict = {
        "wifi_ssid": router.wifi_ssid or "",
        "wifi_password": router.wifi_password or "",
        "wifi_enabled": False,
    }
    if not is_suspended:
        router, wifi_live = sync_router_wifi_from_live(router)

    wifi_enabled = bool(wifi_live.get("wifi_enabled"))
    wifi_ssid_display = (wifi_live.get("wifi_ssid") or router.wifi_ssid or "").strip()
    wifi_password_display = wifi_live.get("wifi_password") or router.wifi_password or ""

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
        include_modals=True,
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
        include_modals=True,
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
        wifi_ssid_display=wifi_ssid_display,
        wifi_password_display=wifi_password_display,
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
                cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
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
            cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
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
            cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
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
            cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
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
            cache.delete(f"mikrotik_live:{org.pk}:{router.pk}")
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

    ports: list[dict] = []
    ports_error = ""
    uplink_live: dict = {}
    if is_suspended:
        ports_error = "Activate this MikroTik account to manage ports."
    else:
        listed = list_mikrotik_ports(
            router.host,
            router.username,
            router.password or "",
            timeout=6.0,
        )
        if listed.get("ok"):
            for row in listed.get("ports") or []:
                name = row.get("name") or ""
                role = resolve_port_role(router, name)
                ports.append(
                    {
                        **row,
                        "role": role,
                        "role_label": dict(MikroTikRouter.PortRole.choices).get(
                            role, "Unassigned"
                        ),
                        "is_bond_iface": (row.get("type") or "").lower() == "bond"
                        or name.lower().startswith("bond"),
                    }
                )
            uplink_live = read_mikrotik_uplink_multi(
                router.host,
                router.username,
                router.password or "",
                timeout=5.0,
            )
        else:
            ports_error = listed.get("error") or "Could not read ports from the MikroTik."

    physical_ports = [p for p in ports if not p.get("is_bond_iface")]
    bond_member_ports = [
        p["name"]
        for p in physical_ports
        if p.get("role") == MikroTikRouter.PortRole.BOND
    ]
    primary_wan_ports = [
        p["name"]
        for p in physical_ports
        if _is_primary_wan_role(p.get("role") or "")
    ]
    backup_wan_ports = [
        p["name"]
        for p in physical_ports
        if p.get("role") == MikroTikRouter.PortRole.WAN_BACKUP
    ]
    can_apply_bond = len(bond_member_ports) >= 2
    can_apply_failover = len(primary_wan_ports) == 1 and len(backup_wan_ports) >= 1

    detail_nav = build_mikrotik_detail_nav(router, include_modals=False)
    uplink_mode = router.uplink_mode or MikroTikRouter.UplinkMode.SINGLE

    ctx = client_page_context(
        request,
        active_nav="mikrotik_detail",
        sidebar_active="ports",
        page_title=f"{router.name} — Ports",
        page_subtitle="Assign each port a role in the table, then apply bonding or failover below.",
        router=router,
        router_model_image=mikrotik_model_image(router.model),
        ports=ports,
        physical_ports=physical_ports,
        ports_error=ports_error,
        role_choices=role_choices,
        bond_mode_choices=bond_mode_choices,
        bond_member_ports=bond_member_ports,
        primary_wan_ports=primary_wan_ports,
        backup_wan_ports=backup_wan_ports,
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
    )
    ctx["client_nav_main"] = [
        *CLIENT_COMMON_NAV_START,
        *detail_nav,
    ]
    ctx["sidebar_label"] = "MikroTik"
    return render(request, "core/mikrotik_ports.html", ctx)

@client_workspace_required
@require_POST
def mikrotik_delete(request, router_id: int):
    """Remove an onboarded MikroTik from this organization's workspace."""
    org = resolve_organization(request.user, request)
    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect("core:mikrotik")

    router = get_object_or_404(MikroTikRouter, pk=router_id, organization=org)
    form = MikroTikDeleteForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Confirm deletion to remove this MikroTik.")
        return redirect("core:mikrotik")

    name = router.name
    router_pk = router.pk
    linked_customers = router.customers.count()
    router.delete()
    cache.delete_many(
        [
            f"mikrotik_status:{org.pk}",
            f"mikrotik_live:{org.pk}:{router_pk}",
            _wifi_fields_cache_key(org.pk, router_pk),
            f"mikrotik_discover:{org.pk}:quick",
            f"mikrotik_discover:{org.pk}:full",
        ]
    )
    if linked_customers:
        messages.success(
            request,
            f"Deleted “{name}”. {linked_customers} linked client"
            f"{'s' if linked_customers != 1 else ''} remain but are no longer assigned to a router.",
        )
    else:
        messages.success(request, f"Deleted “{name}” from the system.")
    return redirect("core:mikrotik")


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
        candidate_hosts = rank_mikrotik_hosts(
            router.host,
            discovered=devices,
            limit=12,
        )
    except Exception:
        candidate_hosts = rank_mikrotik_hosts(router.host, discovered=[], limit=8)

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

        # First resolve the live API IP — recover cannot help if 8728 is closed.
        resolved = resolve_mikrotik_api_login(
            router.host,
            use_username,
            use_password,
            candidate_hosts=candidate_hosts,
            discover=True,
            timeout=3.0,
        )
        if not resolved.get("ok"):
            update_fields = ["updated_at"]
            guessed = ""
            for candidate in resolved.get("discovered_hosts") or []:
                if candidate and candidate != (router.host or "").strip():
                    guessed = candidate
                    break
            if guessed:
                router.host = guessed
                update_fields.append("host")
                router.save(update_fields=update_fields)
                cache.delete(f"mikrotik_status:{org.pk}")
            return JsonResponse(
                {
                    "ok": False,
                    "error": resolved.get("error")
                    or "Could not reconnect to this MikroTik.",
                    "needs_api": bool(resolved.get("needs_api")),
                    "auth_error": bool(resolved.get("auth_error")),
                    "username": use_username,
                    "host": router.host,
                    "name": router.name,
                },
                status=400,
            )

        working_host = (resolved.get("host") or router.host or "").strip()
        result = recover_mikrotik_connection(
            working_host,
            use_username,
            use_password,
            wan_interface=router.wan_interface or "ether1",
            lan_bridge=router.lan_bridge or "bridgeLocal",
            candidate_hosts=candidate_hosts,
            restore_bridge=False,
            remove_clean_rules=False,
            timeout=8.0,
        )
        # Login already works — still report success even if uplink cleanup fails.
        if not result.get("ok") and resolved.get("ok"):
            result = {
                "ok": True,
                "host": working_host,
                "message": resolved.get("message")
                or f"Connected to {working_host}.",
            }
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
            "wan_interface",
            "uplink_mode",
            "uplink_ports",
            "port_roles",
            "bond_interface",
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
        timeout=8.0,
        speed_interfaces=resolve_wan_speed_interfaces(router),
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
                    "needs_api": bool(d.get("needs_api")),
                    "host_guess": bool(d.get("host_guess")),
                }
                for d in annotated
            ],
        }
    )


@client_workspace_required
@require_POST
def mikrotik_connect(request):
    """Verify RouterOS API credentials and resolve the working MikroTik IP."""
    host = (request.POST.get("host") or "").strip()
    username = (request.POST.get("username") or "").strip()
    password = request.POST.get("password") or ""

    # Prefer live-discovered IPs when the typed/saved address is wrong or stale.
    result = resolve_mikrotik_api_login(
        host,
        username,
        password,
        discover=True,
        timeout=4.0,
    )
    if not result.get("ok"):
        return JsonResponse(
            {
                "ok": False,
                "error": result.get("error") or "Connection failed.",
                "tried_hosts": result.get("tried_hosts") or [],
            },
            status=400,
        )

    board = result.get("board") or ""
    working_host = result.get("host") or host
    return JsonResponse(
        {
            "ok": True,
            "host": working_host,
            "host_changed": bool(result.get("host_changed")),
            "message": result.get("message") or "",
            "name": result.get("name") or "",
            "identity": result.get("identity") or "",
            "version": result.get("version") or "",
            "board": board,
            "model": guess_model(board),
            "username": username,
            "wifi_ssid": result.get("wifi_ssid") or "",
            "wifi_password": result.get("wifi_password") or "",
            "wifi_mode": result.get("wifi_mode") or "",
            "wifi_enabled": bool(result.get("wifi_enabled")),
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
        host = router.host
        host_changed = False

        def _connected_payload(working_host: str) -> tuple[int, dict]:
            return router.id, {
                "id": router.id,
                "host": working_host,
                "name": router.name,
                "online": True,
                "reachable": True,
                "auth_ok": True,
                "manageable": True,
                "status": "connected",
                "via": "api",
                "error": "",
                "host_changed": working_host != (router.host or ""),
            }

        if online and via == "api":
            # Port 8728 is open — verify saved credentials so "Connected" means usable.
            login = test_mikrotik_api_login(
                router.host,
                router.username,
                router.password or "",
                timeout=2.5,
            )
            if login.get("ok"):
                return _connected_payload(router.host)
            auth_ok = False
            status = "auth_failed"
            error = login.get("error") or "Login failed"
        elif online and via == "ping":
            status = "limited"
        elif online:
            # Winbox/HTTP up, but don't claim API credentials work.
            status = "reachable"

        # Saved IP is stale / API-closed: rediscover and repair when possible.
        if status != "connected":
            resolved = resolve_mikrotik_api_login(
                router.host,
                router.username,
                router.password or "",
                discover=True,
                timeout=2.0,
            )
            if resolved.get("ok"):
                working = (resolved.get("host") or router.host or "").strip()
                if working and working != (router.host or "").strip():
                    MikroTikRouter.objects.filter(pk=router.pk).update(host=working)
                    host = working
                    host_changed = True
                return router.id, {
                    "id": router.id,
                    "host": host,
                    "name": router.name,
                    "online": True,
                    "reachable": True,
                    "auth_ok": True,
                    "manageable": True,
                    "status": "connected",
                    "via": "api",
                    "error": "",
                    "host_changed": host_changed,
                    "message": resolved.get("message") or "",
                }
            if resolved.get("needs_api"):
                discovered = [
                    h for h in (resolved.get("discovered_hosts") or []) if h
                ]
                guessed = discovered[0] if discovered else ""
                if guessed and guessed != (router.host or "").strip():
                    # Keep a better candidate IP for Reconnect / detail pages.
                    MikroTikRouter.objects.filter(pk=router.pk).update(host=guessed)
                    host = guessed
                    host_changed = True
                return router.id, {
                    "id": router.id,
                    "host": host,
                    "name": router.name,
                    "online": False,
                    "reachable": True,
                    "auth_ok": False,
                    "manageable": False,
                    "status": "api_closed",
                    "via": "mndp",
                    "error": resolved.get("error")
                    or "Router seen on LAN, but API port 8728 is closed.",
                    "host_changed": host_changed,
                }
            if resolved.get("error"):
                error = resolved.get("error") or error

        return router.id, {
            "id": router.id,
            "host": host,
            "name": router.name,
            "online": bool(auth_ok) if via == "api" else online and via != "ping",
            "reachable": online,
            "auth_ok": auth_ok,
            "manageable": bool(auth_ok),
            "status": status,
            "via": via,
            "error": error,
            "host_changed": host_changed,
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
                # Reload relations for provisioning (organization + plan speeds).
                customer = (
                    Customer.objects.select_related("router", "plan", "organization")
                    .get(pk=customer.pk)
                )
                sync = sync_customer_pppoe_to_router(customer)
                if sync.get("ok"):
                    cache.delete(f"clients_live:{org.pk}")
                    messages.success(
                        request,
                        (
                            f"PPPoE client “{customer.full_name}” registered ({customer.account_number}). "
                            f"{sync.get('message') or 'Router is ready for dial-in.'} "
                            "Use this username/password on the client device."
                        ),
                    )
                else:
                    messages.warning(
                        request,
                        (
                            f"Client “{customer.full_name}” was saved, but the MikroTik was not updated: "
                            f"{sync.get('error') or 'sync failed'}. "
                            "Fix API reachability, then click “Sync secrets to MikroTik”."
                        ),
                    )
                return redirect(f"{reverse('core:my_clients')}?tab=pppoe")
            open_modal = "pppoe-register-modal"
            tab = "pppoe"
        elif action == "sync_pppoe_secrets":
            if not org:
                messages.error(request, "No organization is linked to this workspace.")
                return redirect("core:my_clients")
            customers_to_sync = list(
                Customer.objects.filter(
                    organization=org,
                    service_type=Customer.ServiceType.PPPOE,
                )
                .exclude(pppoe_username="")
                .exclude(pppoe_password="")
                .select_related("router", "plan", "organization")
            )
            synced = 0
            skipped = 0
            errors = []
            by_router: dict[int, list] = {}
            for customer in customers_to_sync:
                if not customer.router_id:
                    skipped += 1
                    continue
                by_router.setdefault(customer.router_id, []).append(customer)

            for router_customers in by_router.values():
                for result in sync_pppoe_customers_on_router(
                    router_customers[0].router,
                    router_customers,
                ):
                    if result.get("ok"):
                        synced += 1
                    else:
                        label = result.get("customer_name") or "Client"
                        errors.append(f"{label}: {result.get('error') or 'sync failed'}")
            cache.delete(f"clients_live:{org.pk}")
            if synced:
                messages.success(
                    request,
                    (
                        f"Provisioned {synced} PPPoE client{'s' if synced != 1 else ''} on MikroTik "
                        "(server + secrets + NAT). They can dial and surf with their registered credentials."
                    ),
                )
            if skipped and not synced:
                messages.warning(
                    request,
                    "No clients were synced. Assign each PPPoE client to a MikroTik router first.",
                )
            elif skipped:
                messages.info(
                    request,
                    f"{skipped} client{'s' if skipped != 1 else ''} skipped (no router assigned).",
                )
            if errors:
                messages.error(request, "Some syncs failed: " + " · ".join(errors[:3]))
            return redirect(f"{reverse('core:my_clients')}?tab=pppoe")
        else:
            tab = (request.GET.get("tab") or "pppoe").strip().lower()
    else:
        tab = (request.GET.get("tab") or "pppoe").strip().lower()

    customers = (
        Customer.objects.filter(organization=org)
        .select_related("plan", "router")
        .order_by("-created_at")
        if org
        else Customer.objects.none()
    )

    valid_tabs = {"pppoe", "static", "hotspot"}
    if tab not in valid_tabs:
        tab = "pppoe"

    pppoe_customers = [c for c in customers if c.service_type == Customer.ServiceType.PPPOE]
    static_customers = [c for c in customers if c.service_type == Customer.ServiceType.STATIC]
    hotspot_customers = [c for c in customers if c.service_type == Customer.ServiceType.HOTSPOT]
    pppoe_compulsory = bool(org and org.pppoe_compulsory)
    for group in (pppoe_customers, static_customers, hotspot_customers):
        for customer in group:
            customer.receives_internet = customer_receives_internet(customer, org)

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
            pppoe_count=len(pppoe_customers),
            static_count=len(static_customers),
            hotspot_count=len(hotspot_customers),
            pppoe_form=pppoe_form,
            open_client_modal=open_modal,
            pppoe_compulsory=pppoe_compulsory,
            static_empty=(
                "Static clients are blocked from internet while PPPoE compulsory check is on. Register them as PPPoE instead."
                if pppoe_compulsory
                else "Static IP subscribers for this organization will appear here."
            ),
            hotspot_empty=(
                "Hotspot clients are blocked from internet while PPPoE compulsory check is on. Register them as PPPoE instead."
                if pppoe_compulsory
                else "Hotspot subscribers for this organization will appear here."
            ),
            billing_plans_exist=bool(
                org
                and BillingPlan.objects.filter(organization=org, is_active=True).exists()
            ),
        ),
    )


def _sync_customer_internet_access(customer, *, cut_active_session: bool = False) -> dict:
    """Push Customer.status to MikroTik PPP secret; optionally kick the live session."""
    synced = False
    sync_error = ""
    kicked = 0
    if not (
        customer.service_type == Customer.ServiceType.PPPOE
        and customer.router_id
        and (customer.pppoe_username or "").strip()
        and (customer.pppoe_password or "").strip()
    ):
        return {
            "synced": synced,
            "sync_error": sync_error,
            "kicked": kicked,
            "customer": customer,
        }

    customer = (
        Customer.objects.select_related("plan", "router", "organization").get(pk=customer.pk)
    )
    result = sync_customer_pppoe_to_router(customer)
    if result.get("ok"):
        synced = True
    else:
        sync_error = result.get("error") or "PPPoE could not be synced to the MikroTik."

    if cut_active_session and customer.router:
        disconnect = disconnect_pppoe_active_session(
            customer.router.host,
            customer.router.username,
            customer.router.password,
            pppoe_username=customer.pppoe_username,
        )
        kicked = int(disconnect.get("removed") or 0)
        if not disconnect.get("ok") and synced and not sync_error:
            sync_error = (
                disconnect.get("error")
                or "Secret disabled, but the live session could not be disconnected."
            )
    return {
        "synced": synced,
        "sync_error": sync_error,
        "kicked": kicked,
        "customer": customer,
    }


@client_workspace_required
def client_detail(request, customer_id: int):
    """Subscriber profile (topbar) + usage analysis for one client."""
    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("plan", "router", "organization"),
        pk=customer_id,
        organization=org,
    )

    open_client_modal = ""
    edit_form = ClientEditForm(instance=customer, organization=org)
    delete_form = ClientDeleteForm()

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()

        if action == "sync_pppoe":
            if customer.service_type != Customer.ServiceType.PPPOE:
                messages.error(request, "PPPoE sync is only available for PPPoE clients.")
            elif not customer.router_id:
                messages.warning(
                    request,
                    "Assign a MikroTik router to this client before syncing PPPoE credentials.",
                )
            elif not (customer.pppoe_username or "").strip():
                messages.warning(request, "Add a PPPoE username before syncing to the MikroTik.")
            elif not (customer.pppoe_password or "").strip():
                messages.warning(request, "Add a PPPoE password before syncing to the MikroTik.")
            else:
                customer = (
                    Customer.objects.select_related("plan", "router", "organization")
                    .get(pk=customer.pk)
                )
                result = sync_customer_pppoe_to_router(customer)
                if result.get("ok"):
                    cache.delete(f"clients_live:{org.pk if org else 0}")
                    cache.delete(f"client_usage:{org.pk if org else 0}:{customer.pk}")
                    messages.success(
                        request,
                        result.get("message")
                        or f"PPPoE credentials synced for “{customer.full_name}”.",
                    )
                else:
                    messages.error(
                        request,
                        result.get("error") or "Could not sync PPPoE credentials to the MikroTik.",
                    )
            return redirect("core:client_detail", customer_id=customer.pk)



        if action == "edit_client":
            edit_form = ClientEditForm(
                request.POST,
                instance=customer,
                organization=org,
            )
            if edit_form.is_valid():
                old_router_id = customer.router_id
                old_username = (customer.pppoe_username or "").strip()
                old_password = customer.pppoe_password or ""
                old_plan_id = customer.plan_id
                customer = edit_form.save()
                cache.delete(f"clients_live:{org.pk if org else 0}")
                cache.delete(f"client_usage:{org.pk if org else 0}:{customer.pk}")
                creds_ready = bool(
                    customer.service_type == Customer.ServiceType.PPPOE
                    and customer.router_id
                    and (customer.pppoe_username or "").strip()
                    and (customer.pppoe_password or "").strip()
                )
                changed = (
                    customer.router_id != old_router_id
                    or (customer.pppoe_username or "").strip() != old_username
                    or (customer.pppoe_password or "") != old_password
                    or customer.plan_id != old_plan_id
                )
                if creds_ready and (changed or customer.status == Customer.Status.ACTIVE):
                    sync = _sync_customer_internet_access(
                        customer,
                        cut_active_session=customer.status != Customer.Status.ACTIVE,
                    )
                    if sync["synced"]:
                        messages.success(
                            request,
                            f"Updated “{customer.full_name}” and synced PPPoE to the MikroTik.",
                        )
                    elif sync["sync_error"]:
                        messages.warning(
                            request,
                            f"Account updated, but {sync['sync_error']}",
                        )
                    else:
                        messages.success(
                            request,
                            f"Updated account for “{customer.full_name}”.",
                        )
                else:
                    messages.success(
                        request,
                        f"Updated account for “{customer.full_name}”.",
                    )
                return redirect("core:client_detail", customer_id=customer.pk)
            open_client_modal = "client-edit-modal"
            messages.error(
                request,
                "Could not update this account. Check the highlighted fields.",
            )

        elif action == "delete_client":
            delete_form = ClientDeleteForm(request.POST)
            if delete_form.is_valid():
                customer_name = customer.full_name
                customer_tab = customer.service_type
                if customer.status == Customer.Status.ACTIVE:
                    customer.status = Customer.Status.SUSPENDED
                    customer.save(update_fields=["status"])
                _sync_customer_internet_access(customer, cut_active_session=True)
                cache.delete(f"clients_live:{org.pk if org else 0}")
                cache.delete(f"client_usage:{org.pk if org else 0}:{customer.pk}")
                customer.delete()
                messages.success(request, f"Deleted account “{customer_name}”.")
                return redirect(f"{reverse('core:my_clients')}?tab={customer_tab}")
            open_client_modal = "client-delete-modal"
            messages.error(request, "Confirm deletion to remove this account.")

        elif action == "pause_subscription":

            today = timezone.localdate()
            if customer.status != Customer.Status.ACTIVE:
                messages.error(request, "Only an active surfing subscription can be paused.")
            elif not customer.service_until:
                messages.error(
                    request,
                    "This client has no service end date. Turn surfing on with a period first.",
                )
            else:
                remaining = service_days_remaining(customer.service_until, today=today)
                if remaining <= 0:
                    messages.error(
                        request,
                        "No paid days are left to pause — the service period has already ended.",
                    )
                else:
                    customer.status = Customer.Status.PAUSED
                    customer.paused_days_remaining = remaining
                    customer.paused_at = today
                    customer.save(
                        update_fields=["status", "paused_days_remaining", "paused_at"]
                    )
                    cache.delete(f"clients_live:{org.pk if org else 0}")
                    cache.delete(f"client_usage:{org.pk if org else 0}:{customer.pk}")
                    sync = _sync_customer_internet_access(
                        customer, cut_active_session=True
                    )
                    customer = sync["customer"]
                    day_label = "day" if remaining == 1 else "days"
                    if sync["synced"]:
                        messages.success(
                            request,
                            f"Subscription paused for “{customer.full_name}”. "
                            f"{remaining} {day_label} remain frozen until you continue. "
                            "Surfing stopped on the MikroTik.",
                        )
                    elif sync["sync_error"]:
                        messages.warning(
                            request,
                            f"Subscription paused ({remaining} {day_label} frozen), "
                            f"but {sync['sync_error']}",
                        )
                    else:
                        messages.success(
                            request,
                            f"Subscription paused for “{customer.full_name}”. "
                            f"{remaining} {day_label} remain frozen until you continue.",
                        )
            return redirect("core:client_detail", customer_id=customer.pk)

        if action == "continue_subscription":
            today = timezone.localdate()
            if customer.status != Customer.Status.PAUSED:
                messages.error(request, "This subscription is not paused.")
            else:
                remaining = int(customer.paused_days_remaining or 0)
                if remaining <= 0:
                    messages.error(
                        request,
                        "No frozen days remain. Turn surfing on and choose a new period.",
                    )
                else:
                    service_start = today
                    service_until = service_end_from_remaining_days(today, remaining)
                    customer.status = Customer.Status.ACTIVE
                    customer.service_start = service_start
                    customer.service_until = service_until
                    customer.paused_days_remaining = None
                    customer.paused_at = None
                    customer.save(
                        update_fields=[
                            "status",
                            "service_start",
                            "service_until",
                            "paused_days_remaining",
                            "paused_at",
                        ]
                    )
                    cache.delete(f"clients_live:{org.pk if org else 0}")
                    cache.delete(f"client_usage:{org.pk if org else 0}:{customer.pk}")
                    sync = _sync_customer_internet_access(
                        customer, cut_active_session=False
                    )
                    customer = sync["customer"]
                    ensure_period_invoice(
                        customer,
                        period_start=service_start,
                        period_end=service_until,
                        organization=org,
                    )
                    day_label = "day" if remaining == 1 else "days"
                    period = (
                        f" Continues {service_start.isoformat()} → "
                        f"{service_until.isoformat()} ({remaining} {day_label})."
                    )
                    if sync["synced"]:
                        messages.success(
                            request,
                            f"Subscription continued for “{customer.full_name}”.{period} "
                            "Surfing enabled on the MikroTik.",
                        )
                    elif sync["sync_error"]:
                        messages.warning(
                            request,
                            f"Subscription continued.{period} {sync['sync_error']}",
                        )
                    else:
                        messages.success(
                            request,
                            f"Subscription continued for “{customer.full_name}”.{period}",
                        )
            return redirect("core:client_detail", customer_id=customer.pk)

        if action == "set_internet":
            enable = (request.POST.get("internet_enabled") or "").strip().lower() in {
                "1",
                "true",
                "on",
                "yes",
            }
            service_start = customer.service_start
            service_until = customer.service_until

            if enable:
                start_raw = (request.POST.get("service_start") or "").strip()
                end_raw = (request.POST.get("service_until") or "").strip()
                try:
                    service_start = date.fromisoformat(start_raw)
                except ValueError:
                    messages.error(request, "Choose a valid surfing start date.")
                    return redirect(
                        f"{reverse('core:client_detail', args=[customer.pk])}?enable_surfing=1"
                    )

                if end_raw:
                    try:
                        service_until = date.fromisoformat(end_raw)
                    except ValueError:
                        messages.error(request, "Choose a valid surfing end date.")
                        return redirect(
                            f"{reverse('core:client_detail', args=[customer.pk])}?enable_surfing=1"
                        )
                else:
                    service_until = calculate_service_end(
                        service_start,
                        plan=customer.plan,
                    )

                if service_until < service_start:
                    messages.error(
                        request,
                        "End date must be on or after the start date.",
                    )
                    return redirect(
                        f"{reverse('core:client_detail', args=[customer.pk])}?enable_surfing=1"
                    )

            new_status = Customer.Status.ACTIVE if enable else Customer.Status.SUSPENDED
            customer.status = new_status
            update_fields = ["status"]
            if enable:
                customer.service_start = service_start
                customer.service_until = service_until
                customer.paused_days_remaining = None
                customer.paused_at = None
                update_fields.extend(
                    [
                        "service_start",
                        "service_until",
                        "paused_days_remaining",
                        "paused_at",
                    ]
                )
            customer.save(update_fields=update_fields)

            if enable:
                ensure_period_invoice(
                    customer,
                    period_start=service_start,
                    period_end=service_until,
                    organization=org,
                )

            cache.delete(f"clients_live:{org.pk if org else 0}")
            cache.delete(f"client_usage:{org.pk if org else 0}:{customer.pk}")

            sync = _sync_customer_internet_access(
                customer, cut_active_session=not enable
            )
            customer = sync["customer"]
            synced = sync["synced"]
            sync_error = sync["sync_error"]
            kicked = sync["kicked"]

            if enable:
                period = (
                    f" Period: {service_start.isoformat()} → {service_until.isoformat()}."
                )
                if synced:
                    messages.success(
                        request,
                        f"Internet surfing enabled for “{customer.full_name}”."
                        f"{period} PPPoE secret updated on the MikroTik.",
                    )
                elif sync_error:
                    messages.warning(
                        request,
                        f"Surfing marked on for “{customer.full_name}”.{period} {sync_error}",
                    )
                else:
                    messages.success(
                        request,
                        f"Internet surfing enabled for “{customer.full_name}”.{period}",
                    )
            else:
                if synced:
                    detail = " PPPoE secret disabled on the MikroTik."
                    if kicked:
                        detail += (
                            f" Disconnected {kicked} active "
                            f"session{'s' if kicked != 1 else ''}."
                        )
                    messages.success(
                        request,
                        f"Internet surfing turned off for “{customer.full_name}”." + detail,
                    )
                elif sync_error:
                    messages.warning(
                        request,
                        f"Surfing marked off for “{customer.full_name}”, but {sync_error}",
                    )
                else:
                    messages.success(
                        request,
                        f"Internet surfing turned off for “{customer.full_name}”.",
                    )
            return redirect("core:client_detail", customer_id=customer.pk)

    invoices = (
        list(
            Invoice.objects.filter(customer=customer, organization=org)
            .order_by("-issued_at")
        )
        if org
        else []
    )
    payments = (
        list(
            Payment.objects.filter(invoice__customer=customer, organization=org)
            .select_related("invoice")
            .order_by("-received_at")
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

    today = timezone.localdate()
    subscription_paused = customer.status == Customer.Status.PAUSED
    if subscription_paused:
        days_remaining = int(customer.paused_days_remaining or 0)
    else:
        days_remaining = service_days_remaining(customer.service_until, today=today)

    billing_cycles = build_customer_billing_cycles(
        customer, today=today, organization=org
    )
    current_cycle = next((row for row in billing_cycles if row.get("is_current")), None)
    cycles_paid = sum(1 for row in billing_cycles if row.get("is_paid"))
    cycles_unpaid = sum(
        1
        for row in billing_cycles
        if row.get("payment_code") in {"unpaid", "overdue", "draft"}
    )

    return render(
        request,
        "core/client_detail.html",
        client_page_context(
            request,
            active_nav="client_detail",
            sidebar_active="clients",
            page_title=customer.full_name,
            page_kicker="Client",
            page_subtitle=f"Usage analysis · Account {customer.account_number}",
            customer=customer,
            edit_form=edit_form,
            delete_form=delete_form,
            open_client_modal=open_client_modal or (
                "client-edit-modal"
                if (request.GET.get("edit") or "").strip() in {"1", "true", "yes"}
                else (
                    "client-delete-modal"
                    if (request.GET.get("delete") or "").strip() in {"1", "true", "yes"}
                    else ""
                )
            ),
            back_url=f"{reverse('core:my_clients')}?tab={customer.service_type}",
            invoices=invoices,
            payments=payments,
            invoice_total=invoice_stats.get("total") or 0,
            invoice_pending=invoice_stats.get("pending") or 0,
            invoice_paid=invoice_stats.get("paid") or 0,
            invoice_overdue=invoice_stats.get("overdue") or 0,
            amount_billed=invoice_stats.get("billed") or 0,
            amount_paid=paid_total,
            billing_cycles=billing_cycles,
            current_cycle=current_cycle,
            cycles_total=len(billing_cycles),
            cycles_paid=cycles_paid,
            cycles_unpaid=cycles_unpaid,
            can_live_usage=bool(
                customer.router_id
                and customer.pppoe_username
                and customer.service_type == Customer.ServiceType.PPPOE
            ),
            can_sync_pppoe=bool(
                customer.service_type == Customer.ServiceType.PPPOE
                and customer.router_id
                and (customer.pppoe_username or "").strip()
                and (customer.pppoe_password or "").strip()
            ),
            surfing_on=customer.status == Customer.Status.ACTIVE,
            subscription_paused=subscription_paused,
            days_remaining=days_remaining,
            can_pause_subscription=bool(
                customer.status == Customer.Status.ACTIVE
                and customer.service_until
                and service_days_remaining(customer.service_until, today=today) > 0
            ),
            can_continue_subscription=bool(
                subscription_paused and int(customer.paused_days_remaining or 0) > 0
            ),
            pppoe_compulsory=bool(org and org.pppoe_compulsory),
            receives_internet=customer_receives_internet(customer, org),
            open_surfing_modal=(request.GET.get("enable_surfing") or "").strip()
            in {"1", "true", "yes"},
            plan_duration=(
                customer.plan.duration if customer.plan_id else BillingPlan.Duration.MONTHLY
            ),
            plan_duration_label=(
                customer.plan.get_duration_display() if customer.plan_id else "Monthly"
            ),
            today_iso=today.isoformat(),
        ),
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
        router.password,
        pppoe_username=customer.pppoe_username,
    )
    payload["customer_id"] = customer.pk
    payload["router_id"] = router.pk
    payload["router_name"] = router.name
    # Short cache so live speeds stay useful without hammering the API.
    cache.set(cache_key, payload, 8 if payload.get("session_active") else 4)
    return JsonResponse(payload)


@client_workspace_required
@require_GET
def clients_live_status(request):
    """Live surfing + router status for registered clients (PPPoE compulsory view)."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization."}, status=400)

    force = (request.GET.get("refresh") or "").strip() in {"1", "true", "yes"}
    cache_key = f"clients_live:{org.pk}"
    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            return JsonResponse(cached)

    customers = list(
        Customer.objects.filter(organization=org).select_related("router")
    )

    routers_needed: dict[int, MikroTikRouter] = {}
    for customer in customers:
        if customer.router_id and customer.router_id not in routers_needed:
            routers_needed[customer.router_id] = customer.router

    router_sessions: dict[int, dict] = {}

    def _probe(router: MikroTikRouter) -> tuple[int, dict]:
        if router.account_status == MikroTikRouter.AccountStatus.SUSPENDED:
            return router.id, {
                "ok": False,
                "online": False,
                "usernames": [],
                "suspended": True,
                "error": "MikroTik account is suspended.",
            }
        result = fetch_pppoe_active_usernames(
            router.host,
            router.username,
            router.password or "",
            timeout=2.5,
        )
        return router.id, result

    if routers_needed:
        # Keep concurrent API logins low — MikroTik can stop answering when flooded.
        workers = min(2, len(routers_needed))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_probe, router) for router in routers_needed.values()]
            for future in as_completed(futures):
                router_id, payload = future.result()
                router_sessions[router_id] = payload

    clients = []
    for customer in customers:
        eligible = customer_receives_internet(customer, org)
        router = customer.router
        router_online = False
        surfing = False
        surfing_label = "Not surfing"
        router_label = "No router"

        if not router:
            router_label = "No router"
            if not eligible:
                surfing_label = "Blocked"
        else:
            session = router_sessions.get(router.id) or {}
            router_online = bool(session.get("online"))
            err = (session.get("error") or "").lower()
            if session.get("suspended"):
                router_label = "Suspended"
            elif router_online:
                router_label = "Connected"
            elif "no response" in err or "timed out" in err or "could not reach" in err:
                router_label = "No response"
            else:
                router_label = "Disconnected"

            username = (customer.pppoe_username or "").strip().lower()
            active_names = set(session.get("usernames") or [])
            if not eligible:
                surfing = False
                surfing_label = "Blocked"
            elif customer.service_type != Customer.ServiceType.PPPOE or not username:
                surfing = False
                surfing_label = "Not surfing"
            elif not router_online:
                surfing = False
                surfing_label = "Unknown"
            elif username in active_names:
                surfing = True
                surfing_label = "Surfing"
            else:
                surfing = False
                surfing_label = "Not surfing"

        clients.append(
            {
                "id": customer.id,
                "status": customer.status,
                "status_label": customer.get_status_display(),
                "service_type": customer.service_type,
                "receives_internet": eligible,
                "surfing": surfing,
                "surfing_label": surfing_label,
                "router_id": router.id if router else None,
                "router_online": router_online,
                "router_label": router_label,
            }
        )

    payload = {
        "ok": True,
        "pppoe_compulsory": bool(org.pppoe_compulsory),
        "clients": clients,
    }
    # Longer cache so the clients page does not hammer RouterOS API.
    cache.set(cache_key, payload, 20)
    return JsonResponse(payload)


@client_workspace_required
def pppoe_hotspot(request):
    return render(
        request,
        "core/module_page.html",
        client_page_context(
            request,
            active_nav="pppoe_hotspot",
            page_title="PPPoE & Hotspot",
            page_kicker="Access",
            page_subtitle="PPPoE sessions, Hotspot portals, and voucher access for your network.",
            empty_title="Access services not configured",
            empty_text="PPPoE pools, Hotspot portals, and vouchers will be managed from this page.",
            highlights=[
                "Track active PPPoE sessions",
                "Configure Hotspot portals",
                "Generate and manage vouchers",
            ],
        ),
    )


@client_workspace_required
def my_account(request):
    org = resolve_organization(request.user, request)
    employee = getattr(request.user, "employee_profile", None)
    viewing_client = bool(employee and is_viewing_as_client(request, employee))
    can_edit = bool(org and (org.owner_id == request.user.id or viewing_client))

    if request.method == "POST" and can_edit and org:
        form = OrganizationEditForm(request.POST, request.FILES, instance=org)
        if form.is_valid():
            form.save()
            messages.success(request, "Account details updated.")
            return redirect("core:my_account")
    else:
        form = OrganizationEditForm(instance=org) if org and can_edit else None

    return render(
        request,
        "core/my_account.html",
        client_page_context(
            request,
            active_nav="account",
            page_title="My account",
            page_kicker="Company",
            page_subtitle="Organization profile and contact details.",
            form=form,
            can_edit=can_edit,
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
            sidebar_active="settings",
            page_title="My system settings",
            page_kicker="Settings",
            page_subtitle="Choose a settings area to configure your workspace.",
            settings_links=[
                {
                    "title": "Client settings",
                    "description": "PPPoE compulsory check and client access defaults.",
                    "url_name": "core:client_settings",
                    "cta": "Open client settings",
                },
                {
                    "title": "Hotspot settings",
                    "description": "Portal branding, voucher defaults, and Hotspot access rules.",
                    "url_name": "core:hotspot_settings",
                    "cta": "Open hotspot settings",
                },
                {
                    "title": "Billing settings",
                    "description": "Invoice defaults, payment preferences, and billing cycles.",
                    "url_name": "core:billing_settings",
                    "cta": "Open billing settings",
                },
            ],
        ),
    )


@client_workspace_required
def client_settings(request):
    org = resolve_organization(request.user, request)
    employee = getattr(request.user, "employee_profile", None)
    viewing_client = bool(employee and is_viewing_as_client(request, employee))
    can_edit = bool(org and (org.owner_id == request.user.id or viewing_client))

    if request.method == "POST" and can_edit and org:
        form = ClientSettingsForm(request.POST, instance=org)
        if form.is_valid():
            form.save()
            if form.cleaned_data.get("pppoe_compulsory"):
                messages.success(
                    request,
                    "PPPoE compulsory check is on. Only registered PPPoE clients will receive internet.",
                )
            else:
                messages.success(request, "PPPoE compulsory check is off.")
            return redirect("core:client_settings")
    else:
        form = ClientSettingsForm(instance=org) if org and can_edit else None

    pppoe_count = 0
    if org:
        pppoe_count = Customer.objects.filter(
            organization=org,
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.ACTIVE,
        ).exclude(pppoe_username="").count()

    return render(
        request,
        "core/client_settings.html",
        client_page_context(
            request,
            active_nav="settings",
            sidebar_active="client_settings",
            page_title="Client settings",
            page_kicker="Settings",
            page_subtitle="Configure how client accounts receive internet access.",
            form=form,
            can_edit=can_edit,
            pppoe_compulsory=bool(org and org.pppoe_compulsory),
            pppoe_eligible_count=pppoe_count,
        ),
    )


@client_workspace_required
def hotspot_settings(request):
    return render(
        request,
        "core/module_page.html",
        client_page_context(
            request,
            active_nav="settings",
            sidebar_active="hotspot_settings",
            page_title="Hotspot settings",
            page_kicker="Settings",
            page_subtitle="Configure Hotspot portals, vouchers, and captive portal options.",
            empty_title="Hotspot preferences",
            empty_text="Hotspot portal branding, voucher defaults, and access rules will be managed here.",
        ),
    )


@client_workspace_required
def billing_settings(request):
    return render(
        request,
        "core/module_page.html",
        client_page_context(
            request,
            active_nav="settings",
            sidebar_active="billing_settings",
            page_title="Billing settings",
            page_kicker="Settings",
            page_subtitle="Configure invoices, payment defaults, and billing cycles.",
            empty_title="Billing preferences",
            empty_text="Invoice templates, payment preferences, and billing cycle defaults will be managed here.",
        ),
    )
