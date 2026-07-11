"""Client (organization owner) workspace helpers and module pages."""

from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db.models import Count, Q, Sum
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_GET, require_POST

from accounts.forms import OrganizationEditForm
from accounts.models import Employee, Organization
from accounts.routing import (
    can_switch_roles,
    get_client_view_organization,
    home_url_for_user,
    is_viewing_as_client,
)
from billing.forms import PppoeClientRegisterForm
from billing.models import BillingPlan, Customer, Invoice, Payment
from core.forms import (
    MikroTikCredentialsForm,
    MikroTikEditDetailsForm,
    MikroTikOnboardForm,
    MikroTikSuspendForm,
    MikroTikWifiToggleForm,
)
from core.mikrotik_catalog import mikrotik_model_catalog, mikrotik_model_image
from core.mikrotik_connect import (
    apply_mikrotik_access_changes,
    check_mikrotik_reachable,
    configure_mikrotik_wifi,
    fetch_customer_pppoe_usage,
    fetch_mikrotik_live_snapshot,
    read_mikrotik_wifi,
    set_mikrotik_wifi_enabled,
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
    open_modal = ""

    # Detail sidebar: labels flip with current state.
    detail_nav = []
    for item in CLIENT_SIDEBARS["mikrotik_detail"]["items"]:
        row = dict(item)
        if row.get("key") == "suspend_account":
            row["label"] = "Activate account" if is_suspended else "Suspend account"
        elif row.get("key") == "toggle_wifi":
            row["label"] = "Deactivate Wi‑Fi" if wifi_enabled else "Activate Wi‑Fi"
        detail_nav.append(row)

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

    # Keep sidebar wifi label in sync if a failed POST left the modal open.
    for row in detail_nav:
        if row.get("key") == "toggle_wifi":
            row["label"] = "Deactivate Wi‑Fi" if wifi_enabled else "Activate Wi‑Fi"

    ctx = client_page_context(
        request,
        active_nav="mikrotik_detail",
        sidebar_active="",
        page_title=router.name,
        page_subtitle="Router details and connection settings for this MikroTik.",
        router=router,
        router_model_image=mikrotik_model_image(router.model),
        edit_form=edit_form,
        credentials_form=credentials_form,
        suspend_form=suspend_form,
        wifi_form=wifi_form,
        open_mikrotik_modal=open_modal,
        is_suspended=is_suspended,
        wifi_enabled=wifi_enabled,
        wifi_ssid_display=wifi_ssid_display,
        wifi_password_display=wifi_password_display,
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
        list(MikroTikRouter.objects.filter(organization=org).only("id", "host", "name"))
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
        return router.id, {
            "id": router.id,
            "host": router.host,
            "name": router.name,
            "online": bool(probe.get("online")),
            "status": "connected" if probe.get("online") else "disconnected",
            "via": probe.get("via") or "",
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
                messages.success(
                    request,
                    f"PPPoE client “{customer.full_name}” registered ({customer.account_number}).",
                )
                return redirect(f"{reverse('core:my_clients')}?tab=pppoe")
            open_modal = "pppoe-register-modal"
            tab = "pppoe"
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
            billing_plans_exist=bool(
                org
                and BillingPlan.objects.filter(organization=org, is_active=True).exists()
            ),
        ),
    )


@client_workspace_required
def client_detail(request, customer_id: int):
    """Subscriber profile (topbar) + usage analysis for one client."""
    org = resolve_organization(request.user, request)
    customer = get_object_or_404(
        Customer.objects.select_related("plan", "router", "organization"),
        pk=customer_id,
        organization=org,
    )
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

    return render(
        request,
        "core/client_detail.html",
        client_page_context(
            request,
            active_nav="clients",
            page_title=customer.full_name,
            page_kicker="Client",
            page_subtitle=f"Usage analysis · Account {customer.account_number}",
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
            page_title="My system settings",
            page_kicker="Settings",
            page_subtitle="Organization status, join code, and workspace preferences.",
        ),
    )
