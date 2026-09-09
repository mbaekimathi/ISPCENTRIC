from functools import wraps
import json
import threading

from django.db import transaction
from django.db.models import Max, Q, Sum
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from accounts.communications import (
    CHANNEL_LABELS,
    PLATFORM_TO_ISP_EVENTS,
    PLATFORM_TO_STAFF_EVENTS,
    RECIPIENT_OPTIONS,
    fetch_provider_options,
    normalize_enabled_messages,
    notify_org_event,
    notify_platform_event,
    platform_event_catalog,
    resolve_page_link_path,
)
from accounts.forms import (
    EmployeeAdminEditForm,
    LeadRegisterForm,
    NATIONAL_PHONE_LENGTHS,
    NetworkEquipmentRegisterForm,
    OrganizationEditForm,
    OwnerProfileForm,
    ClientSettingsForm,
    CompanyProfileForm,
    PaymentGatewayForm,
    PlatformCommunicationSettingsForm,
    RegisterForm,
    RoleCommissionForm,
    SalesCommissionForm,
)
from accounts.models import (
    ClientSettings,
    CompanyProfile,
    Employee,
    FaultTicket,
    Lead,
    NetworkEquipment,
    NetworkEquipmentAllocation,
    NetworkEquipmentSerial,
    NetworkEquipmentStockMovement,
    Organization,
    PaymentGateway,
    PlatformCommunicationSettings,
    RoleCommission,
)
from accounts.mpesa_daraja import check_stk_configuration, normalize_gateway_values
from accounts.routing import (
    CLIENT_VIEW_VALUE,
    ROLE_DASHBOARD_NAMES,
    ROLE_SLUGS,
    SWITCHABLE_ROLES,
    can_access_client_portal,
    can_switch_roles,
    clear_client_view,
    get_role_view,
    home_url_for_user,
    set_client_view,
    set_role_view,
    switchable_clients_list,
    switchable_role_options,
)
from billing.forms import (
    CustomerCashRechargeForm,
    PppoeClientRegisterForm,
    SalesClientRegisterForm,
)
from billing.models import BillingPlan, Customer, InstallationDecline, InstallationReject
from billing.services import (
    customer_needs_nas_provision,
    plans_for_router,
    recharge_customer_cash,
)
from core.mikrotik_connect import provision_customer_pppoe
from core.models import MikroTikRouter
from core.subscription_sync import enqueue_customer_subscription_sync


ROLE_PAGE = {
    Employee.Role.SUPER_ADMIN: {
        "title": "Super Admin Dashboard",
        "subtitle": "Full system oversight and configuration.",
        "url_name": "roles:super_admin",
        "highlights": [
            "Manage all roles and access",
            "Oversee billing and network operations",
            "Review system-wide activity",
        ],
    },
    Employee.Role.ADMINISTRATOR: {
        "title": "Administrator Dashboard",
        "subtitle": "Company administration and staff control.",
        "url_name": "roles:administrator",
        "highlights": [
            "Approve and manage employees",
            "Configure company settings",
            "Monitor operational health",
        ],
    },
    Employee.Role.MANAGER: {
        "title": "Customer support",
        "subtitle": "Client care, sales coordination, and field support.",
        "url_name": "roles:customer_support",
        "highlights": [
            "Support ISP clients",
            "Coordinate sales and technicians",
            "Track network equipment",
        ],
    },
    Employee.Role.IT_SUPPORT: {
        "title": "IT Support Dashboard",
        "subtitle": "Technical support and infrastructure.",
        "url_name": "roles:it_support",
        "highlights": [
            "Handle support tickets",
            "Monitor network health",
            "Assist staff with access issues",
        ],
    },
    Employee.Role.SALES: {
        "title": "Sales Dashboard",
        "subtitle": "Leads, plans, and customer acquisition.",
        "url_name": "roles:sales",
        "highlights": [
            "Manage leads and conversions",
            "Present billing plans",
            "Follow up on new sign-ups",
        ],
    },
    Employee.Role.TECHNICIAN: {
        "title": "Technician Dashboard",
        "subtitle": "Installations, repairs, and field jobs.",
        "url_name": "roles:technician",
        "highlights": [
            "View assigned jobs",
            "Update installation status",
            "Log field visit notes",
        ],
    },
}


def role_required(role):
    def decorator(view_func):
        @wraps(view_func)
        @login_required(login_url="accounts:employee_login")
        def _wrapped(request, *args, **kwargs):
            employee = getattr(request.user, "employee_profile", None)
            if employee is None:
                return redirect("core:workspace")
            if not employee.can_access_workspace:
                return redirect("accounts:employee_pending")
            if employee.role == role:
                return view_func(request, *args, **kwargs)
            if can_switch_roles(employee) and role in SWITCHABLE_ROLES:
                return view_func(request, *args, **kwargs)
            return redirect(home_url_for_user(request.user, request))

        return _wrapped

    return decorator


def _role_dashboard(request, role):
    employee = request.user.employee_profile
    meta = ROLE_PAGE[role]
    role_labels = dict(Employee.Role.choices)
    switcher = can_switch_roles(employee)
    if switcher:
        set_role_view(request, role)
    return render(
        request,
        "accounts/role_dashboard.html",
        {
            "employee": employee,
            "organization": employee.organization,
            "role": role,
            "role_label": role_labels.get(role, role),
            "actual_role": employee.role,
            "actual_role_label": employee.get_role_display(),
            "page_title": meta["title"],
            "page_subtitle": meta["subtitle"],
            "highlights": meta["highlights"],
            "dashboard_url_name": meta["url_name"],
            "role_slug": ROLE_SLUGS[role],
            "current_page": "dashboard",
            "can_switch_roles": switcher,
            "is_viewing_as": switcher and role != employee.role,
            "switchable_roles": switchable_role_options(request, employee, selected=role),
            "switchable_clients": switchable_clients_list() if switcher else [],
            "selected_client_id": None,
        },
    )


@login_required(login_url="accounts:employee_login")
@require_POST
def switch_role_view(request):
    employee = getattr(request.user, "employee_profile", None)
    if not can_switch_roles(employee):
        messages.error(request, "Role switch is only available to IT Support.")
        return redirect(home_url_for_user(request.user, request))

    from accounts.audit import record_audit

    role = (request.POST.get("role") or "").strip()
    if role == CLIENT_VIEW_VALUE:
        raw_org = (request.POST.get("organization_id") or "").strip()
        try:
            org_id = int(raw_org)
        except (TypeError, ValueError):
            org_id = None
        org = Organization.objects.filter(pk=org_id).first() if org_id else None
        if org is None:
            messages.error(request, "Choose a client organization to view.")
            return redirect(home_url_for_user(request.user, request))
        set_client_view(request, org.pk)
        record_audit(
            action="client_view",
            request=request,
            target=f"org:{org.pk}",
            detail={"organization": org.name, "join_code": org.join_code},
        )
        messages.success(request, f"Now viewing as client {org.name}.")
        return redirect("core:workspace")

    if role not in SWITCHABLE_ROLES:
        messages.error(request, "Choose a valid role to view.")
        return redirect(home_url_for_user(request.user, request))

    set_role_view(request, role)
    record_audit(
        action="role_switch",
        request=request,
        target=role,
        detail={"role_label": dict(Employee.Role.choices).get(role, role)},
    )
    messages.success(request, f"Now viewing as {dict(Employee.Role.choices)[role]}.")
    return redirect(ROLE_DASHBOARD_NAMES[role])


@role_required(Employee.Role.SUPER_ADMIN)
def super_admin_dashboard(request):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.SUPER_ADMIN)
    return render(
        request,
        "accounts/super_admin_dashboard.html",
        {
            "page_title": "Super Admin Dashboard",
            "current_page": "dashboard",
            "dashboard_url_name": "roles:super_admin",
        },
    )


def _super_admin_clients_context(**extra):
    return {
        "page_title": "Client management",
        "page_kicker": "Clients",
        "current_page": "clients",
        "dashboard_url_name": "roles:super_admin",
        "clients_list_url_name": "roles:super_admin_clients",
        "client_edit_url_name": "roles:super_admin_client_edit",
        "client_suspend_url_name": "roles:super_admin_client_suspend",
        "client_unsuspend_url_name": "roles:super_admin_client_unsuspend",
        "client_delete_url_name": "roles:super_admin_client_delete",
        "list_heading": "Registered organizations",
        "list_intro": "Company accounts currently in ISPCENTRIC.",
        "delete_intro": "This permanently removes the organization and its related billing data.",
        "delete_warning": (
            "will be deleted. Staff accounts stay in the system but lose this "
            "organization link. Customers and plans under this client are removed."
        ),
        **extra,
    }


def _prepare_super_admin_view(request):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.SUPER_ADMIN)
    return employee


@role_required(Employee.Role.SUPER_ADMIN)
def super_admin_clients(request):
    from django.db.models import Count

    _prepare_super_admin_view(request)

    clients = list(
        Organization.objects.select_related("owner")
        .annotate(
            staff_count=Count("employees", distinct=True),
            customer_count=Count("customers", distinct=True),
        )
        .order_by("-created_at")
    )
    return render(
        request,
        "accounts/super_admin_clients.html",
        _super_admin_clients_context(
            clients=clients,
            clients_count=len(clients),
        ),
    )


@role_required(Employee.Role.SUPER_ADMIN)
def super_admin_client_edit(request, pk):
    _prepare_super_admin_view(request)
    client = get_object_or_404(Organization.objects.select_related("owner"), pk=pk)

    if request.method == "POST":
        form = OrganizationEditForm(request.POST, request.FILES, instance=client)
        if form.is_valid():
            form.save()
            messages.success(request, f"Updated {client.name}.")
            return redirect("roles:super_admin_client_edit", pk=client.pk)
    else:
        form = OrganizationEditForm(instance=client)

    return render(
        request,
        "accounts/super_admin_client_edit.html",
        _super_admin_clients_context(
            page_title="Edit client",
            page_kicker="Clients",
            client=client,
            form=form,
        ),
    )


@role_required(Employee.Role.SUPER_ADMIN)
@require_POST
def super_admin_client_suspend(request, pk):
    _prepare_super_admin_view(request)
    client = get_object_or_404(Organization, pk=pk)
    if client.status == Organization.Status.SUSPENDED:
        messages.info(request, f"{client.name} is already suspended.")
    else:
        client.status = Organization.Status.SUSPENDED
        client.save(update_fields=["status"])
        notify_platform_event(
            "platform_isp_status",
            organization=client,
            context={
                "company_name": client.name,
                "status": "suspended",
            },
            subject="ISP account suspended",
        )
        messages.success(request, f"Suspended {client.name}.")
    return redirect("roles:super_admin_clients")


@role_required(Employee.Role.SUPER_ADMIN)
@require_POST
def super_admin_client_unsuspend(request, pk):
    _prepare_super_admin_view(request)
    client = get_object_or_404(Organization, pk=pk)
    if client.status != Organization.Status.SUSPENDED:
        messages.info(request, f"{client.name} is not suspended.")
    else:
        client.status = Organization.Status.ACTIVE
        client.save(update_fields=["status"])
        notify_platform_event(
            "platform_isp_status",
            organization=client,
            context={
                "company_name": client.name,
                "status": "active",
            },
            subject="ISP account activated",
        )
        messages.success(request, f"Unsuspended {client.name}.")
    return redirect("roles:super_admin_clients")


@role_required(Employee.Role.SUPER_ADMIN)
def super_admin_client_delete(request, pk):
    employee = _prepare_super_admin_view(request)
    client = get_object_or_404(Organization, pk=pk)

    if employee.organization_id == client.pk:
        messages.error(request, "You cannot delete your own organization.")
        return redirect("roles:super_admin_clients")

    if request.method == "POST":
        name = client.name
        client.delete()
        messages.success(request, f"Deleted {name}.")
        return redirect("roles:super_admin_clients")

    return render(
        request,
        "accounts/super_admin_client_delete.html",
        _super_admin_clients_context(
            page_title="Delete client",
            page_kicker="Clients",
            client=client,
        ),
    )


@role_required(Employee.Role.SUPER_ADMIN)
def super_admin_hr(request):
    _prepare_super_admin_view(request)

    employees = list(
        Employee.objects.select_related("user", "organization")
        .order_by("-created_at")
    )
    return render(
        request,
        "accounts/super_admin_hr.html",
        _super_admin_hr_context(
            employees=employees,
            employees_count=len(employees),
        ),
    )


def _super_admin_hr_context(**extra):
    return {
        "page_title": "Human resource management",
        "page_kicker": "People",
        "current_page": "hr",
        "dashboard_url_name": "roles:super_admin",
        "hr_list_url_name": "roles:super_admin_hr",
        **extra,
    }


@role_required(Employee.Role.SUPER_ADMIN)
def super_admin_hr_edit(request, pk):
    _prepare_super_admin_view(request)
    member = get_object_or_404(Employee.objects.select_related("user", "organization"), pk=pk)

    if request.method == "POST":
        form = EmployeeAdminEditForm(request.POST, request.FILES, employee=member)
        if form.is_valid():
            form.save()
            name = member.user.get_full_name() or member.user.username
            messages.success(request, f"Updated {name}.")
            return redirect("roles:super_admin_hr_edit", pk=member.pk)
    else:
        form = EmployeeAdminEditForm(employee=member)

    return render(
        request,
        "accounts/hr_employee_edit.html",
        _super_admin_hr_context(
            page_title="Edit employee",
            member=member,
            form=form,
            hr_edit_url_name="roles:super_admin_hr_edit",
        ),
    )


@role_required(Employee.Role.SUPER_ADMIN)
@require_POST
def super_admin_hr_suspend(request, pk):
    actor = _prepare_super_admin_view(request)
    member = get_object_or_404(Employee.objects.select_related("user"), pk=pk)
    name = member.user.get_full_name() or member.user.username

    if member.pk == actor.pk:
        messages.error(request, "You cannot suspend your own account.")
        return redirect("roles:super_admin_hr")

    if member.status == Employee.Status.SUSPENDED:
        messages.info(request, f"{name} is already suspended.")
    else:
        member.status = Employee.Status.SUSPENDED
        member.save(update_fields=["status", "updated_at"])
        messages.success(request, f"Suspended {name}.")
    return redirect("roles:super_admin_hr")


@role_required(Employee.Role.SUPER_ADMIN)
@require_POST
def super_admin_hr_unsuspend(request, pk):
    _prepare_super_admin_view(request)
    member = get_object_or_404(Employee.objects.select_related("user"), pk=pk)
    name = member.user.get_full_name() or member.user.username

    if member.status != Employee.Status.SUSPENDED:
        messages.info(request, f"{name} is not suspended.")
    else:
        member.status = Employee.Status.ACTIVE
        member.save(update_fields=["status", "updated_at"])
        messages.success(request, f"Unsuspended {name}.")
    return redirect("roles:super_admin_hr")


@role_required(Employee.Role.SUPER_ADMIN)
def super_admin_hr_delete(request, pk):
    actor = _prepare_super_admin_view(request)
    member = get_object_or_404(Employee.objects.select_related("user", "organization"), pk=pk)
    name = member.user.get_full_name() or member.user.username
    owned_org = Organization.objects.filter(owner_id=member.user_id).first()

    if member.pk == actor.pk:
        messages.error(request, "You cannot delete your own account.")
        return redirect("roles:super_admin_hr")

    if request.method == "POST":
        user = member.user
        user.delete()
        messages.success(request, f"Deleted {name}.")
        return redirect("roles:super_admin_hr")

    return render(
        request,
        "accounts/hr_employee_delete.html",
        _super_admin_hr_context(
            page_title="Delete employee",
            member=member,
            owned_org=owned_org,
        ),
    )


@role_required(Employee.Role.ADMINISTRATOR)
def administrator_dashboard(request):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.ADMINISTRATOR)
    return render(
        request,
        "accounts/administrator_dashboard.html",
        {
            "page_title": "Administrator Dashboard",
            "current_page": "dashboard",
            "dashboard_url_name": "roles:administrator",
        },
    )


@role_required(Employee.Role.ADMINISTRATOR)
def administrator_clients(request):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.ADMINISTRATOR)
    return render(
        request,
        "accounts/administrator_page.html",
        {
            "page_title": "Client management",
            "page_kicker": "Clients",
            "current_page": "clients",
            "dashboard_url_name": "roles:administrator",
        },
    )


@role_required(Employee.Role.ADMINISTRATOR)
def administrator_hr(request):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.ADMINISTRATOR)
    return render(
        request,
        "accounts/administrator_page.html",
        {
            "page_title": "Human resource management",
            "page_kicker": "People",
            "current_page": "hr",
            "dashboard_url_name": "roles:administrator",
        },
    )


@role_required(Employee.Role.MANAGER)
def manager_dashboard(request):
    employee = request.user.employee_profile
    meta = ROLE_PAGE[Employee.Role.MANAGER]
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.MANAGER)
    return render(
        request,
        "accounts/customer_support_dashboard.html",
        {
            "page_title": meta["title"],
            "page_subtitle": meta["subtitle"],
            "current_page": "dashboard",
            "dashboard_url_name": "roles:customer_support",
            "module_links": [
                {
                    "index": "01",
                    "label": "ISP clients",
                    "hint": "Open an ISP workspace for billing and subscribers.",
                    "url_name": "roles:customer_support_isp_clients",
                },
                {
                    "index": "02",
                    "label": "Sales",
                    "hint": "Register potential clients and review sales leads.",
                    "url_name": "roles:customer_support_sales",
                },
                {
                    "index": "03",
                    "label": "Technician",
                    "hint": "Pending installs, allocate to technicians, and review assignments.",
                    "url_name": "roles:customer_support_technician",
                },
                {
                    "index": "04",
                    "label": "Stock Audit",
                    "hint": "Stock, register, allocate, and audit network equipment movements.",
                    "url_name": "roles:customer_support_network_equipment",
                },
            ],
        },
    )


def _prepare_manager_view(request):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.MANAGER)
    return employee


@role_required(Employee.Role.MANAGER)
def manager_isp_clients(request):
    from django.db.models import Count, IntegerField, OuterRef, Subquery
    from django.db.models.functions import Coalesce

    from billing.models import Customer

    _prepare_manager_view(request)

    def _count_subquery(model, org_field="organization_id"):
        return (
            model.objects.filter(**{org_field: OuterRef("pk")})
            .order_by()
            .values(org_field)
            .annotate(_c=Count("id"))
            .values("_c")
        )

    clients = list(
        Organization.objects.select_related("owner")
        .annotate(
            staff_count=Coalesce(
                Subquery(_count_subquery(Employee), output_field=IntegerField()),
                0,
            ),
            customer_count=Coalesce(
                Subquery(_count_subquery(Customer), output_field=IntegerField()),
                0,
            ),
        )
        .order_by("-created_at")
    )
    suspended_count = sum(
        1 for client in clients if client.status == Organization.Status.SUSPENDED
    )
    active_count = sum(
        1 for client in clients if client.status == Organization.Status.ACTIVE
    )
    return render(
        request,
        "accounts/customer_support_isp_clients.html",
        {
            "page_title": "ISP clients",
            "page_kicker": "Clients",
            "page_subtitle": "Open an ISP workspace to support billing, network, and subscribers.",
            "current_page": "isp_clients",
            "dashboard_url_name": "roles:customer_support",
            "clients": clients,
            "clients_count": len(clients),
            "active_count": active_count,
            "suspended_count": suspended_count,
            "empty_text": "No ISP clients are registered yet.",
        },
    )


@role_required(Employee.Role.MANAGER)
@require_POST
def manager_open_client_portal(request, pk):
    _prepare_manager_view(request)
    client = get_object_or_404(Organization, pk=pk)
    set_client_view(request, client.pk)
    messages.success(request, f"Opened client portal for {client.name}.")
    return redirect("core:workspace")


@role_required(Employee.Role.MANAGER)
def manager_view_customer(request, customer_id):
    """Open the ISP workspace and jump to this PPPoE client's detail page."""
    _prepare_manager_view(request)
    customer = get_object_or_404(
        Customer.objects.select_related("organization"),
        pk=customer_id,
        service_type=Customer.ServiceType.PPPOE,
    )
    if not customer.organization_id:
        messages.error(
            request,
            "That client is not linked to an ISP yet, so details cannot be opened.",
        )
        return redirect("roles:customer_support_sales")
    set_client_view(request, customer.organization_id)
    target = reverse("core:client_detail", kwargs={"customer_id": customer.pk})
    open_modal = (request.GET.get("open") or "").strip().lower()
    if open_modal in {"recharge", "client-recharge-modal"}:
        target = f"{target}?open=recharge"
    return redirect(target)


@role_required(Employee.Role.MANAGER)
@require_POST
def manager_exit_client_portal(request):
    _prepare_manager_view(request)
    clear_client_view(request)
    messages.success(request, "Returned to Customer support.")
    return redirect("roles:customer_support_isp_clients")


def _sales_pppoe_org_options():
    """Active ISP orgs available for CS / sales PPPoE registration."""
    return list(
        Organization.objects.exclude(status=Organization.Status.SUSPENDED)
        .order_by("name")
        .only("id", "name")
    )


def _sales_pppoe_router_plan_maps(isp_clients):
    """Build router / plan JSON maps keyed by organization for PPPoE modals."""
    router_cpe_defaults: dict[str, dict] = {}
    routers_by_org: dict[str, list[dict]] = {}
    plans_by_org: dict[str, list[dict]] = {"_plan_org": {}}
    client_routers = []
    if not isp_clients:
        return router_cpe_defaults, routers_by_org, plans_by_org, client_routers

    org_ids = [org.pk for org in isp_clients]
    client_routers = list(
        MikroTikRouter.objects.filter(organization_id__in=org_ids)
        .order_by("name", "host")
        .only("id", "name", "host", "organization_id")
    )
    for router in MikroTikRouter.objects.filter(organization_id__in=org_ids).only(
        "id",
        "name",
        "host",
        "organization_id",
        "default_cpe_username",
        "default_cpe_password",
        "location",
    ):
        org_key = str(router.organization_id)
        label = (router.name or "").strip() or router.host or f"Router {router.pk}"
        if router.host and router.name:
            label = f"{router.name} ({router.host})"
        routers_by_org.setdefault(org_key, []).append(
            {"id": router.pk, "name": router.name or "", "label": label}
        )
        default_password = (router.default_cpe_password or "").strip()
        router_cpe_defaults[str(router.pk)] = {
            "username": (router.default_cpe_username or "").strip() or "admin",
            "password": default_password,
            "has_password": bool(default_password),
            "address": (router.location or "").strip(),
            "router_name": (router.name or "").strip(),
            "organization_id": router.organization_id,
        }
    for plan in (
        BillingPlan.objects.filter(
            organization_id__in=org_ids,
            is_active=True,
            service_type=Customer.ServiceType.PPPOE,
        )
        .prefetch_related("routers")
        .order_by("price", "name")
        .only("id", "name", "organization_id")
    ):
        org_key = str(plan.organization_id)
        router_ids = list(plan.routers.values_list("id", flat=True))
        plans_by_org.setdefault(org_key, []).append(
            {
                "id": plan.pk,
                "name": plan.name,
                "router_ids": router_ids,
            }
        )
        plans_by_org["_plan_org"][str(plan.pk)] = plan.organization_id
    return router_cpe_defaults, routers_by_org, plans_by_org, client_routers


@role_required(Employee.Role.MANAGER)
def manager_sales(request):
    """Customer support: onboard ISPs / PPPoE-on-MikroTik, and review sales leads."""
    _prepare_manager_view(request)
    employee = request.user.employee_profile
    organization = employee.organization
    isp_clients = _sales_pppoe_org_options()

    open_lead_modal = False
    open_register_modal = False
    open_client_modal = ""
    selected_type = ""
    form = LeadRegisterForm(organization=organization)
    isp_form = RegisterForm(prefix="isp", require_invite=False)
    pppoe_form = PppoeClientRegisterForm(
        organizations=isp_clients,
        default_activate=False,
        allow_activate=False,
        require_serials=False,
    )

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action == "register_pppoe":
            selected_type = "client"
            if not isp_clients:
                messages.error(request, "No ISP clients are available for registration.")
                return redirect("roles:customer_support_sales")
            pppoe_form = PppoeClientRegisterForm(
                request.POST,
                organizations=isp_clients,
                default_activate=False,
                allow_activate=False,
                require_serials=False,
            )
            if pppoe_form.is_valid():
                customer = pppoe_form.save(commit=False)
                customer.registered_by = request.user
                customer.save()
                account_number = customer.account_number
                full_name = customer.full_name
                org_name = (
                    customer.organization.name
                    if customer.organization_id
                    else "ISP client"
                )
                if customer.organization_id:
                    notify_org_event(
                        "client_welcome",
                        organization=customer.organization,
                        client=customer,
                        subject="Welcome — account created",
                    )
                    notify_org_event(
                        "isp_client_registered",
                        organization=customer.organization,
                        client=customer,
                        subject="New client registered",
                    )
                router_label = (
                    (customer.router.name or customer.router.host)
                    if customer.router_id
                    else "MikroTik"
                )
                messages.success(
                    request,
                    (
                        f"PPPoE client “{full_name}” registered "
                        f"({account_number}) under {org_name} on {router_label} "
                        f"(queued for technician install)."
                    ),
                )
                return redirect("roles:customer_support_sales")
            open_client_modal = "pppoe-register-modal"
        elif "registration_type" in request.POST:
            selected_type = (request.POST.get("registration_type") or "").strip()
            open_register_modal = True
            if selected_type == "isp":
                isp_form = RegisterForm(
                    request.POST, request.FILES, prefix="isp", require_invite=False
                )
                if isp_form.is_valid():
                    with transaction.atomic():
                        org = _create_isp_organization_from_register_form(
                            isp_form,
                            registered_by=request.user,
                        )
                    messages.success(
                        request,
                        (
                            f"ISP “{org.name}” onboarded. "
                            f"Owner login: {org.login_code}."
                        ),
                    )
                    return redirect("roles:customer_support_sales")
            elif selected_type == "client":
                # Fallback when JS does not open the PPPoE modal.
                open_client_modal = "pppoe-register-modal"
                open_register_modal = False
            else:
                messages.error(
                    request,
                    "Choose what to register: PPPoE client or new ISP.",
                )
        else:
            form = LeadRegisterForm(request.POST, organization=organization)
            if form.is_valid():
                lead = form.save(created_by=request.user)
                target_org = (
                    getattr(lead, "preferred_isp", None)
                    or getattr(lead, "organization", None)
                )
                lead_ctx = {
                    "client_name": lead.full_name or "",
                    "phone": getattr(lead, "phone", "") or "",
                    "location": getattr(lead, "location", "") or "",
                }
                if target_org is not None:
                    notify_org_event(
                        "isp_lead_open",
                        organization=target_org,
                        context=lead_ctx,
                        subject="New open lead",
                    )
                notify_platform_event(
                    "platform_staff_new_lead",
                    organization=target_org,
                    context=lead_ctx,
                    subject="New sales lead",
                )
                messages.success(
                    request,
                    (
                        f"Lead “{lead.full_name}” registered "
                        f"({lead.lead_number}) for follow-up."
                    ),
                )
                return redirect("roles:customer_support_sales")
            open_lead_modal = True

    # Oversight list: every lead captured by sales-role staff (plus any this
    # customer-support user registered from this page).
    leads = list(
        Lead.objects.select_related(
            "preferred_package",
            "preferred_isp",
            "organization",
            "created_by",
            "created_by__employee_profile",
        )
        .filter(
            Q(created_by__employee_profile__role=Employee.Role.SALES)
            | Q(created_by=request.user)
        )
        .order_by("-created_at")[:300]
    )

    packages_by_org = {}
    all_packages = []
    package_qs = (
        BillingPlan.objects.filter(is_active=True)
        .select_related("organization")
        .order_by("price", "name")
    )
    for plan in package_qs:
        row = {
            "id": plan.pk,
            "label": f"{plan.name} — {plan.price} ({plan.speed_label})",
        }
        packages_by_org.setdefault(str(plan.organization_id), []).append(row)
        all_packages.append(row)

    (
        router_cpe_defaults,
        routers_by_org,
        plans_by_org,
        client_routers,
    ) = _sales_pppoe_router_plan_maps(isp_clients)

    if open_client_modal != "pppoe-register-modal" and request.method != "POST":
        pppoe_initial: dict = {}
        if len(isp_clients) == 1:
            pppoe_initial["organization"] = isp_clients[0].pk
            org_routers = [
                r for r in client_routers if r.organization_id == isp_clients[0].pk
            ]
            if len(org_routers) == 1:
                pppoe_initial["router"] = org_routers[0].pk
        pppoe_form = PppoeClientRegisterForm(
            organizations=isp_clients,
            initial=pppoe_initial,
            default_activate=False,
            allow_activate=False,
            require_serials=False,
        )

    recent_clients = list(
        Customer.objects.select_related(
            "organization",
            "router",
            "assigned_technician",
            "assigned_technician__user",
        )
        .filter(registered_by=request.user, service_type=Customer.ServiceType.PPPOE)
        .order_by("-created_at")[:20]
    )
    recent_isps = list(
        Organization.objects.filter(registered_by=request.user)
        .select_related("owner")
        .order_by("-created_at")[:20]
    )

    return render(
        request,
        "accounts/customer_support_sales.html",
        {
            "page_title": "Sales",
            "page_kicker": "Operations",
            "page_subtitle": (
                "Onboard a new ISP, register a PPPoE client on a specific MikroTik, "
                "or capture a lead — and review sales-team leads."
            ),
            "current_page": "sales",
            "dashboard_url_name": "roles:customer_support",
            "leads": leads,
            "form": form,
            "isp_form": isp_form,
            "pppoe_form": pppoe_form,
            "pppoe_select_isp": True,
            "open_lead_modal": open_lead_modal,
            "open_register_modal": open_register_modal,
            "open_client_modal": open_client_modal,
            "selected_type": selected_type,
            "recent_clients": recent_clients,
            "recent_isps": recent_isps,
            "default_org_id": organization.pk if organization else "",
            "packages_by_org_json": json.dumps(packages_by_org),
            "all_packages_json": json.dumps(all_packages),
            "router_cpe_defaults_json": json.dumps(router_cpe_defaults),
            "routers_by_org_json": json.dumps(routers_by_org),
            "plans_by_org_json": json.dumps(plans_by_org),
            "billing_plans_exist": any(
                key != "_plan_org" and plans_by_org.get(key) for key in plans_by_org
            ),
            "phone_lengths_json": json.dumps(NATIONAL_PHONE_LENGTHS),
            "empty_text": "No sales leads have been registered yet.",
        },
    )


@role_required(Employee.Role.MANAGER)
@require_GET
def manager_places(request):
    """Live location suggestions for customer-support sales registration."""
    from core.places import search_locations

    query = (request.GET.get("q") or "").strip()
    return JsonResponse(search_locations(query, limit=6))


@role_required(Employee.Role.MANAGER)
@require_GET
def manager_place_details(request):
    """Resolve a place_id or free-text location to coordinates."""
    from core.places import resolve_location

    place_id = (request.GET.get("place_id") or "").strip()
    query = (request.GET.get("q") or "").strip()
    details = resolve_location(query, place_id=place_id)
    if not details:
        return JsonResponse({"ok": False, "error": "Place not found."}, status=404)
    return JsonResponse({"ok": True, **details})


@role_required(Employee.Role.MANAGER)
def manager_approved_sales(request):
    """Installed PPPoE tickets awaiting activation, plus recently activated."""
    _prepare_manager_view(request)
    ticket_related = (
        "organization",
        "plan",
        "router",
        "registered_by",
        "assigned_technician",
        "assigned_technician__user",
    )
    installed = list(
        Customer.objects.filter(
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.INSTALLED,
        )
        .select_related(*ticket_related)
        .order_by("-created_at")[:300]
    )
    activated = list(
        Customer.objects.filter(
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.ACTIVE,
        )
        .select_related(*ticket_related)
        .order_by("-created_at")[:100]
    )

    plan_cache: dict[tuple[int | None, int | None, str], list[dict]] = {}
    activation_payload: dict[str, dict] = {}
    for ticket in installed:
        if not ticket.organization_id:
            continue
        service_key = ticket.service_type or ""
        cache_key = (ticket.organization_id, ticket.router_id, service_key)
        if cache_key not in plan_cache:
            qs = plans_for_router(
                ticket.organization,
                ticket.router,
                service_type=ticket.service_type,
            )
            # Fall back to any active package for the ISP so the popup can open
            # even when no PPPoE-specific plans exist yet.
            if not qs.exists():
                qs = plans_for_router(ticket.organization, ticket.router)
            if not qs.exists():
                qs = BillingPlan.objects.filter(
                    organization=ticket.organization,
                    is_active=True,
                ).order_by("price", "name")
            plan_cache[cache_key] = [
                {
                    "id": plan.pk,
                    "name": plan.name,
                    "price": str(plan.price),
                    "duration": plan.duration,
                    "duration_value": plan.duration_value,
                    "duration_unit": plan.duration_unit,
                }
                for plan in qs
            ]
        plans = list(plan_cache[cache_key])
        if ticket.plan_id and not any(p["id"] == ticket.plan_id for p in plans):
            plans.insert(
                0,
                {
                    "id": ticket.plan.pk,
                    "name": ticket.plan.name,
                    "price": str(ticket.plan.price),
                    "duration": ticket.plan.duration,
                    "duration_value": ticket.plan.duration_value,
                    "duration_unit": ticket.plan.duration_unit,
                },
            )
        activation_payload[str(ticket.pk)] = {
            "id": ticket.pk,
            "name": ticket.full_name,
            "account": ticket.sales_ticket_number or ticket.account_number or "",
            "plan_id": ticket.plan_id,
            "plans": plans,
        }

    return render(
        request,
        "accounts/customer_support_approved_sales.html",
        {
            "page_title": "Installed",
            "page_kicker": "Operations",
            "page_subtitle": (
                "Completed installs — Recharge once to collect payment and activate surfing. "
                "Recently activated clients appear below."
            ),
            "current_page": "approved_sales",
            "dashboard_url_name": "roles:customer_support",
            "installed_tickets": installed,
            "activated_tickets": activated,
            "installed_count": len(installed),
            "activated_count": len(activated),
            "activation_payload_json": json.dumps(activation_payload),
            "today_iso": timezone.localdate().isoformat(),
            "empty_text": "No installed tickets yet. When a technician completes an install, it will appear here.",
        },
    )


@role_required(Employee.Role.MANAGER)
@require_POST
def manager_installed_activate_recharge(request, customer_id):
    """One-time cash recharge that activates an installed PPPoE ticket."""
    _prepare_manager_view(request)
    customer = get_object_or_404(
        Customer.objects.select_related("organization", "plan", "router"),
        pk=customer_id,
        service_type=Customer.ServiceType.PPPOE,
        status=Customer.Status.INSTALLED,
    )
    if not customer.organization_id:
        return JsonResponse(
            {"ok": False, "error": "That client is not linked to an ISP yet."},
            status=400,
        )

    form = CustomerCashRechargeForm(
        request.POST,
        organization=customer.organization,
        customer=customer,
    )
    # Match the Installed-page popup: any active ISP package is selectable for
    # this one-time activation (PPPoE packages may not exist yet).
    form.fields["plan"].queryset = BillingPlan.objects.filter(
        organization_id=customer.organization_id,
        is_active=True,
    ).order_by("price", "name")
    if customer.plan_id:
        form.fields["plan"].queryset = (
            BillingPlan.objects.filter(organization_id=customer.organization_id)
            .filter(Q(pk=customer.plan_id) | Q(is_active=True))
            .distinct()
            .order_by("price", "name")
        )
    if not form.is_valid():
        return JsonResponse(
            {"ok": False, "errors": json.loads(form.errors.as_json())},
            status=400,
        )

    try:
        result = recharge_customer_cash(
            customer=customer,
            organization=customer.organization,
            plan=form.cleaned_data["plan"],
            amount=form.cleaned_data["amount"],
            reference=form.cleaned_data.get("reference") or "",
            recorded_by=request.user,
            period_start=form.cleaned_data.get("period_start"),
            period_end=form.cleaned_data.get("period_end"),
            notes="Installed ticket activation recharge",
        )
    except ValueError as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)

    customer = result["customer"]
    invoice = result["invoice"]
    provision = customer_needs_nas_provision(customer)
    enqueue_customer_subscription_sync(
        customer.pk,
        provision,
        wait_first=True,
        quick=True,
        reauthenticate=True,
    )

    amount_label = f"{form.cleaned_data['amount']:.2f}"
    end_label = (
        customer.package_end.isoformat() if customer.package_end else "—"
    )
    start_label = (
        customer.package_start.isoformat() if customer.package_start else "—"
    )
    msg = (
        f"Activated {customer.full_name} with KES {amount_label} "
        f"({invoice.invoice_number}). Surfing window {start_label} → {end_label}."
    )
    return JsonResponse({"ok": True, "message": msg, "customer_id": customer.pk})


@role_required(Employee.Role.MANAGER)
def manager_technician(request):
    """Pending install tickets + allocate to technicians + allocated list."""
    _prepare_manager_view(request)
    redirect_name = "roles:customer_support_technician"

    technicians = list(
        Employee.objects.filter(
            role=Employee.Role.TECHNICIAN,
            status=Employee.Status.ACTIVE,
        )
        .select_related("user", "organization")
        .order_by(
            "user__first_name",
            "user__last_name",
            "user__username",
        )
    )

    open_tickets_qs = (
        Customer.objects.filter(
            service_type=Customer.ServiceType.PPPOE,
            status__in=[Customer.Status.LEAD, Customer.Status.QUEUED],
            assigned_technician__isnull=True,
        )
        .select_related("organization", "plan", "registered_by", "router")
        .order_by("-created_at")
    )

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action == "allocate_technician":
            raw_ticket = (request.POST.get("ticket_id") or "").strip()
            raw_tech = (request.POST.get("technician_id") or "").strip()
            if not raw_ticket.isdigit() or not raw_tech.isdigit():
                messages.error(request, "Choose a ticket and a technician.")
                return redirect(redirect_name)

            with transaction.atomic():
                customer = (
                    Customer.objects.select_for_update()
                    .filter(pk=int(raw_ticket))
                    .first()
                )
                technician = (
                    Employee.objects.select_related("user")
                    .filter(
                        pk=int(raw_tech),
                        role=Employee.Role.TECHNICIAN,
                        status=Employee.Status.ACTIVE,
                    )
                    .first()
                )
                if customer is None:
                    messages.error(request, "That ticket was not found.")
                    return redirect(redirect_name)
                if technician is None:
                    messages.error(request, "Choose an active technician.")
                    return redirect(redirect_name)

                ticket_label = (
                    customer.sales_ticket_number or customer.account_number
                )
                allocatable = (
                    customer.status
                    in (Customer.Status.LEAD, Customer.Status.QUEUED)
                    and customer.assigned_technician_id is None
                ) or customer.status == Customer.Status.ASSIGNED
                if not allocatable:
                    messages.error(
                        request,
                        (
                            f"Ticket {ticket_label} cannot be allocated "
                            f"(status: {customer.get_status_display()})."
                        ),
                    )
                    return redirect(redirect_name)

                customer.status = Customer.Status.ASSIGNED
                customer.assigned_technician = technician
                customer.save(update_fields=["status", "assigned_technician"])
                InstallationDecline.objects.filter(
                    customer=customer, technician=technician
                ).delete()

            tech_name = (
                technician.user.get_full_name() or technician.user.username
            )
            notify_org_event(
                "isp_technician_assigned",
                organization=getattr(customer, "organization", None),
                client=customer,
                technician=technician,
                context={
                    "client_name": customer.full_name or "",
                    "location": getattr(customer, "location", "") or "",
                },
                subject="Installation assigned",
            )
            notify_org_event(
                "lead_installation",
                organization=getattr(customer, "organization", None),
                client=customer,
                technician=technician,
                context={"status": "assigned", "technician_name": tech_name},
                subject="Installation update",
            )
            messages.success(
                request,
                f"Allocated ticket {ticket_label} to {tech_name}.",
            )
            return redirect(redirect_name)

        if action == "release_ticket":
            raw_ticket = (request.POST.get("ticket_id") or "").strip()
            if not raw_ticket.isdigit():
                messages.error(request, "Choose a ticket to release.")
                return redirect(redirect_name)
            with transaction.atomic():
                customer = (
                    Customer.objects.select_for_update()
                    .filter(pk=int(raw_ticket))
                    .first()
                )
                if customer is None or customer.status != Customer.Status.ASSIGNED:
                    messages.error(request, "That allocated ticket was not found.")
                    return redirect(redirect_name)
                ticket_label = (
                    customer.sales_ticket_number or customer.account_number
                )
                customer.status = Customer.Status.QUEUED
                customer.assigned_technician = None
                customer.save(update_fields=["status", "assigned_technician"])
            messages.success(
                request,
                f"Released ticket {ticket_label} back to pending installation.",
            )
            return redirect(redirect_name)

        if action == "raise_fault_ticket":
            raw_customer = (request.POST.get("customer_id") or "").strip()
            raw_tech = (request.POST.get("technician_id") or "").strip()
            issue = (request.POST.get("issue") or "").strip()
            notes = (request.POST.get("notes") or "").strip()
            if not raw_customer.isdigit():
                messages.error(request, "Search and select a client for the fault ticket.")
                return redirect(redirect_name)
            if issue not in FaultTicket.Issue.values:
                messages.error(request, "Choose a valid issue type.")
                return redirect(redirect_name)

            customer = (
                Customer.objects.select_related("organization")
                .filter(pk=int(raw_customer))
                .first()
            )
            if customer is None:
                messages.error(request, "That client was not found.")
                return redirect(redirect_name)

            technician = None
            if raw_tech:
                if not raw_tech.isdigit():
                    messages.error(request, "Choose an active technician.")
                    return redirect(redirect_name)
                technician = (
                    Employee.objects.select_related("user")
                    .filter(
                        pk=int(raw_tech),
                        role=Employee.Role.TECHNICIAN,
                        status=Employee.Status.ACTIVE,
                    )
                    .first()
                )
                if technician is None:
                    messages.error(request, "Choose an active technician.")
                    return redirect(redirect_name)

            ticket = FaultTicket.objects.create(
                ticket_number=FaultTicket.generate_ticket_number(),
                customer=customer,
                organization=customer.organization,
                issue=issue,
                notes=notes,
                status=(
                    FaultTicket.Status.ASSIGNED
                    if technician
                    else FaultTicket.Status.OPEN
                ),
                assigned_technician=technician,
                created_by=request.user,
            )
            if technician:
                tech_name = (
                    technician.user.get_full_name() or technician.user.username
                )
                messages.success(
                    request,
                    (
                        f"Fault ticket {ticket.ticket_number} raised for "
                        f"{customer.full_name} — {ticket.get_issue_display()}, "
                        f"allocated to {tech_name}."
                    ),
                )
            else:
                messages.success(
                    request,
                    (
                        f"Fault ticket {ticket.ticket_number} raised for "
                        f"{customer.full_name} — {ticket.get_issue_display()}."
                    ),
                )
            return redirect(redirect_name)

    open_tickets = list(open_tickets_qs[:300])
    allocated_tickets = list(
        Customer.objects.filter(
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.ASSIGNED,
            assigned_technician__isnull=False,
        )
        .select_related(
            "organization",
            "plan",
            "assigned_technician",
            "assigned_technician__user",
            "registered_by",
            "router",
        )
        .order_by("-created_at")[:300]
    )
    recent_faults = list(
        FaultTicket.objects.select_related(
            "customer",
            "organization",
            "assigned_technician",
            "assigned_technician__user",
            "created_by",
        )
        .exclude(status__in=[FaultTicket.Status.RESOLVED, FaultTicket.Status.CLOSED])
        .order_by("-created_at")[:50]
    )

    return render(
        request,
        "accounts/customer_support_technician.html",
        {
            "page_title": "Technician",
            "page_kicker": "Field work",
            "page_subtitle": (
                "Review tickets pending installation, allocate them to a technician, "
                "raise fault tickets, and see every ticket with its assigned technician."
            ),
            "current_page": "technician",
            "dashboard_url_name": "roles:customer_support",
            "technicians": technicians,
            "open_tickets": open_tickets,
            "tickets": allocated_tickets,
            "open_count": len(open_tickets),
            "allocated_count": len(allocated_tickets),
            "fault_tickets": recent_faults,
            "fault_count": len(recent_faults),
            "fault_issue_choices": FaultTicket.Issue.choices,
            "empty_text": "No tickets are allocated to technicians yet.",
            "open_fault_modal": (
                (request.GET.get("raise_fault") or "").strip() in {"1", "true", "yes"}
            ),
        },
    )


@role_required(Employee.Role.MANAGER)
@require_GET
def manager_technician_client_search(request):
    """Live search active/installed clients for raising fault tickets."""
    _prepare_manager_view(request)
    query = (request.GET.get("q") or "").strip()
    if len(query) < 2:
        return JsonResponse({"results": []})

    customers = (
        Customer.objects.select_related("organization", "plan", "router")
        .filter(
            service_type=Customer.ServiceType.PPPOE,
            status__in=[
                Customer.Status.ACTIVE,
                Customer.Status.INSTALLED,
                Customer.Status.ASSIGNED,
            ],
        )
        .filter(
            Q(full_name__icontains=query)
            | Q(phone__icontains=query)
            | Q(account_number__icontains=query)
            | Q(sales_ticket_number__icontains=query)
            | Q(pppoe_username__icontains=query)
            | Q(building_name__icontains=query)
            | Q(address__icontains=query)
        )
        .order_by("full_name", "id")[:20]
    )
    results = []
    for customer in customers:
        location_parts = [
            part
            for part in [
                (customer.building_name or "").strip(),
                (customer.house_number or "").strip(),
                (customer.address or "").strip(),
            ]
            if part
        ]
        results.append(
            {
                "id": customer.pk,
                "name": customer.full_name or "—",
                "phone": customer.phone or "",
                "account": customer.sales_ticket_number
                or customer.account_number
                or "",
                "pppoe": customer.pppoe_username or "",
                "isp": customer.organization.name if customer.organization_id else "",
                "location": " · ".join(location_parts) if location_parts else "",
                "status": customer.get_status_display(),
            }
        )
    return JsonResponse({"results": results})


@role_required(Employee.Role.MANAGER)
def manager_allocated(request):
    """Legacy URL — technician allocation now lives on the Technician page."""
    _prepare_manager_view(request)
    return redirect("roles:customer_support_technician")


def _log_equipment_stock_movements(
    *,
    equipment,
    movement_type,
    quantity=1,
    serials=None,
    employee=None,
    actor=None,
    notes="",
):
    """Persist one or more stock movement ledger rows."""
    serials = [((s or "").strip().upper()) for s in (serials or []) if (s or "").strip()]
    rows = []
    if serials:
        for serial in serials:
            rows.append(
                NetworkEquipmentStockMovement(
                    equipment=equipment,
                    movement_type=movement_type,
                    quantity=1,
                    serial_number=serial,
                    employee=employee,
                    actor=actor,
                    notes=notes or "",
                )
            )
    else:
        rows.append(
            NetworkEquipmentStockMovement(
                equipment=equipment,
                movement_type=movement_type,
                quantity=max(1, int(quantity or 1)),
                serial_number="",
                employee=employee,
                actor=actor,
                notes=notes or "",
            )
        )
    NetworkEquipmentStockMovement.objects.bulk_create(rows)
    return rows


def _equipment_movement_timeline(equipment):
    """Build a display timeline from the stock movement ledger (or synthesize)."""
    movements = list(
        NetworkEquipmentStockMovement.objects.filter(equipment=equipment)
        .select_related("actor", "employee", "employee__user")
        .order_by("-created_at", "-id")[:500]
    )
    timeline = []
    if movements:
        for row in movements:
            employee_label = ""
            if row.employee_id and row.employee:
                employee_label = (
                    row.employee.user.get_full_name()
                    or row.employee.user.username
                )
            timeline.append(
                {
                    "when": row.created_at,
                    "kind": row.movement_type,
                    "label": row.get_movement_type_display(),
                    "quantity": row.quantity,
                    "serial": row.serial_number,
                    "employee": employee_label,
                    "actor": row.actor,
                    "notes": row.notes,
                }
            )
        return timeline

    # No ledger yet — synthesize from serials and allocations.
    allocated_serial_ids = set(
        NetworkEquipmentAllocation.objects.filter(
            equipment=equipment,
            serial_id__isnull=False,
        ).values_list("serial_id", flat=True)
    )
    for unit in NetworkEquipmentSerial.objects.filter(equipment=equipment).select_related(
        "created_by"
    ):
        timeline.append(
            {
                "when": unit.created_at,
                "kind": NetworkEquipmentStockMovement.MovementType.STOCK_IN,
                "label": "Stock in",
                "quantity": 1,
                "serial": unit.serial_number,
                "employee": "",
                "actor": unit.created_by,
                "notes": "",
            }
        )
        if (
            unit.status == NetworkEquipmentSerial.Status.ISSUED
            and unit.issued_at
            and unit.pk not in allocated_serial_ids
        ):
            timeline.append(
                {
                    "when": unit.issued_at,
                    "kind": NetworkEquipmentStockMovement.MovementType.STOCK_OUT,
                    "label": "Stock out",
                    "quantity": 1,
                    "serial": unit.serial_number,
                    "employee": "",
                    "actor": None,
                    "notes": "",
                }
            )
    for row in (
        NetworkEquipmentAllocation.objects.filter(equipment=equipment)
        .select_related("serial", "employee", "employee__user", "allocated_by")
        .order_by("-allocated_at")
    ):
        employee_label = ""
        if row.employee_id and row.employee:
            employee_label = (
                row.employee.user.get_full_name()
                or row.employee.user.username
            )
        serial = row.serial.serial_number if row.serial_id else ""
        timeline.append(
            {
                "when": row.allocated_at,
                "kind": NetworkEquipmentStockMovement.MovementType.ALLOCATE,
                "label": "Allocated",
                "quantity": row.quantity,
                "serial": serial,
                "employee": employee_label,
                "actor": row.allocated_by,
                "notes": row.notes,
            }
        )
        if row.returned_at:
            timeline.append(
                {
                    "when": row.returned_at,
                    "kind": NetworkEquipmentStockMovement.MovementType.RETURN,
                    "label": "Returned",
                    "quantity": row.quantity,
                    "serial": serial,
                    "employee": employee_label,
                    "actor": None,
                    "notes": "",
                }
            )
    timeline.sort(key=lambda item: item["when"] or timezone.now(), reverse=True)
    return timeline[:500]


def _equipment_stock_movement_report(equipment):
    """Daily stock movement report rows for warehouse inventory."""
    Mt = NetworkEquipmentStockMovement.MovementType
    events = _equipment_movement_timeline(equipment)
    if not events:
        return []

    # Chronological for running balance (oldest first).
    chronological = sorted(
        events,
        key=lambda item: (item["when"] or timezone.now(), item.get("serial") or ""),
    )

    by_date = {}
    date_order = []
    for event in chronological:
        when = event["when"] or timezone.now()
        local_day = timezone.localtime(when).date()
        if local_day not in by_date:
            by_date[local_day] = {
                "date": local_day,
                "stock_in": 0,
                "stock_out": 0,
                "transferred_in": 0,
                "transferred_out": 0,
                "sale": 0,
            }
            date_order.append(local_day)
        bucket = by_date[local_day]
        qty = max(0, int(event.get("quantity") or 0))
        kind = event.get("kind")
        if kind == Mt.STOCK_IN:
            bucket["stock_in"] += qty
        elif kind == Mt.STOCK_OUT:
            bucket["stock_out"] += qty
        elif kind == Mt.RETURN:
            bucket["transferred_in"] += qty
        elif kind == Mt.ALLOCATE:
            bucket["transferred_out"] += qty
        elif kind == Mt.SOLD:
            # Field sales already left warehouse via allocate — show SALE only.
            bucket["sale"] += qty

    net_change = 0
    for day in date_order:
        row = by_date[day]
        # SALE is display-only here (units already counted in transferred_out).
        net_change += (
            row["stock_in"]
            + row["transferred_in"]
            - row["stock_out"]
            - row["transferred_out"]
        )

    running = max(0, int(equipment.quantity or 0) - net_change)
    report = []
    for day in date_order:
        row = by_date[day]
        opening = running
        current = (
            opening
            + row["stock_in"]
            + row["transferred_in"]
            - row["stock_out"]
            - row["transferred_out"]
        )
        if current < 0:
            current = 0
        report.append(
            {
                "date": day,
                "opening_stock": opening,
                "stock_in": row["stock_in"],
                "stock_out": row["stock_out"],
                "transferred_in": row["transferred_in"],
                "transferred_out": row["transferred_out"],
                "sale": row["sale"],
                "current_stock": current,
            }
        )
        running = current

    report.reverse()  # Newest day first
    return report


def _equipment_active_allocations_by_employee(equipment):
    """Aggregate open allocations: one row per employee with total qty."""
    rows = list(
        NetworkEquipmentAllocation.objects.filter(
            equipment=equipment,
            returned_at__isnull=True,
        )
        .values("employee_id")
        .annotate(
            quantity=Sum("quantity"),
            last_allocated_at=Max("allocated_at"),
        )
        .order_by("-last_allocated_at")
    )
    if not rows:
        return []
    employees = {
        emp.pk: emp
        for emp in Employee.objects.select_related("user").filter(
            pk__in=[row["employee_id"] for row in rows]
        )
    }
    result = []
    for row in rows:
        member = employees.get(row["employee_id"])
        if not member:
            continue
        result.append(
            {
                "employee": member,
                "quantity": int(row["quantity"] or 0),
                "last_allocated_at": row["last_allocated_at"],
            }
        )
    return result


def _equipment_employee_movement_events(equipment, employee):
    """Allocate/return/sold events for one equipment ↔ employee pair."""
    Mt = NetworkEquipmentStockMovement.MovementType
    movements = list(
        NetworkEquipmentStockMovement.objects.filter(
            equipment=equipment,
            employee=employee,
            movement_type__in=[Mt.ALLOCATE, Mt.RETURN, Mt.SOLD],
        )
        .select_related("actor")
        .order_by("created_at", "id")[:500]
    )
    events = []
    if movements:
        for row in movements:
            events.append(
                {
                    "when": row.created_at,
                    "kind": row.movement_type,
                    "quantity": row.quantity,
                    "serial": row.serial_number,
                    "actor": row.actor,
                    "notes": row.notes,
                }
            )
        return events

    for row in (
        NetworkEquipmentAllocation.objects.filter(
            equipment=equipment,
            employee=employee,
        )
        .select_related("serial", "allocated_by")
        .order_by("allocated_at", "id")
    ):
        serial = row.serial.serial_number if row.serial_id else ""
        events.append(
            {
                "when": row.allocated_at,
                "kind": Mt.ALLOCATE,
                "quantity": row.quantity,
                "serial": serial,
                "actor": row.allocated_by,
                "notes": row.notes,
            }
        )
        if row.returned_at:
            events.append(
                {
                    "when": row.returned_at,
                    "kind": Mt.RETURN,
                    "quantity": row.quantity,
                    "serial": serial,
                    "actor": None,
                    "notes": "",
                }
            )
    return events


def _equipment_employee_movement_report(equipment, employee):
    """
    Daily report of stock held by an employee for one equipment item.

    From the assignee perspective:
    - allocate → transferred in
    - return → transferred out
    """
    Mt = NetworkEquipmentStockMovement.MovementType
    events = _equipment_employee_movement_events(equipment, employee)
    held_qty = (
        NetworkEquipmentAllocation.objects.filter(
            equipment=equipment,
            employee=employee,
            returned_at__isnull=True,
        ).aggregate(total=Sum("quantity"))["total"]
        or 0
    )
    held = int(held_qty)
    if not events:
        return [], held

    by_date = {}
    date_order = []
    for event in events:
        when = event["when"] or timezone.now()
        local_day = timezone.localtime(when).date()
        if local_day not in by_date:
            by_date[local_day] = {
                "date": local_day,
                "stock_in": 0,
                "stock_out": 0,
                "transferred_in": 0,
                "transferred_out": 0,
                "sale": 0,
            }
            date_order.append(local_day)
        bucket = by_date[local_day]
        qty = max(0, int(event.get("quantity") or 0))
        kind = event.get("kind")
        if kind == Mt.ALLOCATE:
            bucket["transferred_in"] += qty
        elif kind == Mt.RETURN:
            bucket["transferred_out"] += qty
        elif kind == Mt.SOLD:
            bucket["sale"] += qty

    net_change = 0
    for day in date_order:
        row = by_date[day]
        net_change += (
            row["stock_in"]
            + row["transferred_in"]
            - row["stock_out"]
            - row["transferred_out"]
            - row["sale"]
        )

    running = max(0, held - net_change)
    report = []
    for day in date_order:
        row = by_date[day]
        opening = running
        current = (
            opening
            + row["stock_in"]
            + row["transferred_in"]
            - row["stock_out"]
            - row["transferred_out"]
            - row["sale"]
        )
        if current < 0:
            current = 0
        report.append(
            {
                "date": day,
                "opening_stock": opening,
                "stock_in": row["stock_in"],
                "stock_out": row["stock_out"],
                "transferred_in": row["transferred_in"],
                "transferred_out": row["transferred_out"],
                "sale": row["sale"],
                "current_stock": current,
            }
        )
        running = current

    report.reverse()
    return report, held


@role_required(Employee.Role.MANAGER)
def manager_network_equipment(request):
    _prepare_manager_view(request)

    def _redirect_equipment():
        redirect_name = (
            f"roles:{request.resolver_match.url_name}"
            if request.resolver_match and request.resolver_match.url_name
            else "roles:customer_support_network_equipment"
        )
        return redirect(redirect_name)

    open_register_modal = False
    open_edit_modal = False
    open_stock_modal = False
    stock_equipment = None
    stock_direction = "in"
    stock_track_serials = False
    stock_serial_values = []
    edit_form = NetworkEquipmentRegisterForm(prefix="edit")
    form = NetworkEquipmentRegisterForm()

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action == "set_track_serials":
            equipment = get_object_or_404(
                NetworkEquipment,
                pk=request.POST.get("equipment_id"),
            )
            enable = request.POST.get("track_serials") == "1"
            if not enable:
                password = (
                    request.POST.get("verification_password")
                    or request.POST.get("verification_code")
                    or ""
                )
                if not password or not request.user.check_password(password):
                    return JsonResponse(
                        {
                            "ok": False,
                            "error": "Incorrect password.",
                            "track_serials": equipment.track_serials,
                        },
                        status=400,
                    )
            equipment.track_serials = enable
            equipment.save(update_fields=["track_serials", "updated_at"])
            return JsonResponse(
                {
                    "ok": True,
                    "track_serials": equipment.track_serials,
                }
            )
        if action in {"stock_in", "stock_out"}:
            wants_json = (
                request.headers.get("X-Requested-With") == "XMLHttpRequest"
                or "application/json" in (request.headers.get("Accept") or "").lower()
            )

            def stock_error(message, status=400):
                if wants_json:
                    return JsonResponse(
                        {
                            "ok": False,
                            "error": message,
                            "quantity": equipment.quantity,
                        },
                        status=status,
                    )
                messages.error(request, message)
                return None

            equipment = get_object_or_404(
                NetworkEquipment,
                pk=request.POST.get("equipment_id"),
            )
            stock_equipment = equipment
            stock_direction = "in" if action == "stock_in" else "out"
            open_stock_modal = True
            stock_track_serials = request.POST.get("track_serials") == "1"
            if equipment.track_serials:
                stock_track_serials = True
            raw_serials = request.POST.getlist("serial_number")
            serials = []
            seen = set()
            serial_error = False
            for raw in raw_serials:
                value = (raw or "").strip().upper()
                if not value:
                    continue
                if value in seen:
                    err = stock_error(f"Duplicate serial “{value}” in this movement.")
                    if err is not None:
                        return err
                    serial_error = True
                    break
                seen.add(value)
                serials.append(value)
            stock_serial_values = list(serials) if serials else [""]
            if not serial_error:
                if equipment.is_suspended:
                    err = stock_error("Suspended equipment cannot be stocked.")
                    if err is not None:
                        return err
                else:
                    try:
                        amount = int(request.POST.get("amount") or "0")
                    except (TypeError, ValueError):
                        amount = 0
                    if amount < 1:
                        err = stock_error("Enter a quantity of at least 1.")
                        if err is not None:
                            return err
                    elif action == "stock_out" and amount > equipment.quantity:
                        err = stock_error(
                            f"Cannot stock out {amount}. Only {equipment.quantity} in stock."
                        )
                        if err is not None:
                            return err
                    elif stock_track_serials and len(serials) != amount:
                        err = stock_error(
                            "Serial number required. Enter exactly "
                            f"{amount} serial number(s) for this stock movement."
                        )
                        if err is not None:
                            return err
                    else:
                        from django.utils import timezone

                        try:
                            with transaction.atomic():
                                if action == "stock_in":
                                    if stock_track_serials:
                                        existing = set(
                                            NetworkEquipmentSerial.objects.filter(
                                                equipment=equipment,
                                                serial_number__in=serials,
                                            ).values_list("serial_number", flat=True)
                                        )
                                        if existing:
                                            raise ValueError(
                                                "Serial already exists: "
                                                + ", ".join(sorted(existing))
                                            )
                                        NetworkEquipmentSerial.objects.bulk_create(
                                            [
                                                NetworkEquipmentSerial(
                                                    equipment=equipment,
                                                    serial_number=serial,
                                                    status=NetworkEquipmentSerial.Status.IN_STOCK,
                                                    created_by=request.user,
                                                )
                                                for serial in serials
                                            ]
                                        )
                                    equipment.quantity += amount
                                    verb = "Stocked in"
                                else:
                                    if stock_track_serials:
                                        units = list(
                                            NetworkEquipmentSerial.objects.select_for_update().filter(
                                                equipment=equipment,
                                                serial_number__in=serials,
                                                status=NetworkEquipmentSerial.Status.IN_STOCK,
                                            )
                                        )
                                        found = {unit.serial_number for unit in units}
                                        missing = [s for s in serials if s not in found]
                                        if missing:
                                            raise ValueError(
                                                "Serial not in stock: "
                                                + ", ".join(missing)
                                            )
                                        now = timezone.now()
                                        for unit in units:
                                            unit.status = NetworkEquipmentSerial.Status.ISSUED
                                            unit.issued_at = now
                                            unit.save(
                                                update_fields=[
                                                    "status",
                                                    "issued_at",
                                                    "updated_at",
                                                ]
                                            )
                                    equipment.quantity -= amount
                                    verb = "Stocked out"
                                update_fields = ["quantity", "updated_at"]
                                if stock_track_serials and not equipment.track_serials:
                                    equipment.track_serials = True
                                    update_fields.append("track_serials")
                                equipment.save(update_fields=update_fields)
                                move_type = (
                                    NetworkEquipmentStockMovement.MovementType.STOCK_IN
                                    if action == "stock_in"
                                    else NetworkEquipmentStockMovement.MovementType.STOCK_OUT
                                )
                                _log_equipment_stock_movements(
                                    equipment=equipment,
                                    movement_type=move_type,
                                    quantity=amount,
                                    serials=serials if stock_track_serials else None,
                                    actor=request.user,
                                )
                        except ValueError as exc:
                            err = stock_error(str(exc))
                            if err is not None:
                                return err
                        else:
                            if wants_json:
                                return JsonResponse(
                                    {
                                        "ok": True,
                                        "quantity": equipment.quantity,
                                        "amount": amount,
                                        "action": action,
                                        "serials": serials,
                                        "message": (
                                            f"{verb} {amount} × “{equipment.name}”. "
                                            f"Stock is now {equipment.quantity}."
                                        ),
                                    }
                                )
                            messages.success(
                                request,
                                f"{verb} {amount} × “{equipment.name}”. "
                                f"Stock is now {equipment.quantity}.",
                            )
                            return _redirect_equipment()
        elif action == "edit":
            equipment = get_object_or_404(
                NetworkEquipment,
                pk=request.POST.get("equipment_id"),
            )
            edit_form = NetworkEquipmentRegisterForm(
                request.POST,
                request.FILES,
                instance=equipment,
                prefix="edit",
            )
            if edit_form.is_valid():
                edited = edit_form.save()
                messages.success(request, f"Updated “{edited.name}”.")
                return _redirect_equipment()
            open_edit_modal = True
        elif action == "suspend":
            equipment = get_object_or_404(
                NetworkEquipment,
                pk=request.POST.get("equipment_id"),
            )
            if equipment.is_suspended:
                messages.info(request, f"“{equipment.name}” is already suspended.")
            else:
                equipment.status = NetworkEquipment.Status.SUSPENDED
                equipment.save(update_fields=["status", "updated_at"])
                messages.success(request, f"Suspended “{equipment.name}”.")
            return _redirect_equipment()
        elif action == "unsuspend":
            equipment = get_object_or_404(
                NetworkEquipment,
                pk=request.POST.get("equipment_id"),
            )
            if not equipment.is_suspended:
                messages.info(request, f"“{equipment.name}” is not suspended.")
            else:
                equipment.status = NetworkEquipment.Status.ACTIVE
                equipment.save(update_fields=["status", "updated_at"])
                messages.success(request, f"Unsuspended “{equipment.name}”.")
            return _redirect_equipment()
        elif action == "delete":
            equipment = get_object_or_404(
                NetworkEquipment,
                pk=request.POST.get("equipment_id"),
            )
            name = equipment.name
            equipment.delete()
            messages.success(request, f"Deleted “{name}”.")
            return _redirect_equipment()
        else:
            form = NetworkEquipmentRegisterForm(request.POST, request.FILES)
            if form.is_valid():
                equipment = form.save(created_by=request.user)
                messages.success(
                    request,
                    f"Equipment “{equipment.name}” registered.",
                )
                return _redirect_equipment()
            open_register_modal = True
    else:
        open_register_modal = bool(request.GET.get("register"))

    equipment_list = list(
        NetworkEquipment.objects.select_related("created_by").order_by("-created_at")[:200]
    )
    url_name = getattr(request.resolver_match, "url_name", "") or ""
    detail_url_name = (
        "roles:manager_network_equipment_detail"
        if url_name.startswith("manager_")
        else "roles:customer_support_network_equipment_detail"
    )
    return render(
        request,
        "accounts/customer_support_network_equipment.html",
        {
            "page_title": "Stock Audit",
            "page_kicker": "Infrastructure",
            "page_subtitle": "Register equipment, update stock, and audit every movement.",
            "current_page": "stock_audit",
            "dashboard_url_name": "roles:customer_support",
            "detail_url_name": detail_url_name,
            "form": form,
            "edit_form": edit_form,
            "equipment_list": equipment_list,
            "equipment_count": len(equipment_list),
            "open_register_modal": open_register_modal,
            "open_edit_modal": open_edit_modal,
            "open_stock_modal": open_stock_modal,
            "stock_equipment": stock_equipment,
            "stock_direction": stock_direction,
            "stock_track_serials": stock_track_serials,
            "stock_serial_values": stock_serial_values,
            "stock_serial_values_json": json.dumps(stock_serial_values),
            "empty_text": "No network equipment records yet. Use Register equipment to add one.",
        },
    )


@role_required(Employee.Role.MANAGER)
def manager_network_equipment_detail(request, pk):
    """Equipment detail with full stock movement history from stock in onward."""
    _prepare_manager_view(request)
    equipment = get_object_or_404(
        NetworkEquipment.objects.select_related("created_by"),
        pk=pk,
    )
    timeline_report = _equipment_stock_movement_report(equipment)
    movement_log = _equipment_movement_timeline(equipment)
    allocated_employees = _equipment_active_allocations_by_employee(equipment)
    url_name = getattr(request.resolver_match, "url_name", "") or ""
    is_manager_alias = url_name.startswith("manager_")
    list_url_name = (
        "roles:manager_network_equipment"
        if is_manager_alias
        else "roles:customer_support_network_equipment"
    )
    employee_report_url_name = (
        "roles:manager_network_equipment_employee"
        if is_manager_alias
        else "roles:customer_support_network_equipment_employee"
    )

    return render(
        request,
        "accounts/customer_support_network_equipment_detail.html",
        {
            "page_title": equipment.name,
            "page_kicker": "Stock Audit",
            "page_subtitle": "Detailed stock movement audit from stock in onward.",
            "current_page": "stock_audit",
            "dashboard_url_name": "roles:customer_support",
            "list_url_name": list_url_name,
            "employee_report_url_name": employee_report_url_name,
            "equipment": equipment,
            "stock_report": timeline_report,
            "movement_log": movement_log,
            "movement_count": len(timeline_report),
            "movement_log_count": len(movement_log),
            "show_serial_column": bool(equipment.track_serials)
            or any((event.get("serial") or "") for event in movement_log),
            "allocated_employees": allocated_employees,
        },
    )


@role_required(Employee.Role.MANAGER)
def manager_network_equipment_employee(request, pk, employee_id):
    """Movement report for one equipment item assigned to one employee."""
    _prepare_manager_view(request)
    equipment = get_object_or_404(
        NetworkEquipment.objects.select_related("created_by"),
        pk=pk,
    )
    member = get_object_or_404(
        Employee.objects.select_related("user"),
        pk=employee_id,
    )
    stock_report, held_qty = _equipment_employee_movement_report(equipment, member)
    held_serials = list(
        NetworkEquipmentAllocation.objects.filter(
            equipment=equipment,
            employee=member,
            returned_at__isnull=True,
            serial__isnull=False,
        )
        .select_related("serial")
        .order_by("serial__serial_number")
    )
    url_name = getattr(request.resolver_match, "url_name", "") or ""
    is_manager_alias = url_name.startswith("manager_")
    detail_url_name = (
        "roles:manager_network_equipment_detail"
        if is_manager_alias
        else "roles:customer_support_network_equipment_detail"
    )
    employee_name = member.user.get_full_name() or member.user.username

    return render(
        request,
        "accounts/customer_support_network_equipment_employee.html",
        {
            "page_title": f"{equipment.name} · {employee_name}",
            "page_kicker": "Assigned stock",
            "page_subtitle": (
                f"Movement report for {equipment.name} assigned to {employee_name}."
            ),
            "current_page": "stock_audit",
            "dashboard_url_name": "roles:customer_support",
            "detail_url_name": detail_url_name,
            "equipment": equipment,
            "member": member,
            "employee_name": employee_name,
            "held_qty": held_qty,
            "held_serials": held_serials,
            "stock_report": stock_report,
            "movement_count": len(stock_report),
        },
    )


@role_required(Employee.Role.MANAGER)
def manager_allocate(request):
    _prepare_manager_view(request)

    employees = list(
        Employee.objects.select_related("user", "organization").order_by(
            "user__first_name", "user__last_name", "user__username"
        )
    )
    equipment_list = list(
        NetworkEquipment.objects.filter(status=NetworkEquipment.Status.ACTIVE)
        .order_by("name")
    )
    serial_options = {}
    for item in equipment_list:
        if item.track_serials:
            serial_options[str(item.pk)] = list(
                NetworkEquipmentSerial.objects.filter(
                    equipment=item,
                    status=NetworkEquipmentSerial.Status.IN_STOCK,
                )
                .order_by("serial_number")
                .values_list("serial_number", flat=True)[:300]
            )

    return render(
        request,
        "accounts/customer_support_allocate.html",
        {
            "page_title": "Allocate equipment",
            "page_kicker": "Infrastructure",
            "page_subtitle": (
                "Choose an employee, then allocate network equipment from stock."
            ),
            "current_page": "stock_audit",
            "dashboard_url_name": "roles:customer_support",
            "employees": employees,
            "employees_count": len(employees),
            "equipment_list": equipment_list,
            "serial_options_json": json.dumps(serial_options),
            "empty_text": "No employees registered yet.",
        },
    )


@role_required(Employee.Role.MANAGER)
def manager_allocate_employee(request, pk):
    _prepare_manager_view(request)
    member = get_object_or_404(
        Employee.objects.select_related("user", "organization"),
        pk=pk,
    )

    def _redirect_allocate():
        next_url = (request.POST.get("next") or "").strip()
        if next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect("roles:customer_support_allocate_employee", pk=member.pk)

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action == "allocate":
            equipment = get_object_or_404(
                NetworkEquipment,
                pk=request.POST.get("equipment_id"),
            )
            if equipment.is_suspended:
                messages.error(request, "Suspended equipment cannot be allocated.")
                return _redirect_allocate()
            if equipment.quantity < 1:
                messages.error(request, f"“{equipment.name}” has no stock available.")
                return _redirect_allocate()

            from django.utils import timezone

            try:
                with transaction.atomic():
                    if equipment.track_serials:
                        raw_serials = request.POST.getlist("serial_number")
                        serials = []
                        seen = set()
                        for raw in raw_serials:
                            value = (raw or "").strip().upper()
                            if not value:
                                continue
                            if value in seen:
                                raise ValueError(f"Duplicate serial “{value}”.")
                            seen.add(value)
                            serials.append(value)
                        if not serials:
                            raise ValueError("Scan or enter at least one serial to allocate.")
                        if len(serials) > equipment.quantity:
                            raise ValueError(
                                f"Cannot allocate {len(serials)}. Only {equipment.quantity} in stock."
                            )
                        units = list(
                            NetworkEquipmentSerial.objects.select_for_update().filter(
                                equipment=equipment,
                                serial_number__in=serials,
                                status=NetworkEquipmentSerial.Status.IN_STOCK,
                            )
                        )
                        found = {unit.serial_number for unit in units}
                        missing = [s for s in serials if s not in found]
                        if missing:
                            raise ValueError(
                                "Serial not in stock: " + ", ".join(missing)
                            )
                        now = timezone.now()
                        for unit in units:
                            unit.status = NetworkEquipmentSerial.Status.ISSUED
                            unit.issued_at = now
                            unit.save(
                                update_fields=["status", "issued_at", "updated_at"]
                            )
                            NetworkEquipmentAllocation.objects.create(
                                equipment=equipment,
                                employee=member,
                                quantity=1,
                                serial=unit,
                                allocated_by=request.user,
                            )
                        equipment.quantity -= len(units)
                        equipment.save(update_fields=["quantity", "updated_at"])
                        _log_equipment_stock_movements(
                            equipment=equipment,
                            movement_type=NetworkEquipmentStockMovement.MovementType.ALLOCATE,
                            quantity=len(units),
                            serials=serials,
                            employee=member,
                            actor=request.user,
                        )
                        messages.success(
                            request,
                            f"Allocated {len(units)} serial(s) of “{equipment.name}” "
                            f"to {member.user.get_full_name() or member.user.username}.",
                        )
                    else:
                        try:
                            amount = int(request.POST.get("amount") or "0")
                        except (TypeError, ValueError):
                            amount = 0
                        if amount < 1:
                            raise ValueError("Enter a quantity of at least 1.")
                        if amount > equipment.quantity:
                            raise ValueError(
                                f"Cannot allocate {amount}. Only {equipment.quantity} in stock."
                            )
                        equipment.quantity -= amount
                        equipment.save(update_fields=["quantity", "updated_at"])
                        NetworkEquipmentAllocation.objects.create(
                            equipment=equipment,
                            employee=member,
                            quantity=amount,
                            allocated_by=request.user,
                        )
                        _log_equipment_stock_movements(
                            equipment=equipment,
                            movement_type=NetworkEquipmentStockMovement.MovementType.ALLOCATE,
                            quantity=amount,
                            employee=member,
                            actor=request.user,
                        )
                        messages.success(
                            request,
                            f"Allocated {amount} × “{equipment.name}” "
                            f"to {member.user.get_full_name() or member.user.username}.",
                        )
            except ValueError as exc:
                messages.error(request, str(exc))
            return _redirect_allocate()

        if action == "return":
            allocation = get_object_or_404(
                NetworkEquipmentAllocation.objects.select_related(
                    "equipment", "serial"
                ),
                pk=request.POST.get("allocation_id"),
                employee=member,
                returned_at__isnull=True,
            )
            from django.utils import timezone

            with transaction.atomic():
                equipment = NetworkEquipment.objects.select_for_update().get(
                    pk=allocation.equipment_id
                )
                if allocation.serial_id:
                    serial = NetworkEquipmentSerial.objects.select_for_update().get(
                        pk=allocation.serial_id
                    )
                    serial.status = NetworkEquipmentSerial.Status.IN_STOCK
                    serial.issued_at = None
                    serial.save(update_fields=["status", "issued_at", "updated_at"])
                equipment.quantity += allocation.quantity
                equipment.save(update_fields=["quantity", "updated_at"])
                allocation.returned_at = timezone.now()
                allocation.save(update_fields=["returned_at"])
                _log_equipment_stock_movements(
                    equipment=equipment,
                    movement_type=NetworkEquipmentStockMovement.MovementType.RETURN,
                    quantity=allocation.quantity,
                    serials=(
                        [allocation.serial.serial_number]
                        if allocation.serial_id and allocation.serial
                        else None
                    ),
                    employee=member,
                    actor=request.user,
                )
            messages.success(
                request,
                f"Returned {allocation.quantity} × “{allocation.equipment.name}” to stock.",
            )
            return _redirect_allocate()

    active_allocations = list(
        NetworkEquipmentAllocation.objects.filter(
            employee=member,
            returned_at__isnull=True,
        )
        .select_related("equipment", "serial", "allocated_by")
        .order_by("-allocated_at")
    )
    equipment_list = list(
        NetworkEquipment.objects.filter(status=NetworkEquipment.Status.ACTIVE)
        .order_by("name")
    )
    serial_options = {}
    for item in equipment_list:
        if item.track_serials:
            serial_options[str(item.pk)] = list(
                NetworkEquipmentSerial.objects.filter(
                    equipment=item,
                    status=NetworkEquipmentSerial.Status.IN_STOCK,
                )
                .order_by("serial_number")
                .values_list("serial_number", flat=True)[:300]
            )

    return render(
        request,
        "accounts/customer_support_allocate_employee.html",
        {
            "page_title": "Allocate equipment",
            "page_kicker": "Infrastructure",
            "page_subtitle": (
                f"Assign network equipment to "
                f"{member.user.get_full_name() or member.user.username}."
            ),
            "current_page": "stock_audit",
            "dashboard_url_name": "roles:customer_support",
            "member": member,
            "equipment_list": equipment_list,
            "active_allocations": active_allocations,
            "serial_options_json": json.dumps(serial_options),
            "allocate_list_url_name": "roles:customer_support_allocate",
        },
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_dashboard(request):
    return _role_dashboard(request, Employee.Role.IT_SUPPORT)


def _it_support_company_clients_context(**extra):
    return {
        "page_title": "Company clients",
        "page_kicker": "ISPs",
        "current_page": "company_clients",
        "dashboard_url_name": "roles:it_support",
        "clients_list_url_name": "roles:it_support_company_clients",
        "client_edit_url_name": "roles:it_support_company_client_edit",
        "client_suspend_url_name": "roles:it_support_company_client_suspend",
        "client_unsuspend_url_name": "roles:it_support_company_client_unsuspend",
        "client_delete_url_name": "roles:it_support_company_client_delete",
        "list_heading": "ISP accounts",
        "list_intro": "Company / ISP accounts currently registered in ISPCENTRIC.",
        "delete_intro": (
            "This permanently removes the ISP account and everything that belongs "
            "to it. Other ISP accounts are not changed."
        ),
        "delete_warning": (
            "will be permanently deleted, including its owner login, staff, "
            "subscribers, packages, routers, payments, and settings. Other ISP "
            "accounts are not affected."
        ),
        **extra,
    }


def _isp_client_queryset():
    from django.db.models import Count, IntegerField, OuterRef, Subquery
    from django.db.models.functions import Coalesce

    from accounts.models import Employee
    from billing.models import BillingPlan, Customer
    from core.models import MikroTikRouter

    def _count_subquery(model, org_field="organization_id"):
        return (
            model.objects.filter(**{org_field: OuterRef("pk")})
            .order_by()
            .values(org_field)
            .annotate(_c=Count("id"))
            .values("_c")
        )

    return (
        Organization.objects.select_related("owner")
        .annotate(
            staff_count=Coalesce(
                Subquery(_count_subquery(Employee), output_field=IntegerField()),
                0,
            ),
            customer_count=Coalesce(
                Subquery(_count_subquery(Customer), output_field=IntegerField()),
                0,
            ),
            plan_count=Coalesce(
                Subquery(_count_subquery(BillingPlan), output_field=IntegerField()),
                0,
            ),
            router_count=Coalesce(
                Subquery(_count_subquery(MikroTikRouter), output_field=IntegerField()),
                0,
            ),
        )
        .order_by("-created_at")
    )


_IT_SUPPORT_ISP_CLIENTS_CACHE = "it_support:isp_clients:v2"
_IT_SUPPORT_HR_CACHE = "it_support:hr_employees:v1"


def _invalidate_it_support_list_caches():
    from django.core.cache import cache

    cache.delete(_IT_SUPPORT_ISP_CLIENTS_CACHE)
    cache.delete(_IT_SUPPORT_HR_CACHE)


def _render_it_support_company_clients(request, **extra):
    from django.core.cache import cache
    from django.db.models import Count, Q

    _prepare_it_support_view(request)
    force_fresh = bool(
        extra.get("edit_form")
        or extra.get("edit_owner_form")
        or extra.get("open_register_modal")
    )
    clients = None if force_fresh else cache.get(_IT_SUPPORT_ISP_CLIENTS_CACHE)
    if clients is None:
        clients = list(_isp_client_queryset())
        if not force_fresh:
            cache.set(_IT_SUPPORT_ISP_CLIENTS_CACHE, clients, 45)

    status_counts = Organization.objects.aggregate(
        suspended_count=Count(
            "id", filter=Q(status=Organization.Status.SUSPENDED)
        ),
        total_count=Count("id"),
    )
    suspended_count = status_counts["suspended_count"] or 0
    clients_count = status_counts["total_count"] or 0
    open_edit_id = extra.pop("open_edit_id", None)
    if open_edit_id is None:
        raw = (request.GET.get("edit") or "").strip()
        try:
            open_edit_id = int(raw) if raw else None
        except ValueError:
            open_edit_id = None
    extra.setdefault(
        "register_form",
        RegisterForm(prefix="isp", require_invite=False),
    )
    extra.setdefault("open_register_modal", False)
    return render(
        request,
        "accounts/it_support_company_clients.html",
        _it_support_company_clients_context(
            clients=clients,
            clients_count=clients_count,
            active_count=clients_count - suspended_count,
            suspended_count=suspended_count,
            status_choices=Organization.Status.choices,
            open_edit_id=open_edit_id,
            **extra,
        ),
    )


def _create_isp_organization_from_register_form(register_form, *, registered_by):
    user = register_form.save(commit=False)
    user.email = register_form.cleaned_data["email"]
    user.save()
    org = Organization.objects.create(
        name=register_form.cleaned_data["company_name"],
        owner=user,
        login_code=register_form.cleaned_data["username"],
        phone=register_form.cleaned_data.get("phone", ""),
        profile_photo=register_form.cleaned_data.get("profile_photo"),
        status=Organization.Status.REGISTERED,
        registered_by=registered_by,
    )
    notify_platform_event(
        "platform_isp_welcome",
        organization=org,
        context={
            "company_name": org.name,
            "join_code": org.join_code or "",
        },
        subject=f"Welcome to ISPCENTRIC — {org.name}",
    )
    notify_platform_event(
        "platform_staff_new_isp",
        organization=org,
        context={"company_name": org.name},
        subject=f"New ISP registered — {org.name}",
    )
    return org


@role_required(Employee.Role.IT_SUPPORT)
@require_http_methods(["GET", "POST"])
def it_support_company_clients(request):
    register_form = RegisterForm(prefix="isp", require_invite=False)
    open_register_modal = request.GET.get("register") == "1"

    if request.method == "POST" and request.POST.get("form_action") == "register_isp":
        open_register_modal = True
        register_form = RegisterForm(
            request.POST,
            request.FILES,
            prefix="isp",
            require_invite=False,
        )
        if register_form.is_valid():
            with transaction.atomic():
                org = _create_isp_organization_from_register_form(
                    register_form,
                    registered_by=request.user,
                )
            _invalidate_it_support_list_caches()
            messages.success(
                request,
                (
                    f"ISP client “{org.name}” registered. "
                    f"Owner login code: {org.login_code}."
                ),
            )
            return redirect("roles:it_support_company_clients")

    return _render_it_support_company_clients(
        request,
        register_form=register_form,
        open_register_modal=open_register_modal,
    )


def _company_client_owner_form(owner, organization, data=None):
    """Owner login form for IT Support company-client edits."""
    kwargs = {"user": owner, "organization": organization, "id_prefix": "cc_owner"}
    form = OwnerProfileForm(data, **kwargs) if data is not None else OwnerProfileForm(**kwargs)
    form.fields["username"].label = "6-digit login code"
    form.fields["username"].help_text = (
        "ISP clients sign in with this code and their password."
    )
    form.fields["password1"].help_text = (
        "Leave blank to keep the current password. Enter a 6-digit numeric password."
    )
    form.fields["password1"].label = "6-digit password"
    form.fields["password2"].label = "Confirm 6-digit password"
    return form


@role_required(Employee.Role.IT_SUPPORT)
def it_support_company_client_edit(request, pk):
    _prepare_it_support_view(request)
    client = get_object_or_404(Organization.objects.select_related("owner"), pk=pk)

    if request.method != "POST":
        list_url = reverse("roles:it_support_company_clients")
        return redirect(f"{list_url}?edit={client.pk}")

    form = OrganizationEditForm(
        request.POST,
        request.FILES,
        instance=client,
        section=OrganizationEditForm.SECTION_PROFILE,
    )
    owner_form = None
    if client.owner_id:
        owner_form = _company_client_owner_form(client.owner, client, request.POST)

    org_ok = form.is_valid()
    owner_ok = owner_form.is_valid() if owner_form is not None else True
    if org_ok and owner_ok:
        form.save()
        if owner_form is not None:
            owner_form.save()
        _invalidate_it_support_list_caches()
        messages.success(request, f"Updated {client.name}.")
        return redirect("roles:it_support_company_clients")

    return _render_it_support_company_clients(
        request,
        open_edit_id=client.pk,
        edit_form=form,
        edit_owner_form=owner_form,
        edit_client=client,
    )


@role_required(Employee.Role.IT_SUPPORT)
@require_POST
def it_support_company_client_suspend(request, pk):
    _prepare_it_support_view(request)
    client = get_object_or_404(Organization, pk=pk)
    if client.status == Organization.Status.SUSPENDED:
        messages.info(request, f"{client.name} is already suspended.")
    else:
        client.status = Organization.Status.SUSPENDED
        client.save(update_fields=["status"])
        _invalidate_it_support_list_caches()
        notify_platform_event(
            "platform_isp_status",
            organization=client,
            context={
                "company_name": client.name,
                "status": "suspended",
            },
            subject="ISP account suspended",
        )
        messages.success(request, f"Suspended {client.name}.")
    return redirect("roles:it_support_company_clients")


@role_required(Employee.Role.IT_SUPPORT)
@require_POST
def it_support_company_client_unsuspend(request, pk):
    _prepare_it_support_view(request)
    client = get_object_or_404(Organization, pk=pk)
    if client.status != Organization.Status.SUSPENDED:
        messages.info(request, f"{client.name} is not suspended.")
    else:
        client.status = Organization.Status.ACTIVE
        client.save(update_fields=["status"])
        _invalidate_it_support_list_caches()
        notify_platform_event(
            "platform_isp_status",
            organization=client,
            context={
                "company_name": client.name,
                "status": "active",
            },
            subject="ISP account activated",
        )
        messages.success(request, f"Unsuspended {client.name}.")
    return redirect("roles:it_support_company_clients")


@role_required(Employee.Role.IT_SUPPORT)
def it_support_company_client_delete(request, pk):
    employee = _prepare_it_support_view(request)
    client = get_object_or_404(Organization, pk=pk)

    if employee.organization_id == client.pk:
        messages.error(request, "You cannot delete your own organization.")
        return redirect("roles:it_support_company_clients")

    if request.method == "POST":
        name = client.name
        client.purge_account(actor_user_id=request.user.pk)
        _invalidate_it_support_list_caches()
        messages.success(request, f"Deleted {name} and all of its account data.")
        return redirect("roles:it_support_company_clients")

    return render(
        request,
        "accounts/it_support_company_client_delete.html",
        _it_support_company_clients_context(
            page_title="Delete company client",
            client=client,
            deletion_preview=client.deletion_preview(),
        ),
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_hr(request):
    _prepare_it_support_view(request)

    from django.core.cache import cache
    from django.db.models import Count, Q

    employees = cache.get(_IT_SUPPORT_HR_CACHE)
    if employees is None:
        employees = list(
            Employee.objects.select_related("user", "organization")
            .only(
                "id",
                "status",
                "role",
                "phone",
                "login_code",
                "profile_photo",
                "organization_id",
                "user_id",
                "user__id",
                "user__username",
                "user__first_name",
                "user__last_name",
                "user__email",
                "organization__id",
                "organization__name",
            )
            .order_by("-created_at")
        )
        cache.set(_IT_SUPPORT_HR_CACHE, employees, 45)
    status_counts = Employee.objects.aggregate(
        suspended_count=Count(
            "id", filter=Q(status=Employee.Status.SUSPENDED)
        ),
        pending_count=Count(
            "id", filter=Q(status=Employee.Status.PENDING_APPROVAL)
        ),
        active_count=Count("id", filter=Q(status=Employee.Status.ACTIVE)),
        total_count=Count("id"),
    )
    return render(
        request,
        "accounts/it_support_hr.html",
        _it_support_hr_context(
            employees=employees,
            employees_count=status_counts["total_count"] or 0,
            active_count=status_counts["active_count"] or 0,
            suspended_count=status_counts["suspended_count"] or 0,
            pending_count=status_counts["pending_count"] or 0,
        ),
    )


def _prepare_it_support_view(request):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.IT_SUPPORT)
    return employee


def _it_support_hr_context(**extra):
    return {
        "page_title": "Human resource management",
        "page_kicker": "People",
        "current_page": "hr",
        "dashboard_url_name": "roles:it_support",
        "hr_list_url_name": "roles:it_support_hr",
        **extra,
    }


@role_required(Employee.Role.IT_SUPPORT)
def it_support_hr_edit(request, pk):
    _prepare_it_support_view(request)
    member = get_object_or_404(Employee.objects.select_related("user", "organization"), pk=pk)

    if request.method == "POST":
        form = EmployeeAdminEditForm(request.POST, request.FILES, employee=member)
        if form.is_valid():
            form.save()
            _invalidate_it_support_list_caches()
            name = member.user.get_full_name() or member.user.username
            messages.success(request, f"Updated {name}.")
            return redirect("roles:it_support_hr_edit", pk=member.pk)
    else:
        form = EmployeeAdminEditForm(employee=member)

    return render(
        request,
        "accounts/hr_employee_edit.html",
        _it_support_hr_context(
            page_title="Edit employee",
            member=member,
            form=form,
            hr_edit_url_name="roles:it_support_hr_edit",
        ),
    )


@role_required(Employee.Role.IT_SUPPORT)
@require_POST
def it_support_hr_suspend(request, pk):
    actor = _prepare_it_support_view(request)
    member = get_object_or_404(Employee.objects.select_related("user"), pk=pk)
    name = member.user.get_full_name() or member.user.username

    if member.pk == actor.pk:
        messages.error(request, "You cannot suspend your own account.")
        return redirect("roles:it_support_hr")

    if member.status == Employee.Status.SUSPENDED:
        messages.info(request, f"{name} is already suspended.")
    else:
        member.status = Employee.Status.SUSPENDED
        member.save(update_fields=["status", "updated_at"])
        _invalidate_it_support_list_caches()
        messages.success(request, f"Suspended {name}.")
    return redirect("roles:it_support_hr")


@role_required(Employee.Role.IT_SUPPORT)
@require_POST
def it_support_hr_unsuspend(request, pk):
    _prepare_it_support_view(request)
    member = get_object_or_404(Employee.objects.select_related("user"), pk=pk)
    name = member.user.get_full_name() or member.user.username

    if member.status != Employee.Status.SUSPENDED:
        messages.info(request, f"{name} is not suspended.")
    else:
        member.status = Employee.Status.ACTIVE
        member.save(update_fields=["status", "updated_at"])
        _invalidate_it_support_list_caches()
        messages.success(request, f"Unsuspended {name}.")
    return redirect("roles:it_support_hr")


@role_required(Employee.Role.IT_SUPPORT)
def it_support_hr_delete(request, pk):
    actor = _prepare_it_support_view(request)
    member = get_object_or_404(Employee.objects.select_related("user", "organization"), pk=pk)
    name = member.user.get_full_name() or member.user.username
    owned_org = Organization.objects.filter(owner_id=member.user_id).first()

    if member.pk == actor.pk:
        messages.error(request, "You cannot delete your own account.")
        return redirect("roles:it_support_hr")

    if request.method == "POST":
        user = member.user
        user.delete()
        _invalidate_it_support_list_caches()
        messages.success(request, f"Deleted {name}.")
        return redirect("roles:it_support_hr")

    return render(
        request,
        "accounts/hr_employee_delete.html",
        _it_support_hr_context(
            page_title="Delete employee",
            member=member,
            owned_org=owned_org,
        ),
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_payment_gateway(request):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.IT_SUPPORT)

    gateway = PaymentGateway.get_solo()
    if request.method == "POST":
        form = PaymentGatewayForm(request.POST, instance=gateway)
        if form.is_valid():
            form.save()
            messages.success(request, "Payment gateway settings saved.")
            return redirect("roles:it_support_payment_gateway")
    else:
        form = PaymentGatewayForm(instance=gateway)

    return render(
        request,
        "accounts/it_support_payment_gateway.html",
        {
            "page_title": "Company Payment Gateway",
            "page_kicker": "Integrations",
            "current_page": "payment_gateway",
            "dashboard_url_name": "roles:it_support",
            "form": form,
            "gateway": gateway,
            "sandbox_base_url": PaymentGateway.sandbox_base_url(request),
            "sandbox_callback_url": PaymentGateway.default_callback_url(
                PaymentGateway.Environment.SANDBOX,
                request,
            ),
            "sandbox_local_callback_url": PaymentGateway.sandbox_local_callback_url(
                request
            ),
            "sandbox_hosted_callback_url": PaymentGateway.sandbox_hosted_callback_url(
                request
            ),
            "sandbox_callback_options": PaymentGateway.sandbox_callback_options(request),
        },
    )


@role_required(Employee.Role.IT_SUPPORT)
@require_http_methods(["GET", "POST"])
def it_support_payment_gateway_status(request):
    """Live-check whether STK Push / Daraja credentials are well configured."""
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.IT_SUPPORT)

    gateway = PaymentGateway.get_solo()
    draft = None
    if request.method == "POST":
        draft = {
            "enabled": request.POST.get("enabled"),
            "environment": request.POST.get("environment"),
            "payment_type": request.POST.get("payment_type"),
            "shortcode": request.POST.get("shortcode"),
            "consumer_key": request.POST.get("consumer_key"),
            "consumer_secret": request.POST.get("consumer_secret"),
            "passkey": request.POST.get("passkey"),
            "callback_url": request.POST.get("callback_url"),
        }
    values = normalize_gateway_values(draft, gateway)
    live = str(request.GET.get("live") or request.POST.get("live") or "1") != "0"
    result = check_stk_configuration(values, live=live)
    result["saved_enabled"] = bool(gateway.enabled)
    return JsonResponse(result)


def _it_support_settings_page(
    request,
    *,
    current_page,
    page_title,
    page_kicker,
    page_subtitle,
    empty_text,
):
    _prepare_it_support_view(request)
    return render(
        request,
        "accounts/it_support_settings.html",
        {
            "page_title": page_title,
            "page_kicker": page_kicker,
            "page_subtitle": page_subtitle,
            "empty_text": empty_text,
            "current_page": current_page,
            "dashboard_url_name": "roles:it_support",
        },
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_company_profile(request):
    _prepare_it_support_view(request)
    profile = CompanyProfile.get_solo()

    if request.method == "POST":
        form = CompanyProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, "Company profile saved.")
            return redirect("roles:it_support_company_profile")
    else:
        form = CompanyProfileForm(instance=profile)

    return render(
        request,
        "accounts/it_support_company_settings.html",
        {
            "page_title": "Company profile",
            "page_kicker": "Company",
            "page_subtitle": "Update the platform app name, contact details, and logo.",
            "current_page": "company_profile",
            "dashboard_url_name": "roles:it_support",
            "form": form,
            "company_profile": profile,
        },
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_company_settings(request):
    """Legacy URL → company profile."""
    return redirect("roles:it_support_company_profile")


def _commission_role_links():
    links = []
    for row in RoleCommission.commissionable_rows():
        links.append(
            {
                "role": row.role,
                "label": row.get_role_display(),
                "slug": ROLE_SLUGS.get(row.role, row.role.replace("_", "-")),
                "enabled": row.enabled,
                "rate_display": row.rate_display,
            }
        )
    return links


@role_required(Employee.Role.IT_SUPPORT)
def it_support_commissions(request):
    _prepare_it_support_view(request)
    return render(
        request,
        "accounts/it_support_commissions.html",
        {
            "page_title": "Commissions",
            "page_kicker": "Company",
            "page_subtitle": "Set commission rates for each employee role from the sidebar.",
            "current_page": "commissions",
            "dashboard_url_name": "roles:it_support",
            "commission_role_links": _commission_role_links(),
            "commission_role_slug": "",
        },
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_commission_role(request, role_slug):
    _prepare_it_support_view(request)
    role_key = None
    for key, slug in ROLE_SLUGS.items():
        if slug == role_slug and key in RoleCommission.COMMISSIONABLE_ROLES:
            role_key = key
            break
    if role_key is None:
        messages.error(request, "Unknown role for commission settings.")
        return redirect("roles:it_support_commissions")

    commission = RoleCommission.for_role(role_key)
    is_sales = role_key == Employee.Role.SALES
    form_class = SalesCommissionForm if is_sales else RoleCommissionForm
    if is_sales and commission.rate_type not in {
        RoleCommission.RateType.PER_TICKET,
        RoleCommission.RateType.PER_TICKET_PACKAGE,
    }:
        commission.rate_type = RoleCommission.RateType.PER_TICKET
        commission.save(update_fields=["rate_type", "updated_at"])

    if request.method == "POST":
        form = form_class(request.POST, instance=commission)
        if form.is_valid():
            form.save()
            messages.success(
                request,
                f"Saved commission settings for {commission.get_role_display()}.",
            )
            return redirect("roles:it_support_commission_role", role_slug=role_slug)
    else:
        form = form_class(instance=commission)

    return render(
        request,
        "accounts/it_support_commission_role.html",
        {
            "page_title": f"{commission.get_role_display()} commissions",
            "page_kicker": "Commissions",
            "page_subtitle": (
                "Set a fixed ticket price or a percentage of the package price."
                if is_sales
                else "Configure when this role earns commission and at what rate."
            ),
            "current_page": "commissions",
            "dashboard_url_name": "roles:it_support",
            "form": form,
            "commission": commission,
            "role_slug": role_slug,
            "role_label": commission.get_role_display(),
            "commission_role_links": _commission_role_links(),
            "commission_role_slug": role_slug,
            "is_sales_commission": is_sales,
        },
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_company_system_settings(request):
    _prepare_it_support_view(request)
    return render(
        request,
        "accounts/it_support_company_system_settings.html",
        {
            "page_title": "Company System Settings",
            "page_kicker": "Settings",
            "page_subtitle": (
                "Configure platform identity, communications, Company Payment Gateway, "
                "ISP onboarding, and client payment-page themes from one place."
            ),
            "current_page": "company_system_settings",
            "dashboard_url_name": "roles:it_support",
            "settings_modules": [
                {
                    "key": "company_profile",
                    "label": "Company profile",
                    "description": "App name, logo, and contact details shown across the platform.",
                    "url_name": "roles:it_support_company_profile",
                },
                {
                    "key": "company_communications",
                    "label": "Company communications settings",
                    "description": (
                        "SMS, email, and WhatsApp credentials for platform messages. "
                        "See Communications in the sidebar for when those messages are sent."
                    ),
                    "url_name": "roles:it_support_company_communications",
                },
                {
                    "key": "payment_gateway",
                    "label": "Company Payment Gateway",
                    "description": "Company Daraja STK Push credentials used as the default payment gateway.",
                    "url_name": "roles:it_support_payment_gateway",
                },
                {
                    "key": "isp_onboarding_settings",
                    "label": "ISP onboarding settings",
                    "description": "Landing Register, MikroTik onboarding fees, and referral controls.",
                    "url_name": "roles:it_support_isp_onboarding_settings",
                },
                {
                    "key": "company_themes",
                    "label": "Company themes",
                    "description": "Preview pay/pause pages, and toggle Refer & earn for each ISP.",
                    "url_name": "roles:it_support_company_themes",
                },
            ],
        },
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_company_themes(request):
    """Preview client-facing Hotspot / PPPoE payment pages for company themes."""
    _prepare_it_support_view(request)
    # Dropdown only needs id/name/join_code; load the selected org fully once.
    organizations = list(
        Organization.objects.exclude(join_code="")
        .order_by("name")
        .only("id", "name", "join_code")
    )
    selected = None
    org_id = (
        request.POST.get("org")
        or request.GET.get("org")
        or ""
    )
    if org_id:
        selected = (
            Organization.objects.filter(pk=org_id)
            .exclude(join_code="")
            .only(
                "id",
                "name",
                "join_code",
                "hotspot_enabled",
                "pppoe_compulsory",
                "adverts_enabled",
            )
            .first()
        )
    if selected is None and organizations:
        selected = (
            Organization.objects.filter(pk=organizations[0].pk)
            .only(
                "id",
                "name",
                "join_code",
                "hotspot_enabled",
                "pppoe_compulsory",
                "adverts_enabled",
            )
            .first()
        )

    if request.method == "POST" and selected is not None:
        action = (request.POST.get("action") or "").strip()
        if action == "toggle_adverts":
            enabled = (request.POST.get("adverts_enabled") or "") in {
                "1",
                "true",
                "on",
                "yes",
            }
            Organization.objects.filter(pk=selected.pk).update(
                adverts_enabled=enabled,
            )
            selected.adverts_enabled = enabled
            messages.success(
                request,
                (
                    f"Refer & earn is on for {selected.name}."
                    if enabled
                    else f"Refer & earn is off for {selected.name}."
                ),
            )
            return redirect(
                f"{reverse('roles:it_support_company_themes')}?org={selected.pk}"
            )

    hotspot_pay_url = ""
    hotspot_pause_url = ""
    pppoe_pay_url = ""
    pppoe_pause_url = ""
    earn_url = ""
    earn_preview_url = ""
    if selected and selected.join_code:
        hotspot_pay_url = reverse(
            "core:hotspot_pay", kwargs={"join_code": selected.join_code}
        )
        hotspot_pause_url = reverse(
            "core:hotspot_pause", kwargs={"join_code": selected.join_code}
        )
        pppoe_pay_url = reverse(
            "core:pppoe_pay", kwargs={"join_code": selected.join_code}
        )
        pppoe_pause_url = reverse(
            "core:pppoe_pause", kwargs={"join_code": selected.join_code}
        )
        earn_url = reverse(
            "core:click_to_earn", kwargs={"join_code": selected.join_code}
        )
        earn_preview_url = earn_url

    return render(
        request,
        "accounts/it_support_company_themes.html",
        {
            "page_title": "Company themes",
            "page_kicker": "Settings",
            "page_subtitle": (
                "Preview captive pay and pause pages, and turn on Refer & earn "
                "so Wi‑Fi visitors can open the ISP referral page."
            ),
            "current_page": "company_themes",
            "dashboard_url_name": "roles:it_support",
            "theme_organizations": organizations,
            "selected_organization": selected,
            "hotspot_pay_url": hotspot_pay_url,
            "pppoe_pay_url": pppoe_pay_url,
            "earn_url": earn_url,
            "earn_preview_url": earn_preview_url,
            "adverts_enabled": bool(
                getattr(selected, "adverts_enabled", False) if selected else False
            ),
            "hotspot_demo_preview_url": (
                f"{hotspot_pay_url}?preview=demo" if hotspot_pay_url else ""
            ),
            "pppoe_demo_preview_url": (
                f"{pppoe_pay_url}?preview=demo" if pppoe_pay_url else ""
            ),
            "hotspot_paused_preview_url": hotspot_pause_url,
            "pppoe_paused_preview_url": pppoe_pause_url,
        },
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_system_settings_redirect(request):
    return redirect("roles:it_support_company_system_settings")


@role_required(Employee.Role.IT_SUPPORT)
def it_support_settings_payments_redirect(request):
    return redirect("roles:it_support_payment_gateway")


@role_required(Employee.Role.IT_SUPPORT)
def it_support_client_settings_redirect(request):
    return redirect("roles:it_support_isp_onboarding_settings")


# Backwards-compatible alias used by older imports/tests.
it_support_system_settings = it_support_company_system_settings


@role_required(Employee.Role.IT_SUPPORT)
def it_support_communications(request):
    """Configure which platform actions send messages, to whom, and on which channels."""
    _prepare_it_support_view(request)
    comms = PlatformCommunicationSettings.get_solo()
    catalog = platform_event_catalog()
    catalog_by_key = {event["key"]: event for event in catalog}
    statuses = comms.channel_statuses()
    gateway_enabled = {
        "sms": bool(comms.sms_enabled),
        "email": bool(comms.email_enabled),
        "whatsapp": bool(comms.whatsapp_enabled),
    }

    if request.method == "POST":
        form_action = (request.POST.get("form_action") or "").strip()
        if form_action == "save_enabled_messages":
            prefs = normalize_enabled_messages(comms.enabled_messages or {})
            remove_key = (request.POST.get("remove_event") or "").strip()
            if remove_key:
                prefs.pop(remove_key, None)
            else:
                event_key = (request.POST.get("event_key") or "").strip()
                event = catalog_by_key.get(event_key)
                if not event:
                    messages.error(request, "Choose a valid trigger or action.")
                    return redirect("roles:it_support_communications")

                allowed_channels = set(event.get("channels") or ())
                selected_channels = [
                    channel
                    for channel in request.POST.getlist("channels")
                    if channel in allowed_channels and gateway_enabled.get(channel)
                ]
                if not selected_channels:
                    # Back-compat with older checkbox field names.
                    selected_channels = [
                        channel
                        for channel in ("sms", "email", "whatsapp")
                        if request.POST.get(f"channel_{channel}")
                        and channel in allowed_channels
                        and gateway_enabled.get(channel)
                    ]
                allowed_recipients = set(event.get("recipient_options") or ())
                selected_recipients = [
                    rid
                    for rid in request.POST.getlist("recipients")
                    if rid in allowed_recipients
                ]
                message_body = (request.POST.get("message") or "").strip()
                if not message_body:
                    message_body = str(event.get("default_message") or "").strip()
                if not selected_recipients:
                    messages.error(request, "Choose at least one recipient.")
                    return redirect("roles:it_support_communications")
                if not selected_channels:
                    messages.error(
                        request,
                        "Choose at least one enabled platform (SMS, Email, or WhatsApp).",
                    )
                    return redirect("roles:it_support_communications")
                include_link = bool(
                    event.get("page_link") and request.POST.get("include_link")
                )
                prefs[event_key] = {
                    "message": message_body,
                    "recipients": selected_recipients,
                    "channels": selected_channels,
                    "include_link": include_link,
                }
            comms.enabled_messages = normalize_enabled_messages(prefs)
            comms.save(update_fields=["enabled_messages", "updated_at"])
            messages.success(request, "Message settings saved.")
            return redirect("roles:it_support_communications")
        messages.error(request, "Unknown action.")
        return redirect("roles:it_support_communications")

    enabled = normalize_enabled_messages(comms.enabled_messages or {})

    def _enrich_events(raw_events):
        rows = []
        for event in raw_events:
            key = event["key"]
            rule = enabled.get(key) or {}
            selected_recipients = list(rule.get("recipients") or [])
            selected_channels = list(rule.get("channels") or [])
            recipient_options = list(event.get("recipient_options") or ())
            if not selected_recipients and recipient_options:
                selected_recipients = [recipient_options[0]]
            # Channel stays single-select in the UI.
            selected_channels = selected_channels[:1]
            selected_recipient_set = set(selected_recipients)
            selected_channel_set = set(selected_channels)
            channel_choices = []
            for channel in event.get("channels") or ():
                usable = bool(gateway_enabled.get(channel))
                channel_choices.append(
                    {
                        "id": channel,
                        "label": CHANNEL_LABELS.get(channel, channel),
                        "usable": usable,
                        "selected": usable and channel in selected_channel_set,
                    }
                )
            # Prefer a usable selected channel; otherwise leave blank for the placeholder.
            if selected_channels and not any(c["selected"] for c in channel_choices):
                selected_channels = []
                selected_channel_set = set()
            page_link = event.get("page_link")
            page_link_path = resolve_page_link_path(page_link) if page_link else ""
            recipient_choices = [
                {
                    "id": rid,
                    "label": RECIPIENT_OPTIONS.get(rid, rid),
                    "selected": rid in selected_recipient_set,
                }
                for rid in recipient_options
            ]
            rows.append(
                {
                    "key": key,
                    "title": event["title"],
                    "when": event.get("when") or "",
                    "includes": event.get("includes") or "",
                    "message": (rule.get("message") or event.get("default_message") or ""),
                    "is_enabled": key in enabled,
                    "include_link": bool(rule.get("include_link")),
                    "page_link": page_link,
                    "page_link_path": page_link_path,
                    "recipient_choices": recipient_choices,
                    "selected_recipient_labels": [
                        item["label"] for item in recipient_choices if item["selected"]
                    ],
                    "channel_choices": channel_choices,
                }
            )
        return rows

    return render(
        request,
        "accounts/it_support_company_account_communications.html",
        {
            "page_title": "Communications",
            "page_kicker": "Company",
            "page_subtitle": (
                "Choose ISP Client and/or employee roles for each trigger, then pick "
                "the channel. Gateway credentials are under Company communications settings."
            ),
            "current_page": "company_account_communications",
            "dashboard_url_name": "roles:it_support",
            "comms": comms,
            "company_profile": CompanyProfile.get_solo(),
            "sms_status": statuses["sms"],
            "email_status": statuses["email"],
            "whatsapp_status": statuses["whatsapp"],
            "gateway_enabled": gateway_enabled,
            "isp_events": _enrich_events(PLATFORM_TO_ISP_EVENTS),
            "staff_events": _enrich_events(PLATFORM_TO_STAFF_EVENTS),
            "settings_url": reverse("roles:it_support_company_communications"),
        },
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_company_communications(request):
    """Platform SMS / email / WhatsApp credentials (ISPCENTRIC → ISPs), not ISP client gateways."""
    _prepare_it_support_view(request)
    comms = PlatformCommunicationSettings.get_solo()
    if request.method == "POST":
        form = PlatformCommunicationSettingsForm(request.POST, instance=comms)
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
                "Company communications settings saved. " + " · ".join(parts) + ".",
            )
            return redirect("roles:it_support_company_communications")
    else:
        form = PlatformCommunicationSettingsForm(instance=comms)

    statuses = comms.channel_statuses()
    return render(
        request,
        "accounts/it_support_communications.html",
        {
            "page_title": "Company communications settings",
            "page_kicker": "Company",
            "page_subtitle": (
                "Configure ISPCENTRIC SMS, email, and WhatsApp credentials used to "
                "message ISPs and platform staff. Each ISP’s subscriber gateway is "
                "under Communication settings."
            ),
            "current_page": "company_communications",
            "dashboard_url_name": "roles:it_support",
            "form": form,
            "comms": comms,
            "company_profile": CompanyProfile.get_solo(),
            "sms_status": statuses["sms"],
            "email_status": statuses["email"],
            "whatsapp_status": statuses["whatsapp"],
            "comms_fetch_url": reverse("roles:it_support_company_communications_fetch"),
            "events_url": reverse("roles:it_support_communications"),
        },
    )


@role_required(Employee.Role.IT_SUPPORT)
@require_POST
def it_support_company_communications_fetch(request):
    _prepare_it_support_view(request)
    payload = {}
    if "application/json" in (request.content_type or ""):
        try:
            payload = json.loads(request.body.decode() or "{}")
        except json.JSONDecodeError:
            payload = {}
    else:
        payload = {key: request.POST.get(key, "") for key in request.POST}
    result = fetch_provider_options(payload)
    return JsonResponse(result, status=200 if result.get("ok") else 400)


@role_required(Employee.Role.IT_SUPPORT)
def it_support_settings_communications(request):
    return redirect("roles:it_support_company_communications")


@role_required(Employee.Role.IT_SUPPORT)
def it_support_company_payment_links(request):
    return _it_support_settings_page(
        request,
        current_page="company_payment_links",
        page_title="Company payment links",
        page_kicker="Settings",
        page_subtitle="Payment portal and collection links for the company.",
        empty_text="Company payment links settings are coming soon.",
    )


# Backwards-compatible alias.
it_support_settings_payments = it_support_company_payment_links


@role_required(Employee.Role.IT_SUPPORT)
def it_support_isp_onboarding_settings(request):
    _prepare_it_support_view(request)
    settings_obj = ClientSettings.get_solo()

    if request.method == "POST":
        form = ClientSettingsForm(request.POST, instance=settings_obj)
        if form.is_valid():
            form.save()
            messages.success(request, "ISP onboarding settings saved.")
            return redirect("roles:it_support_isp_onboarding_settings")
    else:
        form = ClientSettingsForm(instance=settings_obj)

    return render(
        request,
        "accounts/it_support_client_settings.html",
        {
            "page_title": "ISP onboarding settings",
            "page_kicker": "Settings",
            "page_subtitle": (
                "Control landing-page Register, MikroTik onboarding fees, and referrals."
            ),
            "current_page": "isp_onboarding_settings",
            "dashboard_url_name": "roles:it_support",
            "form": form,
            "client_settings": settings_obj,
        },
    )


# Backwards-compatible alias.
it_support_client_settings = it_support_isp_onboarding_settings


@role_required(Employee.Role.SALES)
def sales_dashboard(request):
    employee = request.user.employee_profile
    meta = ROLE_PAGE[Employee.Role.SALES]
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.SALES)
    return render(
        request,
        "accounts/sales_dashboard.html",
        {
            "page_title": meta["title"],
            "page_subtitle": meta["subtitle"],
            "current_page": "dashboard",
            "dashboard_url_name": "roles:sales",
            "module_links": [
                {
                    "index": "01",
                    "label": "Leads & registration",
                    "hint": "Register leads, PPPoE clients, and business ISPs.",
                    "url_name": "roles:sales_lead_management",
                },
                {
                    "index": "02",
                    "label": "Sales Orders",
                    "hint": "Review and manage confirmed sales orders.",
                    "url_name": "roles:sales_orders",
                },
                {
                    "index": "03",
                    "label": "Promotions & Discounts",
                    "hint": "Manage active offers and discount codes.",
                    "url_name": "roles:sales_promotions_discounts",
                },
                {
                    "index": "04",
                    "label": "Commissions",
                    "hint": "Track earnings tied to closed sales.",
                    "url_name": "roles:sales_commissions",
                },
                {
                    "index": "05",
                    "label": "Reports",
                    "hint": "Performance and conversion summaries.",
                    "url_name": "roles:sales_reports",
                },
            ],
        },
    )


def _sales_module_page(request, *, current_page, page_title, page_kicker, page_subtitle, empty_text):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.SALES)
    return render(
        request,
        "accounts/sales_module.html",
        {
            "page_title": page_title,
            "page_kicker": page_kicker,
            "page_subtitle": page_subtitle,
            "empty_text": empty_text,
            "current_page": current_page,
            "dashboard_url_name": "roles:sales",
        },
    )


@role_required(Employee.Role.SALES)
def sales_lead_management(request):
    """Sales: register leads and customers on one page; list only this user's records."""
    from billing.forms import SalesClientRegisterForm
    from billing.models import Customer

    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.SALES)

    # Sales may be platform-level (no organization) and still register against any ISP.
    organization = employee.organization
    organizations = Organization.objects.order_by("name")

    open_lead_modal = False
    open_customer_modal = False
    selected_type = ""
    form = LeadRegisterForm(organization=organization)
    client_form = SalesClientRegisterForm(
        organization=organization,
        organizations=organizations,
        prefix="client",
    )
    isp_form = RegisterForm(prefix="isp", require_invite=False)

    if request.method == "POST":
        # Customer registration posts include registration_type; lead forms do not.
        if "registration_type" in request.POST:
            selected_type = (request.POST.get("registration_type") or "").strip()
            open_customer_modal = True
            if selected_type == "client":
                client_form = SalesClientRegisterForm(
                    request.POST,
                    organization=organization,
                    organizations=organizations,
                    prefix="client",
                )
                if client_form.is_valid():
                    customer = client_form.save(registered_by=request.user)
                    org_label = (
                        customer.organization.name
                        if customer.organization_id
                        else "no specific ISP provider"
                    )
                    if customer.organization_id:
                        notify_org_event(
                            "client_welcome",
                            organization=customer.organization,
                            client=customer,
                            subject="Welcome — account created",
                        )
                        notify_org_event(
                            "isp_client_registered",
                            organization=customer.organization,
                            client=customer,
                            subject="New client registered",
                        )
                    messages.success(
                        request,
                        (
                            f"PPPoE client “{customer.full_name}” registered "
                            f"(ticket {customer.sales_ticket_number}, "
                            f"account {customer.account_number}) — {org_label}."
                        ),
                    )
                    return redirect("roles:sales_lead_management")
            elif selected_type == "isp":
                isp_form = RegisterForm(
                    request.POST, request.FILES, prefix="isp", require_invite=False
                )
                if isp_form.is_valid():
                    with transaction.atomic():
                        org = _create_isp_organization_from_register_form(
                            isp_form,
                            registered_by=request.user,
                        )
                    messages.success(
                        request,
                        (
                            f"Business (ISP) “{org.name}” registered. "
                            f"Owner login: {org.login_code}."
                        ),
                    )
                    return redirect("roles:sales_lead_management")
            else:
                messages.error(
                    request,
                    "Choose what to register: PPPoE client or business (ISP).",
                )
        else:
            form = LeadRegisterForm(request.POST, organization=organization)
            if form.is_valid():
                lead = form.save(created_by=request.user)
                target_org = (
                    getattr(lead, "preferred_isp", None)
                    or getattr(lead, "organization", None)
                )
                lead_ctx = {
                    "client_name": lead.full_name or "",
                    "phone": getattr(lead, "phone", "") or "",
                    "location": getattr(lead, "location", "") or "",
                }
                if target_org is not None:
                    notify_org_event(
                        "isp_lead_open",
                        organization=target_org,
                        context=lead_ctx,
                        subject="New open lead",
                    )
                notify_platform_event(
                    "platform_staff_new_lead",
                    organization=target_org,
                    context=lead_ctx,
                    subject="New sales lead",
                )
                messages.success(
                    request,
                    (
                        f"Potential client “{lead.full_name}” registered "
                        f"(lead {lead.lead_number}) for follow-up."
                    ),
                )
                return redirect("roles:sales_lead_management")
            open_lead_modal = True

    # Only leads / registrations linked to the signed-in sales user.
    leads = list(
        Lead.objects.select_related(
            "preferred_package",
            "preferred_isp",
            "organization",
            "created_by",
        )
        .filter(created_by=request.user)
        .order_by("-created_at")[:100]
    )
    packages_by_org = {}
    all_packages = []
    package_qs = (
        BillingPlan.objects.filter(is_active=True)
        .select_related("organization")
        .order_by("price", "name")
    )
    for plan in package_qs:
        row = {
            "id": plan.pk,
            "label": f"{plan.name} — {plan.price} ({plan.speed_label})",
        }
        packages_by_org.setdefault(str(plan.organization_id), []).append(row)
        all_packages.append(row)

    recent_clients = list(
        Customer.objects.select_related("organization")
        .filter(registered_by=request.user)
        .order_by("-created_at")[:20]
    )
    recent_isps = list(
        organizations.filter(registered_by=request.user)
        .select_related("owner")
        .order_by("-created_at")[:20]
    )

    return render(
        request,
        "accounts/sales_lead_management.html",
        {
            "page_title": "Leads & registration",
            "page_kicker": "Sales",
            "page_subtitle": (
                "Register potential clients as leads, or onboard PPPoE clients "
                "and business (ISP) accounts — only your records are listed."
            ),
            "current_page": "lead_management",
            "dashboard_url_name": "roles:sales",
            "form": form,
            "leads": leads,
            "open_lead_modal": open_lead_modal,
            "open_customer_modal": open_customer_modal,
            "selected_type": selected_type,
            "client_form": client_form,
            "isp_form": isp_form,
            "recent_clients": recent_clients,
            "recent_isps": recent_isps,
            "employee_organization": organization,
            "default_org_id": organization.pk if organization else "",
            "packages_by_org_json": json.dumps(packages_by_org),
            "all_packages_json": json.dumps(all_packages),
            "phone_lengths_json": json.dumps(NATIONAL_PHONE_LENGTHS),
        },
    )


@role_required(Employee.Role.SALES)
@require_GET
def sales_places(request):
    """Live location suggestions for sales lead registration."""
    from core.places import search_locations

    query = (request.GET.get("q") or "").strip()
    return JsonResponse(search_locations(query, limit=6))


@role_required(Employee.Role.SALES)
@require_GET
def sales_place_details(request):
    """Resolve a place_id or free-text location to coordinates for sales leads."""
    from core.places import resolve_location

    place_id = (request.GET.get("place_id") or "").strip()
    query = (request.GET.get("q") or "").strip()
    details = resolve_location(query, place_id=place_id)
    if not details:
        return JsonResponse({"ok": False, "error": "Place not found."}, status=404)
    return JsonResponse({"ok": True, **details})


@role_required(Employee.Role.SALES)
def sales_customer_registration(request):
    """Legacy URL — customer registration now lives on lead management."""
    return redirect("roles:sales_lead_management")


@role_required(Employee.Role.SALES)
def sales_orders(request):
    return _sales_module_page(
        request,
        current_page="sales_orders",
        page_title="Sales Orders",
        page_kicker="Sales",
        page_subtitle="Review and manage sales orders.",
        empty_text="No sales orders yet.",
    )


@role_required(Employee.Role.SALES)
def sales_promotions_discounts(request):
    return _sales_module_page(
        request,
        current_page="promotions_discounts",
        page_title="Promotions & Discounts",
        page_kicker="Sales",
        page_subtitle="Manage active promotions and discount offers.",
        empty_text="No promotions or discounts yet.",
    )


@role_required(Employee.Role.SALES)
def sales_commissions(request):
    return _sales_module_page(
        request,
        current_page="commissions",
        page_title="Commissions",
        page_kicker="Sales",
        page_subtitle="View commission earnings and payouts.",
        empty_text="No commission records yet.",
    )


@role_required(Employee.Role.SALES)
def sales_reports(request):
    return _sales_module_page(
        request,
        current_page="reports",
        page_title="Reports",
        page_kicker="Sales",
        page_subtitle="Sales performance and conversion reports.",
        empty_text="No sales reports yet.",
    )


@role_required(Employee.Role.TECHNICIAN)
def technician_dashboard(request):
    employee = request.user.employee_profile
    meta = ROLE_PAGE[Employee.Role.TECHNICIAN]
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    open_ticket_count = _pending_connection_pool_qs().count()
    assigned_ticket_count = Customer.objects.filter(
        status=Customer.Status.ASSIGNED,
        assigned_technician=employee,
        service_type=Customer.ServiceType.PPPOE,
    ).count()
    ticket_count = open_ticket_count + assigned_ticket_count
    fault_qs = _active_fault_tickets_qs()
    fault_count = fault_qs.count()
    fault_open_count = fault_qs.filter(status=FaultTicket.Status.OPEN).count()
    fault_assigned_count = fault_qs.filter(assigned_technician=employee).count()

    ticket_notice = ""
    if assigned_ticket_count and open_ticket_count:
        ticket_notice = (
            f"You have {assigned_ticket_count} assigned ticket"
            f"{'' if assigned_ticket_count == 1 else 's'} and "
            f"{open_ticket_count} queued install ticket"
            f"{'' if open_ticket_count == 1 else 's'} waiting."
        )
    elif assigned_ticket_count:
        ticket_notice = (
            f"You have {assigned_ticket_count} assigned install ticket"
            f"{'' if assigned_ticket_count == 1 else 's'} to complete."
        )
    elif open_ticket_count:
        ticket_notice = (
            f"There {'is' if open_ticket_count == 1 else 'are'} "
            f"{open_ticket_count} queued install ticket"
            f"{'' if open_ticket_count == 1 else 's'} available to accept."
        )

    fault_notice = _fault_ticket_notice(
        total_count=fault_count,
        open_count=fault_open_count,
        assigned_count=fault_assigned_count,
    )

    if ticket_notice:
        messages.warning(request, ticket_notice)
    if fault_notice:
        messages.warning(request, fault_notice)

    tickets_hint = "Queued installs, installed awaiting activation, and activated clients."
    if ticket_count:
        tickets_hint = (
            f"{ticket_count} ticket{'s' if ticket_count != 1 else ''} need attention — "
            "open Tickets and pick a category."
        )

    return render(
        request,
        "accounts/technician_dashboard.html",
        {
            "page_title": meta["title"],
            "page_subtitle": meta["subtitle"],
            "current_page": "dashboard",
            "dashboard_url_name": "roles:technician",
            "ticket_count": ticket_count,
            "open_ticket_count": open_ticket_count,
            "assigned_ticket_count": assigned_ticket_count,
            "ticket_notice": ticket_notice,
            "fault_count": fault_count,
            "fault_notice": fault_notice,
            "module_links": [
                {
                    "index": "01",
                    "label": "New Customer Installation",
                    "hint": "Accept jobs, navigate to site, and register PPPoE clients.",
                    "url_name": "roles:technician_installations",
                },
                {
                    "index": "02",
                    "label": "Tickets",
                    "hint": tickets_hint,
                    "url_name": "roles:technician_tickets_hub",
                    "badge": ticket_count or None,
                },
                {
                    "index": "03",
                    "label": "My Stock",
                    "hint": "Gear currently allocated to you for installs and repairs.",
                    "url_name": "roles:technician_my_stock",
                },
            ],
        },
    )


def _technician_module_page(request, *, current_page, page_title, page_kicker, page_subtitle, empty_text):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)
    return render(
        request,
        "accounts/technician_module.html",
        {
            "page_title": page_title,
            "page_kicker": page_kicker,
            "page_subtitle": page_subtitle,
            "empty_text": empty_text,
            "current_page": current_page,
            "dashboard_url_name": "roles:technician",
        },
    )


@role_required(Employee.Role.TECHNICIAN)
def technician_installations(request):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    # Technicians pick the ISP client first, then that client's MikroTiks.
    isp_clients = list(
        Organization.objects.exclude(status=Organization.Status.SUSPENDED)
        .order_by("name")
        .only("id", "name")
    )
    open_modal = ""
    pppoe_form = PppoeClientRegisterForm(
        organizations=isp_clients,
        default_activate=False,
        allow_activate=False,
        require_serials=True,
    )

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action == "register_pppoe":
            if not isp_clients:
                messages.error(request, "No ISP clients are available for registration.")
                return redirect("roles:technician_installations")
            pppoe_form = PppoeClientRegisterForm(
                request.POST,
                organizations=isp_clients,
                default_activate=False,
                allow_activate=False,
                require_serials=True,
            )
            if pppoe_form.is_valid():
                customer = pppoe_form.save(commit=False)
                customer.registered_by = request.user
                customer.assigned_technician = employee
                customer.save()
                if customer.organization_id:
                    notify_org_event(
                        "client_welcome",
                        organization=customer.organization,
                        client=customer,
                        subject="Welcome — account created",
                    )
                    notify_org_event(
                        "isp_client_registered",
                        organization=customer.organization,
                        client=customer,
                        subject="New client registered",
                    )
                customer_pk = customer.pk
                account_number = customer.account_number
                full_name = customer.full_name
                org_name = (
                    customer.organization.name
                    if customer.organization_id
                    else "ISP client"
                )

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
                        f"PPPoE client “{full_name}” registered "
                        f"({account_number}) under {org_name} as installed. "
                        "The CPE can dial in, but surfing stays blocked until an ISP client activates the account."
                    ),
                )
                return redirect("roles:technician_installations")
            open_modal = "pppoe-register-modal"

    # Clients this technician registered (also include older rows only linked via assignment).
    my_clients = list(
        Customer.objects.filter(
            Q(registered_by=request.user) | Q(assigned_technician=employee)
        )
        .select_related("organization", "plan", "router")
        .distinct()
        .order_by("-created_at")[:300]
    )
    inactive_count = sum(
        1 for c in my_clients if c.status == Customer.Status.INSTALLED
    )
    active_count = sum(1 for c in my_clients if c.status == Customer.Status.ACTIVE)

    # Open pool: allocated-open, plus closed tickets with no assignee.
    # Closed assigned: only tickets for the technician in session.
    # Hide tickets this technician marked as not interested.
    tickets = list(
        Customer.objects.filter(
            Q(status=Customer.Status.QUEUED)
            | Q(
                status=Customer.Status.ASSIGNED,
                assigned_technician__isnull=True,
            )
            | Q(
                status=Customer.Status.ASSIGNED,
                assigned_technician=employee,
            )
        )
        .exclude(installation_declines__technician=employee)
        .exclude(pk__in=[c.pk for c in my_clients])
        .select_related(
            "organization",
            "plan",
            "assigned_technician",
            "assigned_technician__user",
        )
        .distinct()
        .order_by("-created_at")[:100]
    )

    router_cpe_defaults: dict[str, dict] = {}
    routers_by_org: dict[str, list[dict]] = {}
    plans_by_org: dict[str, list[dict]] = {"_plan_org": {}}
    client_routers = []
    if isp_clients:
        org_ids = [org.pk for org in isp_clients]
        client_routers = list(
            MikroTikRouter.objects.filter(organization_id__in=org_ids)
            .order_by("name", "host")
            .only("id", "name", "host", "organization_id")
        )
        for router in MikroTikRouter.objects.filter(organization_id__in=org_ids).only(
            "id",
            "name",
            "host",
            "organization_id",
            "default_cpe_username",
            "default_cpe_password",
            "location",
        ):
            org_key = str(router.organization_id)
            label = (router.name or "").strip() or router.host or f"Router {router.pk}"
            if router.host and router.name:
                label = f"{router.name} ({router.host})"
            routers_by_org.setdefault(org_key, []).append(
                {"id": router.pk, "name": router.name or "", "label": label}
            )
            default_password = (router.default_cpe_password or "").strip()
            router_cpe_defaults[str(router.pk)] = {
                "username": (router.default_cpe_username or "").strip() or "admin",
                "password": default_password,
                "has_password": bool(default_password),
                "address": (router.location or "").strip(),
                "router_name": (router.name or "").strip(),
                "organization_id": router.organization_id,
            }
        for plan in (
            BillingPlan.objects.filter(
                organization_id__in=org_ids,
                is_active=True,
                service_type=Customer.ServiceType.PPPOE,
            )
            .prefetch_related("routers")
            .order_by("price", "name")
            .only("id", "name", "organization_id")
        ):
            org_key = str(plan.organization_id)
            router_ids = list(plan.routers.values_list("id", flat=True))
            plans_by_org.setdefault(org_key, []).append(
                {
                    "id": plan.pk,
                    "name": plan.name,
                    "router_ids": router_ids,
                }
            )
            plans_by_org["_plan_org"][str(plan.pk)] = plan.organization_id

    if open_modal != "pppoe-register-modal" and request.method != "POST":
        pppoe_initial: dict = {}
        if len(isp_clients) == 1:
            pppoe_initial["organization"] = isp_clients[0].pk
            org_routers = [
                r for r in client_routers if r.organization_id == isp_clients[0].pk
            ]
            if len(org_routers) == 1:
                pppoe_initial["router"] = org_routers[0].pk
        pppoe_form = PppoeClientRegisterForm(
            organizations=isp_clients,
            initial=pppoe_initial,
            default_activate=False,
            allow_activate=False,
            require_serials=True,
        )

    return render(
        request,
        "accounts/technician_installations.html",
        {
            "page_title": "New Customer Installation",
            "page_kicker": "Field work",
            "page_subtitle": (
                "Clients you registered, plus open installation tickets."
            ),
            "empty_text": "No clients registered yet. Register a PPPoE client to get started.",
            "current_page": "installations",
            "dashboard_url_name": "roles:technician",
            "my_clients": my_clients,
            "tickets": tickets,
            "employee_profile": employee,
            "registered_count": len(my_clients),
            "inactive_count": inactive_count,
            "active_count": active_count,
            "assigned_count": sum(
                1 for t in tickets if t.assigned_technician_id == employee.pk
            ),
            "open_pool_count": sum(
                1
                for t in tickets
                if t.status == Customer.Status.QUEUED
                or (
                    t.status == Customer.Status.ASSIGNED
                    and t.assigned_technician_id is None
                )
            ),
            "pppoe_form": pppoe_form,
            "pppoe_select_isp": True,
            "router_cpe_defaults_json": json.dumps(router_cpe_defaults),
            "routers_by_org_json": json.dumps(routers_by_org),
            "plans_by_org_json": json.dumps(plans_by_org),
            "open_client_modal": open_modal,
            "billing_plans_exist": any(
                key != "_plan_org" and plans_by_org.get(key)
                for key in plans_by_org
            ),
        },
    )


def _technician_installation_is_open_pool(customer: Customer) -> bool:
    if customer.status == Customer.Status.QUEUED:
        return True
    return (
        customer.status == Customer.Status.ASSIGNED
        and customer.assigned_technician_id is None
    )


@role_required(Employee.Role.TECHNICIAN)
@require_POST
def technician_installation_accept(request, customer_id):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    with transaction.atomic():
        customer = (
            Customer.objects.select_for_update()
            .filter(pk=customer_id)
            .first()
        )
        if customer is None:
            messages.error(request, "That installation ticket was not found.")
            return redirect("roles:technician_installations")

        ticket = customer.sales_ticket_number or customer.account_number
        if InstallationDecline.objects.filter(
            customer=customer, technician=employee
        ).exists():
            messages.error(
                request,
                f"Ticket {ticket} was hidden after you marked it not interested.",
            )
            return redirect("roles:technician_installations")

        if customer.assigned_technician_id == employee.pk:
            messages.info(request, f"Ticket {ticket} is already assigned to you.")
            return redirect("roles:technician_installations")

        if not _technician_installation_is_open_pool(customer):
            if customer.assigned_technician_id:
                messages.error(
                    request,
                    f"Ticket {ticket} was already accepted by another technician.",
                )
            else:
                messages.error(request, f"Ticket {ticket} is not available to accept.")
            return redirect("roles:technician_installations")

        customer.status = Customer.Status.ASSIGNED
        customer.assigned_technician = employee
        customer.save(update_fields=["status", "assigned_technician"])
        InstallationDecline.objects.filter(
            customer=customer, technician=employee
        ).delete()

    notify_org_event(
        "isp_installation_result",
        organization=getattr(customer, "organization", None),
        client=customer,
        technician=employee,
        context={"status": "accepted"},
        subject="Installation accepted",
    )
    notify_org_event(
        "lead_installation",
        organization=getattr(customer, "organization", None),
        client=customer,
        technician=employee,
        context={"status": "accepted"},
        subject="Installation update",
    )
    messages.success(
        request,
        f"Accepted ticket {ticket}. Status is now Assigned.",
    )
    return redirect("roles:technician_installations")


@role_required(Employee.Role.TECHNICIAN)
@require_POST
def technician_installation_not_interested(request, customer_id):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    reason_labels = dict(InstallationDecline.Reason.choices)
    detail_required = InstallationDecline.DETAIL_REQUIRED
    category = (request.POST.get("reason_category") or "").strip()
    detail = (request.POST.get("reason_detail") or "").strip()
    reason = (request.POST.get("reason") or "").strip()

    label = reason_labels.get(category)
    if not label:
        messages.error(request, "Choose a reason for not interested.")
        return redirect("roles:technician_installations")
    if category in detail_required and not detail:
        messages.error(request, f"Enter details for “{label}”.")
        return redirect("roles:technician_installations")

    if category in detail_required:
        reason = f"{label}: {detail}"[:255]
    else:
        reason = label

    with transaction.atomic():
        customer = (
            Customer.objects.select_for_update()
            .filter(pk=customer_id)
            .first()
        )
        if customer is None:
            messages.error(request, "That installation ticket was not found.")
            return redirect("roles:technician_installations")

        ticket = customer.sales_ticket_number or customer.account_number
        open_pool = _technician_installation_is_open_pool(customer)
        assigned_to_me = customer.assigned_technician_id == employee.pk
        if not open_pool and not assigned_to_me:
            messages.error(request, f"Ticket {ticket} is not available to hide.")
            return redirect("roles:technician_installations")

        # If this tech had accepted it, release it back to the open pool.
        if assigned_to_me:
            customer.status = Customer.Status.QUEUED
            customer.assigned_technician = None
            customer.save(update_fields=["status", "assigned_technician"])

        InstallationDecline.objects.update_or_create(
            customer=customer,
            technician=employee,
            defaults={
                "reason_category": category,
                "reason": reason,
            },
        )

    messages.success(
        request,
        f"Marked ticket {ticket} as not interested ({reason}). It is hidden for you.",
    )
    return redirect("roles:technician_installations")


@role_required(Employee.Role.TECHNICIAN)
@require_POST
def technician_installation_reject(request, customer_id):
    """Release an accepted ticket back to the allocated-open pool."""
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    reason_labels = dict(InstallationReject.Reason.choices)
    detail_required = InstallationReject.DETAIL_REQUIRED
    category = (request.POST.get("reason_category") or "").strip()
    detail = (request.POST.get("reason_detail") or "").strip()

    label = reason_labels.get(category)
    if not label:
        messages.error(request, "Choose a reason for rejecting this ticket.")
        return redirect("roles:technician_installations")
    if category in detail_required and not detail:
        messages.error(request, f"Enter a note for “{label}”.")
        return redirect("roles:technician_installations")

    if category in detail_required:
        reason = f"{label}: {detail}"[:255]
    else:
        reason = label

    with transaction.atomic():
        customer = (
            Customer.objects.select_for_update()
            .filter(pk=customer_id)
            .first()
        )
        if customer is None:
            messages.error(request, "That installation ticket was not found.")
            return redirect("roles:technician_installations")

        ticket = customer.sales_ticket_number or customer.account_number
        if customer.assigned_technician_id != employee.pk:
            messages.error(
                request,
                f"Only the assigned technician can reject ticket {ticket}.",
            )
            return redirect("roles:technician_installations")

        customer.status = Customer.Status.QUEUED
        customer.assigned_technician = None
        customer.save(update_fields=["status", "assigned_technician"])
        InstallationReject.objects.create(
            customer=customer,
            technician=employee,
            reason_category=category,
            reason=reason,
        )

    notify_org_event(
        "isp_installation_result",
        organization=getattr(customer, "organization", None),
        client=customer,
        technician=employee,
        context={"status": "declined", "reason": reason},
        subject="Installation declined",
    )
    notify_org_event(
        "lead_installation",
        organization=getattr(customer, "organization", None),
        client=customer,
        technician=employee,
        context={"status": "declined", "reason": reason},
        subject="Installation update",
    )
    messages.success(
        request,
        f"Rejected ticket {ticket} ({reason}). It is back in the open pool.",
    )
    return redirect("roles:technician_installations")


def _technician_ticket_clients(employee, user):
    """Clients this technician registered or has assigned."""
    return (
        Customer.objects.filter(
            Q(registered_by=user) | Q(assigned_technician=employee)
        )
        .select_related("organization", "plan", "router")
        .distinct()
        .order_by("-created_at")
    )


def _pending_connection_pool_qs():
    """Open install tickets awaiting a technician (leads + queued)."""
    return (
        Customer.objects.filter(
            status__in=[Customer.Status.LEAD, Customer.Status.QUEUED],
            service_type=Customer.ServiceType.PPPOE,
            assigned_technician__isnull=True,
        )
        .select_related(
            "organization",
            "plan",
            "router",
            "registered_by",
            "assigned_technician",
            "assigned_technician__user",
        )
        .order_by("-created_at")
    )


def _active_fault_tickets_qs():
    """Fault tickets still open for field work (not resolved/closed)."""
    return FaultTicket.objects.exclude(
        status__in=[FaultTicket.Status.RESOLVED, FaultTicket.Status.CLOSED]
    )


def _fault_ticket_notice(*, total_count: int, open_count: int, assigned_count: int) -> str:
    """Short technician-facing summary when fault tickets need attention."""
    if total_count < 1:
        return ""
    if assigned_count and open_count:
        return (
            f"You have {assigned_count} assigned fault ticket"
            f"{'' if assigned_count == 1 else 's'} and "
            f"{open_count} open fault ticket"
            f"{'' if open_count == 1 else 's'} waiting."
        )
    if assigned_count:
        return (
            f"You have {assigned_count} assigned fault ticket"
            f"{'' if assigned_count == 1 else 's'} to resolve."
        )
    if open_count:
        return (
            f"There {'is' if open_count == 1 else 'are'} "
            f"{open_count} open fault ticket"
            f"{'' if open_count == 1 else 's'} that need attention."
        )
    return (
        f"There {'is' if total_count == 1 else 'are'} "
        f"{total_count} active fault ticket"
        f"{'' if total_count == 1 else 's'}."
    )


@role_required(Employee.Role.TECHNICIAN)
def technician_tickets_pending_connections(request):
    """Install queue: open pool + this technician's assigned work."""
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    open_tickets = list(_pending_connection_pool_qs()[:200])
    in_progress_tickets = list(
        Customer.objects.filter(
            status=Customer.Status.ASSIGNED,
            assigned_technician=employee,
            service_type=Customer.ServiceType.PPPOE,
        )
        .select_related(
            "organization",
            "plan",
            "router",
            "registered_by",
            "assigned_technician",
            "assigned_technician__user",
        )
        .order_by("-created_at")[:200]
    )
    in_progress_ids = {t.pk for t in in_progress_tickets}
    tickets = list(in_progress_tickets) + [
        t for t in open_tickets if t.pk not in in_progress_ids
    ]
    pending_activation_count = (
        _technician_ticket_clients(employee, request.user)
        .filter(status=Customer.Status.INSTALLED)
        .count()
    )
    connected_count = (
        _technician_ticket_clients(employee, request.user)
        .filter(
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.ACTIVE,
        )
        .count()
    )
    technician_stock = _technician_held_stock_catalog(employee)

    return render(
        request,
        "accounts/technician_tickets.html",
        {
            "page_title": "Queued for install",
            "page_kicker": "Field work",
            "page_subtitle": (
                "Accept a queued ticket to take ownership, then complete the install "
                "with stock used when the site visit is done."
            ),
            "empty_text": (
                "No queued install tickets yet. When sales or customer support "
                "registers a PPPoE client, it will appear here."
            ),
            "current_page": "tickets_pending_connections",
            "dashboard_url_name": "roles:technician",
            "ticket_view": "pending_connections",
            "tickets": tickets,
            "open_count": len(open_tickets),
            "in_progress_count": len(in_progress_tickets),
            "pending_count": pending_activation_count,
            "pending_connections_count": len(tickets),
            "connected_count": connected_count,
            "fault_count": _active_fault_tickets_qs().count(),
            "employee_profile": employee,
            "technician_stock": technician_stock,
        },
    )


@role_required(Employee.Role.TECHNICIAN)
@require_GET
def technician_places(request):
    """Live building / place suggestions for install completion."""
    from core.places import search_locations

    query = (request.GET.get("q") or "").strip()
    return JsonResponse(search_locations(query, limit=6))


@role_required(Employee.Role.TECHNICIAN)
@require_GET
def technician_place_details(request):
    """Resolve a place_id or free-text location to coordinates."""
    from core.places import resolve_location

    place_id = (request.GET.get("place_id") or "").strip()
    query = (request.GET.get("q") or "").strip()
    details = resolve_location(query, place_id=place_id)
    if not details:
        return JsonResponse({"ok": False, "error": "Place not found."}, status=404)
    return JsonResponse({"ok": True, **details})


@role_required(Employee.Role.TECHNICIAN)
@require_GET
def technician_place_reverse(request):
    """Resolve current GPS coordinates to a place label."""
    from core.places import reverse_geocode

    details = reverse_geocode(request.GET.get("lat"), request.GET.get("lng"))
    if not details:
        return JsonResponse({"ok": False, "error": "Could not resolve location."}, status=404)
    return JsonResponse({"ok": True, **details})


@role_required(Employee.Role.TECHNICIAN)
@require_POST
def technician_ticket_receive(request, customer_id):
    """Accept a lead/queued ticket → Assigned."""
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    with transaction.atomic():
        customer = (
            Customer.objects.select_for_update()
            .filter(pk=customer_id)
            .first()
        )
        if customer is None:
            messages.error(request, "That ticket was not found.")
            return redirect("roles:technician_tickets_pending_connections")

        ticket = customer.sales_ticket_number or customer.account_number
        if customer.status == Customer.Status.ASSIGNED:
            if customer.assigned_technician_id == employee.pk:
                messages.info(
                    request, f"Ticket {ticket} is already assigned to you."
                )
            else:
                messages.error(
                    request,
                    f"Ticket {ticket} was already accepted by another technician.",
                )
            return redirect("roles:technician_tickets_pending_connections")

        if customer.status not in (Customer.Status.LEAD, Customer.Status.QUEUED):
            messages.error(
                request,
                f"Ticket {ticket} is not available to accept.",
            )
            return redirect("roles:technician_tickets_pending_connections")

        if (
            customer.assigned_technician_id
            and customer.assigned_technician_id != employee.pk
        ):
            messages.error(
                request,
                f"Ticket {ticket} was already accepted by another technician.",
            )
            return redirect("roles:technician_tickets_pending_connections")

        customer.status = Customer.Status.ASSIGNED
        customer.assigned_technician = employee
        customer.save(update_fields=["status", "assigned_technician"])

    messages.success(
        request,
        f"Accepted ticket {ticket}. Status is now Assigned.",
    )
    return redirect("roles:technician_tickets_pending_connections")


def _normalize_install_serials(raw_values) -> list[str]:
    serials: list[str] = []
    seen: set[str] = set()
    for raw in raw_values or []:
        value = (raw or "").strip().upper()
        if not value or value in seen:
            continue
        seen.add(value)
        serials.append(value)
    return serials


def _technician_held_stock_catalog(employee):
    """Active allocations for a technician, grouped for install stock pickers."""
    allocations = list(
        NetworkEquipmentAllocation.objects.filter(
            employee=employee,
            returned_at__isnull=True,
        )
        .select_related("equipment", "serial")
        .order_by("equipment__name", "serial__serial_number", "-allocated_at")
    )
    groups = {}
    for row in allocations:
        equipment = row.equipment
        if equipment is None:
            continue
        entry = groups.get(equipment.pk)
        if entry is None:
            entry = {
                "id": equipment.pk,
                "name": equipment.name,
                "quantity": 0,
                "track_serials": bool(equipment.track_serials),
                "serials": [],
                "type": equipment.get_equipment_type_display(),
            }
            groups[equipment.pk] = entry
        entry["quantity"] += int(row.quantity or 0)
        if row.serial_id and row.serial:
            serial = (row.serial.serial_number or "").strip().upper()
            if serial and serial not in entry["serials"]:
                entry["serials"].append(serial)

    return sorted(
        groups.values(),
        key=lambda item: (item["name"] or "").lower(),
    )


def _parse_install_stock_usage(raw_payload):
    """
    Parse JSON stock usage from the complete-install form.

    Expected shape:
      [{"equipment_id": 1, "quantity": 2, "serials": ["SN1", "SN2"]}, ...]
    """
    if isinstance(raw_payload, (list, tuple)):
        payload = raw_payload
    else:
        text = (raw_payload or "").strip()
        if not text:
            return []
        try:
            payload = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid stock usage payload.") from exc
    if not isinstance(payload, list):
        raise ValueError("Stock usage must be a list of items.")

    lines = []
    seen_equipment = set()
    for row in payload:
        if not isinstance(row, dict):
            raise ValueError("Each stock line must be an object.")
        try:
            equipment_id = int(row.get("equipment_id") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid equipment selected.") from exc
        if equipment_id < 1:
            raise ValueError("Select a stock item.")
        if equipment_id in seen_equipment:
            raise ValueError("Each stock item can only be added once per install.")
        seen_equipment.add(equipment_id)

        serials = _normalize_install_serials(row.get("serials") or [])
        try:
            quantity = int(row.get("quantity") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("Enter a valid quantity.") from exc
        if serials:
            quantity = len(serials)
        if quantity < 1:
            raise ValueError("Enter a quantity of at least 1 for each stock item.")
        lines.append(
            {
                "equipment_id": equipment_id,
                "quantity": quantity,
                "serials": serials,
            }
        )
    return lines


def _consume_technician_stock_as_sold(
    *,
    employee,
    lines,
    actor=None,
    notes="",
):
    """
    Mark selected technician-held stock as sold.

    Closes matching open allocations and writes SOLD ledger rows.
    Returns the list of serial numbers consumed (may be empty).
    """
    if not lines:
        raise ValueError("Select at least one stock item used on this install.")

    now = timezone.now()
    used_serials: list[str] = []
    for line in lines:
        equipment = (
            NetworkEquipment.objects.select_for_update()
            .filter(pk=line["equipment_id"])
            .first()
        )
        if equipment is None:
            raise ValueError("A selected stock item was not found.")

        open_allocations = list(
            NetworkEquipmentAllocation.objects.select_for_update()
            .filter(
                employee=employee,
                equipment=equipment,
                returned_at__isnull=True,
            )
            .select_related("serial")
            .order_by("allocated_at", "id")
        )
        held_qty = sum(int(row.quantity or 0) for row in open_allocations)
        quantity = int(line["quantity"] or 0)
        serials = list(line.get("serials") or [])
        track_serials = bool(equipment.track_serials)

        if quantity > held_qty:
            raise ValueError(
                f"Cannot sell {quantity} × “{equipment.name}”. "
                f"You only hold {held_qty}."
            )

        if track_serials:
            if not serials:
                raise ValueError(
                    f"“{equipment.name}” requires serial numbers. "
                    "Search and select the units used."
                )
            if len(serials) != quantity:
                raise ValueError(
                    f"Select {quantity} serial(s) for “{equipment.name}”."
                )
            by_serial = {
                (row.serial.serial_number or "").strip().upper(): row
                for row in open_allocations
                if row.serial_id and row.serial
            }
            missing = [serial for serial in serials if serial not in by_serial]
            if missing:
                raise ValueError(
                    "Serial not in your stock: " + ", ".join(missing)
                )
            for serial in serials:
                allocation = by_serial[serial]
                allocation.returned_at = now
                allocation.save(update_fields=["returned_at"])
                unit = (
                    NetworkEquipmentSerial.objects.select_for_update()
                    .filter(pk=allocation.serial_id)
                    .first()
                )
                if unit is not None:
                    unit.status = NetworkEquipmentSerial.Status.SOLD
                    unit.save(update_fields=["status", "updated_at"])
                used_serials.append(serial)
            _log_equipment_stock_movements(
                equipment=equipment,
                movement_type=NetworkEquipmentStockMovement.MovementType.SOLD,
                quantity=len(serials),
                serials=serials,
                employee=employee,
                actor=actor,
                notes=notes,
            )
        else:
            remaining = quantity
            for allocation in open_allocations:
                if remaining < 1:
                    break
                take = min(int(allocation.quantity or 0), remaining)
                if take < 1:
                    continue
                if take == int(allocation.quantity or 0):
                    allocation.returned_at = now
                    allocation.save(update_fields=["returned_at"])
                else:
                    allocation.quantity = int(allocation.quantity or 0) - take
                    allocation.save(update_fields=["quantity"])
                remaining -= take
            if remaining > 0:
                raise ValueError(
                    f"Could not reserve {quantity} × “{equipment.name}” from your stock."
                )
            _log_equipment_stock_movements(
                equipment=equipment,
                movement_type=NetworkEquipmentStockMovement.MovementType.SOLD,
                quantity=quantity,
                employee=employee,
                actor=actor,
                notes=notes,
            )

    return used_serials


@role_required(Employee.Role.TECHNICIAN)
@require_POST
def technician_ticket_mark_done(request, customer_id):
    """Complete an assigned install → Installed (pending ISP activation)."""
    from decimal import Decimal, InvalidOperation

    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    try:
        stock_lines = _parse_install_stock_usage(request.POST.get("stock_used"))
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("roles:technician_tickets_pending_connections")

    building_name = (request.POST.get("building_name") or "").strip()
    address = (request.POST.get("address") or "").strip()
    raw_lat = (request.POST.get("location_lat") or "").strip()
    raw_lng = (request.POST.get("location_lng") or "").strip()
    lat = lng = None
    if raw_lat or raw_lng:
        try:
            lat = Decimal(raw_lat).quantize(Decimal("0.000001"))
            lng = Decimal(raw_lng).quantize(Decimal("0.000001"))
        except (InvalidOperation, TypeError, ValueError):
            messages.error(request, "Location coordinates are invalid.")
            return redirect("roles:technician_tickets_pending_connections")
        if not (-90 <= lat <= 90 and -180 <= lng <= 180):
            messages.error(request, "Location coordinates are out of range.")
            return redirect("roles:technician_tickets_pending_connections")

    with transaction.atomic():
        customer = (
            Customer.objects.select_for_update()
            .filter(pk=customer_id)
            .first()
        )
        if customer is None:
            messages.error(request, "That ticket was not found.")
            return redirect("roles:technician_tickets_pending_connections")

        ticket = customer.sales_ticket_number or customer.account_number
        if customer.assigned_technician_id != employee.pk:
            messages.error(request, f"Ticket {ticket} is not assigned to you.")
            return redirect("roles:technician_tickets_pending_connections")

        if customer.status != Customer.Status.ASSIGNED:
            messages.error(
                request,
                f"Ticket {ticket} must be assigned before you can complete the install.",
            )
            return redirect("roles:technician_tickets_pending_connections")

        if not stock_lines:
            messages.error(
                request,
                f"Select the stock items used to complete ticket {ticket}.",
            )
            return redirect("roles:technician_tickets_pending_connections")

        try:
            sold_serials = _consume_technician_stock_as_sold(
                employee=employee,
                lines=stock_lines,
                actor=request.user,
                notes=f"Install sold on ticket {ticket}",
            )
        except ValueError as exc:
            messages.error(request, str(exc))
            transaction.set_rollback(True)
            return redirect("roles:technician_tickets_pending_connections")

        customer.status = Customer.Status.INSTALLED
        customer.equipment_serials = sold_serials
        update_fields = ["status", "equipment_serials"]
        if building_name:
            customer.building_name = building_name[:150].upper()
            update_fields.append("building_name")
        if address:
            customer.address = address[:255].upper()
            update_fields.append("address")
        if lat is not None and lng is not None:
            customer.location_lat = lat
            customer.location_lng = lng
            update_fields.extend(["location_lat", "location_lng"])
        customer.save(update_fields=update_fields)

    item_count = sum(int(line["quantity"] or 0) for line in stock_lines)
    messages.success(
        request,
        (
            f"Ticket {ticket} install completed — {item_count} stock unit(s) marked sold. "
            "Now installed (pending ISP activation)."
        ),
    )
    return redirect("roles:technician_tickets")


def _technician_pppoe_register_bundle(request, employee, *, redirect_name: str):
    """PPPoE register form + maps for technician pages.

    Returns ``(redirect_response, None)`` after a successful POST, otherwise
    ``(None, context_dict)`` for the modal includes.
    """
    isp_clients = list(
        Organization.objects.exclude(status=Organization.Status.SUSPENDED)
        .order_by("name")
        .only("id", "name")
    )
    open_modal = ""
    pppoe_form = PppoeClientRegisterForm(
        organizations=isp_clients,
        default_activate=False,
        allow_activate=False,
        require_serials=True,
    )

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action == "register_pppoe":
            if not isp_clients:
                messages.error(request, "No ISP clients are available for registration.")
                return redirect(redirect_name), None
            pppoe_form = PppoeClientRegisterForm(
                request.POST,
                organizations=isp_clients,
                default_activate=False,
                allow_activate=False,
                require_serials=True,
            )
            if pppoe_form.is_valid():
                customer = pppoe_form.save(commit=False)
                customer.registered_by = request.user
                customer.assigned_technician = employee
                customer.save()
                if customer.organization_id:
                    notify_org_event(
                        "client_welcome",
                        organization=customer.organization,
                        client=customer,
                        subject="Welcome — account created",
                    )
                    notify_org_event(
                        "isp_client_registered",
                        organization=customer.organization,
                        client=customer,
                        subject="New client registered",
                    )
                customer_pk = customer.pk
                account_number = customer.account_number
                full_name = customer.full_name
                org_name = (
                    customer.organization.name
                    if customer.organization_id
                    else "ISP client"
                )

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
                        f"PPPoE client “{full_name}” registered "
                        f"({account_number}) under {org_name} as installed. "
                        "The CPE can dial in, but surfing stays blocked until an ISP client activates the account."
                    ),
                )
                return redirect(redirect_name), None
            open_modal = "pppoe-register-modal"

    router_cpe_defaults: dict[str, dict] = {}
    routers_by_org: dict[str, list[dict]] = {}
    plans_by_org: dict[str, list[dict]] = {"_plan_org": {}}
    client_routers = []
    if isp_clients:
        org_ids = [org.pk for org in isp_clients]
        client_routers = list(
            MikroTikRouter.objects.filter(organization_id__in=org_ids)
            .order_by("name", "host")
            .only("id", "name", "host", "organization_id")
        )
        for router in MikroTikRouter.objects.filter(organization_id__in=org_ids).only(
            "id",
            "name",
            "host",
            "organization_id",
            "default_cpe_username",
            "default_cpe_password",
            "location",
        ):
            org_key = str(router.organization_id)
            label = (router.name or "").strip() or router.host or f"Router {router.pk}"
            if router.host and router.name:
                label = f"{router.name} ({router.host})"
            routers_by_org.setdefault(org_key, []).append(
                {"id": router.pk, "name": router.name or "", "label": label}
            )
            default_password = (router.default_cpe_password or "").strip()
            router_cpe_defaults[str(router.pk)] = {
                "username": (router.default_cpe_username or "").strip() or "admin",
                "password": default_password,
                "has_password": bool(default_password),
                "address": (router.location or "").strip(),
                "router_name": (router.name or "").strip(),
                "organization_id": router.organization_id,
            }
        for plan in (
            BillingPlan.objects.filter(
                organization_id__in=org_ids,
                is_active=True,
                service_type=Customer.ServiceType.PPPOE,
            )
            .prefetch_related("routers")
            .order_by("price", "name")
            .only("id", "name", "organization_id")
        ):
            org_key = str(plan.organization_id)
            router_ids = list(plan.routers.values_list("id", flat=True))
            plans_by_org.setdefault(org_key, []).append(
                {
                    "id": plan.pk,
                    "name": plan.name,
                    "router_ids": router_ids,
                }
            )
            plans_by_org["_plan_org"][str(plan.pk)] = plan.organization_id

    if open_modal != "pppoe-register-modal" and request.method != "POST":
        pppoe_initial: dict = {}
        if len(isp_clients) == 1:
            pppoe_initial["organization"] = isp_clients[0].pk
            org_routers = [
                r for r in client_routers if r.organization_id == isp_clients[0].pk
            ]
            if len(org_routers) == 1:
                pppoe_initial["router"] = org_routers[0].pk
        pppoe_form = PppoeClientRegisterForm(
            organizations=isp_clients,
            initial=pppoe_initial,
            default_activate=False,
            allow_activate=False,
            require_serials=True,
        )

    return None, {
        "pppoe_form": pppoe_form,
        "pppoe_select_isp": True,
        "router_cpe_defaults_json": json.dumps(router_cpe_defaults),
        "routers_by_org_json": json.dumps(routers_by_org),
        "plans_by_org_json": json.dumps(plans_by_org),
        "open_client_modal": open_modal,
        "billing_plans_exist": any(
            key != "_plan_org" and plans_by_org.get(key) for key in plans_by_org
        ),
    }


@role_required(Employee.Role.TECHNICIAN)
def technician_tickets_hub(request):
    """Tickets landing page — choose a ticket category or register PPPoE."""
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    redirect_resp, pppoe_ctx = _technician_pppoe_register_bundle(
        request,
        employee,
        redirect_name="roles:technician_tickets_hub",
    )
    if redirect_resp is not None:
        return redirect_resp

    pending_connections_count = (
        _pending_connection_pool_qs().count()
        + Customer.objects.filter(
            status=Customer.Status.ASSIGNED,
            assigned_technician=employee,
            service_type=Customer.ServiceType.PPPOE,
        ).count()
    )
    pending_count = (
        _technician_ticket_clients(employee, request.user)
        .filter(
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.INSTALLED,
        )
        .count()
    )
    connected_count = (
        _technician_ticket_clients(employee, request.user)
        .filter(
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.ACTIVE,
        )
        .count()
    )
    fault_count = _active_fault_tickets_qs().count()

    my_clients = list(
        Customer.objects.filter(registered_by=request.user)
        .select_related("organization", "plan", "router")
        .order_by("-created_at")[:300]
    )
    installed_count = sum(
        1 for c in my_clients if c.status == Customer.Status.INSTALLED
    )
    active_count = sum(1 for c in my_clients if c.status == Customer.Status.ACTIVE)

    context = {
        "page_title": "Tickets",
        "page_kicker": "Field work",
        "page_subtitle": "Clients you registered, plus ticket categories for field work.",
        "current_page": "tickets_hub",
        "dashboard_url_name": "roles:technician",
        "ticket_view": "hub",
        "pending_connections_count": pending_connections_count,
        "pending_count": pending_count,
        "connected_count": connected_count,
        "fault_count": fault_count,
        "my_clients": my_clients,
        "registered_count": len(my_clients),
        "installed_count": installed_count,
        "active_count": active_count,
        "empty_text": "No clients registered yet. Register a PPPoE client to get started.",
    }
    context.update(pppoe_ctx or {})
    return render(request, "accounts/technician_tickets_hub.html", context)


@role_required(Employee.Role.TECHNICIAN)
def technician_tickets(request):
    """Installed clients waiting for ISP activation."""
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    tickets = list(
        _technician_ticket_clients(employee, request.user).filter(
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.INSTALLED,
        )[:200]
    )
    connected_count = (
        _technician_ticket_clients(employee, request.user)
        .filter(
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.ACTIVE,
        )
        .count()
    )
    pending_connections_count = (
        _pending_connection_pool_qs().count()
        + Customer.objects.filter(
            status=Customer.Status.ASSIGNED,
            assigned_technician=employee,
            service_type=Customer.ServiceType.PPPOE,
        ).count()
    )

    return render(
        request,
        "accounts/technician_tickets.html",
        {
            "page_title": "Installed — pending activation",
            "page_kicker": "Field work",
            "page_subtitle": (
                "Clients you installed that are waiting for ISP activation."
            ),
            "empty_text": (
                "No installed clients awaiting activation yet. Accept a queued "
                "ticket and complete the install, or register a PPPoE client from Installations."
            ),
            "current_page": "tickets",
            "dashboard_url_name": "roles:technician",
            "ticket_view": "pending",
            "tickets": tickets,
            "pending_count": len(tickets),
            "pending_connections_count": pending_connections_count,
            "connected_count": connected_count,
            "fault_count": _active_fault_tickets_qs().count(),
            "employee_profile": employee,
            "technician_stock": [],
        },
    )


@role_required(Employee.Role.TECHNICIAN)
def technician_tickets_connected(request):
    """Activated clients this technician connected (filterable by activation date)."""
    from billing.usage_samples import parse_usage_filter

    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    tickets_filter = parse_usage_filter(request, default_range="month")
    since = tickets_filter.get("since")
    until = tickets_filter.get("until")

    base_qs = _technician_ticket_clients(employee, request.user).filter(
        service_type=Customer.ServiceType.PPPOE,
        status=Customer.Status.ACTIVE,
    )
    connected_total = base_qs.count()

    tickets_qs = base_qs
    if since is not None and until is not None:
        # Prefer package_start (activation); fall back to updated_at when unset.
        tickets_qs = tickets_qs.filter(
            Q(package_start__gte=since, package_start__lt=until)
            | Q(
                package_start__isnull=True,
                created_at__gte=since,
                created_at__lt=until,
            )
        )

    tickets = list(tickets_qs[:300])
    pending_count = (
        _technician_ticket_clients(employee, request.user)
        .filter(status=Customer.Status.INSTALLED)
        .count()
    )
    pending_connections_count = (
        _pending_connection_pool_qs().count()
        + Customer.objects.filter(
            status=Customer.Status.ASSIGNED,
            assigned_technician=employee,
            service_type=Customer.ServiceType.PPPOE,
        ).count()
    )
    filter_label = tickets_filter.get("label") or "selected period"
    empty_text = (
        f"No activated clients in {filter_label}. Try another day, period, month, or year."
        if connected_total
        else (
            "No activated clients yet. After an install is activated by the ISP, "
            "it will appear here."
        )
    )

    return render(
        request,
        "accounts/technician_tickets.html",
        {
            "page_title": "Activated clients",
            "page_kicker": "Field work",
            "page_subtitle": (
                f"Clients you connected that are now activated — showing {filter_label}."
            ),
            "empty_text": empty_text,
            "current_page": "tickets_connected",
            "dashboard_url_name": "roles:technician",
            "ticket_view": "connected",
            "tickets": tickets,
            "pending_count": pending_count,
            "pending_connections_count": pending_connections_count,
            "connected_count": connected_total,
            "active_count": len(tickets),
            "fault_count": _active_fault_tickets_qs().count(),
            "employee_profile": employee,
            "technician_stock": [],
            "tickets_filter": tickets_filter,
        },
    )


@role_required(Employee.Role.TECHNICIAN)
def technician_fault_tickets(request):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    faults = list(
        _active_fault_tickets_qs()
        .select_related(
            "customer",
            "organization",
            "assigned_technician",
            "assigned_technician__user",
            "created_by",
        )
        .order_by("-created_at")[:200]
    )
    tickets = []
    assigned_count = 0
    open_count = 0
    for fault in faults:
        assigned_to_you = fault.assigned_technician_id == employee.pk
        is_open = fault.status == FaultTicket.Status.OPEN
        if assigned_to_you:
            assigned_count += 1
        if is_open:
            open_count += 1
        customer = fault.customer
        building_name = (customer.building_name or "").strip() if customer else ""
        house_number = (customer.house_number or "").strip() if customer else ""
        address = (customer.address or "").strip() if customer else ""
        location_lat = customer.location_lat if customer else None
        location_lng = customer.location_lng if customer else None
        location_parts = [part for part in [building_name, house_number, address] if part]
        tickets.append(
            {
                "reference": fault.ticket_number,
                "client_name": customer.full_name if customer else "",
                "status_label": fault.get_status_display(),
                "issue": fault.get_issue_display(),
                "building_name": building_name,
                "house_number": house_number,
                "address": address,
                "location": " · ".join(location_parts) if location_parts else "",
                "location_lat": location_lat,
                "location_lng": location_lng,
                "notes": fault.notes or "",
                "assigned_to_you": assigned_to_you,
                "is_open": is_open,
                "created_at": fault.created_at,
            }
        )

    fault_count = len(tickets)
    fault_notice = _fault_ticket_notice(
        total_count=fault_count,
        open_count=open_count,
        assigned_count=assigned_count,
    )
    if fault_notice:
        messages.warning(request, fault_notice)

    pending_connections_count = (
        _pending_connection_pool_qs().count()
        + Customer.objects.filter(
            status=Customer.Status.ASSIGNED,
            assigned_technician=employee,
            service_type=Customer.ServiceType.PPPOE,
        ).count()
    )
    pending_count = (
        _technician_ticket_clients(employee, request.user)
        .filter(
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.INSTALLED,
        )
        .count()
    )
    connected_count = (
        _technician_ticket_clients(employee, request.user)
        .filter(
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.ACTIVE,
        )
        .count()
    )

    return render(
        request,
        "accounts/technician_fault_tickets.html",
        {
            "page_title": "Fault Tickets",
            "page_kicker": "Field work",
            "page_subtitle": "Active and recent fault tickets for field resolution.",
            "empty_text": "When support raises a repair or outage, it will show up here for you to work.",
            "current_page": "fault_tickets",
            "dashboard_url_name": "roles:technician",
            "ticket_view": "fault",
            "tickets": tickets,
            "assigned_count": assigned_count,
            "open_count": open_count,
            "fault_count": fault_count,
            "fault_notice": fault_notice,
            "pending_connections_count": pending_connections_count,
            "pending_count": pending_count,
            "connected_count": connected_count,
        },
    )


MY_STOCK_URL_NAMES = {
    Employee.Role.SUPER_ADMIN: "roles:super_admin_my_stock",
    Employee.Role.ADMINISTRATOR: "roles:administrator_my_stock",
    Employee.Role.MANAGER: "roles:customer_support_my_stock",
    Employee.Role.IT_SUPPORT: "roles:it_support_my_stock",
    Employee.Role.SALES: "roles:sales_my_stock",
    Employee.Role.TECHNICIAN: "roles:technician_my_stock",
}

MY_STOCK_ITEM_URL_NAMES = {
    Employee.Role.SUPER_ADMIN: "roles:super_admin_my_stock_item",
    Employee.Role.ADMINISTRATOR: "roles:administrator_my_stock_item",
    Employee.Role.MANAGER: "roles:customer_support_my_stock_item",
    Employee.Role.IT_SUPPORT: "roles:it_support_my_stock_item",
    Employee.Role.SALES: "roles:sales_my_stock_item",
    Employee.Role.TECHNICIAN: "roles:technician_my_stock_item",
}


def _resolve_my_stock_context(request):
    """Resolve employee + viewed role for My Stock pages; may return a redirect."""
    employee = getattr(request.user, "employee_profile", None)
    if employee is None:
        return None, None, redirect("core:workspace")
    if not employee.can_access_workspace:
        return None, None, redirect("accounts:employee_pending")

    viewed = get_role_view(request, employee) or employee.role
    path = request.path or ""
    role_from_path = None
    for role, slug in ROLE_SLUGS.items():
        marker = f"/{slug}/my-stock"
        if marker in path:
            role_from_path = role
            break
    if role_from_path:
        allowed = employee.role == role_from_path or (
            can_switch_roles(employee) and role_from_path in SWITCHABLE_ROLES
        )
        if not allowed:
            stock_name = MY_STOCK_URL_NAMES.get(employee.role)
            if stock_name:
                return None, None, redirect(stock_name)
            return None, None, redirect(home_url_for_user(request.user, request))
        viewed = role_from_path
        if can_switch_roles(employee):
            set_role_view(request, viewed)
    elif can_switch_roles(employee) and viewed in SWITCHABLE_ROLES:
        set_role_view(request, viewed)

    if viewed not in ROLE_DASHBOARD_NAMES:
        viewed = employee.role
    return employee, viewed, None


@login_required(login_url="accounts:employee_login")
def my_stock(request):
    """List equipment currently allocated to the signed-in employee."""
    employee, viewed, early = _resolve_my_stock_context(request)
    if early is not None:
        return early

    allocations = list(
        NetworkEquipmentAllocation.objects.filter(
            employee=employee,
            returned_at__isnull=True,
        )
        .select_related("equipment", "serial")
        .order_by("equipment__name", "serial__serial_number", "-allocated_at")
    )
    groups = {}
    for row in allocations:
        entry = groups.get(row.equipment_id)
        if entry is None:
            entry = {
                "equipment": row.equipment,
                "quantity": 0,
                "serials": [],
                "track_serials": bool(row.equipment.track_serials or row.serial_id),
            }
            groups[row.equipment_id] = entry
        entry["quantity"] += int(row.quantity or 0)
        if row.serial_id and row.serial:
            entry["serials"].append(row.serial.serial_number)

    stock_rows = sorted(
        groups.values(),
        key=lambda item: (item["equipment"].name or "").lower(),
    )

    item_url_name = MY_STOCK_ITEM_URL_NAMES.get(viewed) or MY_STOCK_ITEM_URL_NAMES.get(
        employee.role
    )

    return render(
        request,
        "accounts/my_stock.html",
        {
            "page_title": "My Stock",
            "page_kicker": "Inventory",
            "page_subtitle": "Equipment currently allocated to you.",
            "empty_text": (
                "Nothing is checked out to you yet. When gear is allocated to your "
                "account, it will appear here."
            ),
            "current_page": "my_stock",
            "dashboard_url_name": ROLE_DASHBOARD_NAMES.get(viewed)
            or ROLE_DASHBOARD_NAMES.get(employee.role),
            "stock_rows": stock_rows,
            "assigned_count": len(stock_rows),
            "qty_total": sum(row["quantity"] for row in stock_rows),
            "item_url_name": item_url_name,
        },
    )


@login_required(login_url="accounts:employee_login")
def my_stock_item(request, pk):
    """Show one allocated equipment item and its movement report for this user."""
    employee, viewed, early = _resolve_my_stock_context(request)
    if early is not None:
        return early

    equipment = get_object_or_404(
        NetworkEquipment.objects.select_related("created_by"),
        pk=pk,
    )
    has_history = NetworkEquipmentAllocation.objects.filter(
        employee=employee,
        equipment=equipment,
    ).exists()
    if not has_history:
        list_url = MY_STOCK_URL_NAMES.get(viewed) or MY_STOCK_URL_NAMES.get(employee.role)
        messages.error(request, "That item is not in your stock.")
        return redirect(list_url)

    stock_report, held_qty = _equipment_employee_movement_report(equipment, employee)
    held_serials = list(
        NetworkEquipmentAllocation.objects.filter(
            equipment=equipment,
            employee=employee,
            returned_at__isnull=True,
            serial__isnull=False,
        )
        .select_related("serial")
        .order_by("serial__serial_number")
    )
    focus_serial = (request.GET.get("serial") or "").strip().upper()
    list_url_name = MY_STOCK_URL_NAMES.get(viewed) or MY_STOCK_URL_NAMES.get(
        employee.role
    )
    employee_name = (
        request.user.get_full_name() or request.user.username
    )

    return render(
        request,
        "accounts/my_stock_item.html",
        {
            "page_title": equipment.name,
            "page_kicker": "My Stock",
            "page_subtitle": "Your stock movement report for this item.",
            "current_page": "my_stock",
            "dashboard_url_name": ROLE_DASHBOARD_NAMES.get(viewed)
            or ROLE_DASHBOARD_NAMES.get(employee.role),
            "list_url_name": list_url_name,
            "equipment": equipment,
            "employee_name": employee_name,
            "held_qty": held_qty,
            "is_active_hold": held_qty > 0,
            "held_serials": held_serials,
            "focus_serial": focus_serial,
            "stock_report": stock_report,
            "movement_count": len(stock_report),
        },
    )


@role_required(Employee.Role.TECHNICIAN)
def technician_network_equipment(request):
    """Legacy technician gear URL — redirect to My Stock."""
    if can_switch_roles(request.user.employee_profile):
        set_role_view(request, Employee.Role.TECHNICIAN)
    return redirect("roles:technician_my_stock")
