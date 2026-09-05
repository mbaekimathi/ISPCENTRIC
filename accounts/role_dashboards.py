from functools import wraps
import json
import threading

from django.db import transaction
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from accounts.communications import fetch_provider_options
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
    Lead,
    NetworkEquipment,
    NetworkEquipmentAllocation,
    NetworkEquipmentSerial,
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
    home_url_for_user,
    set_client_view,
    set_role_view,
    switchable_clients_list,
    switchable_role_options,
)
from billing.forms import PppoeClientRegisterForm, SalesClientRegisterForm
from billing.models import BillingPlan, Customer, InstallationDecline, InstallationReject
from core.mikrotik_connect import provision_customer_pppoe
from core.models import MikroTikRouter


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
                    "label": "Approved sales",
                    "hint": "Tickets that have moved past new status.",
                    "url_name": "roles:customer_support_approved_sales",
                },
                {
                    "index": "04",
                    "label": "Technician",
                    "hint": "Open and assigned installation work.",
                    "url_name": "roles:customer_support_technician",
                },
                {
                    "index": "05",
                    "label": "Allocated",
                    "hint": "Closed technician allocations.",
                    "url_name": "roles:customer_support_allocated",
                },
                {
                    "index": "06",
                    "label": "Network equipment",
                    "hint": "Stock, register, and manage install gear.",
                    "url_name": "roles:customer_support_network_equipment",
                },
                {
                    "index": "07",
                    "label": "Allocate",
                    "hint": "Assign employees to organizations.",
                    "url_name": "roles:customer_support_allocate",
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
    from django.db.models import Count

    _prepare_manager_view(request)
    clients = list(
        Organization.objects.select_related("owner")
        .annotate(
            staff_count=Count("employees", distinct=True),
            customer_count=Count("customers", distinct=True),
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
@require_POST
def manager_exit_client_portal(request):
    _prepare_manager_view(request)
    clear_client_view(request)
    messages.success(request, "Returned to Customer support.")
    return redirect("roles:customer_support_isp_clients")


@role_required(Employee.Role.MANAGER)
def manager_sales(request):
    """Customer support: register potential clients and review all sales-role leads."""
    _prepare_manager_view(request)
    employee = request.user.employee_profile
    organization = employee.organization

    open_register_modal = False
    if request.method == "POST":
        form = LeadRegisterForm(request.POST, organization=organization)
        if form.is_valid():
            lead = form.save(created_by=request.user)
            messages.success(
                request,
                (
                    f"Potential client “{lead.full_name}” registered "
                    f"(lead {lead.lead_number}) for follow-up."
                ),
            )
            return redirect("roles:customer_support_sales")
        open_register_modal = True
    else:
        form = LeadRegisterForm(organization=organization)

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

    return render(
        request,
        "accounts/customer_support_sales.html",
        {
            "page_title": "Sales",
            "page_kicker": "Operations",
            "page_subtitle": (
                "Register potential clients as leads for follow-up and review "
                "all leads captured by the sales team."
            ),
            "current_page": "sales",
            "dashboard_url_name": "roles:customer_support",
            "leads": leads,
            "form": form,
            "open_register_modal": open_register_modal,
            "default_org_id": organization.pk if organization else "",
            "packages_by_org_json": json.dumps(packages_by_org),
            "all_packages_json": json.dumps(all_packages),
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
    _prepare_manager_view(request)
    sales = list(
        Customer.objects.exclude(status=Customer.Status.NEW)
        .select_related(
            "organization",
            "plan",
            "registered_by",
            "assigned_technician",
            "assigned_technician__user",
        )
        .order_by("-created_at")[:300]
    )
    return render(
        request,
        "accounts/customer_support_approved_sales.html",
        {
            "page_title": "Approved sales",
            "page_kicker": "Operations",
            "page_subtitle": "Sales tickets that are no longer new.",
            "current_page": "approved_sales",
            "dashboard_url_name": "roles:customer_support",
            "sales": sales,
            "empty_text": "No approved sales tickets yet.",
        },
    )


@role_required(Employee.Role.MANAGER)
def manager_technician(request):
    _prepare_manager_view(request)
    tickets = list(
        Customer.objects.filter(status=Customer.Status.ALLOCATED_OPEN)
        .select_related(
            "organization",
            "plan",
            "assigned_technician",
            "assigned_technician__user",
            "registered_by",
        )
        .order_by("-created_at")[:300]
    )
    return render(
        request,
        "accounts/customer_support_technician.html",
        {
            "page_title": "Technician",
            "page_kicker": "Field work",
            "page_subtitle": "All allocated-open installation tickets in the technician pool.",
            "current_page": "technician",
            "dashboard_url_name": "roles:customer_support",
            "tickets": tickets,
            "empty_text": "No allocated-open tickets yet.",
        },
    )


@role_required(Employee.Role.MANAGER)
def manager_allocated(request):
    _prepare_manager_view(request)
    tickets = list(
        Customer.objects.filter(status=Customer.Status.ALLOCATED_CLOSED)
        .select_related(
            "organization",
            "plan",
            "assigned_technician",
            "assigned_technician__user",
            "registered_by",
        )
        .order_by("-created_at")[:300]
    )
    return render(
        request,
        "accounts/customer_support_allocated.html",
        {
            "page_title": "Allocated",
            "page_kicker": "Field work",
            "page_subtitle": "All allocated-closed tickets assigned to a technician.",
            "current_page": "allocated",
            "dashboard_url_name": "roles:customer_support",
            "tickets": tickets,
            "empty_text": "No allocated-closed tickets yet.",
        },
    )


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
                            f"Enter exactly {amount} serial number(s) for this movement."
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
    return render(
        request,
        "accounts/customer_support_network_equipment.html",
        {
            "page_title": "Network equipment",
            "page_kicker": "Infrastructure",
            "page_subtitle": "Register and track network equipment used for installs and repairs.",
            "current_page": (
                "register_equipment" if open_register_modal else "network_equipment"
            ),
            "dashboard_url_name": "roles:customer_support",
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
            "empty_text": "No network equipment records yet. Use Register equipment in the sidebar to add one.",
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
    return render(
        request,
        "accounts/customer_support_allocate.html",
        {
            "page_title": "Allocate",
            "page_kicker": "Infrastructure",
            "page_subtitle": "Choose an employee to allocate network equipment to.",
            "current_page": "allocate",
            "dashboard_url_name": "roles:customer_support",
            "employees": employees,
            "employees_count": len(employees),
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
            "current_page": "allocate",
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
    from django.db.models import Count

    return (
        Organization.objects.select_related("owner")
        .annotate(
            staff_count=Count("employees", distinct=True),
            customer_count=Count("customers", distinct=True),
            plan_count=Count("plans", distinct=True),
            router_count=Count("mikrotik_routers", distinct=True),
        )
        .order_by("-created_at")
    )


def _render_it_support_company_clients(request, **extra):
    _prepare_it_support_view(request)
    clients = list(_isp_client_queryset())
    suspended_count = sum(
        1 for client in clients if client.status == Organization.Status.SUSPENDED
    )
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
            clients_count=len(clients),
            active_count=len(clients) - suspended_count,
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
    return Organization.objects.create(
        name=register_form.cleaned_data["company_name"],
        owner=user,
        login_code=register_form.cleaned_data["username"],
        phone=register_form.cleaned_data.get("phone", ""),
        profile_photo=register_form.cleaned_data.get("profile_photo"),
        status=Organization.Status.REGISTERED,
        registered_by=registered_by,
    )


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

    employees = list(
        Employee.objects.select_related("user", "organization")
        .order_by("-created_at")
    )
    suspended_count = sum(
        1 for member in employees if member.status == Employee.Status.SUSPENDED
    )
    pending_count = sum(
        1
        for member in employees
        if member.status == Employee.Status.PENDING_APPROVAL
    )
    active_count = sum(
        1 for member in employees if member.status == Employee.Status.ACTIVE
    )
    return render(
        request,
        "accounts/it_support_hr.html",
        _it_support_hr_context(
            employees=employees,
            employees_count=len(employees),
            active_count=active_count,
            suspended_count=suspended_count,
            pending_count=pending_count,
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
                    "label": "Company communications",
                    "description": "SMS, email, and WhatsApp credentials used for platform messages.",
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
                    "description": "Preview pay/pause pages, and toggle Click to earn adverts for each ISP.",
                    "url_name": "roles:it_support_company_themes",
                },
            ],
        },
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_company_themes(request):
    """Preview client-facing Hotspot / PPPoE payment pages for company themes."""
    _prepare_it_support_view(request)
    organizations = list(
        Organization.objects.exclude(join_code="")
        .order_by("name")
        .only(
            "id",
            "name",
            "join_code",
            "hotspot_enabled",
            "pppoe_compulsory",
            "adverts_enabled",
            "adverts_redirect_url",
        )
    )
    selected = None
    org_id = (
        request.POST.get("org")
        or request.GET.get("org")
        or ""
    )
    if org_id:
        selected = next((row for row in organizations if str(row.pk) == str(org_id)), None)
    if selected is None and organizations:
        selected = organizations[0]

    if request.method == "POST" and selected is not None:
        action = (request.POST.get("action") or "").strip()
        if action == "toggle_adverts":
            enabled = (request.POST.get("adverts_enabled") or "") in {
                "1",
                "true",
                "on",
                "yes",
            }
            redirect_url = (request.POST.get("adverts_redirect_url") or "").strip()
            if redirect_url and not redirect_url.lower().startswith(("http://", "https://")):
                redirect_url = f"https://{redirect_url}"
            Organization.objects.filter(pk=selected.pk).update(
                adverts_enabled=enabled,
                adverts_redirect_url=redirect_url,
            )
            selected.adverts_enabled = enabled
            selected.adverts_redirect_url = redirect_url
            for row in organizations:
                if row.pk == selected.pk:
                    row.adverts_enabled = enabled
                    row.adverts_redirect_url = redirect_url
            messages.success(
                request,
                (
                    f"Click to earn is on for {selected.name}."
                    if enabled
                    else f"Click to earn is off for {selected.name}."
                ),
            )
            return redirect(
                f"{reverse('roles:it_support_company_themes')}?org={selected.pk}"
            )

    hotspot_pay_url = ""
    pppoe_pay_url = ""
    earn_url = ""
    earn_preview_url = ""
    if selected and selected.join_code:
        hotspot_pay_url = reverse(
            "core:hotspot_pay", kwargs={"join_code": selected.join_code}
        )
        pppoe_pay_url = reverse(
            "core:pppoe_pay", kwargs={"join_code": selected.join_code}
        )
        earn_url = reverse(
            "core:click_to_earn", kwargs={"join_code": selected.join_code}
        )
        custom = (getattr(selected, "adverts_redirect_url", None) or "").strip()
        earn_preview_url = custom or earn_url

    return render(
        request,
        "accounts/it_support_company_themes.html",
        {
            "page_title": "Company themes",
            "page_kicker": "Settings",
            "page_subtitle": (
                "Preview captive pay and pause pages, and turn on Click to earn "
                "so Wi‑Fi visitors can open the ISP adverts page."
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
            "adverts_redirect_url": (
                (getattr(selected, "adverts_redirect_url", None) or "").strip()
                if selected
                else ""
            ),
            "hotspot_demo_preview_url": (
                f"{hotspot_pay_url}?preview=demo" if hotspot_pay_url else ""
            ),
            "pppoe_demo_preview_url": (
                f"{pppoe_pay_url}?preview=demo" if pppoe_pay_url else ""
            ),
            "hotspot_paused_preview_url": (
                f"{hotspot_pay_url}?preview=paused" if hotspot_pay_url else ""
            ),
            "pppoe_paused_preview_url": (
                f"{pppoe_pay_url}?preview=paused" if pppoe_pay_url else ""
            ),
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
    return render(
        request,
        "accounts/technician_dashboard.html",
        {
            "page_title": meta["title"],
            "page_subtitle": meta["subtitle"],
            "current_page": "dashboard",
            "dashboard_url_name": "roles:technician",
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
                    "hint": "Pending connections, pending activation, and tickets you have connected.",
                    "url_name": "roles:technician_tickets_pending_connections",
                },
                {
                    "index": "03",
                    "label": "Fault Tickets",
                    "hint": "Work repair and outage tickets assigned to you.",
                    "url_name": "roles:technician_fault_tickets",
                },
                {
                    "index": "04",
                    "label": "Network Equipment",
                    "hint": "Review gear, CPE, and field inventory for jobs.",
                    "url_name": "roles:technician_network_equipment",
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
                        f"({account_number}) under {org_name} as inactive. "
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
        1 for c in my_clients if c.status == Customer.Status.INACTIVE
    )
    active_count = sum(1 for c in my_clients if c.status == Customer.Status.ACTIVE)

    # Open pool: allocated-open, plus closed tickets with no assignee.
    # Closed assigned: only tickets for the technician in session.
    # Hide tickets this technician marked as not interested.
    tickets = list(
        Customer.objects.filter(
            Q(status=Customer.Status.ALLOCATED_OPEN)
            | Q(
                status=Customer.Status.ALLOCATED_CLOSED,
                assigned_technician__isnull=True,
            )
            | Q(
                status=Customer.Status.ALLOCATED_CLOSED,
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
                if t.status == Customer.Status.ALLOCATED_OPEN
                or (
                    t.status == Customer.Status.ALLOCATED_CLOSED
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
    if customer.status == Customer.Status.ALLOCATED_OPEN:
        return True
    return (
        customer.status == Customer.Status.ALLOCATED_CLOSED
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

        customer.status = Customer.Status.ALLOCATED_CLOSED
        customer.assigned_technician = employee
        customer.save(update_fields=["status", "assigned_technician"])
        InstallationDecline.objects.filter(
            customer=customer, technician=employee
        ).delete()

    messages.success(
        request,
        f"Accepted ticket {ticket}. ISP details are now visible.",
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
            customer.status = Customer.Status.ALLOCATED_OPEN
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

        customer.status = Customer.Status.ALLOCATED_OPEN
        customer.assigned_technician = None
        customer.save(update_fields=["status", "assigned_technician"])
        InstallationReject.objects.create(
            customer=customer,
            technician=employee,
            reason_category=category,
            reason=reason,
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
    """Open pending-connection tickets awaiting a technician."""
    return (
        Customer.objects.filter(
            status=Customer.Status.NEW,
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


@role_required(Employee.Role.TECHNICIAN)
def technician_tickets_pending_connections(request):
    """Pending-connection tickets: open pool + this technician's in-progress work."""
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    open_tickets = list(_pending_connection_pool_qs()[:200])
    in_progress_tickets = list(
        Customer.objects.filter(
            status=Customer.Status.IN_PROGRESS,
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
        .filter(status=Customer.Status.INACTIVE)
        .count()
    )
    connected_count = _technician_ticket_clients(employee, request.user).count()

    return render(
        request,
        "accounts/technician_tickets.html",
        {
            "page_title": "Pending connections",
            "page_kicker": "Field work",
            "page_subtitle": (
                "Receive a pending-connection ticket to take it in progress, "
                "then mark it done when the site visit is complete."
            ),
            "empty_text": (
                "No pending connection tickets yet. When sales or customer support "
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
            "employee_profile": employee,
        },
    )


@role_required(Employee.Role.TECHNICIAN)
@require_POST
def technician_ticket_receive(request, customer_id):
    """Receive a pending-connection ticket → In progress."""
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
        if customer.status == Customer.Status.IN_PROGRESS:
            if customer.assigned_technician_id == employee.pk:
                messages.info(
                    request, f"Ticket {ticket} is already in progress with you."
                )
            else:
                messages.error(
                    request,
                    f"Ticket {ticket} was already received by another technician.",
                )
            return redirect("roles:technician_tickets_pending_connections")

        if customer.status != Customer.Status.NEW:
            messages.error(
                request,
                f"Ticket {ticket} is not a pending connection ticket.",
            )
            return redirect("roles:technician_tickets_pending_connections")

        if (
            customer.assigned_technician_id
            and customer.assigned_technician_id != employee.pk
        ):
            messages.error(
                request,
                f"Ticket {ticket} was already received by another technician.",
            )
            return redirect("roles:technician_tickets_pending_connections")

        customer.status = Customer.Status.IN_PROGRESS
        customer.assigned_technician = employee
        customer.save(update_fields=["status", "assigned_technician"])

    messages.success(
        request,
        f"Received ticket {ticket}. Status is now In progress.",
    )
    return redirect("roles:technician_tickets_pending_connections")


@role_required(Employee.Role.TECHNICIAN)
@require_POST
def technician_ticket_mark_done(request, customer_id):
    """Mark an in-progress ticket done → Pending activation."""
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
        if customer.assigned_technician_id != employee.pk:
            messages.error(request, f"Ticket {ticket} is not assigned to you.")
            return redirect("roles:technician_tickets_pending_connections")

        if customer.status != Customer.Status.IN_PROGRESS:
            messages.error(
                request,
                f"Ticket {ticket} must be in progress before you can mark it done.",
            )
            return redirect("roles:technician_tickets_pending_connections")

        customer.status = Customer.Status.INACTIVE
        customer.save(update_fields=["status"])

    messages.success(
        request,
        f"Ticket {ticket} marked done — now pending activation.",
    )
    return redirect("roles:technician_tickets")


@role_required(Employee.Role.TECHNICIAN)
def technician_tickets(request):
    """Pending-activation clients for this technician."""
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    tickets = list(
        _technician_ticket_clients(employee, request.user).filter(
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.INACTIVE,
        )[:200]
    )
    connected_count = _technician_ticket_clients(employee, request.user).count()
    pending_connections_count = (
        _pending_connection_pool_qs().count()
        + Customer.objects.filter(
            status=Customer.Status.IN_PROGRESS,
            assigned_technician=employee,
            service_type=Customer.ServiceType.PPPOE,
        ).count()
    )

    return render(
        request,
        "accounts/technician_tickets.html",
        {
            "page_title": "Pending activation",
            "page_kicker": "Field work",
            "page_subtitle": (
                "Clients you connected that are waiting for ISP activation."
            ),
            "empty_text": (
                "No pending activation clients yet. Receive a pending connection "
                "ticket and mark it done, or register a PPPoE client from Installations."
            ),
            "current_page": "tickets",
            "dashboard_url_name": "roles:technician",
            "ticket_view": "pending",
            "tickets": tickets,
            "pending_count": len(tickets),
            "pending_connections_count": pending_connections_count,
            "connected_count": connected_count,
            "employee_profile": employee,
        },
    )


@role_required(Employee.Role.TECHNICIAN)
def technician_tickets_connected(request):
    """All tickets this technician has connected, with status."""
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    tickets = list(_technician_ticket_clients(employee, request.user)[:300])
    pending_count = sum(
        1 for t in tickets if t.status == Customer.Status.INACTIVE
    )
    active_count = sum(1 for t in tickets if t.status == Customer.Status.ACTIVE)
    pending_connections_count = (
        _pending_connection_pool_qs().count()
        + Customer.objects.filter(
            status=Customer.Status.IN_PROGRESS,
            assigned_technician=employee,
            service_type=Customer.ServiceType.PPPOE,
        ).count()
    )

    return render(
        request,
        "accounts/technician_tickets.html",
        {
            "page_title": "My connected tickets",
            "page_kicker": "Field work",
            "page_subtitle": (
                "Every client ticket you have connected, with current status."
            ),
            "empty_text": (
                "You have not connected any tickets yet. Receive a pending "
                "connection or register a PPPoE client to get started."
            ),
            "current_page": "tickets_connected",
            "dashboard_url_name": "roles:technician",
            "ticket_view": "connected",
            "tickets": tickets,
            "pending_count": pending_count,
            "pending_connections_count": pending_connections_count,
            "connected_count": len(tickets),
            "active_count": active_count,
            "employee_profile": employee,
        },
    )


@role_required(Employee.Role.TECHNICIAN)
def technician_fault_tickets(request):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    tickets = []
    return render(
        request,
        "accounts/technician_fault_tickets.html",
        {
            "page_title": "Fault Tickets",
            "page_kicker": "Field work",
            "page_subtitle": "Active and recent fault tickets for field resolution.",
            "empty_text": "When support assigns a repair or outage, it will show up here for you to work.",
            "current_page": "fault_tickets",
            "dashboard_url_name": "roles:technician",
            "tickets": tickets,
            "assigned_count": 0,
            "open_count": 0,
        },
    )


@role_required(Employee.Role.TECHNICIAN)
def technician_network_equipment(request):
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.TECHNICIAN)

    allocations = list(
        NetworkEquipmentAllocation.objects.filter(
            employee=employee,
            returned_at__isnull=True,
        )
        .select_related("equipment", "serial", "allocated_by")
        .order_by("-allocated_at")[:100]
    )
    serial_count = sum(1 for row in allocations if row.serial_id)
    catalog_count = NetworkEquipment.objects.filter(
        status=NetworkEquipment.Status.ACTIVE
    ).count()

    return render(
        request,
        "accounts/technician_network_equipment.html",
        {
            "page_title": "Network Equipment",
            "page_kicker": "Field work",
            "page_subtitle": "Gear assigned to you for installs and repairs.",
            "empty_text": "Nothing is checked out to you yet. When support allocates routers, ONUs, or other gear, it will appear here.",
            "current_page": "network_equipment",
            "dashboard_url_name": "roles:technician",
            "allocations": allocations,
            "assigned_count": len(allocations),
            "serial_count": serial_count,
            "catalog_count": catalog_count,
        },
    )
