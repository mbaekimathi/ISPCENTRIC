from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from accounts.forms import EmployeeAdminEditForm, OrganizationEditForm
from accounts.models import Employee, Organization
from accounts.routing import (
    CLIENT_VIEW_VALUE,
    ROLE_DASHBOARD_NAMES,
    ROLE_SLUGS,
    SWITCHABLE_ROLES,
    can_switch_roles,
    home_url_for_user,
    set_client_view,
    set_role_view,
    switchable_clients_list,
    switchable_role_options,
)


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
        "title": "Manager Dashboard",
        "subtitle": "Team performance and daily operations.",
        "url_name": "roles:manager",
        "highlights": [
            "Track team targets",
            "Review customer accounts",
            "Coordinate field and sales work",
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
        messages.success(request, f"Now viewing as client {org.name}.")
        return redirect("core:workspace")

    if role not in SWITCHABLE_ROLES:
        messages.error(request, "Choose a valid role to view.")
        return redirect(home_url_for_user(request.user, request))

    set_role_view(request, role)
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

    clients = (
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
            clients_count=clients.count(),
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

    employees = (
        Employee.objects.select_related("user", "organization")
        .order_by("-created_at")
    )
    return render(
        request,
        "accounts/super_admin_hr.html",
        _super_admin_hr_context(
            employees=employees,
            employees_count=employees.count(),
        ),
    )


def _super_admin_hr_context(**extra):
    return {
        "page_title": "Human resource management",
        "page_kicker": "People",
        "current_page": "hr",
        "dashboard_url_name": "roles:super_admin",
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
        "accounts/super_admin_hr_edit.html",
        _super_admin_hr_context(
            page_title="Edit employee",
            member=member,
            form=form,
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
        "accounts/super_admin_hr_delete.html",
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
    return _role_dashboard(request, Employee.Role.MANAGER)


@role_required(Employee.Role.IT_SUPPORT)
def it_support_dashboard(request):
    return _role_dashboard(request, Employee.Role.IT_SUPPORT)


@role_required(Employee.Role.SALES)
def sales_dashboard(request):
    return _role_dashboard(request, Employee.Role.SALES)


@role_required(Employee.Role.TECHNICIAN)
def technician_dashboard(request):
    return _role_dashboard(request, Employee.Role.TECHNICIAN)
