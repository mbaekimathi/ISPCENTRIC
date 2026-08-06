from functools import wraps
import json

from django.db import transaction
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from accounts.forms import (
    EmployeeAdminEditForm,
    LeadRegisterForm,
    NATIONAL_PHONE_LENGTHS,
    NetworkEquipmentRegisterForm,
    OrganizationEditForm,
    ClientSettingsForm,
    CompanyProfileForm,
    PaymentGatewayForm,
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
from billing.models import Customer, InstallationDecline, InstallationReject


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
                    "url_name": "roles:customer_support_isp_clients",
                },
                {
                    "index": "02",
                    "label": "Sales",
                    "url_name": "roles:customer_support_sales",
                },
                {
                    "index": "03",
                    "label": "Approved sales",
                    "url_name": "roles:customer_support_approved_sales",
                },
                {
                    "index": "04",
                    "label": "Technician",
                    "url_name": "roles:customer_support_technician",
                },
                {
                    "index": "05",
                    "label": "Allocated",
                    "url_name": "roles:customer_support_allocated",
                },
                {
                    "index": "06",
                    "label": "Network equipment",
                    "url_name": "roles:customer_support_network_equipment",
                },
                {
                    "index": "07",
                    "label": "Allocate",
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
    return render(
        request,
        "accounts/customer_support_isp_clients.html",
        {
            "page_title": "ISP clients",
            "page_kicker": "Clients",
            "page_subtitle": "ISP company accounts registered on ISPCENTRIC.",
            "current_page": "isp_clients",
            "dashboard_url_name": "roles:customer_support",
            "clients": clients,
            "clients_count": len(clients),
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
    _prepare_manager_view(request)
    sales = list(
        Customer.objects.filter(
            status=Customer.Status.NEW,
            organization__isnull=True,
        )
        .select_related("plan", "registered_by")
        .order_by("-created_at")[:300]
    )
    return render(
        request,
        "accounts/customer_support_sales.html",
        {
            "page_title": "Sales",
            "page_kicker": "Operations",
            "page_subtitle": "All new sales tickets waiting for ISP allocation.",
            "current_page": "sales",
            "dashboard_url_name": "roles:customer_support",
            "sales": sales,
            "empty_text": "No new sales tickets are open yet.",
        },
    )


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


@role_required(Employee.Role.IT_SUPPORT)
def it_support_hr(request):
    _prepare_it_support_view(request)

    employees = list(
        Employee.objects.select_related("user", "organization")
        .order_by("-created_at")
    )
    return render(
        request,
        "accounts/it_support_hr.html",
        _it_support_hr_context(
            employees=employees,
            employees_count=len(employees),
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
            "page_title": "Payment Gateway",
            "page_kicker": "Integrations",
            "current_page": "payment_gateway",
            "dashboard_url_name": "roles:it_support",
            "form": form,
            "gateway": gateway,
            "sandbox_base_url": PaymentGateway.sandbox_base_url(),
            "sandbox_callback_url": PaymentGateway.default_callback_url(
                PaymentGateway.Environment.SANDBOX
            ),
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
def it_support_company_settings(request):
    _prepare_it_support_view(request)
    profile = CompanyProfile.get_solo()

    if request.method == "POST":
        form = CompanyProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, "Company profile saved.")
            return redirect("roles:it_support_company_settings")
    else:
        form = CompanyProfileForm(instance=profile)

    return render(
        request,
        "accounts/it_support_company_settings.html",
        {
            "page_title": "Company settings",
            "page_kicker": "Company",
            "page_subtitle": "Update the platform app name, contact details, and logo.",
            "current_page": "company_settings",
            "dashboard_url_name": "roles:it_support",
            "form": form,
            "company_profile": profile,
        },
    )


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
def it_support_system_settings(request):
    return _it_support_settings_page(
        request,
        current_page="system_settings",
        page_title="Company settings",
        page_kicker="Settings",
        page_subtitle="Organization and workspace preferences for the platform.",
        empty_text="Additional company preferences are coming soon. Use Client settings for landing and onboarding controls.",
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_settings_communications(request):
    return _it_support_settings_page(
        request,
        current_page="communications",
        page_title="Communications link",
        page_kicker="Settings",
        page_subtitle="Share and manage the links clients use to reach support channels.",
        empty_text="Communications link settings are coming soon.",
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_settings_payments(request):
    return _it_support_settings_page(
        request,
        current_page="payments_links",
        page_title="Payments links",
        page_kicker="Settings",
        page_subtitle="Payment portal and collection links for clients.",
        empty_text="Payments links settings are coming soon.",
    )


@role_required(Employee.Role.IT_SUPPORT)
def it_support_client_settings(request):
    _prepare_it_support_view(request)
    settings_obj = ClientSettings.get_solo()

    if request.method == "POST":
        form = ClientSettingsForm(request.POST, instance=settings_obj)
        if form.is_valid():
            form.save()
            messages.success(request, "Client settings saved.")
            return redirect("roles:it_support_client_settings")
    else:
        form = ClientSettingsForm(instance=settings_obj)

    return render(
        request,
        "accounts/it_support_client_settings.html",
        {
            "page_title": "Client settings",
            "page_kicker": "Settings",
            "page_subtitle": (
                "Control landing-page Register, MikroTik onboarding fees, and referrals."
            ),
            "current_page": "client_settings",
            "dashboard_url_name": "roles:it_support",
            "form": form,
            "client_settings": settings_obj,
        },
    )


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
                    "label": "Lead Management",
                    "url_name": "roles:sales_lead_management",
                },
                {
                    "index": "02",
                    "label": "Customer Registration",
                    "url_name": "roles:sales_customer_registration",
                },
                {
                    "index": "03",
                    "label": "Sales Orders",
                    "url_name": "roles:sales_orders",
                },
                {
                    "index": "04",
                    "label": "Installation Requests",
                    "url_name": "roles:sales_installation_requests",
                },
                {
                    "index": "05",
                    "label": "Promotions & Discounts",
                    "url_name": "roles:sales_promotions_discounts",
                },
                {
                    "index": "06",
                    "label": "Commissions",
                    "url_name": "roles:sales_commissions",
                },
                {
                    "index": "07",
                    "label": "Reports",
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
    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.SALES)

    # Sales may be platform-level (no organization) and still register leads
    # against any ISP via preferred_isp.
    organization = employee.organization

    from billing.models import BillingPlan

    open_register_modal = False
    if request.method == "POST":
        form = LeadRegisterForm(request.POST, organization=organization)
        if form.is_valid():
            lead = form.save(created_by=request.user)
            messages.success(
                request,
                f"Lead {lead.lead_number} registered for {lead.full_name}.",
            )
            return redirect("roles:sales_lead_management")
        open_register_modal = True
    else:
        form = LeadRegisterForm(organization=organization)

    lead_qs = Lead.objects.select_related(
        "preferred_package",
        "preferred_isp",
        "organization",
        "created_by",
    ).filter(created_by=request.user)
    leads = lead_qs.order_by("-created_at")[:100]
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
        "accounts/sales_lead_management.html",
        {
            "page_title": "Lead Management",
            "page_kicker": "Sales",
            "page_subtitle": "Register and track sales leads.",
            "current_page": "lead_management",
            "dashboard_url_name": "roles:sales",
            "form": form,
            "leads": leads,
            "open_register_modal": open_register_modal,
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
    from django.db import transaction

    from billing.forms import SalesClientRegisterForm
    from billing.models import Customer

    employee = request.user.employee_profile
    if can_switch_roles(employee):
        set_role_view(request, Employee.Role.SALES)

    # Sales staff may be platform-level (no organization) and still register
    # personal clients against any ISP, or create new ISP / business accounts.
    organization = employee.organization
    organizations = Organization.objects.order_by("name")

    selected_type = ""
    open_register_modal = False
    client_form = SalesClientRegisterForm(
        organization=organization,
        organizations=organizations,
        prefix="client",
    )
    isp_form = RegisterForm(prefix="isp", require_invite=False)

    if request.method == "POST":
        selected_type = (request.POST.get("registration_type") or "").strip()
        open_register_modal = True
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
                return redirect("roles:sales_customer_registration")
        elif selected_type == "isp":
            isp_form = RegisterForm(
                request.POST, request.FILES, prefix="isp", require_invite=False
            )
            if isp_form.is_valid():
                with transaction.atomic():
                    user = isp_form.save(commit=False)
                    user.email = isp_form.cleaned_data["email"]
                    user.save()
                    org = Organization.objects.create(
                        name=isp_form.cleaned_data["company_name"],
                        owner=user,
                        phone=isp_form.cleaned_data.get("phone", ""),
                        profile_photo=isp_form.cleaned_data.get("profile_photo"),
                        status=Organization.Status.REGISTERED,
                        registered_by=request.user,
                    )
                messages.success(
                    request,
                    (
                        f"Business (ISP) “{org.name}” registered. "
                        f"Owner login: {user.username}."
                    ),
                )
                return redirect("roles:sales_customer_registration")
        else:
            messages.error(
                request,
                "Choose what to register: PPPoE client or business (ISP).",
            )

    client_qs = Customer.objects.select_related("organization").filter(
        registered_by=request.user
    )
    recent_clients = client_qs.order_by("-created_at")[:20]
    recent_isps = (
        organizations.filter(registered_by=request.user)
        .select_related("owner")
        .order_by("-created_at")[:20]
    )

    return render(
        request,
        "accounts/sales_customer_registration.html",
        {
            "page_title": "Customer Registration",
            "page_kicker": "Sales",
            "page_subtitle": "Register a PPPoE client, or create a business (ISP) account.",
            "current_page": "customer_registration",
            "dashboard_url_name": "roles:sales",
            "selected_type": selected_type,
            "open_register_modal": open_register_modal,
            "client_form": client_form,
            "isp_form": isp_form,
            "recent_clients": recent_clients,
            "recent_isps": recent_isps,
            "employee_organization": organization,
            "phone_lengths_json": json.dumps(NATIONAL_PHONE_LENGTHS),
        },
    )


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
def sales_installation_requests(request):
    return _sales_module_page(
        request,
        current_page="installation_requests",
        page_title="Installation Requests",
        page_kicker="Sales",
        page_subtitle="Submit and track installation requests for new customers.",
        empty_text="No installation requests yet.",
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
                    "url_name": "roles:technician_installations",
                },
                {
                    "index": "02",
                    "label": "Fault Tickets",
                    "url_name": "roles:technician_fault_tickets",
                },
                {
                    "index": "03",
                    "label": "Network Equipment",
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
        .select_related(
            "organization",
            "plan",
            "assigned_technician",
            "assigned_technician__user",
        )
        .distinct()
        .order_by("-created_at")[:200]
    )

    return render(
        request,
        "accounts/technician_installations.html",
        {
            "page_title": "New Customer Installation",
            "page_kicker": "Field work",
            "page_subtitle": (
                "Open technician requests and tickets assigned to you."
            ),
            "empty_text": "No open or assigned installation tickets yet.",
            "current_page": "installations",
            "dashboard_url_name": "roles:technician",
            "tickets": tickets,
            "employee_profile": employee,
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


@role_required(Employee.Role.TECHNICIAN)
def technician_fault_tickets(request):
    return _technician_module_page(
        request,
        current_page="fault_tickets",
        page_title="Fault Tickets",
        page_kicker="Field work",
        page_subtitle="Active and recent fault tickets for field resolution.",
        empty_text="No fault tickets are open yet.",
    )


@role_required(Employee.Role.TECHNICIAN)
def technician_network_equipment(request):
    return _technician_module_page(
        request,
        current_page="network_equipment",
        page_title="Network Equipment",
        page_kicker="Field work",
        page_subtitle="Network equipment used for installs and repairs.",
        empty_text="No network equipment records yet.",
    )
