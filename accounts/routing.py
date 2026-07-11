"""Post-login routing by account type and employee role."""

from django.urls import reverse

from accounts.models import Employee


ROLE_DASHBOARD_NAMES = {
    Employee.Role.SUPER_ADMIN: "roles:super_admin",
    Employee.Role.ADMINISTRATOR: "roles:administrator",
    Employee.Role.MANAGER: "roles:manager",
    Employee.Role.IT_SUPPORT: "roles:it_support",
    Employee.Role.SALES: "roles:sales",
    Employee.Role.TECHNICIAN: "roles:technician",
}

ROLE_SLUGS = {
    Employee.Role.SUPER_ADMIN: "super-admin",
    Employee.Role.ADMINISTRATOR: "administrator",
    Employee.Role.MANAGER: "manager",
    Employee.Role.IT_SUPPORT: "it-support",
    Employee.Role.SALES: "sales",
    Employee.Role.TECHNICIAN: "technician",
}

# Base sidebar links for each role.
ROLE_NAV_ITEMS = {
    Employee.Role.SUPER_ADMIN: [
        {"key": "dashboard", "label": "Dashboard", "url_name": "roles:super_admin"},
    ],
    Employee.Role.ADMINISTRATOR: [
        {"key": "dashboard", "label": "Dashboard", "url_name": "roles:administrator"},
    ],
    Employee.Role.MANAGER: [
        {"key": "dashboard", "label": "Dashboard", "url_name": "roles:manager"},
    ],
    Employee.Role.IT_SUPPORT: [
        {"key": "dashboard", "label": "Dashboard", "url_name": "roles:it_support"},
    ],
    Employee.Role.SALES: [
        {"key": "dashboard", "label": "Dashboard", "url_name": "roles:sales"},
    ],
    Employee.Role.TECHNICIAN: [
        {"key": "dashboard", "label": "Dashboard", "url_name": "roles:technician"},
    ],
}

# Extra sidebar links shown only on that role's dashboard page.
ROLE_DASHBOARD_ONLY_NAV = {
    Employee.Role.SUPER_ADMIN: [
        {"key": "clients", "label": "Client management", "url_name": "roles:super_admin_clients"},
        {"key": "hr", "label": "Human resource", "url_name": "roles:super_admin_hr"},
    ],
    Employee.Role.ADMINISTRATOR: [
        {"key": "clients", "label": "Client management", "url_name": "roles:administrator_clients"},
        {"key": "hr", "label": "Human resource", "url_name": "roles:administrator_hr"},
    ],
}

SWITCHABLE_ROLES = [
    Employee.Role.SUPER_ADMIN,
    Employee.Role.ADMINISTRATOR,
    Employee.Role.MANAGER,
    Employee.Role.IT_SUPPORT,
    Employee.Role.SALES,
    Employee.Role.TECHNICIAN,
]

SESSION_ROLE_VIEW = "role_view"


def nav_items_for_role(role: str, current_page: str | None = None) -> list:
    """Sidebar links for a role. Dashboard-only extras appear on dashboard pages."""
    items = list(ROLE_NAV_ITEMS.get(role, []))
    if current_page == "dashboard":
        items.extend(ROLE_DASHBOARD_ONLY_NAV.get(role, []))
    return items


def page_key_from_path(path: str) -> str | None:
    path = (path or "").rstrip("/") + "/"
    if "/clients/" in path:
        return "clients"
    if "/human-resources/" in path:
        return "hr"
    if path.endswith("/dashboard/"):
        return "dashboard"
    if "/employee/profile/" in path:
        return "profile"
    return None


def can_switch_roles(employee) -> bool:
    return (
        employee is not None
        and employee.can_access_workspace
        and employee.role == Employee.Role.IT_SUPPORT
    )


def get_role_view(request, employee) -> str | None:
    """Active role view for IT Support (session), else the employee's own role."""
    if not can_switch_roles(employee):
        return employee.role if employee else None
    viewed = request.session.get(SESSION_ROLE_VIEW)
    if viewed in SWITCHABLE_ROLES:
        return viewed
    return employee.role


def set_role_view(request, role: str) -> None:
    if role in SWITCHABLE_ROLES:
        request.session[SESSION_ROLE_VIEW] = role


def home_url_for_user(user, request=None) -> str:
    """Return the path a user should land on after login."""
    if not user.is_authenticated:
        return reverse("core:landing")

    employee = getattr(user, "employee_profile", None)
    if employee is not None:
        if not employee.can_access_workspace:
            return reverse("accounts:employee_pending")
        role = employee.role
        if request is not None and can_switch_roles(employee):
            role = get_role_view(request, employee) or role
        name = ROLE_DASHBOARD_NAMES.get(role)
        if name:
            return reverse(name)
        return reverse("accounts:employee_pending")

    return reverse("core:workspace")
