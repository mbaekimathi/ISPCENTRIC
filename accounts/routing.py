"""Post-login routing by account type and employee role."""

from django.core.cache import cache
from django.urls import reverse

from accounts.models import Employee, Organization


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

# Pseudo-role for IT Support “view as client” (Organization workspace).
CLIENT_VIEW_VALUE = "client"
CLIENT_VIEW_LABEL = "Client"

SESSION_ROLE_VIEW = "role_view"
SESSION_CLIENT_VIEW = "client_view_org_id"

SWITCHABLE_CLIENTS_CACHE_KEY = "switchable_clients:v1"
SWITCHABLE_CLIENTS_TTL = 60


def nav_items_for_role(role: str, current_page: str | None = None) -> dict:
    """Dashboard at top, role links in the middle, Logout pinned to the bottom."""
    items = list(ROLE_NAV_ITEMS.get(role, []))
    if not any(item.get("key") == "dashboard" for item in items):
        dash = ROLE_DASHBOARD_NAMES.get(role)
        if dash:
            items.insert(0, {"key": "dashboard", "label": "Dashboard", "url_name": dash})
    if current_page == "dashboard":
        items.extend(ROLE_DASHBOARD_ONLY_NAV.get(role, []))
    return {
        "main": items,
        "end": [{"key": "logout", "label": "Logout", "action": "logout"}],
    }


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


def clear_client_view(request) -> None:
    request.session.pop(SESSION_CLIENT_VIEW, None)
    if hasattr(request, "_client_view_organization"):
        delattr(request, "_client_view_organization")
    if hasattr(request, "_client_view_org_resolved"):
        delattr(request, "_client_view_org_resolved")


def get_client_view_org_id(request, employee) -> int | None:
    if not can_switch_roles(employee):
        return None
    raw = request.session.get(SESSION_CLIENT_VIEW)
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def get_client_view_organization(request, employee):
    """Resolve the client-view org once per request."""
    if getattr(request, "_client_view_org_resolved", False):
        return getattr(request, "_client_view_organization", None)

    org_id = get_client_view_org_id(request, employee)
    org = Organization.objects.filter(pk=org_id).first() if org_id else None
    request._client_view_organization = org
    request._client_view_org_resolved = True
    return org


def is_viewing_as_client(request, employee) -> bool:
    return get_client_view_organization(request, employee) is not None


def set_client_view(request, organization_id: int) -> None:
    request.session[SESSION_CLIENT_VIEW] = int(organization_id)
    request.session.pop(SESSION_ROLE_VIEW, None)
    if hasattr(request, "_client_view_organization"):
        delattr(request, "_client_view_organization")
    if hasattr(request, "_client_view_org_resolved"):
        delattr(request, "_client_view_org_resolved")


def get_role_view(request, employee) -> str | None:
    """Active role view for IT Support (session), else the employee's own role."""
    if not can_switch_roles(employee):
        return employee.role if employee else None
    if is_viewing_as_client(request, employee):
        return CLIENT_VIEW_VALUE
    viewed = request.session.get(SESSION_ROLE_VIEW)
    if viewed in SWITCHABLE_ROLES:
        return viewed
    return employee.role


def set_role_view(request, role: str) -> None:
    if role in SWITCHABLE_ROLES:
        request.session[SESSION_ROLE_VIEW] = role
        clear_client_view(request)


def switchable_clients_list() -> list:
    """Cached org id/name pairs for the IT Support client switcher."""
    cached = cache.get(SWITCHABLE_CLIENTS_CACHE_KEY)
    if cached is not None:
        return cached
    clients = list(Organization.objects.order_by("name").values("id", "name"))
    cache.set(SWITCHABLE_CLIENTS_CACHE_KEY, clients, SWITCHABLE_CLIENTS_TTL)
    return clients


def invalidate_switchable_clients_cache() -> None:
    cache.delete(SWITCHABLE_CLIENTS_CACHE_KEY)


def switchable_role_options(request, employee, selected: str | None = None) -> list:
    """Options for the IT Support role-switch modal, including Client."""
    role_labels = dict(Employee.Role.choices)
    if selected is None:
        selected = get_role_view(request, employee) or (employee.role if employee else None)
    options = [
        {
            "value": r,
            "label": role_labels[r],
            "url_name": ROLE_DASHBOARD_NAMES[r],
            "slug": ROLE_SLUGS[r],
            "path": f"/{ROLE_SLUGS[r]}/dashboard/",
            "selected": r == selected,
            "needs_client": False,
        }
        for r in SWITCHABLE_ROLES
    ]
    options.append(
        {
            "value": CLIENT_VIEW_VALUE,
            "label": CLIENT_VIEW_LABEL,
            "url_name": "core:workspace",
            "slug": "app",
            "path": "/app/",
            "selected": selected == CLIENT_VIEW_VALUE,
            "needs_client": True,
        }
    )
    return options


def home_url_for_user(user, request=None) -> str:
    """Return the path a user should land on after login."""
    if not user.is_authenticated:
        return reverse("core:landing")

    employee = getattr(user, "employee_profile", None)
    if employee is not None:
        if not employee.can_access_workspace:
            return reverse("accounts:employee_pending")
        if request is not None and can_switch_roles(employee):
            if is_viewing_as_client(request, employee):
                return reverse("core:workspace")
            role = get_role_view(request, employee) or employee.role
        else:
            role = employee.role
        name = ROLE_DASHBOARD_NAMES.get(role)
        if name:
            return reverse(name)
        return reverse("accounts:employee_pending")

    return reverse("core:workspace")
