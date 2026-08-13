"""Post-login routing by account type and employee role."""

from django.core.cache import cache
from django.urls import reverse

from accounts.models import Employee, Organization


ROLE_DASHBOARD_NAMES = {
    Employee.Role.SUPER_ADMIN: "roles:super_admin",
    Employee.Role.ADMINISTRATOR: "roles:administrator",
    Employee.Role.MANAGER: "roles:customer_support",
    Employee.Role.IT_SUPPORT: "roles:it_support",
    Employee.Role.SALES: "roles:sales",
    Employee.Role.TECHNICIAN: "roles:technician",
}

ROLE_SLUGS = {
    Employee.Role.SUPER_ADMIN: "super-admin",
    Employee.Role.ADMINISTRATOR: "administrator",
    Employee.Role.MANAGER: "customer-support",
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
        {"key": "dashboard", "label": "Dashboard", "url_name": "roles:customer_support"},
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
    Employee.Role.MANAGER: [
        {"key": "isp_clients", "label": "ISP clients", "url_name": "roles:customer_support_isp_clients"},
        {"key": "sales", "label": "Sales", "url_name": "roles:customer_support_sales"},
        {
            "key": "approved_sales",
            "label": "Approved sales",
            "url_name": "roles:customer_support_approved_sales",
        },
        {"key": "technician", "label": "Technician", "url_name": "roles:customer_support_technician"},
        {"key": "allocated", "label": "Allocated", "url_name": "roles:customer_support_allocated"},
        {
            "key": "network_equipment",
            "label": "Network equipment",
            "url_name": "roles:customer_support_network_equipment",
        },
        {
            "key": "allocate",
            "label": "Allocate",
            "url_name": "roles:customer_support_allocate",
        },
    ],
    Employee.Role.IT_SUPPORT: [
        {
            "key": "company_clients",
            "label": "Company clients",
            "url_name": "roles:it_support_company_clients",
        },
        {"key": "hr", "label": "Human resource", "url_name": "roles:it_support_hr"},
        {
            "key": "company_settings",
            "label": "Company settings",
            "url_name": "roles:it_support_company_settings",
        },
        {
            "key": "system_settings",
            "label": "System settings",
            "url_name": "roles:it_support_system_settings",
        },
    ],
    Employee.Role.SALES: [
        {
            "key": "lead_management",
            "label": "Lead Management",
            "url_name": "roles:sales_lead_management",
        },
        {
            "key": "customer_registration",
            "label": "Customer Registration",
            "url_name": "roles:sales_customer_registration",
        },
        {
            "key": "sales_orders",
            "label": "Sales Orders",
            "url_name": "roles:sales_orders",
        },
        {
            "key": "installation_requests",
            "label": "Installation Requests",
            "url_name": "roles:sales_installation_requests",
        },
        {
            "key": "promotions_discounts",
            "label": "Promotions & Discounts",
            "url_name": "roles:sales_promotions_discounts",
        },
        {
            "key": "commissions",
            "label": "Commissions",
            "url_name": "roles:sales_commissions",
        },
        {
            "key": "reports",
            "label": "Reports",
            "url_name": "roles:sales_reports",
        },
    ],
    Employee.Role.TECHNICIAN: [
        {
            "key": "installations",
            "label": "New Customer Installation",
            "url_name": "roles:technician_installations",
        },
        {
            "key": "fault_tickets",
            "label": "Fault Tickets",
            "url_name": "roles:technician_fault_tickets",
        },
        {
            "key": "network_equipment",
            "label": "Network Equipment",
            "url_name": "roles:technician_network_equipment",
        },
    ],
}

# Sidebar links shown while inside IT Support company settings and related pages.
# These are rendered only by those page templates (not the dashboard nav).
IT_SUPPORT_COMPANY_SETTINGS_NAV = [
    {
        "key": "company_settings",
        "label": "Company settings",
        "url_name": "roles:it_support_company_settings",
    },
    {
        "key": "company_communications",
        "label": "Company communications settings",
        "url_name": "roles:it_support_company_communications",
    },
    {
        "key": "payment_gateway",
        "label": "Company Payment Gateway",
        "url_name": "roles:it_support_payment_gateway",
    },
    {
        "key": "commissions",
        "label": "Commissions",
        "url_name": "roles:it_support_commissions",
    },
]

IT_SUPPORT_COMPANY_SETTINGS_PAGES = frozenset(
    item["key"] for item in IT_SUPPORT_COMPANY_SETTINGS_NAV
)

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


# Customer support sales section links (shown on Sales / Approved sales pages).
CUSTOMER_SUPPORT_SALES_NAV = [
    {"key": "sales", "label": "Sales", "url_name": "roles:customer_support_sales"},
    {
        "key": "approved_sales",
        "label": "Approved sales",
        "url_name": "roles:customer_support_approved_sales",
    },
]

# Customer support equipment section links.
CUSTOMER_SUPPORT_EQUIPMENT_NAV = [
    {
        "key": "network_equipment",
        "label": "Network equipment",
        "url_name": "roles:customer_support_network_equipment",
    },
    {
        "key": "allocate",
        "label": "Allocate",
        "url_name": "roles:customer_support_allocate",
    },
]

CUSTOMER_SUPPORT_REGISTER_EQUIPMENT_NAV = {
    "key": "register_equipment",
    "label": "Register equipment",
    "url_name": "roles:customer_support_network_equipment",
    "query": "register=1",
}


def nav_items_for_role(role: str, current_page: str | None = None) -> dict:
    """Dashboard at top, page-only module links on the dashboard, Logout at the bottom.

    Module links in ROLE_DASHBOARD_ONLY_NAV appear only on the dashboard page.
    They do not follow you onto other pages unless added to that page's nav.
    Company settings sub-links (Payment Gateway, Commissions) are template-only.
    """
    items = list(ROLE_NAV_ITEMS.get(role, []))
    if not any(item.get("key") == "dashboard" for item in items):
        dash = ROLE_DASHBOARD_NAMES.get(role)
        if dash:
            items.insert(0, {"key": "dashboard", "label": "Dashboard", "url_name": dash})
    if current_page == "dashboard":
        items.extend(ROLE_DASHBOARD_ONLY_NAV.get(role, []))
    elif role == Employee.Role.MANAGER and current_page in {
        "sales",
        "approved_sales",
    }:
        items.extend(CUSTOMER_SUPPORT_SALES_NAV)
    elif role == Employee.Role.MANAGER and current_page in {
        "network_equipment",
        "register_equipment",
        "allocate",
    }:
        equipment_nav = list(CUSTOMER_SUPPORT_EQUIPMENT_NAV)
        # Register equipment is only shown on the network equipment page.
        if current_page in {"network_equipment", "register_equipment"}:
            equipment_nav.insert(1, CUSTOMER_SUPPORT_REGISTER_EQUIPMENT_NAV)
        items.extend(equipment_nav)
    return {
        "main": items,
        "end": [{"key": "logout", "label": "Logout", "action": "logout"}],
    }


def page_key_from_path(path: str) -> str | None:
    path = (path or "").rstrip("/") + "/"
    if "/company-clients/" in path:
        return "company_clients"
    if "/isp-clients/" in path:
        return "isp_clients"
    if "/clients/" in path:
        return "clients"
    if "/human-resources/" in path:
        return "hr"
    if "/payment-gateway/" in path:
        return "payment_gateway"
    if "/company-settings/communications/" in path:
        return "company_communications"
    if "/company-settings/" in path:
        return "company_settings"
    if "/client-settings/" in path:
        return "client_settings"
    if "/system-settings/communications/" in path:
        return "communications"
    if "/system-settings/payments/" in path:
        return "payments_links"
    if "/system-settings/" in path:
        return "system_settings"
    if "/installations/" in path:
        return "installations"
    if "/fault-tickets/" in path:
        return "fault_tickets"
    if "/network-equipment/" in path:
        return "network_equipment"
    if "/customer-support/allocate/" in path or "/manager/allocate/" in path:
        return "allocate"
    if "/lead-management/" in path:
        return "lead_management"
    if "/customer-registration/" in path:
        return "customer_registration"
    if "/sales-orders/" in path:
        return "sales_orders"
    if "/installation-requests/" in path:
        return "installation_requests"
    if "/promotions-discounts/" in path:
        return "promotions_discounts"
    if "/commissions/" in path:
        return "commissions"
    if "/reports/" in path:
        return "reports"
    if "/customer-support/approved-sales/" in path or "/manager/approved-sales/" in path:
        return "approved_sales"
    if "/customer-support/sales/" in path or "/manager/sales/" in path:
        return "sales"
    if "/customer-support/allocated/" in path or "/manager/allocated/" in path:
        return "allocated"
    if "/customer-support/technician/" in path or "/manager/technician/" in path:
        return "technician"
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


def can_access_client_portal(employee) -> bool:
    """IT Support and Customer support can open an ISP client workspace."""
    return (
        employee is not None
        and employee.can_access_workspace
        and employee.role
        in {
            Employee.Role.IT_SUPPORT,
            Employee.Role.MANAGER,
        }
    )


def clear_client_view(request) -> None:
    request.session.pop(SESSION_CLIENT_VIEW, None)
    if hasattr(request, "_client_view_organization"):
        delattr(request, "_client_view_organization")
    if hasattr(request, "_client_view_org_resolved"):
        delattr(request, "_client_view_org_resolved")


def get_client_view_org_id(request, employee) -> int | None:
    if not can_access_client_portal(employee):
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
        if request is not None and can_access_client_portal(employee):
            if is_viewing_as_client(request, employee):
                return reverse("core:workspace")
            if can_switch_roles(employee):
                role = get_role_view(request, employee) or employee.role
            else:
                role = employee.role
        else:
            role = employee.role
        name = ROLE_DASHBOARD_NAMES.get(role)
        if name:
            return reverse(name)
        return reverse("accounts:employee_pending")

    return reverse("core:workspace")
