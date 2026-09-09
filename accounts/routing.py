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
        {"key": "my_stock", "label": "My Stock", "url_name": "roles:super_admin_my_stock"},
    ],
    Employee.Role.ADMINISTRATOR: [
        {"key": "dashboard", "label": "Dashboard", "url_name": "roles:administrator"},
        {"key": "my_stock", "label": "My Stock", "url_name": "roles:administrator_my_stock"},
    ],
    Employee.Role.MANAGER: [
        {"key": "dashboard", "label": "Dashboard", "url_name": "roles:customer_support"},
        {"key": "my_stock", "label": "My Stock", "url_name": "roles:customer_support_my_stock"},
    ],
    Employee.Role.IT_SUPPORT: [
        {"key": "dashboard", "label": "Dashboard", "url_name": "roles:it_support"},
        {"key": "my_stock", "label": "My Stock", "url_name": "roles:it_support_my_stock"},
    ],
    Employee.Role.SALES: [
        {"key": "dashboard", "label": "Dashboard", "url_name": "roles:sales"},
        {"key": "my_stock", "label": "My Stock", "url_name": "roles:sales_my_stock"},
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
        {"key": "technician", "label": "Technician", "url_name": "roles:customer_support_technician"},
        {
            "key": "stock_audit",
            "label": "Stock Audit",
            "url_name": "roles:customer_support_network_equipment",
        },
    ],
    Employee.Role.IT_SUPPORT: [
        {
            "key": "company_clients",
            "label": "Company clients",
            "url_name": "roles:it_support_company_clients",
        },
        {
            "key": "company_communications",
            "label": "Company communications",
            "url_name": "roles:it_support_communications",
        },
        {"key": "hr", "label": "Human resource", "url_name": "roles:it_support_hr"},
    ],
    Employee.Role.SALES: [
        {
            "key": "lead_management",
            "label": "Leads & registration",
            "url_name": "roles:sales_lead_management",
        },
        {
            "key": "sales_orders",
            "label": "Sales Orders",
            "url_name": "roles:sales_orders",
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
            "key": "tickets",
            "label": "Tickets",
            "url_name": "roles:technician_tickets_hub",
        },
    ],
}

# Tickets section links (queued → installed → connected → faults).
TECHNICIAN_TICKETS_NAV = [
    {
        "key": "tickets_pending_connections",
        "label": "Queued for install",
        "url_name": "roles:technician_tickets_pending_connections",
    },
    {
        "key": "tickets",
        "label": "Installed",
        "url_name": "roles:technician_tickets",
    },
    {
        "key": "tickets_connected",
        "label": "Activated",
        "url_name": "roles:technician_tickets_connected",
    },
    {
        "key": "fault_tickets",
        "label": "Fault Tickets",
        "url_name": "roles:technician_fault_tickets",
    },
]

TECHNICIAN_REGISTER_PPPOE_NAV = {
    "key": "register_pppoe",
    "label": "Register PPPoE",
    "action": "open_modal",
    "modal_id": "pppoe-register-modal",
}

# Module links for /it-support/company-system-settings/ only (not child pages).
IT_SUPPORT_COMPANY_SYSTEM_SETTINGS_NAV = [
    {
        "key": "company_profile",
        "label": "Company profile",
        "url_name": "roles:it_support_company_profile",
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
        "key": "isp_onboarding_settings",
        "label": "ISP onboarding settings",
        "url_name": "roles:it_support_isp_onboarding_settings",
    },
    {
        "key": "google_login_settings",
        "label": "Google login settings",
        "url_name": "roles:it_support_google_login_settings",
    },
    {
        "key": "company_themes",
        "label": "Company themes",
        "url_name": "roles:it_support_company_themes",
    },
]

# Links pinned above the Signed in block (bottom of sidebar, above logout).
ROLE_NAV_BEFORE_META = {
    Employee.Role.IT_SUPPORT: [
        {
            "key": "company_account_communications",
            "label": "Communications",
            "url_name": "roles:it_support_communications",
        },
        {
            "key": "company_system_settings",
            "label": "Company System Settings",
            "url_name": "roles:it_support_company_system_settings",
        },
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


# Customer support sales section links (shown on Sales and related pages only).
CUSTOMER_SUPPORT_SALES_NAV = [
    {"key": "sales", "label": "Sales", "url_name": "roles:customer_support_sales"},
    {
        "key": "technician",
        "label": "Technician",
        "url_name": "roles:customer_support_technician",
    },
]

# Installed (approved-sales URL) is only shown on the Sales page (and itself).
CUSTOMER_SUPPORT_APPROVED_SALES_NAV = {
    "key": "approved_sales",
    "label": "Installed",
    "url_name": "roles:customer_support_approved_sales",
}

CUSTOMER_SUPPORT_SALES_PAGES = frozenset(
    {item["key"] for item in CUSTOMER_SUPPORT_SALES_NAV} | {"approved_sales"}
)

# Customer support equipment section links.
CUSTOMER_SUPPORT_EQUIPMENT_NAV = [
    {
        "key": "stock_audit",
        "label": "Stock Audit",
        "url_name": "roles:customer_support_network_equipment",
    },
]

CUSTOMER_SUPPORT_EQUIPMENT_PAGES = frozenset(
    {
        "stock_audit",
        "network_equipment",
        "register_equipment",
        "allocate",
    }
)

# Customer support technician page: raise fault tickets from the sidebar (desktop).
CUSTOMER_SUPPORT_TECHNICIAN_NAV = [
    {
        "key": "raise_fault_ticket",
        "label": "Fault tickets",
        "action": "open_modal",
        "modal_id": "fault-ticket-modal",
    },
]

IT_SUPPORT_REGISTER_ISP_NAV = {
    "key": "register_isp",
    "label": "Register ISP client",
    "action": "open_modal",
    "modal_id": "cc-register-isp-modal",
}


def nav_items_for_role(role: str, current_page: str | None = None) -> dict:
    """Dashboard at top, page-only module links on the dashboard, Logout at the bottom.

    Module links in ROLE_DASHBOARD_ONLY_NAV appear only on the dashboard page.
    They do not follow you onto other pages unless added to that page's nav.
    Company System Settings module links appear only on that hub page.
    """
    items = list(ROLE_NAV_ITEMS.get(role, []))
    if not any(item.get("key") == "dashboard" for item in items):
        dash = ROLE_DASHBOARD_NAMES.get(role)
        if dash:
            items.insert(0, {"key": "dashboard", "label": "Dashboard", "url_name": dash})
    if current_page == "dashboard":
        items.extend(ROLE_DASHBOARD_ONLY_NAV.get(role, []))
    elif role == Employee.Role.TECHNICIAN and current_page in {
        "tickets",
        "tickets_hub",
        "tickets_connected",
        "tickets_pending_connections",
        "fault_tickets",
    }:
        items.extend(TECHNICIAN_TICKETS_NAV)
        if current_page == "tickets_hub":
            items.append(TECHNICIAN_REGISTER_PPPOE_NAV)
    elif role == Employee.Role.MANAGER and current_page in {
        "sales",
        "approved_sales",
    }:
        sales_nav = list(CUSTOMER_SUPPORT_SALES_NAV)
        sales_nav.insert(1, CUSTOMER_SUPPORT_APPROVED_SALES_NAV)
        items.extend(sales_nav)
    elif role == Employee.Role.MANAGER and current_page == "technician":
        items.extend(CUSTOMER_SUPPORT_TECHNICIAN_NAV)
    elif role == Employee.Role.MANAGER and current_page in CUSTOMER_SUPPORT_EQUIPMENT_PAGES:
        items.extend(CUSTOMER_SUPPORT_EQUIPMENT_NAV)
    elif role == Employee.Role.IT_SUPPORT and current_page == "company_clients":
        items.extend(
            [
                {
                    "key": "company_clients",
                    "label": "Company clients",
                    "url_name": "roles:it_support_company_clients",
                },
                IT_SUPPORT_REGISTER_ISP_NAV,
            ]
        )
    elif role == Employee.Role.IT_SUPPORT and current_page == "company_system_settings":
        items.extend(IT_SUPPORT_COMPANY_SYSTEM_SETTINGS_NAV)
    elif role == Employee.Role.IT_SUPPORT and current_page == "payment_gateway":
        items = [item for item in items if item.get("key") != "my_stock"]
    elif role == Employee.Role.IT_SUPPORT and current_page == "isp_onboarding_settings":
        items = [item for item in items if item.get("key") != "my_stock"]
    elif role == Employee.Role.IT_SUPPORT and current_page == "google_login_settings":
        items = [item for item in items if item.get("key") != "my_stock"]
    elif role == Employee.Role.IT_SUPPORT and current_page == "company_profile":
        items = [item for item in items if item.get("key") != "my_stock"]
    elif role == Employee.Role.IT_SUPPORT and current_page == "company_themes":
        items = [item for item in items if item.get("key") != "my_stock"]
    elif role == Employee.Role.IT_SUPPORT and current_page == "company_communications":
        items = [item for item in items if item.get("key") != "my_stock"]
        items.append(
            {
                "key": "company_account_communications",
                "label": "Communications",
                "url_name": "roles:it_support_communications",
            }
        )
    elif role == Employee.Role.IT_SUPPORT and current_page == "company_account_communications":
        items = [item for item in items if item.get("key") != "my_stock"]
    before_meta = list(ROLE_NAV_BEFORE_META.get(role, []))
    if role == Employee.Role.IT_SUPPORT and current_page == "company_communications":
        # Shown in main nav on this page; avoid a duplicate above Signed in.
        before_meta = [
            item
            for item in before_meta
            if item.get("key") != "company_account_communications"
        ]
    return {
        "main": items,
        "before_meta": before_meta,
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
    if path.endswith("/it-support/communications/") or "/it-support/communications/" in path:
        return "company_account_communications"
    if "/company-profile/" in path:
        return "company_profile"
    if "/company-settings/" in path:
        # Legacy company-settings URL redirects to company profile.
        return "company_profile"
    if "/isp-onboarding-settings/" in path or "/client-settings/" in path:
        return "isp_onboarding_settings"
    if "/company-payment-links/" in path:
        return "company_payment_links"
    if "/company-themes/" in path:
        return "company_themes"
    if "/company-system-settings/communications/" in path or "/system-settings/communications/" in path:
        return "communications"
    if "/company-system-settings/payments/" in path or "/system-settings/payments/" in path:
        return "payment_gateway"
    if "/company-system-settings/" in path or "/system-settings/" in path:
        return "company_system_settings"
    if "/installations/" in path:
        return "installations"
    if "/tickets/connected/" in path:
        return "tickets_connected"
    if "/tickets/pending-connections/" in path:
        return "tickets_pending_connections"
    if "/tickets/installed/" in path:
        return "tickets"
    if "/tickets/" in path:
        return "tickets_hub"
    if "/fault-tickets/" in path:
        return "fault_tickets"
    if "/my-stock/" in path:
        return "my_stock"
    if "/network-equipment/" in path:
        return "stock_audit"
    if "/customer-support/allocate/" in path or "/manager/allocate/" in path:
        return "stock_audit"
    if "/lead-management/" in path or "/customer-registration/" in path:
        return "lead_management"
    if "/sales-orders/" in path:
        return "sales_orders"
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
