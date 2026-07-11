"""Template context for staff workspace chrome (header role dropdown)."""

from accounts.models import Employee
from accounts.routing import (
    CLIENT_VIEW_LABEL,
    ROLE_DASHBOARD_NAMES,
    ROLE_SLUGS,
    can_switch_roles,
    get_client_view_organization,
    get_role_view,
    is_viewing_as_client,
    nav_items_for_role,
    page_key_from_path,
    switchable_clients_list,
    switchable_role_options,
)


def staff_workspace(request):
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return {}

    employee = getattr(user, "employee_profile", None)
    if employee is None or not employee.can_access_workspace:
        return {}

    role_labels = dict(Employee.Role.choices)
    viewed = get_role_view(request, employee) or employee.role
    switcher = can_switch_roles(employee)
    viewing_client = is_viewing_as_client(request, employee)
    client_org = get_client_view_organization(request, employee) if viewing_client else None
    if viewing_client:
        dashboard_name = "core:workspace"
        role_label = f"{CLIENT_VIEW_LABEL} · {client_org.name}" if client_org else CLIENT_VIEW_LABEL
        role_slug = "app"
        organization = client_org or employee.organization
    else:
        dashboard_name = ROLE_DASHBOARD_NAMES.get(viewed) or ROLE_DASHBOARD_NAMES.get(employee.role)
        role_label = role_labels.get(viewed, viewed)
        role_slug = ROLE_SLUGS.get(viewed, "")
        organization = employee.organization
    current_page = page_key_from_path(getattr(request, "path", ""))
    nav = {} if viewing_client else nav_items_for_role(viewed, current_page)

    return {
        "employee": employee,
        "organization": organization,
        "actual_role": employee.role,
        "actual_role_label": employee.get_role_display(),
        "role": viewed,
        "role_label": role_label,
        "is_viewing_as": switcher and (viewing_client or viewed != employee.role),
        "is_viewing_as_client": viewing_client,
        "viewed_client": client_org,
        "can_switch_roles": switcher,
        "dashboard_url_name": dashboard_name,
        "role_slug": role_slug,
        "staff_nav_main": nav.get("main", []),
        "staff_nav_end": nav.get("end", []),
        "staff_nav_items": nav.get("main", []) + nav.get("end", []),
        "switchable_roles": switchable_role_options(request, employee, selected=viewed),
        "switchable_clients": switchable_clients_list() if switcher else [],
        "selected_client_id": client_org.pk if client_org else None,
    }
