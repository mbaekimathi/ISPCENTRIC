"""Template context for staff workspace chrome (header role dropdown)."""

from accounts.models import Employee
from accounts.routing import (
    ROLE_DASHBOARD_NAMES,
    ROLE_SLUGS,
    SWITCHABLE_ROLES,
    can_switch_roles,
    get_role_view,
    nav_items_for_role,
    page_key_from_path,
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
    dashboard_name = ROLE_DASHBOARD_NAMES.get(viewed) or ROLE_DASHBOARD_NAMES.get(employee.role)
    current_page = page_key_from_path(getattr(request, "path", ""))

    return {
        "employee": employee,
        "organization": employee.organization,
        "actual_role": employee.role,
        "actual_role_label": employee.get_role_display(),
        "role": viewed,
        "role_label": role_labels.get(viewed, viewed),
        "is_viewing_as": switcher and viewed != employee.role,
        "can_switch_roles": switcher,
        "dashboard_url_name": dashboard_name,
        "role_slug": ROLE_SLUGS.get(viewed, ""),
        "staff_nav_items": nav_items_for_role(viewed, current_page),
        "switchable_roles": [
            {
                "value": r,
                "label": role_labels[r],
                "url_name": ROLE_DASHBOARD_NAMES[r],
                "slug": ROLE_SLUGS[r],
                "selected": r == viewed,
            }
            for r in SWITCHABLE_ROLES
        ],
    }
