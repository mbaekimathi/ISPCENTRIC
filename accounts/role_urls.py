"""Role-prefixed workspace URLs, e.g. /it-support/dashboard/."""

from django.urls import path

from . import role_dashboards

app_name = "roles"

urlpatterns = [
    path("super-admin/dashboard/", role_dashboards.super_admin_dashboard, name="super_admin"),
    path("super-admin/clients/", role_dashboards.super_admin_clients, name="super_admin_clients"),
    path(
        "super-admin/clients/<int:pk>/edit/",
        role_dashboards.super_admin_client_edit,
        name="super_admin_client_edit",
    ),
    path(
        "super-admin/clients/<int:pk>/suspend/",
        role_dashboards.super_admin_client_suspend,
        name="super_admin_client_suspend",
    ),
    path(
        "super-admin/clients/<int:pk>/unsuspend/",
        role_dashboards.super_admin_client_unsuspend,
        name="super_admin_client_unsuspend",
    ),
    path(
        "super-admin/clients/<int:pk>/delete/",
        role_dashboards.super_admin_client_delete,
        name="super_admin_client_delete",
    ),
    path(
        "super-admin/human-resources/",
        role_dashboards.super_admin_hr,
        name="super_admin_hr",
    ),
    path(
        "super-admin/human-resources/<int:pk>/edit/",
        role_dashboards.super_admin_hr_edit,
        name="super_admin_hr_edit",
    ),
    path(
        "super-admin/human-resources/<int:pk>/suspend/",
        role_dashboards.super_admin_hr_suspend,
        name="super_admin_hr_suspend",
    ),
    path(
        "super-admin/human-resources/<int:pk>/unsuspend/",
        role_dashboards.super_admin_hr_unsuspend,
        name="super_admin_hr_unsuspend",
    ),
    path(
        "super-admin/human-resources/<int:pk>/delete/",
        role_dashboards.super_admin_hr_delete,
        name="super_admin_hr_delete",
    ),
    path("administrator/dashboard/", role_dashboards.administrator_dashboard, name="administrator"),
    path("administrator/clients/", role_dashboards.administrator_clients, name="administrator_clients"),
    path(
        "administrator/human-resources/",
        role_dashboards.administrator_hr,
        name="administrator_hr",
    ),
    path("manager/dashboard/", role_dashboards.manager_dashboard, name="manager"),
    path("it-support/dashboard/", role_dashboards.it_support_dashboard, name="it_support"),
    path("it-support/switch-role/", role_dashboards.switch_role_view, name="switch_role"),
    path("sales/dashboard/", role_dashboards.sales_dashboard, name="sales"),
    path("technician/dashboard/", role_dashboards.technician_dashboard, name="technician"),
]
