from django.urls import path

from . import views
from .landing import LandingView

app_name = "core"

urlpatterns = [
    path("", LandingView.as_view(), name="landing"),
    path("app/", views.workspace, name="workspace"),
    path("app/mikrotik/", views.mikrotik, name="mikrotik"),
    path("app/mikrotik/<int:router_id>/", views.mikrotik_detail, name="mikrotik_detail"),
    path("app/mikrotik/<int:router_id>/ports/", views.mikrotik_ports, name="mikrotik_ports"),
    path(
        "app/mikrotik/<int:router_id>/ports/live/",
        views.mikrotik_ports_live,
        name="mikrotik_ports_live",
    ),
    path(
        "app/mikrotik/<int:router_id>/pppoe-settings/",
        views.mikrotik_pppoe_settings,
        name="mikrotik_pppoe_settings",
    ),
    path(
        "app/mikrotik/<int:router_id>/hotspot-settings/",
        views.mikrotik_hotspot_settings,
        name="mikrotik_hotspot_settings",
    ),
    path("app/mikrotik/<int:router_id>/live/", views.mikrotik_live, name="mikrotik_live"),
    path("app/mikrotik/<int:router_id>/wifi/", views.mikrotik_wifi, name="mikrotik_wifi"),
    path(
        "app/mikrotik/<int:router_id>/reconnect/",
        views.mikrotik_reconnect,
        name="mikrotik_reconnect",
    ),
    path("app/mikrotik/discover/", views.mikrotik_discover, name="mikrotik_discover"),
    path("app/mikrotik/connect/", views.mikrotik_connect, name="mikrotik_connect"),
    path(
        "app/mikrotik/tunnel-script/",
        views.mikrotik_tunnel_script,
        name="mikrotik_tunnel_script",
    ),
    path("app/mikrotik/status/", views.mikrotik_status, name="mikrotik_status"),
    path("app/mikrotik/places/", views.mikrotik_places, name="mikrotik_places"),
    path("app/mikrotik/places/details/", views.mikrotik_place_details, name="mikrotik_place_details"),
    path("app/clients/", views.my_clients, name="my_clients"),
    path("app/clients/surfing/", views.clients_surfing_status, name="clients_surfing"),
    path("app/clients/<int:customer_id>/", views.client_detail, name="client_detail"),
    path("app/clients/<int:customer_id>/usage/", views.client_usage, name="client_usage"),
    path(
        "app/clients/<int:customer_id>/subscription/",
        views.client_subscription,
        name="client_subscription",
    ),
    path(
        "app/clients/<int:customer_id>/cpe-wifi/",
        views.client_cpe_wifi,
        name="client_cpe_wifi",
    ),
    # Legacy PPPoE & Hotspot URLs → first onboarded router (or MikroTik list).
    path("app/pppoe-hotspot/", views.pppoe_hotspot_redirect, name="pppoe_hotspot"),
    path(
        "app/pppoe-hotspot/pppoe-settings/",
        views.pppoe_settings_redirect,
        name="pppoe_settings",
    ),
    path(
        "app/pppoe-hotspot/hotspot-settings/",
        views.hotspot_settings_redirect,
        name="hotspot_settings",
    ),
    path(
        "hotspot/<str:join_code>/welcome/",
        views.hotspot_welcome,
        name="hotspot_welcome",
    ),
    path(
        "hotspot/<str:join_code>/pay/",
        views.hotspot_pay,
        name="hotspot_pay",
    ),
    path(
        "pppoe/<str:join_code>/pay/",
        views.pppoe_pay,
        name="pppoe_pay",
    ),
    path(
        "pppoe/<str:join_code>/pay/start/",
        views.pppoe_payment_start,
        name="pppoe_payment_start",
    ),
    path(
        "pppoe/<str:join_code>/pay/status/<int:stk_id>/",
        views.pppoe_payment_status,
        name="pppoe_payment_status",
    ),
    path(
        "hotspot/<str:join_code>/pay/start/",
        views.hotspot_payment_start,
        name="hotspot_payment_start",
    ),
    path(
        "hotspot/<str:join_code>/pay/status/<int:stk_id>/",
        views.hotspot_payment_status,
        name="hotspot_payment_status",
    ),
    path(
        "hotspot/<str:join_code>/pay/activate/<int:stk_id>/",
        views.hotspot_payment_activate,
        name="hotspot_payment_activate",
    ),
    path(
        "hotspot/<str:join_code>/pages/login.html",
        views.hotspot_portal_login_page,
        name="hotspot_portal_login_page",
    ),
    path(
        "hotspot/<str:join_code>/pages/alogin.html",
        views.hotspot_alogin_page,
        name="hotspot_alogin_page",
    ),
    path("app/account/", views.my_account, name="my_account"),
    path("app/sales-representatives/", views.sales_reps, name="sales_reps"),
    path("app/technicians/", views.technicians, name="technicians"),
    path("app/settings/", views.system_settings, name="system_settings"),
]
