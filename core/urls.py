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
    path("app/mikrotik/<int:router_id>/live/", views.mikrotik_live, name="mikrotik_live"),
    path(
        "app/mikrotik/<int:router_id>/delete/",
        views.mikrotik_delete,
        name="mikrotik_delete",
    ),
    path(
        "app/mikrotik/<int:router_id>/reconnect/",
        views.mikrotik_reconnect,
        name="mikrotik_reconnect",
    ),
    path("app/mikrotik/discover/", views.mikrotik_discover, name="mikrotik_discover"),
    path("app/mikrotik/connect/", views.mikrotik_connect, name="mikrotik_connect"),
    path("app/mikrotik/status/", views.mikrotik_status, name="mikrotik_status"),
    path("app/mikrotik/places/", views.mikrotik_places, name="mikrotik_places"),
    path("app/mikrotik/places/details/", views.mikrotik_place_details, name="mikrotik_place_details"),
    path("app/clients/", views.my_clients, name="my_clients"),
    path("app/clients/live/", views.clients_live_status, name="clients_live_status"),
    path("app/clients/<int:customer_id>/", views.client_detail, name="client_detail"),
    path("app/clients/<int:customer_id>/usage/", views.client_usage, name="client_usage"),
    path("app/pppoe-hotspot/", views.pppoe_hotspot, name="pppoe_hotspot"),
    path("app/account/", views.my_account, name="my_account"),
    path("app/sales-representatives/", views.sales_reps, name="sales_reps"),
    path("app/technicians/", views.technicians, name="technicians"),
    path("app/settings/", views.system_settings, name="system_settings"),
    path("app/settings/clients/", views.client_settings, name="client_settings"),
    path("app/settings/hotspot/", views.hotspot_settings, name="hotspot_settings"),
    path("app/settings/billing/", views.billing_settings, name="billing_settings"),
]
