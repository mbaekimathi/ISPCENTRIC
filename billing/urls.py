from django.urls import path

from . import views

app_name = "billing"

urlpatterns = [
    path("dashboard/", views.dashboard, name="dashboard"),
    path("lead-payments/", views.lead_payments, name="lead_payments"),
    path("packages/", views.packages, name="packages"),
    path(
        "customers/<int:customer_id>/stk-pay/",
        views.subscription_stk_pay,
        name="subscription_stk_pay",
    ),
    path(
        "stk/<int:stk_id>/status/",
        views.subscription_stk_status,
        name="subscription_stk_status",
    ),
    path("renew/<str:token>/", views.subscription_renew, name="subscription_renew"),
    path(
        "renew/<str:token>/hotspot.html",
        views.subscription_renew_hotspot,
        name="subscription_renew_hotspot",
    ),
]
