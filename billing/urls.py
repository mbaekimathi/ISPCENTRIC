from django.urls import path

from . import views

app_name = "billing"

urlpatterns = [
    path("dashboard/", views.dashboard, name="dashboard"),
    path("packages/", views.packages, name="packages"),
]
