from django.urls import path

from .views import (
    CheckLoginCodeView,
    EmployeeLoginView,
    EmployeePendingView,
    EmployeeProfileView,
    EmployeeRegisterView,
    RegisterView,
    UserLoginView,
    UserLogoutView,
)

app_name = "accounts"

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", UserLoginView.as_view(), name="login"),
    path("logout/", UserLogoutView.as_view(), name="logout"),
    path("employee/login/", EmployeeLoginView.as_view(), name="employee_login"),
    path("employee/register/", EmployeeRegisterView.as_view(), name="employee_register"),
    path("employee/pending/", EmployeePendingView.as_view(), name="employee_pending"),
    path("employee/profile/", EmployeeProfileView.as_view(), name="employee_profile"),
    path("employee/check-code/", CheckLoginCodeView.as_view(), name="check_login_code"),
]
