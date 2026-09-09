from django.urls import path

from .views import (
    CheckLoginCodeView,
    EmployeeLoginView,
    EmployeePendingView,
    EmployeeProfileView,
    EmployeeRegisterView,
    GoogleLoginCallbackView,
    GoogleLoginStartView,
    GoogleRegisterStartView,
    OwnerPasswordResetCompleteView,
    OwnerPasswordResetConfirmView,
    OwnerPasswordResetDoneView,
    OwnerPasswordResetView,
    RegisterView,
    UserLoginView,
    UserLogoutView,
)

app_name = "accounts"

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path(
        "register/google/",
        GoogleRegisterStartView.as_view(),
        name="google_register",
    ),
    path("login/", UserLoginView.as_view(), name="login"),
    path("login/google/", GoogleLoginStartView.as_view(), name="google_login"),
    path(
        "login/google/callback/",
        GoogleLoginCallbackView.as_view(),
        name="google_callback",
    ),
    path("logout/", UserLogoutView.as_view(), name="logout"),
    path("password-reset/", OwnerPasswordResetView.as_view(), name="password_reset"),
    path(
        "password-reset/done/",
        OwnerPasswordResetDoneView.as_view(),
        name="password_reset_done",
    ),
    path(
        "password-reset/<uidb64>/<token>/",
        OwnerPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "password-reset/complete/",
        OwnerPasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),
    path("employee/login/", EmployeeLoginView.as_view(), name="employee_login"),
    path("employee/register/", EmployeeRegisterView.as_view(), name="employee_register"),
    path("employee/pending/", EmployeePendingView.as_view(), name="employee_pending"),
    path("employee/profile/", EmployeeProfileView.as_view(), name="employee_profile"),
    path("employee/check-code/", CheckLoginCodeView.as_view(), name="check_login_code"),
]
