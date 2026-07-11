from django.contrib import messages
from django.contrib.auth import login, update_session_auth_hash
from django.contrib.auth.views import LoginView, LogoutView
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils import timezone
from django.views import View

from .forms import (
    EmployeeLoginForm,
    EmployeeProfileForm,
    EmployeeRegisterForm,
    LoginForm,
    RegisterForm,
)
from .models import Employee, Organization
from .routing import home_url_for_user


def _user_session_name(user):
    """Prefer the signed-in person's name from the session user."""
    return (user.get_full_name() or "").strip() or user.username


def _local_hour():
    return timezone.localtime().hour


def _login_greeting(name):
    hour = _local_hour()
    if hour < 12:
        return f"Good morning, {name}. Welcome back."
    if hour < 17:
        return f"Good afternoon, {name}. Welcome back."
    if hour < 21:
        return f"Good evening, {name}. Welcome back."
    return f"Good night, {name}. Welcome back."


def _logout_farewell(name):
    hour = _local_hour()
    if hour < 12:
        return f"Goodbye, {name}. Have a great morning."
    if hour < 17:
        return f"Goodbye, {name}. Have a great afternoon."
    if hour < 21:
        return f"Goodbye, {name}. Have a lovely evening."
    return f"Good night, {name}. Rest well."


class RegisterView(View):
    template_name = "accounts/register.html"

    def get(self, request):
        if request.user.is_authenticated:
            return redirect(home_url_for_user(request.user))
        return render(request, self.template_name, {"form": RegisterForm()})

    def post(self, request):
        form = RegisterForm(request.POST, request.FILES)
        if form.is_valid():
            user = form.save(commit=False)
            user.email = form.cleaned_data["email"]
            user.save()
            Organization.objects.create(
                name=form.cleaned_data["company_name"],
                owner=user,
                phone=form.cleaned_data.get("phone", ""),
                profile_photo=form.cleaned_data.get("profile_photo"),
                status=Organization.Status.REGISTERED,
            )
            login(request, user)
            return redirect(home_url_for_user(user))
        return render(request, self.template_name, {"form": form})


class UserLoginView(LoginView):
    template_name = "accounts/login.html"
    authentication_form = LoginForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        response = super().form_valid(form)
        name = _user_session_name(self.request.user)
        messages.success(self.request, _login_greeting(name))
        return response

    def get_success_url(self):
        return home_url_for_user(self.request.user)


class UserLogoutView(LogoutView):
    next_page = reverse_lazy("core:landing")

    def dispatch(self, request, *args, **kwargs):
        farewell = None
        if request.user.is_authenticated:
            farewell = _logout_farewell(_user_session_name(request.user))
        response = super().dispatch(request, *args, **kwargs)
        if farewell:
            messages.success(request, farewell)
        return response


class EmployeeRegisterView(View):
    template_name = "accounts/employee_register.html"

    def get(self, request):
        if request.user.is_authenticated and hasattr(request.user, "employee_profile"):
            return redirect(home_url_for_user(request.user))
        return render(request, self.template_name, {"form": EmployeeRegisterForm()})

    def post(self, request):
        form = EmployeeRegisterForm(request.POST, request.FILES)
        if form.is_valid():
            user = form.save(commit=False)
            user.email = form.cleaned_data["email"]
            user.first_name = form.cleaned_data["first_name"]
            user.last_name = form.cleaned_data["last_name"]
            user.save()
            Employee.objects.create(
                user=user,
                organization=None,
                phone=form.cleaned_data.get("phone", ""),
                login_code=form.cleaned_data["login_code"],
                profile_photo=form.cleaned_data.get("profile_photo") or None,
                status=Employee.Status.PENDING_APPROVAL,
                role=Employee.Role.PENDING,
            )
            login(request, user)
            messages.info(
                request,
                f"Registration received. Your login code is {form.cleaned_data['login_code']}. "
                "Your account is pending approval and role allocation.",
            )
            return redirect("accounts:employee_pending")
        return render(request, self.template_name, {"form": form})


class EmployeeLoginView(LoginView):
    template_name = "accounts/employee_login.html"
    authentication_form = EmployeeLoginForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        response = super().form_valid(form)
        name = _user_session_name(self.request.user)
        messages.success(self.request, _login_greeting(name))
        return response

    def get_success_url(self):
        return home_url_for_user(self.request.user, self.request)


class EmployeePendingView(View):
    template_name = "accounts/employee_pending.html"

    def get(self, request):
        if not request.user.is_authenticated:
            return redirect("accounts:employee_login")
        employee = getattr(request.user, "employee_profile", None)
        if not employee:
            return redirect("accounts:employee_login")
        if employee.can_access_workspace:
            return redirect(home_url_for_user(request.user, request))
        return render(
            request,
            self.template_name,
            {
                "employee": employee,
                "organization": employee.organization,
            },
        )


class CheckLoginCodeView(View):
    """Live check whether a 6-digit employee login code is available."""

    def get(self, request):
        raw = (request.GET.get("code") or "").strip()
        code = "".join(ch for ch in raw if ch.isdigit())
        if len(code) != 6:
            return JsonResponse(
                {
                    "valid": False,
                    "available": False,
                    "message": "Enter all 6 digits",
                }
            )
        taken = Employee.objects.filter(login_code=code).exists()
        if taken:
            return JsonResponse(
                {
                    "valid": False,
                    "available": False,
                    "message": "Code not available - already in use",
                }
            )
        return JsonResponse(
            {
                "valid": True,
                "available": True,
                "message": "Code available - you can use this to log in",
            }
        )


class EmployeeProfileView(View):
    template_name = "accounts/employee_profile.html"

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("accounts:employee_login")
        employee = getattr(request.user, "employee_profile", None)
        if employee is None:
            return redirect("accounts:employee_login")
        if not employee.can_access_workspace:
            return redirect("accounts:employee_pending")
        self.employee = employee
        return super().dispatch(request, *args, **kwargs)

    def _form(self, data=None, files=None):
        user = self.request.user
        employee = self.employee
        initial = {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "phone": employee.phone,
        }
        return EmployeeProfileForm(
            data,
            files,
            user=user,
            employee=employee,
            initial=initial if data is None else None,
        )

    def get(self, request):
        return render(
            request,
            self.template_name,
            {
                "form": self._form(),
                "current_page": "profile",
                "page_title": "My profile settings",
            },
        )

    def post(self, request):
        form = self._form(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            if form.cleaned_data.get("password1"):
                update_session_auth_hash(request, request.user)
            messages.success(request, "Profile settings saved.")
            return redirect("accounts:employee_profile")
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "current_page": "profile",
                "page_title": "My profile settings",
            },
        )
