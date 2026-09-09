import json
import logging
import secrets
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, update_session_auth_hash
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.views import (
    LoginView,
    LogoutView,
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    PasswordResetDoneView,
    PasswordResetView,
)
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .forms import (
    EmployeeLoginForm,
    EmployeeProfileForm,
    EmployeeRegisterForm,
    LoginForm,
    OwnerSetPasswordForm,
    RegisterForm,
)
from .models import ClientSettings, Employee, Organization
from .routing import home_url_for_user
from .security import (
    AuthRateLimitExceeded,
    assert_auth_allowed,
    clear_auth_failures,
    employee_login_code_taken,
    google_login_gate_required,
    google_verified_email_from_request,
    GOOGLE_VERIFIED_EMAIL_SESSION_KEY,
    owner_invite_required,
    owner_registration_open,
    record_auth_failure,
)

logger = logging.getLogger(__name__)

REFERRAL_SESSION_KEY = "referral_code"
GOOGLE_OAUTH_STATE_SESSION_KEY = "google_oauth_state"
GOOGLE_OAUTH_PROMPT_SESSION_KEY = "google_oauth_prompt"
GOOGLE_OAUTH_INTENT_SESSION_KEY = "google_oauth_intent"
GOOGLE_REGISTER_PROFILE_SESSION_KEY = "google_register_profile"


def _google_oauth_enabled() -> bool:
    client_id = getattr(settings, "GOOGLE_OAUTH_CLIENT_ID", "").strip()
    client_secret = getattr(settings, "GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
    if not (client_id and client_secret):
        return False
    try:
        return bool(ClientSettings.get_solo().google_login_enabled)
    except Exception:
        return False


def _google_require_email_match() -> bool:
    try:
        return bool(ClientSettings.get_solo().google_login_require_email_match)
    except Exception:
        return True


def _google_verified_email(request) -> str:
    return google_verified_email_from_request(request)


def _set_google_verified_email(request, email: str) -> None:
    request.session[GOOGLE_VERIFIED_EMAIL_SESSION_KEY] = (email or "").strip().lower()


def _clear_google_verified_email(request) -> None:
    request.session.pop(GOOGLE_VERIFIED_EMAIL_SESSION_KEY, None)


def _google_gate_required() -> bool:
    """When Google login is on, ISP clients must connect Google before code login."""
    return google_login_gate_required()


def _google_register_profile(request) -> dict:
    raw = request.session.get(GOOGLE_REGISTER_PROFILE_SESSION_KEY) or {}
    return raw if isinstance(raw, dict) else {}


def _set_google_register_profile(request, profile: dict) -> None:
    request.session[GOOGLE_REGISTER_PROFILE_SESSION_KEY] = {
        "email": (profile.get("email") or "").strip().lower(),
        "name": (profile.get("name") or "").strip(),
        "given_name": (profile.get("given_name") or "").strip(),
        "family_name": (profile.get("family_name") or "").strip(),
    }


def _clear_google_register_profile(request) -> None:
    request.session.pop(GOOGLE_REGISTER_PROFILE_SESSION_KEY, None)


def _start_google_oauth(request, *, intent: str):
    state = secrets.token_urlsafe(24)
    request.session[GOOGLE_OAUTH_STATE_SESSION_KEY] = state
    request.session[GOOGLE_OAUTH_INTENT_SESSION_KEY] = intent
    request.session[GOOGLE_OAUTH_PROMPT_SESSION_KEY] = bool(
        request.GET.get("prompt_account")
    )
    params = {
        "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
        "redirect_uri": _google_oauth_redirect_uri(request),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "include_granted_scopes": "true",
    }
    if request.GET.get("prompt_account"):
        params["prompt"] = "select_account"
    return redirect(
        "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    )


def _fetch_google_userinfo(request, code: str) -> dict:
    token_data = _google_json_request(
        "https://oauth2.googleapis.com/token",
        data={
            "code": code,
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
            "redirect_uri": _google_oauth_redirect_uri(request),
            "grant_type": "authorization_code",
        },
    )
    access_token = (token_data.get("access_token") or "").strip()
    if not access_token:
        raise ValueError("missing_access_token")
    req = Request(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
        method="GET",
    )
    with urlopen(req, timeout=10) as response:  # nosec B310
        payload = response.read().decode("utf-8")
    userinfo = json.loads(payload or "{}")
    if not isinstance(userinfo, dict):
        raise ValueError("invalid_userinfo")
    return userinfo


def _find_isp_owner_by_email(email: str):
    email = (email or "").strip().lower()
    if not email:
        return None
    user = (
        User.objects.filter(
            email__iexact=email,
            is_active=True,
            organization__isnull=False,
        )
        .select_related("organization")
        .first()
    )
    if user is not None:
        return user
    org = (
        Organization.objects.filter(
            owner__email__iexact=email,
            owner__is_active=True,
        )
        .select_related("owner")
        .first()
    )
    return org.owner if org is not None else None


def _google_oauth_redirect_uri(request) -> str:
    configured = (getattr(settings, "GOOGLE_OAUTH_REDIRECT_URI", "") or "").strip()
    if configured:
        return configured
    return request.build_absolute_uri(reverse("accounts:google_callback"))


def _google_json_request(url: str, data: dict | None = None) -> dict:
    body = None
    headers = {"Accept": "application/json"}
    method = "GET"
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urlencode(data).encode("utf-8")
        method = "POST"
    req = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=10) as response:  # nosec B310
            payload = response.read().decode("utf-8")
    except HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            err_body = ""
        logger.warning("Google OAuth HTTP %s for %s: %s", exc.code, url, err_body[:500])
        try:
            parsed_err = json.loads(err_body or "{}")
        except json.JSONDecodeError:
            parsed_err = {}
        if isinstance(parsed_err, dict) and parsed_err.get("error"):
            raise ValueError(str(parsed_err.get("error"))) from exc
        raise
    parsed = json.loads(payload or "{}")
    if not isinstance(parsed, dict):
        return {}
    return parsed


def _google_oauth_user_message(exc: Exception) -> str:
    detail = str(exc or "").strip().lower()
    if detail in {"invalid_client", "unauthorized_client"}:
        return (
            "Google client ID/secret is invalid. Reset the client secret in Google Cloud "
            "and update GOOGLE_OAUTH_CLIENT_SECRET in .env."
        )
    if detail in {"redirect_uri_mismatch"}:
        return (
            "Google redirect URI mismatch. Use exactly "
            "http://localhost:8000/accounts/login/google/callback/ in Google Cloud."
        )
    if detail in {"invalid_grant"}:
        return "Google sign-in expired. Please try Continue with Google again."
    return "Could not complete Google sign-in right now. Please try again."


def _capture_referral_code(request):
    """Persist ?ref=… into the session when referrals are enabled."""
    ref = (request.GET.get("ref") or "").strip()
    if not ref:
        return
    if ClientSettings.get_solo().referral_enabled:
        request.session[REFERRAL_SESSION_KEY] = ref[:64]


def _session_referral_code(request) -> str:
    return (request.session.get(REFERRAL_SESSION_KEY) or "").strip()


def _resolve_referrer(request, code: str | None = None):
    """Return the referring Organization from an explicit code or session."""
    if not ClientSettings.get_solo().referral_enabled:
        return None
    raw = (code or "").strip() or _session_referral_code(request)
    if not raw:
        return None
    return Organization.lookup_by_referral_code(raw)


def _register_form(request, data=None, files=None):
    initial_ref = _session_referral_code(request)
    kwargs = {
        "require_invite": owner_invite_required(),
        "initial_referral": initial_ref,
    }
    profile = _google_register_profile(request)
    google_email = (profile.get("email") or "").strip().lower()
    if google_email:
        kwargs["google_email"] = google_email
        if data is None:
            initial = {"email": google_email}
            google_name = (profile.get("name") or "").strip()
            if google_name:
                initial["company_name"] = google_name.upper()
            kwargs["initial_google"] = initial
    if data is not None:
        return RegisterForm(data, files, **kwargs)
    return RegisterForm(**kwargs)


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


def _employee_register_form(request, data=None, files=None):
    _capture_referral_code(request)
    kwargs = {"initial_referral": _session_referral_code(request)}
    if data is not None:
        return EmployeeRegisterForm(data, files, **kwargs)
    return EmployeeRegisterForm(**kwargs)


def _rate_limited_response(request, template_name, form):
    messages.error(
        request,
        "Too many attempts from this network. Please wait about 15 minutes and try again.",
    )
    return render(request, template_name, {"form": form}, status=429)


class RegisterView(View):
    template_name = "accounts/register.html"

    def _referral_hint(self, request):
        _capture_referral_code(request)
        return (
            (request.GET.get("ref") or "").strip()
            or _session_referral_code(request)
            or (request.POST.get("referral_code") or "").strip()
        )

    def _render(self, request, form, referrer=None, status=200):
        profile = _google_register_profile(request)
        google_email = (profile.get("email") or "").strip().lower()
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "referrer_organization": referrer,
                "google_oauth_enabled": _google_oauth_enabled(),
                "google_register_connected": bool(google_email),
                "google_register_email": google_email,
            },
            status=status,
        )

    def get(self, request):
        if request.user.is_authenticated:
            return redirect(home_url_for_user(request.user))
        ref_hint = self._referral_hint(request)
        if not owner_registration_open(referral_code=ref_hint):
            return render(
                request,
                "accounts/register_closed.html",
                status=403,
            )
        try:
            assert_auth_allowed("register", request, limit=10, window=3600)
        except AuthRateLimitExceeded:
            return _rate_limited_response(
                request, self.template_name, _register_form(request)
            )
        form = _register_form(request)
        referrer = _resolve_referrer(request, form.initial.get("referral_code"))
        return self._render(request, form, referrer=referrer)

    def post(self, request):
        ref_hint = self._referral_hint(request)
        if not owner_registration_open(referral_code=ref_hint):
            return render(
                request,
                "accounts/register_closed.html",
                status=403,
            )
        try:
            assert_auth_allowed("register", request, limit=10, window=3600)
        except AuthRateLimitExceeded:
            return _rate_limited_response(
                request, self.template_name, _register_form(request)
            )
        form = _register_form(request, request.POST, request.FILES)
        if form.is_valid():
            user = form.save(commit=False)
            user.email = form.cleaned_data["email"]
            profile = _google_register_profile(request)
            if profile.get("given_name"):
                user.first_name = (profile.get("given_name") or "")[:150]
            if profile.get("family_name"):
                user.last_name = (profile.get("family_name") or "")[:150]
            user.save()
            referrer = getattr(form, "resolved_referrer", None)
            if referrer is None:
                referrer = _resolve_referrer(
                    request, form.cleaned_data.get("referral_code")
                )
            org_kwargs = {
                "name": form.cleaned_data["company_name"],
                "owner": user,
                "login_code": form.cleaned_data["username"],
                "phone": form.cleaned_data.get("phone", ""),
                "profile_photo": form.cleaned_data.get("profile_photo"),
                "status": Organization.Status.REGISTERED,
            }
            if referrer is not None:
                org_kwargs["referred_by"] = referrer
                org_kwargs["referral_status"] = Organization.ReferralStatus.PENDING
            org = Organization.objects.create(**org_kwargs)
            from accounts.communications import notify_platform_event

            notify_platform_event(
                "platform_isp_welcome",
                organization=org,
                context={
                    "company_name": org.name,
                    "join_code": org.join_code or "",
                },
                subject=f"Welcome to ISPCENTRIC — {org.name}",
            )
            notify_platform_event(
                "platform_staff_new_isp",
                organization=org,
                context={"company_name": org.name},
                subject=f"New ISP registered — {org.name}",
            )
            request.session.pop(REFERRAL_SESSION_KEY, None)
            if (user.email or "").strip():
                _set_google_verified_email(request, user.email)
            _clear_google_register_profile(request)
            clear_auth_failures("register", request)
            login(request, user)
            return redirect(home_url_for_user(user))
        record_auth_failure("register", request, limit=10, window=3600)
        referrer = getattr(form, "resolved_referrer", None) or _resolve_referrer(
            request, form.data.get("referral_code")
        )
        return self._render(request, form, referrer=referrer)


class UserLoginView(LoginView):
    template_name = "accounts/login.html"
    authentication_form = LoginForm
    redirect_authenticated_user = True

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["landing_register_enabled"] = bool(
            ClientSettings.get_solo().landing_register_enabled
        )
        google_enabled = _google_oauth_enabled()
        google_verified = _google_verified_email(self.request)
        gate_required = _google_gate_required()
        context["google_oauth_enabled"] = google_enabled
        context["google_gate_required"] = gate_required
        context["google_verified_email"] = google_verified
        context["google_connected"] = bool(google_verified) if gate_required else True
        return context

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs

    def dispatch(self, request, *args, **kwargs):
        try:
            assert_auth_allowed("login", request, limit=20, window=900)
        except AuthRateLimitExceeded:
            return _rate_limited_response(
                request, self.template_name, self.get_form_class()()
            )
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        username = (form.cleaned_data.get("username") or "").strip().upper()
        clear_auth_failures("login", self.request)
        clear_auth_failures("login_user", self.request, username)
        response = super().form_valid(form)
        # Code/password completed — Google gate no longer needed this session.
        _clear_google_verified_email(self.request)
        name = _user_session_name(self.request.user)
        messages.success(self.request, _login_greeting(name))
        return response

    def form_invalid(self, form):
        username = (self.request.POST.get("username") or "").strip().upper()
        record_auth_failure("login", self.request, limit=20, window=900)
        if username:
            record_auth_failure("login_user", self.request, username, limit=8, window=900)
            from .security import is_auth_rate_limited

            if is_auth_rate_limited("login_user", self.request, username, limit=8):
                messages.error(
                    self.request,
                    "Too many failed attempts for this account. Try again in about 15 minutes.",
                )
        return super().form_invalid(form)

    def get_success_url(self):
        return home_url_for_user(self.request.user)


class GoogleLoginStartView(View):
    def get(self, request):
        if not _google_oauth_enabled():
            messages.error(
                request,
                "Google sign-in is not configured yet. Please use login code and password.",
            )
            return redirect("accounts:login")
        try:
            assert_auth_allowed("google_login", request, limit=20, window=900)
        except AuthRateLimitExceeded:
            return _rate_limited_response(request, "accounts/login.html", LoginForm())
        return _start_google_oauth(request, intent="login")


class GoogleRegisterStartView(View):
    def get(self, request):
        if not _google_oauth_enabled():
            messages.error(
                request,
                "Google sign-up is not configured yet. Please complete the form manually.",
            )
            return redirect("accounts:register")
        ref_hint = (
            (request.GET.get("ref") or "").strip()
            or _session_referral_code(request)
        )
        if not owner_registration_open(referral_code=ref_hint):
            return render(request, "accounts/register_closed.html", status=403)
        try:
            assert_auth_allowed("google_register", request, limit=20, window=900)
        except AuthRateLimitExceeded:
            return _rate_limited_response(
                request, "accounts/register.html", _register_form(request)
            )
        return _start_google_oauth(request, intent="register")


class GoogleLoginCallbackView(View):
    def get(self, request):
        intent = (request.session.pop(GOOGLE_OAUTH_INTENT_SESSION_KEY, "") or "login").strip()
        expected_state = request.session.pop(GOOGLE_OAUTH_STATE_SESSION_KEY, "")
        request.session.pop(GOOGLE_OAUTH_PROMPT_SESSION_KEY, None)
        fail_url = "accounts:register" if intent == "register" else "accounts:login"
        state = (request.GET.get("state") or "").strip()
        if not expected_state or not state or state != expected_state:
            messages.error(request, "Google sign-in failed. Please try again.")
            return redirect(fail_url)

        code = (request.GET.get("code") or "").strip()
        if not code:
            messages.error(request, "Google sign-in was cancelled.")
            return redirect(fail_url)
        try:
            userinfo = _fetch_google_userinfo(request, code)
        except (HTTPError, URLError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("Google OAuth callback failed: %s", exc)
            messages.error(request, _google_oauth_user_message(exc))
            return redirect(fail_url)

        email = (userinfo.get("email") or "").strip().lower()
        email_verified = bool(userinfo.get("email_verified"))
        if not email or not email_verified:
            messages.error(
                request,
                "Your Google account must have a verified email address.",
            )
            return redirect(fail_url)

        if not _google_oauth_enabled():
            messages.error(
                request,
                "Google sign-in is currently disabled.",
            )
            return redirect(fail_url)

        if intent == "register":
            existing = _find_isp_owner_by_email(email)
            if existing is not None:
                messages.error(
                    request,
                    "An ISP client account already uses this Google email. Sign in instead.",
                )
                return redirect("accounts:login")
            clear_auth_failures("google_register", request)
            _set_google_register_profile(
                request,
                {
                    "email": email,
                    "name": userinfo.get("name") or "",
                    "given_name": userinfo.get("given_name") or "",
                    "family_name": userinfo.get("family_name") or "",
                },
            )
            messages.success(
                request,
                f"Google connected as {email}. Review the prefilled details, then finish registration.",
            )
            return redirect("accounts:register")

        if not _google_require_email_match():
            messages.error(
                request,
                "Google sign-in requires matching email. Ask IT Support to enable that setting.",
            )
            return redirect("accounts:login")

        user = _find_isp_owner_by_email(email)
        if not user or not hasattr(user, "organization"):
            logger.info("Google connect rejected: no ISP owner for email %s", email)
            _clear_google_verified_email(request)
            from accounts.security import google_wrong_profile_message

            messages.error(
                request,
                google_wrong_profile_message(connected_email=email),
            )
            return redirect("accounts:login")

        clear_auth_failures("google_login", request)
        _set_google_verified_email(request, email)
        messages.success(
            request,
            f"Google connected as {email}. Only this profile can unlock login for that ISP account. "
            "Now enter your 6-digit login code and password.",
        )
        return redirect("accounts:login")


class UserLogoutView(LogoutView):
    next_page = reverse_lazy("core:landing")

    def dispatch(self, request, *args, **kwargs):
        farewell = None
        if request.user.is_authenticated:
            farewell = _logout_farewell(_user_session_name(request.user))
        _clear_google_verified_email(request)
        _clear_google_register_profile(request)
        response = super().dispatch(request, *args, **kwargs)
        if farewell:
            messages.success(request, farewell)
        return response


class EmployeeRegisterView(View):
    template_name = "accounts/employee_register.html"

    def _render(self, request, form, status=200):
        referrer = _resolve_referrer(request, form.initial.get("referral_code"))
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "referrer_organization": referrer,
            },
            status=status,
        )

    def get(self, request):
        if request.user.is_authenticated and hasattr(request.user, "employee_profile"):
            return redirect(home_url_for_user(request.user))
        try:
            assert_auth_allowed("employee_register", request, limit=10, window=3600)
        except AuthRateLimitExceeded:
            return _rate_limited_response(
                request, self.template_name, _employee_register_form(request)
            )
        return self._render(request, _employee_register_form(request))

    def post(self, request):
        try:
            assert_auth_allowed("employee_register", request, limit=10, window=3600)
        except AuthRateLimitExceeded:
            return _rate_limited_response(
                request, self.template_name, _employee_register_form(request)
            )
        form = _employee_register_form(request, data=request.POST, files=request.FILES)
        if form.is_valid():
            user = form.save(commit=False)
            user.email = form.cleaned_data["email"]
            user.first_name = form.cleaned_data["first_name"]
            user.last_name = form.cleaned_data["last_name"]
            user.save()
            organization = form.cleaned_data.get("organization")
            Employee.objects.create(
                user=user,
                organization=organization,
                phone=form.cleaned_data.get("phone", ""),
                login_code=form.cleaned_data["login_code"],
                profile_photo=form.cleaned_data.get("profile_photo") or None,
                status=Employee.Status.PENDING_APPROVAL,
                role=Employee.Role.PENDING,
            )
            from accounts.communications import notify_org_event, notify_platform_event

            employee_name = (
                f"{form.cleaned_data.get('first_name', '')} "
                f"{form.cleaned_data.get('last_name', '')}"
            ).strip() or user.username
            if organization is not None:
                notify_org_event(
                    "isp_employee_joined",
                    organization=organization,
                    context={
                        "employee_name": employee_name,
                        "join_code": getattr(organization, "join_code", "") or "",
                    },
                    subject="Employee joined",
                )
            notify_platform_event(
                "platform_staff_employee_joined",
                organization=organization,
                context={
                    "employee_name": employee_name,
                    "company_name": getattr(organization, "name", "") or "",
                },
                subject="Employee joined an ISP",
            )
            clear_auth_failures("employee_register", request)
            # Do not auto-login — account must be approved first.
            messages.success(
                request,
                f"Registration received for login code {form.cleaned_data['login_code']}. "
                "Sign in after your company admin approves your account and assigns a role.",
            )
            return redirect("accounts:employee_login")
        record_auth_failure("employee_register", request, limit=10, window=3600)
        return self._render(request, form)


class EmployeeLoginView(LoginView):
    template_name = "accounts/employee_login.html"
    authentication_form = EmployeeLoginForm
    redirect_authenticated_user = True

    def dispatch(self, request, *args, **kwargs):
        try:
            assert_auth_allowed("employee_login", request, limit=20, window=900)
        except AuthRateLimitExceeded:
            return _rate_limited_response(
                request, self.template_name, self.get_form_class()()
            )
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        code = "".join(
            ch for ch in (self.request.POST.get("username") or "") if ch.isdigit()
        )
        clear_auth_failures("employee_login", self.request)
        if code:
            clear_auth_failures("employee_login_code", self.request, code)
        response = super().form_valid(form)
        name = _user_session_name(self.request.user)
        messages.success(self.request, _login_greeting(name))
        return response

    def form_invalid(self, form):
        code = "".join(
            ch for ch in (self.request.POST.get("username") or "") if ch.isdigit()
        )
        record_auth_failure("employee_login", self.request, limit=20, window=900)
        if code:
            record_auth_failure(
                "employee_login_code", self.request, code, limit=8, window=900
            )
            from .security import is_auth_rate_limited

            if is_auth_rate_limited(
                "employee_login_code", self.request, code, limit=8
            ):
                messages.error(
                    self.request,
                    "Too many failed attempts for this login code. Try again in about 15 minutes.",
                )
        return super().form_invalid(form)

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
    """Live check whether a 6-digit employee login code is available (rate-limited)."""

    def get(self, request):
        try:
            assert_auth_allowed("check_login_code", request, limit=30, window=900)
        except AuthRateLimitExceeded:
            return JsonResponse(
                {
                    "valid": False,
                    "available": False,
                    "message": "Too many checks. Try again later.",
                },
                status=429,
            )
        record_auth_failure("check_login_code", request, limit=30, window=900)
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
        taken = employee_login_code_taken(code)
        if taken:
            return JsonResponse(
                {
                    "valid": False,
                    "available": False,
                    "message": "Choose a different code",
                }
            )
        return JsonResponse(
            {
                "valid": True,
                "available": True,
                "message": "Code available",
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


class OwnerPasswordResetForm(PasswordResetForm):
    """Password reset is only for ISP client (organization owner) accounts."""

    def get_users(self, email):
        active_users = User.objects.filter(email__iexact=email, is_active=True)
        return (
            user
            for user in active_users
            if Organization.objects.filter(owner=user).exists()
        )


class OwnerPasswordResetView(PasswordResetView):
    template_name = "accounts/password_reset_form.html"
    email_template_name = "accounts/password_reset_email.txt"
    subject_template_name = "accounts/password_reset_subject.txt"
    success_url = reverse_lazy("accounts:password_reset_done")
    form_class = OwnerPasswordResetForm

    def dispatch(self, request, *args, **kwargs):
        try:
            assert_auth_allowed("password_reset", request, limit=5, window=3600)
        except AuthRateLimitExceeded:
            messages.error(
                request,
                "Too many password reset attempts. Please wait and try again later.",
            )
            return render(
                request,
                self.template_name,
                {"form": self.get_form_class()()},
                status=429,
            )
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        record_auth_failure("password_reset", self.request, limit=5, window=3600)
        return super().form_valid(form)


class OwnerPasswordResetDoneView(PasswordResetDoneView):
    template_name = "accounts/password_reset_done.html"


class OwnerPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = "accounts/password_reset_confirm.html"
    success_url = reverse_lazy("accounts:password_reset_complete")
    form_class = OwnerSetPasswordForm


class OwnerPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = "accounts/password_reset_complete.html"


@csrf_exempt
@require_POST
def mpesa_stk_callback(request):
    """
    Daraja STK Push result callback.

    Sandbox accepts both local (http://localhost…) and hosted (https://…) callbacks.
    Always acknowledges so Safaricom treats the callback as received.
    Success fulfillment is verified inside process_stk_callback_payload (amount +
    Daraja STK Query) so a forged POST alone cannot activate service.
    """
    import json
    import logging

    from django.conf import settings

    from billing.stk import process_stk_callback_payload, redact_stk_callback_for_log

    logger = logging.getLogger(__name__)

    allowed_raw = (getattr(settings, "MPESA_CALLBACK_ALLOWED_IPS", "") or "").strip()
    if allowed_raw:
        peer = (request.META.get("REMOTE_ADDR") or "").strip()
        allowed = {ip.strip() for ip in allowed_raw.split(",") if ip.strip()}
        if peer not in allowed:
            logger.warning("Rejected M-Pesa STK callback from non-allowlisted IP %s", peer)
            return JsonResponse({"ResultCode": 0, "ResultDesc": "Accepted"})

    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except (TypeError, ValueError, UnicodeDecodeError):
        payload = {"raw": "[unparseable body]"}

    logger.info(
        "M-Pesa STK callback received: %s",
        redact_stk_callback_for_log(payload if isinstance(payload, dict) else {}),
    )
    try:
        process_stk_callback_payload(payload if isinstance(payload, dict) else {})
    except Exception:  # noqa: BLE001 — never fail the HTTP ack to Safaricom
        logger.exception("Failed processing M-Pesa STK callback")
    return JsonResponse({"ResultCode": 0, "ResultDesc": "Accepted"})
