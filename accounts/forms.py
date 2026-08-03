import re

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User
from django.db import models

from .countries import DEFAULT_COUNTRY, country_choices, dial_from_choice, get_country_options, option_for_value
from .models import (
    CompanyProfile,
    Employee,
    Lead,
    NetworkEquipment,
    Organization,
    PaymentGateway,
    RoleCommission,
)
from .security import (
    owner_invite_required,
    validate_account_password,
    validate_flexible_password,
)


def normalize_phone(country_choice: str, phone: str) -> str:
    """Force phone to start with the selected country dial code."""
    phone = (phone or "").strip()
    if not phone:
        return ""

    dial = dial_from_choice(country_choice)
    digits = re.sub(r"\D", "", phone)

    if not digits:
        return ""

    # Drop dial code if the user already typed it
    if digits.startswith(dial):
        digits = digits[len(dial) :]

    # Drop national trunk prefix (leading zeros)
    digits = digits.lstrip("0")

    if not digits:
        return f"+{dial}"

    return f"+{dial}{digits}"


# Expected national digit count after the country dial code.
NATIONAL_PHONE_LENGTHS = {
    "1": 10,  # US / Canada
    "20": 10,
    "27": 9,
    "33": 9,
    "44": 10,
    "49": 10,
    "61": 9,
    "91": 10,
    "211": 9,
    "212": 9,
    "213": 9,
    "216": 8,
    "218": 9,
    "221": 9,
    "225": 10,
    "230": 8,
    "233": 9,
    "234": 10,
    "248": 7,
    "249": 9,
    "250": 9,
    "251": 9,
    "252": 9,
    "253": 8,
    "254": 9,  # Kenya
    "255": 9,
    "256": 9,
    "257": 8,
    "258": 9,
    "260": 9,
    "263": 9,
    "264": 9,
    "265": 9,
    "266": 8,
    "267": 8,
    "268": 8,
}


def national_phone_length(country_choice: str) -> int:
    return NATIONAL_PHONE_LENGTHS.get(dial_from_choice(country_choice), 9)


def validate_and_normalize_phone(
    country_choice: str,
    phone: str,
    *,
    required: bool = True,
) -> str:
    """Normalize to +<dial><national> and require the exact national digit count."""
    raw = (phone or "").strip()
    if not raw:
        if required:
            raise forms.ValidationError("Enter a phone number.")
        return ""

    dial = dial_from_choice(country_choice)
    expected = national_phone_length(country_choice)
    normalized = normalize_phone(country_choice, raw)
    digits = re.sub(r"\D", "", normalized)
    if not digits.startswith(dial):
        raise forms.ValidationError("Enter a valid phone number for the selected country.")
    national = digits[len(dial) :]
    if len(national) != expected:
        raise forms.ValidationError(
            f"Enter exactly {expected} digits after +{dial}."
        )
    if not national.isdigit():
        raise forms.ValidationError("Phone number may only contain digits.")
    return f"+{dial}{national}"


def is_six_digit_code(value: str) -> bool:
    """True when value is exactly six numeric digits."""
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    return len(digits) == 6 and digits == str(value or "")


class RegisterForm(UserCreationForm):
    company_name = forms.CharField(
        max_length=150,
        label="Company / ISP name",
        widget=forms.TextInput(
            attrs={
                "placeholder": "e.g. MTAANI FIBER",
                "autocomplete": "organization",
                "class": "form-control text-upper",
            }
        ),
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(
            attrs={
                "placeholder": "you@company.com",
                "autocomplete": "email",
                "class": "form-control text-lower",
            }
        ),
    )
    country_code = forms.ChoiceField(
        label="Country",
        choices=country_choices,
        initial=DEFAULT_COUNTRY,
        widget=forms.HiddenInput(attrs={"id": "id_country_code"}),
    )
    phone = forms.CharField(
        max_length=30,
        required=False,
        label="Phone number",
        widget=forms.TextInput(
            attrs={
                "placeholder": "7XX XXX XXX",
                "autocomplete": "tel-national",
                "inputmode": "tel",
                "class": "form-control text-upper phone-local",
            }
        ),
    )
    profile_photo = forms.ImageField(
        required=False,
        label="Profile photo (optional)",
        widget=forms.FileInput(
            attrs={
                "accept": "image/*",
                "class": "form-control form-file",
            }
        ),
    )
    invite_key = forms.CharField(
        required=False,
        label="Registration invite key",
        help_text="Required when public owner signup is invite-only.",
        widget=forms.TextInput(
            attrs={
                "placeholder": "Invite key",
                "autocomplete": "off",
                "class": "form-control",
            }
        ),
    )

    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "company_name",
            "country_code",
            "phone",
            "password1",
            "password2",
            "profile_photo",
        )
        widgets = {
            "username": forms.TextInput(
                attrs={
                    "placeholder": "CHOOSE A USERNAME",
                    "autocomplete": "username",
                    "class": "form-control text-upper",
                }
            ),
        }

    def __init__(self, *args, require_invite: bool | None = None, **kwargs):
        self.require_invite = (
            owner_invite_required() if require_invite is None else bool(require_invite)
        )
        super().__init__(*args, **kwargs)
        if not self.require_invite:
            self.fields.pop("invite_key", None)
        else:
            self.fields["invite_key"].required = True
        self.fields["username"].help_text = "Letters, numbers, or a 6-digit login code (identifier only)."
        self.fields["username"].widget.attrs.update(
            {
                "placeholder": "USERNAME OR 6-DIGIT CODE",
                "autocomplete": "username",
                "class": "form-control text-upper",
            }
        )
        self.fields["password1"].help_text = (
            "At least 12 characters, not entirely numeric, and not a common password."
        )
        self.fields["password1"].widget.attrs.update(
            {
                "placeholder": "Create a strong password",
                "autocomplete": "new-password",
                "class": "form-control password-input",
            }
        )
        self.fields["password2"].widget.attrs.update(
            {
                "placeholder": "Confirm password",
                "autocomplete": "new-password",
                "class": "form-control password-input",
            }
        )
        self.country_options = get_country_options()
        selected = self.data.get("country_code") if self.is_bound else self.fields["country_code"].initial
        if self.prefix and self.is_bound:
            selected = self.data.get(self.add_prefix("country_code")) or selected
        self.selected_country = option_for_value(selected or DEFAULT_COUNTRY)
        if self.prefix:
            self.fields["country_code"].widget.attrs["id"] = f"id_{self.prefix}_country_code"
            self.fields["phone"].widget.attrs["id"] = f"id_{self.prefix}_phone"
        self.phone_national_length = national_phone_length(selected or DEFAULT_COUNTRY)

    def clean_username(self):
        username = self.cleaned_data["username"].strip().upper()
        if is_six_digit_code(username):
            return username
        if not username:
            raise forms.ValidationError("Enter a username or 6-digit login code.")
        return username

    def clean_invite_key(self):
        if not self.require_invite:
            return ""
        from django.conf import settings

        expected = (getattr(settings, "OWNER_REGISTER_INVITE_KEY", "") or "").strip()
        provided = (self.cleaned_data.get("invite_key") or "").strip()
        if not expected or provided != expected:
            raise forms.ValidationError("Invalid registration invite key.")
        return provided

    def clean_email(self):
        return self.cleaned_data["email"].strip().lower()

    def clean_company_name(self):
        return self.cleaned_data["company_name"].strip().upper()

    def clean(self):
        cleaned = super().clean()
        country = cleaned.get("country_code") or DEFAULT_COUNTRY
        phone = cleaned.get("phone") or ""
        try:
            cleaned["phone"] = validate_and_normalize_phone(
                country, phone, required=False
            )
        except forms.ValidationError as exc:
            self.add_error("phone", exc)
        return cleaned


class LoginForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].label = "Username or 6-digit code"
        self.fields["username"].widget.attrs.update(
            {
                "class": "form-control text-upper",
                "placeholder": "USERNAME OR 6-DIGIT CODE",
                "autocomplete": "username",
            }
        )
        self.fields["password"].widget.attrs.update(
            {
                "class": "form-control password-input",
                "placeholder": "Password",
                "autocomplete": "current-password",
            }
        )
        self.error_messages["invalid_login"] = (
            "Invalid username or password."
        )

    def clean_username(self):
        return self.cleaned_data["username"].strip().upper()


class EmployeeRegisterForm(UserCreationForm):
    first_name = forms.CharField(
        max_length=150,
        label="First name",
        widget=forms.TextInput(
            attrs={
                "placeholder": "FIRST NAME",
                "autocomplete": "given-name",
                "class": "form-control text-upper",
            }
        ),
    )
    last_name = forms.CharField(
        max_length=150,
        label="Last name",
        widget=forms.TextInput(
            attrs={
                "placeholder": "LAST NAME",
                "autocomplete": "family-name",
                "class": "form-control text-upper",
            }
        ),
    )
    email = forms.EmailField(
        required=True,
        label="Personal email",
        widget=forms.EmailInput(
            attrs={
                "placeholder": "you@email.com",
                "autocomplete": "email",
                "class": "form-control text-lower",
            }
        ),
    )
    country_code = forms.ChoiceField(
        label="Country",
        choices=country_choices,
        initial=DEFAULT_COUNTRY,
        widget=forms.HiddenInput(attrs={"id": "id_country_code"}),
    )
    phone = forms.CharField(
        max_length=30,
        required=True,
        label="Phone number",
        widget=forms.TextInput(
            attrs={
                "placeholder": "7XX XXX XXX",
                "autocomplete": "tel-national",
                "inputmode": "tel",
                "class": "form-control text-upper phone-local",
            }
        ),
    )
    login_code = forms.CharField(
        min_length=6,
        max_length=6,
        label="6-digit login code",
        help_text="Choose a unique code you will use to sign in (this is your username, not your password).",
        widget=forms.TextInput(
            attrs={
                "placeholder": "000000",
                "inputmode": "numeric",
                "pattern": "[0-9]{6}",
                "maxlength": "6",
                "autocomplete": "off",
                "class": "form-control join-code-input",
                "id": "id_login_code",
            }
        ),
    )
    company_join_code = forms.CharField(
        min_length=6,
        max_length=6,
        label="Company join code",
        help_text="Ask your company admin for the 6-digit company join code.",
        widget=forms.TextInput(
            attrs={
                "placeholder": "000000",
                "inputmode": "numeric",
                "pattern": "[0-9]{6}",
                "maxlength": "6",
                "autocomplete": "off",
                "class": "form-control join-code-input",
                "id": "id_company_join_code",
            }
        ),
    )
    profile_photo = forms.ImageField(
        required=False,
        label="Profile photo (optional)",
        widget=forms.FileInput(
            attrs={
                "accept": "image/*",
                "class": "form-control form-file",
            }
        ),
    )

    class Meta:
        model = User
        fields = (
            "username",
            "first_name",
            "last_name",
            "email",
            "country_code",
            "phone",
            "company_join_code",
            "login_code",
            "password1",
            "password2",
            "profile_photo",
        )
        widgets = {
            "username": forms.TextInput(
                attrs={
                    "placeholder": "USERNAME",
                    "autocomplete": "username",
                    "class": "form-control text-upper",
                }
            ),
        }
        labels = {
            "username": "Username",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].label = "Username"
        self.fields["password1"].label = "Password"
        self.fields["password2"].label = "Confirm password"
        self.fields["password1"].help_text = (
            "At least 12 characters, not entirely numeric, and not a common password."
        )
        self.fields["password2"].help_text = ""
        self.fields["password1"].widget.attrs.update(
            {
                "placeholder": "Create a strong password",
                "autocomplete": "new-password",
                "class": "form-control password-input",
            }
        )
        self.fields["password2"].widget.attrs.update(
            {
                "placeholder": "Confirm password",
                "autocomplete": "new-password",
                "class": "form-control password-input",
            }
        )
        self.country_options = get_country_options()
        selected = self.data.get("country_code") if self.is_bound else self.fields["country_code"].initial
        self.selected_country = option_for_value(selected or DEFAULT_COUNTRY)
        self._organization = None

    def clean_username(self):
        return self.cleaned_data["username"].strip().upper()

    def clean_first_name(self):
        return self.cleaned_data["first_name"].strip().upper()

    def clean_last_name(self):
        return self.cleaned_data["last_name"].strip().upper()

    def clean_email(self):
        return self.cleaned_data["email"].strip().lower()

    def clean_login_code(self):
        code = "".join(ch for ch in (self.cleaned_data.get("login_code") or "") if ch.isdigit())
        if len(code) != 6:
            raise forms.ValidationError("Enter a 6-digit login code.")
        if Employee.objects.filter(login_code=code).exists():
            raise forms.ValidationError("This login code is not available. Choose another.")
        return code

    def clean_company_join_code(self):
        code = "".join(
            ch for ch in (self.cleaned_data.get("company_join_code") or "") if ch.isdigit()
        )
        if len(code) != 6:
            raise forms.ValidationError("Enter your company's 6-digit join code.")
        organization = Organization.objects.filter(join_code=code).first()
        if organization is None:
            raise forms.ValidationError("Invalid company join code.")
        if organization.status == Organization.Status.SUSPENDED:
            raise forms.ValidationError("This company account is suspended.")
        self._organization = organization
        return code

    def clean(self):
        cleaned = super().clean()
        country = cleaned.get("country_code") or DEFAULT_COUNTRY
        phone = cleaned.get("phone") or ""
        cleaned["phone"] = normalize_phone(country, phone)
        if not cleaned.get("phone"):
            self.add_error("phone", "Enter a valid phone number.")
        if self._organization is not None:
            cleaned["organization"] = self._organization
        return cleaned


class EmployeeLoginForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].label = "6-digit login code"
        self.fields["username"].widget.attrs.update(
            {
                "class": "form-control join-code-input",
                "placeholder": "000000",
                "inputmode": "numeric",
                "pattern": "[0-9]{6}",
                "maxlength": "6",
                "autocomplete": "username",
            }
        )
        self.fields["password"].widget.attrs.update(
            {
                "class": "form-control password-input",
                "placeholder": "Password",
                "autocomplete": "current-password",
            }
        )
        self.error_messages["invalid_login"] = (
            "Invalid login code or password."
        )

    def clean_username(self):
        code = "".join(ch for ch in (self.cleaned_data.get("username") or "") if ch.isdigit())
        if len(code) != 6:
            raise forms.ValidationError("Enter your 6-digit login code.")
        employee = Employee.objects.filter(login_code=code).select_related("user").first()
        self._employee = employee
        # Do not reveal whether the login code exists — let auth fail generically.
        if employee:
            return employee.user.get_username()
        return f"__missing_login_code_{code}__"

    def confirm_login_allowed(self, user):
        super().confirm_login_allowed(user)
        employee = Employee.objects.filter(user=user).select_related("organization").first()
        if not employee:
            raise forms.ValidationError(
                self.error_messages["invalid_login"],
                code="invalid_login",
                params={"username": self.username_field.verbose_name},
            )
        if employee.status == Employee.Status.SUSPENDED:
            raise forms.ValidationError(
                "Your account is suspended. Contact your company administrator.",
                code="suspended",
            )
        if employee.status == Employee.Status.BURNED:
            raise forms.ValidationError(
                "This employee account has been burned and can no longer sign in.",
                code="burned",
            )


class EmployeeProfileForm(forms.Form):
    first_name = forms.CharField(
        max_length=150,
        label="First name",
        widget=forms.TextInput(
            attrs={
                "placeholder": "FIRST NAME",
                "autocomplete": "given-name",
                "class": "form-control text-upper",
            }
        ),
    )
    last_name = forms.CharField(
        max_length=150,
        label="Last name",
        widget=forms.TextInput(
            attrs={
                "placeholder": "LAST NAME",
                "autocomplete": "family-name",
                "class": "form-control text-upper",
            }
        ),
    )
    email = forms.EmailField(
        required=True,
        label="Personal email",
        widget=forms.EmailInput(
            attrs={
                "placeholder": "you@email.com",
                "autocomplete": "email",
                "class": "form-control text-lower",
            }
        ),
    )
    phone = forms.CharField(
        max_length=30,
        required=True,
        label="Phone number",
        widget=forms.TextInput(
            attrs={
                "placeholder": "+2547XXXXXXXX",
                "autocomplete": "tel",
                "inputmode": "tel",
                "class": "form-control",
            }
        ),
    )
    profile_photo = forms.ImageField(
        required=False,
        label="Profile photo",
        widget=forms.FileInput(
            attrs={
                "accept": "image/*",
                "class": "org-edit-file-input",
                "id": "id_profile_photo",
            }
        ),
    )
    password1 = forms.CharField(
        required=False,
        label="New password",
        help_text="Leave blank to keep your current password. At least 12 characters; not entirely numeric.",
        widget=forms.PasswordInput(
            attrs={
                "placeholder": "New strong password",
                "autocomplete": "new-password",
                "class": "form-control password-input",
            }
        ),
    )
    password2 = forms.CharField(
        required=False,
        label="Confirm new password",
        widget=forms.PasswordInput(
            attrs={
                "placeholder": "Confirm new password",
                "autocomplete": "new-password",
                "class": "form-control password-input",
            }
        ),
    )

    def __init__(self, *args, user=None, employee=None, **kwargs):
        self.user = user
        self.employee = employee
        super().__init__(*args, **kwargs)

    def clean_first_name(self):
        return self.cleaned_data["first_name"].strip().upper()

    def clean_last_name(self):
        return self.cleaned_data["last_name"].strip().upper()

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        qs = User.objects.filter(email__iexact=email)
        if self.user:
            qs = qs.exclude(pk=self.user.pk)
        if qs.exists():
            raise forms.ValidationError("That email is already in use.")
        return email

    def clean_phone(self):
        phone = (self.cleaned_data.get("phone") or "").strip()
        digits = re.sub(r"\D", "", phone)
        if len(digits) < 8:
            raise forms.ValidationError("Enter a valid phone number.")
        if phone.startswith("+"):
            return f"+{digits}"
        return f"+{digits}"

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1") or ""
        p2 = cleaned.get("password2") or ""
        if p1 or p2:
            try:
                cleaned["password1"] = validate_account_password(
                    p1, p2, user=self.user
                )
            except forms.ValidationError as exc:
                self.add_error("password1", exc)
        return cleaned

    def save(self):
        user = self.user
        employee = self.employee
        user.first_name = self.cleaned_data["first_name"]
        user.last_name = self.cleaned_data["last_name"]
        user.email = self.cleaned_data["email"]
        if self.cleaned_data.get("password1"):
            user.set_password(self.cleaned_data["password1"])
        user.save()
        employee.phone = self.cleaned_data["phone"]
        photo = self.cleaned_data.get("profile_photo")
        if photo:
            employee.profile_photo = photo
        employee.save()
        return employee


class OwnerProfileForm(forms.Form):
    """Let an organization owner update login identity and password."""

    username = forms.CharField(
        max_length=150,
        label="Username or 6-digit code",
        help_text="Sign in with this username or 6-digit code.",
        widget=forms.TextInput(
            attrs={
                "placeholder": "USERNAME OR 6-DIGIT CODE",
                "autocomplete": "username",
                "class": "form-control text-upper",
                "id": "id_owner_username",
            }
        ),
    )
    first_name = forms.CharField(
        max_length=150,
        required=False,
        label="First name",
        widget=forms.TextInput(
            attrs={
                "placeholder": "FIRST NAME",
                "autocomplete": "given-name",
                "class": "form-control text-upper",
                "id": "id_owner_first_name",
            }
        ),
    )
    last_name = forms.CharField(
        max_length=150,
        required=False,
        label="Last name",
        widget=forms.TextInput(
            attrs={
                "placeholder": "LAST NAME",
                "autocomplete": "family-name",
                "class": "form-control text-upper",
                "id": "id_owner_last_name",
            }
        ),
    )
    email = forms.EmailField(
        required=True,
        label="Email",
        widget=forms.EmailInput(
            attrs={
                "placeholder": "you@company.com",
                "autocomplete": "email",
                "class": "form-control text-lower",
                "id": "id_owner_email",
            }
        ),
    )
    password1 = forms.CharField(
        required=False,
        label="New password",
        help_text="Leave blank to keep your current password. At least 12 characters; not entirely numeric.",
        widget=forms.PasswordInput(
            attrs={
                "placeholder": "New strong password",
                "autocomplete": "new-password",
                "class": "form-control password-input",
                "id": "id_owner_password1",
            }
        ),
    )
    password2 = forms.CharField(
        required=False,
        label="Confirm new password",
        widget=forms.PasswordInput(
            attrs={
                "placeholder": "Confirm new password",
                "autocomplete": "new-password",
                "class": "form-control password-input",
                "id": "id_owner_password2",
            }
        ),
    )

    def __init__(self, *args, user=None, id_prefix="owner", **kwargs):
        self.user = user
        self.id_prefix = (id_prefix or "owner").strip() or "owner"
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            field.widget.attrs["id"] = f"id_{self.id_prefix}_{name}"

    def clean_username(self):
        username = (self.cleaned_data.get("username") or "").strip().upper()
        if not username:
            raise forms.ValidationError("Enter a username or 6-digit login code.")
        if is_six_digit_code(username):
            pass
        elif len(username) < 3:
            raise forms.ValidationError("Username must be at least 3 characters.")
        qs = User.objects.filter(username__iexact=username)
        if self.user:
            qs = qs.exclude(pk=self.user.pk)
        if qs.exists():
            raise forms.ValidationError("That username is already taken.")
        return username

    def clean_first_name(self):
        return (self.cleaned_data.get("first_name") or "").strip().upper()

    def clean_last_name(self):
        return (self.cleaned_data.get("last_name") or "").strip().upper()

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        qs = User.objects.filter(email__iexact=email)
        if self.user:
            qs = qs.exclude(pk=self.user.pk)
        if qs.exists():
            raise forms.ValidationError("That email is already in use.")
        return email

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1") or ""
        p2 = cleaned.get("password2") or ""
        if p1 or p2:
            try:
                cleaned["password1"] = validate_account_password(
                    p1, p2, user=self.user
                )
            except forms.ValidationError as exc:
                self.add_error("password1", exc)
        return cleaned

    def save(self):
        user = self.user
        user.username = self.cleaned_data["username"]
        user.first_name = self.cleaned_data.get("first_name") or ""
        user.last_name = self.cleaned_data.get("last_name") or ""
        user.email = self.cleaned_data["email"]
        if self.cleaned_data.get("password1"):
            user.set_password(self.cleaned_data["password1"])
        user.save()
        return user


class OrganizationEditForm(forms.ModelForm):
    """Company profile + M-Pesa receive method + Daraja STK Push settings."""

    SECTION_PROFILE = "profile"
    SECTION_PAYMENTS = "payments"
    SECTION_DARAJA = "daraja"
    SECTION_ALL = "all"

    PROFILE_FIELDS = ("name", "phone", "status", "profile_photo")
    PAYMENTS_FIELDS = ("mpesa_payment_type", "mpesa_number", "mpesa_account", "mpesa_account_mode")
    DARAJA_FIELDS = (
        "daraja_enabled",
        "daraja_environment",
        "daraja_consumer_key",
        "daraja_consumer_secret",
        "daraja_passkey",
    )

    class MpesaAccountMode(models.TextChoices):
        CLIENT = "client", "Client account number"
        CUSTOM = "custom", "Custom account"

    mpesa_account_mode = forms.ChoiceField(
        choices=MpesaAccountMode.choices,
        required=False,
        initial=MpesaAccountMode.CLIENT,
        widget=forms.Select(attrs={"id": "id_mpesa_account_mode", "class": "form-control"}),
        label="Manual Paybill account",
        help_text=(
            "Shown on manual Paybill payment instructions. "
            "STK Push always uses each client's account number."
        ),
    )

    class Meta:
        model = Organization
        fields = [
            "name",
            "phone",
            "status",
            "profile_photo",
            "mpesa_payment_type",
            "mpesa_number",
            "mpesa_account",
            "daraja_enabled",
            "daraja_environment",
            "daraja_consumer_key",
            "daraja_consumer_secret",
            "daraja_passkey",
        ]
        widgets = {
            "name": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "autocomplete": "organization",
                }
            ),
            "phone": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "tel",
                }
            ),
            "status": forms.Select(attrs={"class": "form-control"}),
            "profile_photo": forms.FileInput(
                attrs={
                    "class": "account-photo-input",
                    "accept": "image/*",
                    "id": "id_profile_photo",
                }
            ),
            "daraja_enabled": forms.CheckboxInput(attrs={"id": "id_daraja_enabled"}),
            "daraja_environment": forms.Select(
                attrs={"class": "form-control", "id": "id_daraja_environment"}
            ),
            "mpesa_payment_type": forms.Select(
                attrs={
                    "class": "form-control",
                    "id": "id_mpesa_payment_type",
                }
            ),
            "mpesa_number": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "inputmode": "numeric",
                    "autocomplete": "off",
                    "placeholder": "e.g. 522522 or 174379",
                    "id": "id_mpesa_number",
                }
            ),
            "mpesa_account": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "off",
                    "placeholder": "e.g. your name, business name, or account",
                    "id": "id_mpesa_account",
                }
            ),
            "daraja_consumer_key": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "off",
                    "id": "id_daraja_consumer_key",
                }
            ),
            "daraja_consumer_secret": forms.PasswordInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "new-password",
                    "id": "id_daraja_consumer_secret",
                },
                render_value=True,
            ),
            "daraja_passkey": forms.PasswordInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "new-password",
                    "id": "id_daraja_passkey",
                },
                render_value=True,
            ),
        }
        labels = {
            "name": "Organization name",
            "phone": "Contact phone",
            "status": "Status",
            "profile_photo": "Profile photo",
            "daraja_enabled": "Enable Daraja STK Push",
            "daraja_environment": "Mode",
            "mpesa_payment_type": "Receive via",
            "mpesa_number": "Paybill / Till number",
            "mpesa_account": "Custom account value",
            "daraja_consumer_key": "Consumer key",
            "daraja_consumer_secret": "Consumer secret",
            "daraja_passkey": "Lipa Na M-Pesa passkey",
        }
        help_texts = {
            "daraja_enabled": (
                "When on, clients can pay subscriptions with M-Pesa STK Push "
                "to your Paybill or Till."
            ),
            "daraja_environment": (
                "Sandbox uses IT Support Payment Gateway credentials for testing. "
                "Production uses this organization's own Daraja app."
            ),
            "mpesa_payment_type": "Choose Paybill or Buy Goods Till to receive subscription money.",
            "mpesa_number": "Your Paybill or Till shortcode that receives M-Pesa payments.",
            "mpesa_account": (
                "Enter the Account name clients should type for manual Paybill payments "
                "(your name, company name, or any reference)."
            ),
            "daraja_consumer_key": "Required in Production mode only.",
            "daraja_consumer_secret": "Required in Production mode only.",
            "daraja_passkey": "Required in Production mode only.",
        }

    def __init__(self, *args, section=SECTION_ALL, **kwargs):
        self.section = (section or self.SECTION_ALL).strip().lower()
        super().__init__(*args, **kwargs)
        keep = None
        if self.section == self.SECTION_PROFILE:
            keep = set(self.PROFILE_FIELDS)
        elif self.section == self.SECTION_PAYMENTS:
            keep = set(self.PAYMENTS_FIELDS)
        elif self.section == self.SECTION_DARAJA:
            # Receive money + Daraja live on the same account page.
            keep = set(self.PAYMENTS_FIELDS) | set(self.DARAJA_FIELDS)
        if keep is not None:
            for name in list(self.fields):
                if name not in keep:
                    self.fields.pop(name)
        for name in (
            "status",
            "profile_photo",
            "mpesa_payment_type",
            "mpesa_number",
            "mpesa_account",
            "mpesa_account_mode",
            "daraja_consumer_key",
            "daraja_consumer_secret",
            "daraja_passkey",
        ):
            if name in self.fields:
                self.fields[name].required = False
        if "daraja_environment" in self.fields and not (
            self.instance.daraja_environment or ""
        ).strip():
            self.initial.setdefault(
                "daraja_environment", Organization.DarajaEnvironment.SANDBOX
            )
        if "mpesa_account_mode" in self.fields and not self.data:
            has_custom = bool((getattr(self.instance, "mpesa_account", None) or "").strip())
            self.initial["mpesa_account_mode"] = (
                self.MpesaAccountMode.CUSTOM
                if has_custom
                else self.MpesaAccountMode.CLIENT
            )

    def clean_name(self):
        return self.cleaned_data["name"].strip().upper()

    def clean_phone(self):
        return (self.cleaned_data.get("phone") or "").strip()

    def clean_mpesa_number(self):
        return (self.cleaned_data.get("mpesa_number") or "").strip()

    def clean_mpesa_account(self):
        return (self.cleaned_data.get("mpesa_account") or "").strip()

    def clean_daraja_consumer_key(self):
        return (self.cleaned_data.get("daraja_consumer_key") or "").strip()

    def clean_daraja_consumer_secret(self):
        return (self.cleaned_data.get("daraja_consumer_secret") or "").strip()

    def clean_daraja_passkey(self):
        return (self.cleaned_data.get("daraja_passkey") or "").strip()

    def _validate_receive_method(self, cleaned):
        payment_type = (cleaned.get("mpesa_payment_type") or "").strip()
        number = (cleaned.get("mpesa_number") or "").strip()
        account = (cleaned.get("mpesa_account") or "").strip()
        account_mode = (cleaned.get("mpesa_account_mode") or self.MpesaAccountMode.CLIENT).strip()

        if payment_type and not number:
            self.add_error("mpesa_number", "Enter the Paybill or Till number.")
        if number and not payment_type:
            self.add_error("mpesa_payment_type", "Select Paybill or Buy Goods Till.")
        if number and not number.isdigit():
            self.add_error("mpesa_number", "Use digits only for the Paybill or Till number.")

        if payment_type != Organization.MpesaPaymentType.PAYBILL:
            cleaned["mpesa_account"] = ""
            cleaned["mpesa_account_mode"] = self.MpesaAccountMode.CLIENT
        elif account_mode == self.MpesaAccountMode.CLIENT:
            cleaned["mpesa_account"] = ""
            cleaned["mpesa_account_mode"] = self.MpesaAccountMode.CLIENT
        else:
            cleaned["mpesa_account_mode"] = self.MpesaAccountMode.CUSTOM
            if not account:
                self.add_error(
                    "mpesa_account",
                    "Enter a custom Paybill account (name or any reference).",
                )
            elif len(account) > 64:
                self.add_error("mpesa_account", "Account reference is too long.")
            else:
                cleaned["mpesa_account"] = account

        if not payment_type:
            cleaned["mpesa_number"] = ""
            cleaned["mpesa_account"] = ""
            cleaned["mpesa_account_mode"] = self.MpesaAccountMode.CLIENT
        return payment_type, number

    def _validate_daraja(self, cleaned, payment_type, number):
        if not cleaned.get("daraja_enabled"):
            return

        environment = (
            cleaned.get("daraja_environment") or Organization.DarajaEnvironment.SANDBOX
        ).strip()
        if environment != Organization.DarajaEnvironment.PRODUCTION:
            cleaned["daraja_environment"] = Organization.DarajaEnvironment.SANDBOX
        else:
            cleaned["daraja_environment"] = Organization.DarajaEnvironment.PRODUCTION

        if not payment_type or not number:
            self.add_error(
                "daraja_enabled",
                "Select Paybill or Till and enter the number above, then enable Daraja.",
            )
            return

        if cleaned["daraja_environment"] == Organization.DarajaEnvironment.SANDBOX:
            gateway = PaymentGateway.get_solo()
            if not gateway.is_stk_ready():
                self.add_error(
                    "daraja_enabled",
                    "Sandbox needs IT Support → Payment Gateway activated with Daraja credentials first.",
                )
            return

        if not (cleaned.get("daraja_consumer_key") or "").strip():
            self.add_error("daraja_consumer_key", "Consumer key is required for Production.")
        if not (cleaned.get("daraja_consumer_secret") or "").strip():
            self.add_error(
                "daraja_consumer_secret",
                "Consumer secret is required for Production.",
            )
        if not (cleaned.get("daraja_passkey") or "").strip():
            self.add_error("daraja_passkey", "Passkey is required for Production.")

    def clean(self):
        cleaned = super().clean()
        if self.section == self.SECTION_PROFILE:
            return cleaned

        if self.section == self.SECTION_PAYMENTS:
            payment_type, number = self._validate_receive_method(cleaned)
            if self.instance.daraja_enabled and (not payment_type or not number):
                self.add_error(
                    "mpesa_payment_type",
                    "Daraja STK Push is enabled — keep Paybill/Till set, or turn Daraja off first.",
                )
            return cleaned

        if self.section == self.SECTION_DARAJA:
            payment_type, number = self._validate_receive_method(cleaned)
            self._validate_daraja(cleaned, payment_type, number)
            return cleaned

        payment_type, number = self._validate_receive_method(cleaned)
        self._validate_daraja(cleaned, payment_type, number)
        return cleaned

    def save(self, commit=True):
        org = super().save(commit=False)
        if not (org.daraja_environment or "").strip():
            org.daraja_environment = Organization.DarajaEnvironment.SANDBOX
        if not org.daraja_enabled:
            # Keep stored production secrets so re-enabling is easy.
            pass
        if commit:
            org.save()
        return org


class PaymentGatewayForm(forms.ModelForm):
    """M-Pesa Daraja STK Push settings (IT Support)."""

    class Meta:
        model = PaymentGateway
        fields = [
            "enabled",
            "environment",
            "payment_type",
            "shortcode",
            "consumer_key",
            "consumer_secret",
            "passkey",
            "callback_url",
        ]
        widgets = {
            "enabled": forms.CheckboxInput(attrs={"id": "id_gateway_enabled"}),
            "environment": forms.Select(
                attrs={"class": "form-control", "id": "id_gateway_environment"}
            ),
            "payment_type": forms.Select(
                attrs={"class": "form-control", "id": "id_gateway_payment_type"}
            ),
            "shortcode": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "inputmode": "numeric",
                    "autocomplete": "off",
                    "placeholder": "e.g. 174379",
                    "id": "id_gateway_shortcode",
                }
            ),
            "consumer_key": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "off",
                    "id": "id_gateway_consumer_key",
                }
            ),
            "consumer_secret": forms.PasswordInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "new-password",
                    "id": "id_gateway_consumer_secret",
                },
                render_value=True,
            ),
            "passkey": forms.PasswordInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "new-password",
                    "id": "id_gateway_passkey",
                },
                render_value=True,
            ),
            "callback_url": forms.URLInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "off",
                    "placeholder": "http://localhost:8000/api/mpesa/stk-callback/",
                    "id": "id_gateway_callback_url",
                }
            ),
        }
        labels = {
            "enabled": "Activate STK Push",
            "environment": "Daraja environment",
            "payment_type": "STK transaction type",
            "shortcode": "Business shortcode",
            "consumer_key": "Consumer key",
            "consumer_secret": "Consumer secret",
            "passkey": "Lipa Na M-Pesa passkey",
            "callback_url": "STK callback URL",
        }
        help_texts = {
            "enabled": "When on, the platform can send Lipa Na M-Pesa Online (STK Push) prompts.",
            "environment": (
                "Sandbox supports local testing with http://localhost:8000. "
                "Use Production only with a public HTTPS domain."
            ),
            "payment_type": "Paybill uses CustomerPayBillOnline; Till uses CustomerBuyGoodsOnline.",
            "shortcode": "The Lipa Na M-Pesa Online shortcode from Safaricom Daraja.",
            "consumer_key": "App Consumer Key from the Safaricom Daraja developer portal.",
            "consumer_secret": "App Consumer Secret from the Safaricom Daraja developer portal.",
            "passkey": "Passkey paired with your Lipa Na M-Pesa Online shortcode.",
            "callback_url": (
                "Sandbox: http://localhost:8000/api/mpesa/stk-callback/ is allowed for local testing. "
                "Production must use a public HTTPS URL."
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name in (
            "payment_type",
            "shortcode",
            "consumer_key",
            "consumer_secret",
            "passkey",
            "callback_url",
        ):
            self.fields[name].required = False
        if not self.is_bound and not (self.instance.callback_url or "").strip():
            env = self.instance.environment or PaymentGateway.Environment.SANDBOX
            self.initial["callback_url"] = PaymentGateway.default_callback_url(env)
            if not (self.instance.environment or "").strip():
                self.initial["environment"] = PaymentGateway.Environment.SANDBOX

    def clean_shortcode(self):
        return (self.cleaned_data.get("shortcode") or "").strip()

    def clean_consumer_key(self):
        return (self.cleaned_data.get("consumer_key") or "").strip()

    def clean_consumer_secret(self):
        return (self.cleaned_data.get("consumer_secret") or "").strip()

    def clean_passkey(self):
        return (self.cleaned_data.get("passkey") or "").strip()

    def clean_callback_url(self):
        return (self.cleaned_data.get("callback_url") or "").strip()

    @staticmethod
    def _is_local_sandbox_url(url: str) -> bool:
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        host = (parsed.hostname or "").lower()
        return parsed.scheme == "http" and host in {"localhost", "127.0.0.1"}

    def clean(self):
        cleaned = super().clean()
        enabled = cleaned.get("enabled")
        environment = (cleaned.get("environment") or "").strip()
        payment_type = (cleaned.get("payment_type") or "").strip()
        shortcode = (cleaned.get("shortcode") or "").strip()
        callback_url = (cleaned.get("callback_url") or "").strip()

        if enabled and not callback_url and environment == PaymentGateway.Environment.SANDBOX:
            callback_url = PaymentGateway.default_callback_url(environment)
            cleaned["callback_url"] = callback_url

        if enabled:
            if not payment_type:
                self.add_error("payment_type", "Select Paybill or Buy Goods Till.")
            if not shortcode:
                self.add_error("shortcode", "Enter the Lipa Na M-Pesa shortcode.")
            if not (cleaned.get("consumer_key") or "").strip():
                self.add_error(
                    "consumer_key", "Consumer key is required to activate STK Push."
                )
            if not (cleaned.get("consumer_secret") or "").strip():
                self.add_error(
                    "consumer_secret",
                    "Consumer secret is required to activate STK Push.",
                )
            if not (cleaned.get("passkey") or "").strip():
                self.add_error("passkey", "Passkey is required to activate STK Push.")
            if not callback_url:
                self.add_error(
                    "callback_url", "Callback URL is required to activate STK Push."
                )

        if callback_url:
            if environment == PaymentGateway.Environment.SANDBOX:
                if not (
                    callback_url.startswith("https://")
                    or self._is_local_sandbox_url(callback_url)
                ):
                    self.add_error(
                        "callback_url",
                        "Sandbox callback must be https://… or http://localhost:8000… "
                        "(local testing).",
                    )
            elif environment == PaymentGateway.Environment.PRODUCTION:
                if not callback_url.startswith("https://"):
                    self.add_error(
                        "callback_url",
                        "Production callback URL must use HTTPS (not localhost).",
                    )
                if self._is_local_sandbox_url(callback_url):
                    self.add_error(
                        "callback_url",
                        "localhost is only allowed in Sandbox.",
                    )

        if payment_type and not shortcode:
            self.add_error("shortcode", "Enter the Lipa Na M-Pesa shortcode.")
        if shortcode and not payment_type:
            self.add_error("payment_type", "Select Paybill or Buy Goods Till.")
        if shortcode and not shortcode.isdigit():
            self.add_error("shortcode", "Use digits only for the shortcode.")
        # Live Paybill/Till credentials belong on the production Daraja host.
        if shortcode and shortcode != "174379":
            cleaned["environment"] = PaymentGateway.Environment.PRODUCTION
        if not payment_type:
            cleaned["shortcode"] = ""
        return cleaned

    def save(self, commit=True):
        gateway = super().save(commit=False)
        # AccountReference for STK Push is always the client's account number.
        gateway.account_reference = ""
        shortcode = (gateway.shortcode or "").strip()
        if shortcode and shortcode != "174379":
            gateway.environment = PaymentGateway.Environment.PRODUCTION
        if (
            gateway.environment == PaymentGateway.Environment.SANDBOX
            and not (gateway.callback_url or "").strip()
        ):
            gateway.callback_url = PaymentGateway.default_callback_url(
                gateway.environment
            )
        if commit:
            gateway.save()
        return gateway


class CompanyProfileForm(forms.ModelForm):
    """Platform company profile (IT Support)."""

    clear_logo = forms.BooleanField(
        required=False,
        label="Remove current logo",
        widget=forms.CheckboxInput(attrs={"id": "id_clear_logo"}),
    )

    class Meta:
        model = CompanyProfile
        fields = ["app_name", "email", "phone", "whatsapp", "logo"]
        widgets = {
            "app_name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "organization",
                    "placeholder": "e.g. ISPCENTRIC",
                    "id": "id_app_name",
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "email",
                    "placeholder": "support@example.com",
                    "id": "id_company_email",
                }
            ),
            "phone": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "tel",
                    "placeholder": "e.g. +254712345678",
                    "id": "id_company_phone",
                }
            ),
            "whatsapp": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "autocomplete": "tel",
                    "placeholder": "e.g. +254712345678",
                    "id": "id_company_whatsapp",
                }
            ),
            "logo": forms.FileInput(
                attrs={
                    "class": "org-edit-file-input",
                    "accept": "image/*",
                    "id": "id_company_logo",
                }
            ),
        }
        labels = {
            "app_name": "App name",
            "email": "Email",
            "phone": "Phone number",
            "whatsapp": "WhatsApp number",
            "logo": "Logo",
        }
        help_texts = {
            "app_name": "Brand name shown in the sidebar and across the platform.",
            "email": "Public support or company email address.",
            "phone": "Main company phone number.",
            "whatsapp": "WhatsApp contact number for support.",
            "logo": "Square images work best. PNG or JPG up to a few MB.",
        }

    def clean_app_name(self):
        name = (self.cleaned_data.get("app_name") or "").strip()
        if not name:
            raise forms.ValidationError("Enter the app / company name.")
        return name

    def clean_email(self):
        return (self.cleaned_data.get("email") or "").strip()

    def clean_phone(self):
        return (self.cleaned_data.get("phone") or "").strip()

    def clean_whatsapp(self):
        return (self.cleaned_data.get("whatsapp") or "").strip()

    def save(self, commit=True):
        profile = super().save(commit=False)
        if self.cleaned_data.get("clear_logo") and profile.logo:
            profile.logo.delete(save=False)
            profile.logo = None
        if commit:
            profile.save()
        return profile


class RoleCommissionForm(forms.ModelForm):
    """Per-role commission rate settings (IT Support)."""

    class Meta:
        model = RoleCommission
        fields = ["enabled", "rate_type", "rate_value", "notes"]
        widgets = {
            "enabled": forms.CheckboxInput(attrs={"id": "id_commission_enabled"}),
            "rate_type": forms.Select(
                attrs={"class": "form-control", "id": "id_commission_rate_type"}
            ),
            "rate_value": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "id": "id_commission_rate_value",
                    "step": "0.01",
                    "min": "0",
                    "placeholder": "0.00",
                }
            ),
            "notes": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "id": "id_commission_notes",
                    "placeholder": "Optional note for this role",
                    "autocomplete": "off",
                }
            ),
        }
        labels = {
            "enabled": "Enable commissions",
            "rate_type": "Rate type",
            "rate_value": "Rate value",
            "notes": "Notes",
        }
        help_texts = {
            "enabled": "Turn on commission tracking for people in this role.",
            "rate_type": "Percentage of sale amount, flat amount, or price per ticket.",
            "rate_value": "For percentage use e.g. 5.00. For money amounts use e.g. 250.00.",
            "notes": "Optional note about when this commission applies.",
        }

    def clean_rate_value(self):
        value = self.cleaned_data.get("rate_value")
        if value is None:
            raise forms.ValidationError("Enter a rate value.")
        if value < 0:
            raise forms.ValidationError("Rate value cannot be negative.")
        rate_type = self.cleaned_data.get("rate_type") or self.instance.rate_type
        if rate_type in {
            RoleCommission.RateType.PERCENT,
            RoleCommission.RateType.PER_TICKET_PACKAGE,
        } and value > 100:
            raise forms.ValidationError("Percentage cannot be greater than 100.")
        return value

    def clean_notes(self):
        return (self.cleaned_data.get("notes") or "").strip()


class SalesCommissionForm(RoleCommissionForm):
    """Sales commissions: exactly one module — fixed per ticket, or % of package."""

    SALES_RATE_CHOICES = (
        (RoleCommission.RateType.PER_TICKET, "Per ticket"),
        (
            RoleCommission.RateType.PER_TICKET_PACKAGE,
            "Per ticket package price",
        ),
    )

    class Meta(RoleCommissionForm.Meta):
        fields = ["enabled", "rate_type", "rate_value", "notes"]
        labels = {
            "enabled": "Enable sales commissions",
            "rate_type": "Commission module",
            "rate_value": "Price / percentage",
            "notes": "Notes",
        }
        help_texts = {
            "enabled": "Pay sales staff for each completed sales ticket.",
            "rate_type": "Only one sales commission module can be active at a time.",
            "rate_value": (
                "For fixed price use e.g. 500.00. For package % use e.g. 10.00."
            ),
            "notes": "Optional note about when the ticket commission is paid.",
        }
        widgets = {
            "enabled": forms.CheckboxInput(attrs={"id": "id_commission_enabled"}),
            "rate_type": forms.RadioSelect(attrs={"class": "commission-module-radio"}),
            "rate_value": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "id": "id_commission_rate_value",
                    "step": "0.01",
                    "min": "0",
                    "placeholder": "0.00",
                }
            ),
            "notes": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "id": "id_commission_notes",
                    "placeholder": "Optional note for sales tickets",
                    "autocomplete": "off",
                }
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["rate_type"].choices = self.SALES_RATE_CHOICES
        if not self.is_bound:
            current = self.instance.rate_type if self.instance.pk else ""
            if current not in {
                RoleCommission.RateType.PER_TICKET,
                RoleCommission.RateType.PER_TICKET_PACKAGE,
            }:
                self.initial["rate_type"] = RoleCommission.RateType.PER_TICKET

    def clean_rate_type(self):
        rate_type = self.cleaned_data.get("rate_type")
        allowed = {c[0] for c in self.SALES_RATE_CHOICES}
        if rate_type not in allowed:
            raise forms.ValidationError("Choose exactly one sales commission module.")
        return rate_type

    def clean_rate_value(self):
        value = self.cleaned_data.get("rate_value")
        if value is None:
            raise forms.ValidationError("Enter a price or percentage.")
        if value < 0:
            raise forms.ValidationError("Value cannot be negative.")
        rate_type = self.cleaned_data.get("rate_type") or self.instance.rate_type
        if (
            rate_type == RoleCommission.RateType.PER_TICKET_PACKAGE
            and value > 100
        ):
            raise forms.ValidationError("Percentage cannot be greater than 100.")
        return value

    def save(self, commit=True):
        commission = super().save(commit=False)
        if commission.rate_type not in {
            RoleCommission.RateType.PER_TICKET,
            RoleCommission.RateType.PER_TICKET_PACKAGE,
        }:
            commission.rate_type = RoleCommission.RateType.PER_TICKET
        if commit:
            commission.save()
        return commission


class PppoeSettingsForm(forms.ModelForm):
    """Toggle PPPoE enforcement for an organization."""

    class Meta:
        model = Organization
        fields = ["pppoe_compulsory"]
        labels = {
            "pppoe_compulsory": "PPPoE enforcement",
        }
        help_texts = {
            "pppoe_compulsory": (
                "Block free LAN browsing. Registered PPPoE clients that dial in keep internet; "
                "other devices can use Hotspot login when Hotspot is enabled."
            ),
        }
        widgets = {
            "pppoe_compulsory": forms.CheckboxInput(
                attrs={"id": "id_pppoe_compulsory"}
            ),
        }


class HotspotSettingsForm(forms.ModelForm):
    """Portal, login page, welcome page, and voucher defaults for Hotspot access."""

    class Meta:
        model = Organization
        fields = [
            "hotspot_enabled",
            "hotspot_portal_title",
            "hotspot_login_message",
            "hotspot_use_welcome_page",
            "hotspot_welcome_title",
            "hotspot_welcome_message",
            "hotspot_welcome_button_label",
            "hotspot_welcome_button_url",
            "hotspot_redirect_url",
            "hotspot_voucher_validity_hours",
            "hotspot_default_download_mbps",
            "hotspot_default_upload_mbps",
            "hotspot_idle_timeout_minutes",
        ]
        labels = {
            "hotspot_enabled": "Enable Hotspot",
            "hotspot_portal_title": "Portal title",
            "hotspot_login_message": "Login message",
            "hotspot_use_welcome_page": "Use ISPCENTRIC welcome page",
            "hotspot_welcome_title": "Welcome page title",
            "hotspot_welcome_message": "Welcome page message",
            "hotspot_welcome_button_label": "Button label",
            "hotspot_welcome_button_url": "Button link (optional)",
            "hotspot_redirect_url": "Custom redirect URL",
            "hotspot_voucher_validity_hours": "Default voucher validity (hours)",
            "hotspot_default_download_mbps": "Default download (Mbps)",
            "hotspot_default_upload_mbps": "Default upload (Mbps)",
            "hotspot_idle_timeout_minutes": "Idle timeout (minutes)",
        }
        help_texts = {
            "hotspot_enabled": (
                "Turn on Hotspot portals and voucher defaults for this organization."
            ),
            "hotspot_portal_title": "Shown as the heading on the Hotspot login page.",
            "hotspot_login_message": "Short welcome text clients see before they log in.",
            "hotspot_use_welcome_page": (
                "After login, open your branded welcome page. Turn off to use a custom URL instead."
            ),
            "hotspot_welcome_title": "Headline clients see after they log in.",
            "hotspot_welcome_message": "Short message under the headline.",
            "hotspot_welcome_button_label": "Defaults to “Continue browsing” if left blank.",
            "hotspot_welcome_button_url": (
                "Where Continue browsing opens. Leave blank to use a connectivity check "
                "page (recommended for captive portals)."
            ),
            "hotspot_redirect_url": "Full URL clients open after login when the welcome page is off.",
            "hotspot_voucher_validity_hours": "Used when creating new Hotspot vouchers.",
            "hotspot_default_download_mbps": "Default download speed for new vouchers.",
            "hotspot_default_upload_mbps": "Default upload speed for new vouchers.",
            "hotspot_idle_timeout_minutes": "0 means sessions stay open until validity ends.",
        }
        widgets = {
            "hotspot_enabled": forms.CheckboxInput(attrs={"id": "id_hotspot_enabled"}),
            "hotspot_portal_title": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "e.g. Welcome to Acme Wi‑Fi",
                    "autocomplete": "off",
                }
            ),
            "hotspot_login_message": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 3,
                    "placeholder": "Enter voucher code or username to get online.",
                }
            ),
            "hotspot_use_welcome_page": forms.CheckboxInput(
                attrs={"id": "id_hotspot_use_welcome_page"}
            ),
            "hotspot_welcome_title": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "You're online",
                    "autocomplete": "off",
                }
            ),
            "hotspot_welcome_message": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 3,
                    "placeholder": "Enjoy your internet session. Thank you for choosing us.",
                }
            ),
            "hotspot_welcome_button_label": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Continue browsing",
                    "autocomplete": "off",
                }
            ),
            "hotspot_welcome_button_url": forms.URLInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "https://yourwebsite.com",
                    "autocomplete": "off",
                    "id": "id_hotspot_welcome_button_url",
                }
            ),
            "hotspot_redirect_url": forms.URLInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "https://example.com",
                    "autocomplete": "off",
                    "id": "id_hotspot_redirect_url",
                }
            ),
            "hotspot_voucher_validity_hours": forms.NumberInput(
                attrs={"class": "form-control", "min": 1, "step": 1}
            ),
            "hotspot_default_download_mbps": forms.NumberInput(
                attrs={"class": "form-control", "min": 1, "step": 1}
            ),
            "hotspot_default_upload_mbps": forms.NumberInput(
                attrs={"class": "form-control", "min": 1, "step": 1}
            ),
            "hotspot_idle_timeout_minutes": forms.NumberInput(
                attrs={"class": "form-control", "min": 0, "step": 1}
            ),
        }

    def clean_hotspot_portal_title(self):
        return (self.cleaned_data.get("hotspot_portal_title") or "").strip()

    def clean_hotspot_login_message(self):
        return (self.cleaned_data.get("hotspot_login_message") or "").strip()

    def clean_hotspot_welcome_title(self):
        return (self.cleaned_data.get("hotspot_welcome_title") or "").strip()

    def clean_hotspot_welcome_message(self):
        return (self.cleaned_data.get("hotspot_welcome_message") or "").strip()

    def clean_hotspot_welcome_button_label(self):
        return (self.cleaned_data.get("hotspot_welcome_button_label") or "").strip()

    def clean_hotspot_welcome_button_url(self):
        return (self.cleaned_data.get("hotspot_welcome_button_url") or "").strip()

    def clean_hotspot_redirect_url(self):
        return (self.cleaned_data.get("hotspot_redirect_url") or "").strip()

    def clean(self):
        cleaned = super().clean()
        use_welcome = cleaned.get("hotspot_use_welcome_page")
        redirect_url = cleaned.get("hotspot_redirect_url") or ""
        if not use_welcome and not redirect_url:
            self.add_error(
                "hotspot_redirect_url",
                "Enter a custom redirect URL, or turn on the ISPCENTRIC welcome page.",
            )
        return cleaned

    def clean_hotspot_voucher_validity_hours(self):
        value = self.cleaned_data.get("hotspot_voucher_validity_hours")
        if value is None or value < 1:
            raise forms.ValidationError("Validity must be at least 1 hour.")
        return value

    def clean_hotspot_default_download_mbps(self):
        value = self.cleaned_data.get("hotspot_default_download_mbps")
        if value is None or value < 1:
            raise forms.ValidationError("Download speed must be at least 1 Mbps.")
        return value

    def clean_hotspot_default_upload_mbps(self):
        value = self.cleaned_data.get("hotspot_default_upload_mbps")
        if value is None or value < 1:
            raise forms.ValidationError("Upload speed must be at least 1 Mbps.")
        return value


class EmployeeAdminEditForm(forms.Form):
    first_name = forms.CharField(
        max_length=150,
        label="First name",
        widget=forms.TextInput(
            attrs={
                "class": "form-control text-upper",
                "autocomplete": "given-name",
            }
        ),
    )
    last_name = forms.CharField(
        max_length=150,
        label="Last name",
        widget=forms.TextInput(
            attrs={
                "class": "form-control text-upper",
                "autocomplete": "family-name",
            }
        ),
    )
    email = forms.EmailField(
        required=True,
        label="Email",
        widget=forms.EmailInput(
            attrs={
                "class": "form-control text-lower",
                "autocomplete": "email",
            }
        ),
    )
    phone = forms.CharField(
        max_length=30,
        required=False,
        label="Phone",
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "autocomplete": "tel",
            }
        ),
    )
    organization = forms.ModelChoiceField(
        queryset=Organization.objects.none(),
        required=False,
        empty_label="— No organization —",
        label="Organization",
        help_text="Optional for Sales and Technician. Required for company-scoped roles.",
        widget=forms.Select(attrs={"class": "form-control"}),
    )
    role = forms.ChoiceField(
        choices=Employee.Role.choices,
        label="Role",
        widget=forms.Select(attrs={"class": "form-control"}),
    )
    status = forms.ChoiceField(
        choices=Employee.Status.choices,
        label="Status",
        widget=forms.Select(attrs={"class": "form-control"}),
    )
    profile_photo = forms.ImageField(
        required=False,
        label="Profile photo",
        widget=forms.FileInput(
            attrs={
                "class": "org-edit-file-input",
                "accept": "image/*",
                "id": "id_profile_photo",
            }
        ),
    )

    def __init__(self, *args, employee=None, **kwargs):
        self.employee = employee
        super().__init__(*args, **kwargs)
        self.fields["organization"].queryset = Organization.objects.order_by("name")
        if employee and not self.is_bound:
            user = employee.user
            self.fields["first_name"].initial = user.first_name
            self.fields["last_name"].initial = user.last_name
            self.fields["email"].initial = user.email
            self.fields["phone"].initial = employee.phone
            self.fields["organization"].initial = employee.organization_id
            self.fields["role"].initial = employee.role
            self.fields["status"].initial = employee.status

    def clean_first_name(self):
        return self.cleaned_data["first_name"].strip().upper()

    def clean_last_name(self):
        return self.cleaned_data["last_name"].strip().upper()

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        qs = User.objects.filter(email__iexact=email)
        if self.employee:
            qs = qs.exclude(pk=self.employee.user_id)
        if qs.exists():
            raise forms.ValidationError("That email is already in use.")
        return email

    def clean_phone(self):
        return (self.cleaned_data.get("phone") or "").strip()

    def clean(self):
        cleaned = super().clean()
        role = cleaned.get("role")
        organization = cleaned.get("organization")
        company_scoped = {
            Employee.Role.ADMINISTRATOR,
            Employee.Role.MANAGER,
            Employee.Role.IT_SUPPORT,
        }
        if role in company_scoped and organization is None:
            self.add_error(
                "organization",
                "Assign an organization for this role.",
            )
        return cleaned

    def save(self):
        employee = self.employee
        user = employee.user
        user.first_name = self.cleaned_data["first_name"]
        user.last_name = self.cleaned_data["last_name"]
        user.email = self.cleaned_data["email"]
        user.save()
        employee.phone = self.cleaned_data["phone"]
        employee.organization = self.cleaned_data.get("organization")
        employee.role = self.cleaned_data["role"]
        employee.status = self.cleaned_data["status"]
        photo = self.cleaned_data.get("profile_photo")
        if photo:
            employee.profile_photo = photo
        employee.save()
        return employee


class LeadRegisterForm(forms.ModelForm):
    """Register a sales lead with map-backed location coordinates."""

    place_id = forms.CharField(
        required=False,
        widget=forms.HiddenInput(attrs={"id": "id_lead_place_id"}),
    )
    location_lat = forms.DecimalField(
        required=False,
        max_digits=9,
        decimal_places=6,
        widget=forms.HiddenInput(attrs={"id": "id_lead_location_lat"}),
    )
    location_lng = forms.DecimalField(
        required=False,
        max_digits=9,
        decimal_places=6,
        widget=forms.HiddenInput(attrs={"id": "id_lead_location_lng"}),
    )
    country_code = forms.ChoiceField(
        label="Country",
        choices=country_choices,
        initial=DEFAULT_COUNTRY,
        widget=forms.HiddenInput(attrs={"id": "id_lead_country_code"}),
    )
    alt_country_code = forms.ChoiceField(
        label="Alt country",
        choices=country_choices,
        initial=DEFAULT_COUNTRY,
        required=False,
        widget=forms.HiddenInput(attrs={"id": "id_lead_alt_country_code"}),
    )

    class Meta:
        model = Lead
        fields = [
            "customer_category",
            "full_name",
            "phone",
            "alternative_phone",
            "email",
            "location",
            "location_lat",
            "location_lng",
            "service_type",
            "preferred_package",
            "preferred_isp",
            "lead_source",
            "preferred_installation_date",
            "customer_requirements",
        ]
        widgets = {
            "customer_category": forms.Select(
                attrs={"class": "form-control", "id": "id_lead_customer_category"}
            ),
            "full_name": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "FULL NAME",
                    "autocomplete": "name",
                    "autocapitalize": "characters",
                    "id": "id_lead_full_name",
                }
            ),
            "phone": forms.TextInput(
                attrs={
                    "class": "form-control text-upper phone-local",
                    "placeholder": "7XX XXX XXX",
                    "autocomplete": "tel-national",
                    "inputmode": "tel",
                    "id": "id_lead_phone",
                }
            ),
            "alternative_phone": forms.TextInput(
                attrs={
                    "class": "form-control text-upper phone-local",
                    "placeholder": "7XX XXX XXX",
                    "autocomplete": "tel-national",
                    "inputmode": "tel",
                    "id": "id_lead_alternative_phone",
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "class": "form-control text-lower",
                    "placeholder": "you@email.com",
                    "autocomplete": "email",
                    "autocapitalize": "off",
                }
            ),
            "location": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "START TYPING A PLACE OR ADDRESS…",
                    "autocomplete": "off",
                    "autocapitalize": "characters",
                    "spellcheck": "false",
                    "id": "id_lead_location",
                    "role": "combobox",
                    "aria-autocomplete": "list",
                    "aria-controls": "lead-location-suggest",
                }
            ),
            "service_type": forms.Select(attrs={"class": "form-control"}),
            "preferred_package": forms.Select(
                attrs={"class": "form-control", "id": "id_lead_preferred_package"}
            ),
            "preferred_isp": forms.Select(
                attrs={"class": "form-control", "id": "id_lead_preferred_isp"}
            ),
            "lead_source": forms.Select(attrs={"class": "form-control"}),
            "preferred_installation_date": forms.DateInput(
                format="%Y-%m-%d",
                attrs={
                    "class": "form-control",
                    "type": "date",
                    "id": "id_lead_preferred_installation_date",
                },
            ),
            "customer_requirements": forms.Textarea(
                attrs={
                    "class": "form-control text-upper",
                    "rows": 3,
                    "placeholder": "OPTIONAL NOTES ABOUT WHAT THE CUSTOMER NEEDS",
                    "autocapitalize": "characters",
                }
            ),
        }

    def __init__(self, *args, organization=None, **kwargs):
        from billing.models import BillingPlan
        from core.forms import CoordinateField

        super().__init__(*args, **kwargs)
        self.organization = organization

        self.fields["location_lat"] = CoordinateField(
            widget=forms.HiddenInput(attrs={"id": "id_lead_location_lat"})
        )
        self.fields["location_lng"] = CoordinateField(
            widget=forms.HiddenInput(attrs={"id": "id_lead_location_lng"})
        )

        self.fields["customer_category"].label = "Customer type"
        self.fields["full_name"].label = "Full name or company name"
        self.fields["phone"].label = "Phone number or company number"
        self.fields["alternative_phone"].label = "Alternative phone or company number"
        self.fields["email"].label = "Email address"
        self.fields["location"].label = "Location"
        self.fields["service_type"].label = "Service type"
        self.fields["preferred_package"].label = "Preferred package"
        self.fields["preferred_isp"].label = "Preferred ISP"
        self.fields["lead_source"].label = "Lead source"
        self.fields["preferred_installation_date"].label = "Preferred installation date"
        self.fields["customer_requirements"].label = "Customer requirements"
        self.fields["preferred_package"].required = False
        self.fields["preferred_isp"].required = False
        self.fields["preferred_installation_date"].required = False
        self.fields["email"].required = False
        self.fields["alternative_phone"].required = False
        self.fields["customer_requirements"].required = False
        self.fields["location"].required = True
        self.fields["preferred_installation_date"].input_formats = ["%Y-%m-%d"]

        self.country_options = get_country_options()
        selected = DEFAULT_COUNTRY
        alt_selected = DEFAULT_COUNTRY
        if self.is_bound:
            selected = self.data.get("country_code") or selected
            alt_selected = self.data.get("alt_country_code") or alt_selected
        self.selected_country = option_for_value(selected or DEFAULT_COUNTRY)
        self.alt_selected_country = option_for_value(alt_selected or DEFAULT_COUNTRY)
        self.phone_national_length = national_phone_length(selected or DEFAULT_COUNTRY)
        self.alt_phone_national_length = national_phone_length(
            alt_selected or DEFAULT_COUNTRY
        )

        org_qs = Organization.objects.exclude(
            status=Organization.Status.SUSPENDED
        ).order_by("name")
        self.fields["preferred_isp"].queryset = org_qs
        if organization is None:
            self.fields["preferred_isp"].label = "ISP / organization"
        self.fields["preferred_isp"].empty_label = "— No specific ISP —"
        self.fields["preferred_isp"].help_text = (
            "Leave open if you do not have a specific ISP in mind yet."
        )

        package_org_ids = list(org_qs.values_list("pk", flat=True))
        if organization is not None and organization.pk not in package_org_ids:
            package_org_ids.append(organization.pk)
        packages = (
            BillingPlan.objects.filter(organization_id__in=package_org_ids, is_active=True)
            .select_related("organization")
            .order_by("organization__name", "price", "name")
        )
        self._packages = packages

        preferred_isp = None
        if self.is_bound:
            raw_isp = self.data.get("preferred_isp") or ""
            if raw_isp:
                preferred_isp = org_qs.filter(pk=raw_isp).first()
        elif self.instance and self.instance.preferred_isp_id:
            preferred_isp = self.instance.preferred_isp
        scope_org = preferred_isp or organization
        if scope_org is not None:
            self.fields["preferred_package"].queryset = packages.filter(organization=scope_org)
        else:
            # No ISP chosen yet — still allow picking any active package optionally.
            self.fields["preferred_package"].queryset = packages
        self.fields["preferred_package"].empty_label = "— Optional —"

    def clean_full_name(self):
        return (self.cleaned_data.get("full_name") or "").strip().upper()

    def clean_email(self):
        return (self.cleaned_data.get("email") or "").strip().lower()

    def clean_location(self):
        return (self.cleaned_data.get("location") or "").strip().upper()

    def clean_customer_requirements(self):
        return (self.cleaned_data.get("customer_requirements") or "").strip().upper()

    def clean(self):
        from core.places import apply_resolved_coords

        cleaned = super().clean()
        country = cleaned.get("country_code") or DEFAULT_COUNTRY
        alt_country = cleaned.get("alt_country_code") or country or DEFAULT_COUNTRY

        try:
            cleaned["phone"] = validate_and_normalize_phone(
                country, cleaned.get("phone") or "", required=True
            )
        except forms.ValidationError as exc:
            self.add_error("phone", exc)

        try:
            cleaned["alternative_phone"] = validate_and_normalize_phone(
                alt_country, cleaned.get("alternative_phone") or "", required=False
            )
        except forms.ValidationError as exc:
            self.add_error("alternative_phone", exc)

        location = cleaned.get("location") or ""
        if not location:
            self.add_error("location", "Enter and select a location.")
            return cleaned

        label, lat, lng = apply_resolved_coords(
            location,
            cleaned.get("location_lat"),
            cleaned.get("location_lng"),
            place_id=cleaned.get("place_id") or "",
        )
        cleaned["location"] = (label or "").strip().upper()
        cleaned["location_lat"] = lat
        cleaned["location_lng"] = lng
        if lat is None or lng is None:
            self.add_error(
                "location",
                "Choose a suggested location so latitude and longitude can be saved.",
            )

        preferred_isp = cleaned.get("preferred_isp")
        preferred_package = cleaned.get("preferred_package")
        if preferred_package and preferred_isp and preferred_package.organization_id != preferred_isp.pk:
            self.add_error(
                "preferred_package",
                "Choose a package that belongs to the preferred ISP.",
            )
        elif preferred_package and not preferred_isp and self.organization is not None:
            if preferred_package.organization_id != self.organization.pk:
                self.add_error(
                    "preferred_package",
                    "Choose a package from your organization, or pick a preferred ISP first.",
                )
        return cleaned

    def save(self, commit=True, *, created_by=None):
        lead = super().save(commit=False)
        preferred_isp = self.cleaned_data.get("preferred_isp")
        if self.organization is not None:
            lead.organization = self.organization
        elif preferred_isp is not None:
            lead.organization = preferred_isp
        else:
            lead.organization = None
        if not lead.lead_number:
            lead.lead_number = Lead.generate_lead_number(lead.organization)
        if created_by is not None:
            lead.created_by = created_by
        if commit:
            lead.save()
            self.save_m2m()
        return lead


class NetworkEquipmentRegisterForm(forms.ModelForm):
    """Register or edit network equipment used for installs and repairs."""

    class Meta:
        model = NetworkEquipment
        fields = [
            "name",
            "equipment_type",
        ]
        widgets = {
            "name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "e.g. MikroTik hAP ax3",
                    "autocomplete": "off",
                    "id": "id_equipment_name",
                }
            ),
            "equipment_type": forms.Select(
                attrs={"class": "form-control", "id": "id_equipment_type"}
            ),
        }
        labels = {
            "name": "Equipment name",
            "equipment_type": "Type",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields["name"].widget.attrs["id"] = "id_equipment_edit_name"
            self.fields["equipment_type"].widget.attrs["id"] = "id_equipment_edit_type"

    def save(self, commit=True, *, created_by=None):
        equipment = super().save(commit=False)
        if created_by is not None and not equipment.pk:
            equipment.created_by = created_by
        if commit:
            equipment.save()
            self.save_m2m()
        return equipment
