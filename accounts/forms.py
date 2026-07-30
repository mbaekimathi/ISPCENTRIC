import re

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User

from .countries import DEFAULT_COUNTRY, country_choices, dial_from_choice, get_country_options, option_for_value
from .models import Employee, Organization, PaymentGateway


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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["password1"].widget.attrs.update(
            {
                "placeholder": "Create a password",
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

    def clean_username(self):
        return self.cleaned_data["username"].strip().upper()

    def clean_email(self):
        return self.cleaned_data["email"].strip().lower()

    def clean_company_name(self):
        return self.cleaned_data["company_name"].strip().upper()

    def clean(self):
        cleaned = super().clean()
        country = cleaned.get("country_code") or DEFAULT_COUNTRY
        phone = cleaned.get("phone") or ""
        cleaned["phone"] = normalize_phone(country, phone)
        return cleaned


class LoginForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs.update(
            {
                "class": "form-control text-upper",
                "placeholder": "USERNAME",
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
        help_text="Choose a unique code you will use to sign in.",
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
        self.fields["password1"].widget.attrs.update(
            {
                "placeholder": "Create a password",
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
            raise forms.ValidationError("This code is not available. Choose another 6-digit code.")
        return code

    def clean(self):
        cleaned = super().clean()
        country = cleaned.get("country_code") or DEFAULT_COUNTRY
        phone = cleaned.get("phone") or ""
        cleaned["phone"] = normalize_phone(country, phone)
        if not cleaned.get("phone"):
            self.add_error("phone", "Enter a valid phone number.")
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

    def clean_username(self):
        code = "".join(ch for ch in (self.cleaned_data.get("username") or "") if ch.isdigit())
        if len(code) != 6:
            raise forms.ValidationError("Enter your 6-digit login code.")
        employee = Employee.objects.filter(login_code=code).select_related("user").first()
        if not employee:
            raise forms.ValidationError("Invalid login code.")
        self._employee = employee
        return employee.user.get_username()

    def confirm_login_allowed(self, user):
        super().confirm_login_allowed(user)
        employee = Employee.objects.filter(user=user).select_related("organization").first()
        if not employee:
            raise forms.ValidationError(
                "This account is not registered as an employee. Use employee registration first.",
                code="not_employee",
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
        widget=forms.PasswordInput(
            attrs={
                "placeholder": "Leave blank to keep current password",
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
            if p1 != p2:
                self.add_error("password2", "Passwords do not match.")
            elif len(p1) < 8:
                self.add_error("password1", "Use at least 8 characters.")
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


class OrganizationEditForm(forms.ModelForm):
    """Company profile + M-Pesa receive method + Daraja STK Push settings."""

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
                    "placeholder": "Optional manual Paybill account",
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
            "mpesa_account": "Manual Paybill account (optional)",
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
                "Optional for manual Paybill instructions only. "
                "STK Push always uses the client account number."
            ),
            "daraja_consumer_key": "Required in Production mode only.",
            "daraja_consumer_secret": "Required in Production mode only.",
            "daraja_passkey": "Required in Production mode only.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name in (
            "status",
            "profile_photo",
            "mpesa_payment_type",
            "mpesa_number",
            "mpesa_account",
            "daraja_consumer_key",
            "daraja_consumer_secret",
            "daraja_passkey",
        ):
            self.fields[name].required = False
        if not (self.instance.daraja_environment or "").strip():
            self.initial.setdefault(
                "daraja_environment", Organization.DarajaEnvironment.SANDBOX
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

        if payment_type and not number:
            self.add_error("mpesa_number", "Enter the Paybill or Till number.")
        if number and not payment_type:
            self.add_error("mpesa_payment_type", "Select Paybill or Buy Goods Till.")
        if number and not number.isdigit():
            self.add_error("mpesa_number", "Use digits only for the Paybill or Till number.")

        if payment_type != Organization.MpesaPaymentType.PAYBILL:
            cleaned["mpesa_account"] = ""
        elif account and len(account) > 64:
            self.add_error("mpesa_account", "Account reference is too long.")

        if not payment_type:
            cleaned["mpesa_number"] = ""
            cleaned["mpesa_account"] = ""
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
                "Select Paybill or Till and enter the number in step 2, then enable Daraja again.",
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
            "hotspot_welcome_button_url": "Where the button goes. Leave blank to hide the button link.",
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
