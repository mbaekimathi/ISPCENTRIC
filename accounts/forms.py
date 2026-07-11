import re

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User

from .countries import DEFAULT_COUNTRY, country_choices, dial_from_choice, get_country_options, option_for_value
from .models import Employee, Organization


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
                "class": "form-control form-file",
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
    class Meta:
        model = Organization
        fields = ["name", "phone", "status", "profile_photo"]
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
                    "class": "org-edit-file-input",
                    "accept": "image/*",
                    "id": "id_profile_photo",
                }
            ),
        }
        labels = {
            "name": "Organization name",
            "phone": "Contact phone",
            "status": "Status",
            "profile_photo": "Profile photo",
        }

    def clean_name(self):
        return self.cleaned_data["name"].strip().upper()

    def clean_phone(self):
        return (self.cleaned_data.get("phone") or "").strip()


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
