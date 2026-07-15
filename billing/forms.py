from django import forms
from django.db.models import Q

from billing.models import BillingPlan, Customer
from core.models import MikroTikRouter


class PppoeClientRegisterForm(forms.ModelForm):
    """Register a new PPPoE subscriber for an organization."""

    class Meta:
        model = Customer
        fields = [
            "full_name",
            "phone",
            "email",
            "address",
            "plan",
            "router",
            "pppoe_username",
            "pppoe_password",
        ]
        widgets = {
            "full_name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Full name",
                    "autocomplete": "name",
                }
            ),
            "phone": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Phone number",
                    "autocomplete": "tel",
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Email (optional)",
                    "autocomplete": "email",
                }
            ),
            "address": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Install address (optional)",
                    "autocomplete": "street-address",
                }
            ),
            "plan": forms.Select(attrs={"class": "form-control"}),
            "router": forms.Select(attrs={"class": "form-control", "id": "id_pppoe_router"}),
            "pppoe_username": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "PPPoE username",
                    "autocomplete": "off",
                }
            ),
            "pppoe_password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "PPPoE password",
                    "autocomplete": "new-password",
                },
                render_value=True,
            ),
        }
        labels = {
            "full_name": "Full name",
            "phone": "Phone",
            "email": "Email",
            "address": "Address",
            "plan": "Billing plan",
            "router": "MikroTik router",
            "pppoe_username": "PPPoE username",
            "pppoe_password": "PPPoE password",
        }

    def __init__(self, *args, organization=None, **kwargs):
        self.organization = organization
        super().__init__(*args, **kwargs)
        self.fields["email"].required = False
        self.fields["address"].required = False
        self.fields["plan"].required = False
        self.fields["router"].required = True
        self.fields["plan"].empty_label = "No plan yet"
        self.fields["router"].empty_label = "Select MikroTik router"
        if organization is not None:
            self.fields["plan"].queryset = BillingPlan.objects.filter(
                organization=organization,
                is_active=True,
            ).order_by("price", "name")
            self.fields["router"].queryset = MikroTikRouter.objects.filter(
                organization=organization,
            ).order_by("name")
        else:
            self.fields["plan"].queryset = BillingPlan.objects.none()
            self.fields["router"].queryset = MikroTikRouter.objects.none()

    def clean_full_name(self):
        name = (self.cleaned_data.get("full_name") or "").strip()
        if not name:
            raise forms.ValidationError("Enter the client’s full name.")
        return name

    def clean_phone(self):
        phone = (self.cleaned_data.get("phone") or "").strip()
        if not phone:
            raise forms.ValidationError("Enter a phone number.")
        return phone

    def clean_pppoe_username(self):
        username = (self.cleaned_data.get("pppoe_username") or "").strip()
        if not username:
            raise forms.ValidationError("Enter the PPPoE username.")
        qs = Customer.objects.filter(
            organization=self.organization,
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username__iexact=username,
        )
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if self.organization and qs.exists():
            raise forms.ValidationError("That PPPoE username is already registered.")
        return username

    def clean_pppoe_password(self):
        password = self.cleaned_data.get("pppoe_password") or ""
        if not password:
            raise forms.ValidationError("Enter the PPPoE password.")
        if len(password) < 4:
            raise forms.ValidationError("PPPoE password must be at least 4 characters.")
        return password

    def clean_router(self):
        router = self.cleaned_data.get("router")
        if not router:
            raise forms.ValidationError(
                "Select the MikroTik this client dials — credentials are created there so they can get internet."
            )
        if self.organization and router.organization_id != self.organization.pk:
            raise forms.ValidationError("Choose a router from this organization.")
        return router

    def save(self, commit=True):
        customer = super().save(commit=False)
        customer.organization = self.organization
        customer.service_type = Customer.ServiceType.PPPOE
        customer.status = Customer.Status.ACTIVE
        if not customer.account_number:
            from billing.services import generate_customer_account_number

            customer.account_number = generate_customer_account_number(
                self.organization,
                prefix="PPP",
            )
        if commit:
            customer.save()
        return customer


class ClientEditForm(forms.ModelForm):
    """Edit an existing subscriber account (contact, plan, router, PPPoE)."""

    class Meta:
        model = Customer
        fields = [
            "full_name",
            "phone",
            "email",
            "address",
            "plan",
            "router",
            "pppoe_username",
            "pppoe_password",
        ]
        widgets = {
            "full_name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Full name",
                    "autocomplete": "name",
                    "id": "id_edit_full_name",
                }
            ),
            "phone": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Phone number",
                    "autocomplete": "tel",
                    "id": "id_edit_phone",
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Email (optional)",
                    "autocomplete": "email",
                    "id": "id_edit_email",
                }
            ),
            "address": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Install address (optional)",
                    "autocomplete": "street-address",
                    "id": "id_edit_address",
                }
            ),
            "plan": forms.Select(attrs={"class": "form-control", "id": "id_edit_plan"}),
            "router": forms.Select(attrs={"class": "form-control", "id": "id_edit_router"}),
            "pppoe_username": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "PPPoE username",
                    "autocomplete": "off",
                    "id": "id_edit_pppoe_username",
                }
            ),
            "pppoe_password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "PPPoE password",
                    "autocomplete": "new-password",
                    "id": "id_edit_pppoe_password",
                },
                render_value=True,
            ),
        }
        labels = {
            "full_name": "Full name",
            "phone": "Phone",
            "email": "Email",
            "address": "Address",
            "plan": "Billing plan",
            "router": "MikroTik router",
            "pppoe_username": "PPPoE username",
            "pppoe_password": "PPPoE password",
        }

    def __init__(self, *args, organization=None, **kwargs):
        self.organization = organization
        super().__init__(*args, **kwargs)
        self.fields["email"].required = False
        self.fields["address"].required = False
        self.fields["plan"].required = False
        self.fields["plan"].empty_label = "No plan"
        self.fields["router"].empty_label = "No router"
        is_pppoe = (
            self.instance
            and self.instance.pk
            and self.instance.service_type == Customer.ServiceType.PPPOE
        )
        self.fields["router"].required = bool(is_pppoe)
        if not is_pppoe:
            self.fields["pppoe_username"].required = False
            self.fields["pppoe_password"].required = False
            self.fields.pop("pppoe_username", None)
            self.fields.pop("pppoe_password", None)
        if organization is not None:
            self.fields["plan"].queryset = BillingPlan.objects.filter(
                organization=organization,
                is_active=True,
            ).order_by("price", "name")
            # Keep current plan visible even if inactive.
            if self.instance and self.instance.plan_id:
                self.fields["plan"].queryset = (
                    BillingPlan.objects.filter(organization=organization)
                    .filter(Q(is_active=True) | Q(pk=self.instance.plan_id))
                    .order_by("price", "name")
                )
            self.fields["router"].queryset = MikroTikRouter.objects.filter(
                organization=organization,
            ).order_by("name")
        else:
            self.fields["plan"].queryset = BillingPlan.objects.none()
            self.fields["router"].queryset = MikroTikRouter.objects.none()

    def clean_full_name(self):
        name = (self.cleaned_data.get("full_name") or "").strip()
        if not name:
            raise forms.ValidationError("Enter the client’s full name.")
        return name

    def clean_phone(self):
        phone = (self.cleaned_data.get("phone") or "").strip()
        if not phone:
            raise forms.ValidationError("Enter a phone number.")
        return phone

    def clean_pppoe_username(self):
        username = (self.cleaned_data.get("pppoe_username") or "").strip()
        if not username:
            raise forms.ValidationError("Enter the PPPoE username.")
        qs = Customer.objects.filter(
            organization=self.organization,
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username__iexact=username,
        )
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if self.organization and qs.exists():
            raise forms.ValidationError("That PPPoE username is already registered.")
        return username

    def clean_pppoe_password(self):
        password = self.cleaned_data.get("pppoe_password") or ""
        if not password:
            raise forms.ValidationError("Enter the PPPoE password.")
        if len(password) < 4:
            raise forms.ValidationError("PPPoE password must be at least 4 characters.")
        return password

    def clean_router(self):
        router = self.cleaned_data.get("router")
        is_pppoe = (
            self.instance
            and self.instance.pk
            and self.instance.service_type == Customer.ServiceType.PPPOE
        )
        if is_pppoe and not router:
            raise forms.ValidationError(
                "Select the MikroTik this client dials — credentials are stored there."
            )
        if router and self.organization and router.organization_id != self.organization.pk:
            raise forms.ValidationError("Choose a router from this organization.")
        return router


class ClientDeleteForm(forms.Form):
    """Confirm permanent deletion of a subscriber account."""

    confirm = forms.BooleanField(
        required=True,
        label="Confirm deletion",
        widget=forms.CheckboxInput(attrs={"id": "id_delete_client_confirm"}),
        error_messages={"required": "Confirm that you want to delete this account."},
    )


class BillingPackageRegisterForm(forms.ModelForm):
    """Register a new billing package / plan for an organization."""

    class Meta:
        model = BillingPlan
        fields = [
            "name",
            "description",
            "price",
            "download_speed_mbps",
            "upload_speed_mbps",
            "duration",
            "image",
            "is_active",
        ]
        widgets = {
            "name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": 'e.g. "Home 10 Mbps"',
                    "autocomplete": "off",
                    "id": "id_package_name",
                }
            ),
            "description": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "placeholder": "Optional package details",
                    "rows": 3,
                    "id": "id_package_description",
                }
            ),
            "price": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "0.00",
                    "step": "0.01",
                    "min": "0",
                    "id": "id_package_price",
                }
            ),
            "download_speed_mbps": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "10",
                    "min": "1",
                    "id": "id_package_download_speed",
                }
            ),
            "upload_speed_mbps": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "5",
                    "min": "1",
                    "id": "id_package_upload_speed",
                }
            ),
            "duration": forms.Select(
                attrs={
                    "class": "form-control",
                    "id": "id_package_duration",
                }
            ),
            "image": forms.FileInput(
                attrs={
                    "class": "org-edit-file-input",
                    "accept": "image/*",
                    "id": "id_package_image",
                }
            ),
            "is_active": forms.CheckboxInput(
                attrs={
                    "id": "id_package_is_active",
                }
            ),
        }
        labels = {
            "name": "Package name",
            "description": "Description",
            "price": "Price",
            "download_speed_mbps": "Download speed (Mbps)",
            "upload_speed_mbps": "Upload speed (Mbps)",
            "duration": "Billing period",
            "image": "Package image",
            "is_active": "Active package",
        }

    def __init__(self, *args, organization=None, **kwargs):
        self.organization = organization
        super().__init__(*args, **kwargs)
        self.fields["description"].required = False
        self.fields["image"].required = False
        self.fields["is_active"].required = False
        if not self.is_bound and not self.initial.get("is_active"):
            self.fields["is_active"].initial = True

    def clean_name(self):
        name = (self.cleaned_data.get("name") or "").strip()
        if not name:
            raise forms.ValidationError("Enter a package name.")
        qs = BillingPlan.objects.filter(
            organization=self.organization,
            name__iexact=name,
        )
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if self.organization and qs.exists():
            raise forms.ValidationError("A package with that name already exists.")
        return name

    def clean_description(self):
        return (self.cleaned_data.get("description") or "").strip()

    def clean_image(self):
        image = self.cleaned_data.get("image")
        if not image:
            return image
        content_type = getattr(image, "content_type", "") or ""
        if content_type and not content_type.startswith("image/"):
            raise forms.ValidationError("Upload an image file (PNG, JPG, or WebP).")
        # ~5 MB limit
        if getattr(image, "size", 0) > 5 * 1024 * 1024:
            raise forms.ValidationError("Image must be 5 MB or smaller.")
        return image

    def clean_price(self):
        price = self.cleaned_data.get("price")
        if price is None:
            raise forms.ValidationError("Enter the package price.")
        if price < 0:
            raise forms.ValidationError("Price cannot be negative.")
        return price

    def clean_download_speed_mbps(self):
        speed = self.cleaned_data.get("download_speed_mbps")
        if not speed or speed < 1:
            raise forms.ValidationError("Enter a download speed of at least 1 Mbps.")
        return speed

    def clean_upload_speed_mbps(self):
        speed = self.cleaned_data.get("upload_speed_mbps")
        if not speed or speed < 1:
            raise forms.ValidationError("Enter an upload speed of at least 1 Mbps.")
        return speed

    def save(self, commit=True):
        plan = super().save(commit=False)
        plan.organization = self.organization
        if self.cleaned_data.get("is_active") is None:
            plan.is_active = True
        plan.sync_general_speed()
        if commit:
            plan.save()
        return plan
