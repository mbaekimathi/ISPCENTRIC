from datetime import date, datetime, time, timedelta

from django import forms
from django.utils import timezone

from billing.models import BillingPlan, Customer
from billing.services import compute_package_end
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
            "cpe_username",
            "cpe_password",
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
            "cpe_username": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "admin",
                    "autocomplete": "off",
                    "id": "id_pppoe_cpe_username",
                }
            ),
            "cpe_password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "CPE Winbox password (optional)",
                    "autocomplete": "new-password",
                    "id": "id_pppoe_cpe_password",
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
            "cpe_username": "CPE username",
            "cpe_password": "CPE password",
        }

    def __init__(self, *args, organization=None, **kwargs):
        self.organization = organization
        super().__init__(*args, **kwargs)
        self.fields["email"].required = False
        self.fields["address"].required = False
        self.fields["plan"].required = False
        self.fields["cpe_username"].required = False
        self.fields["cpe_password"].required = False
        # Router is required so the PPPoE secret can be installed on the NAS.
        self.fields["router"].required = True
        self.fields["plan"].empty_label = "No plan yet"
        self.fields["router"].empty_label = "Select MikroTik router"
        if not self.is_bound and not (self.initial.get("cpe_username") or getattr(self.instance, "cpe_username", "")):
            self.fields["cpe_username"].initial = "admin"
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

    def clean_cpe_username(self):
        return (self.cleaned_data.get("cpe_username") or "").strip() or "admin"

    def clean_cpe_password(self):
        return self.cleaned_data.get("cpe_password") or ""

    def clean_router(self):
        router = self.cleaned_data.get("router")
        if not router:
            raise forms.ValidationError(
                "Select the MikroTik this client dials into so the PPPoE login can be installed."
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
        if customer.plan_id and not customer.package_start:
            customer.package_start = timezone.localtime()
            customer.package_end = compute_package_end(
                customer.package_start,
                customer.plan,
            )
        if commit:
            customer.save()
        return customer


class CustomerPackageForm(forms.ModelForm):
    """Change a client's billing plan."""

    class Meta:
        model = Customer
        fields = ["plan"]
        widgets = {
            "plan": forms.Select(attrs={"class": "form-control", "id": "id_client_package_plan"}),
        }
        labels = {
            "plan": "Package / plan",
        }

    def __init__(self, *args, organization=None, **kwargs):
        self.organization = organization
        super().__init__(*args, **kwargs)
        self.fields["plan"].required = True
        self.fields["plan"].empty_label = "Select a plan"
        if self.organization:
            self.fields["plan"].queryset = BillingPlan.objects.filter(
                organization=self.organization, is_active=True,
            )
        else:
            self.fields["plan"].queryset = BillingPlan.objects.none()

    def clean_plan(self):
        plan = self.cleaned_data.get("plan")
        if not plan:
            raise forms.ValidationError("Select a billing plan.")
        return plan

    def save(self, commit=True):
        customer = super().save(commit=False)
        if customer.package_start and customer.plan_id:
            customer.package_end = compute_package_end(
                customer.package_start,
                customer.plan,
            )
        if commit:
            customer.save()
        return customer


class CustomerPeriodForm(forms.ModelForm):
    """Change a client's package start and end (calendar for months, clock for hours)."""

    class Meta:
        model = Customer
        fields = ["package_start", "package_end"]
        labels = {
            "package_start": "Package starts",
            "package_end": "Package ends",
        }

    def __init__(self, *args, organization=None, **kwargs):
        self.organization = organization
        super().__init__(*args, **kwargs)
        plan = getattr(self.instance, "plan", None)
        self.is_hourly = bool(
            plan and getattr(plan, "duration", "") == BillingPlan.Duration.HOURLY
        )

        self.fields["package_start"].required = True
        self.fields["package_end"].required = False

        if self.is_hourly:
            start_initial = None
            end_initial = None
            if getattr(self.instance, "package_start", None):
                start_initial = timezone.localtime(self.instance.package_start).time().replace(second=0, microsecond=0)
            if getattr(self.instance, "package_end", None):
                end_initial = timezone.localtime(self.instance.package_end).time().replace(second=0, microsecond=0)
            self.fields["package_start"] = forms.TimeField(
                label="Starts at",
                required=True,
                initial=start_initial,
                input_formats=["%H:%M", "%H:%M:%S"],
                widget=forms.TimeInput(
                    format="%H:%M",
                    attrs={
                        "class": "form-control",
                        "type": "time",
                        "id": "id_package_start",
                    },
                ),
            )
            self.fields["package_end"] = forms.TimeField(
                label="Ends at",
                required=False,
                initial=end_initial,
                input_formats=["%H:%M", "%H:%M:%S"],
                widget=forms.TimeInput(
                    format="%H:%M",
                    attrs={
                        "class": "form-control",
                        "type": "time",
                        "id": "id_package_end",
                    },
                ),
                help_text="Clock times apply to today. Leave blank to end one hour after the start time.",
            )
        else:
            start_initial = None
            end_initial = None
            if getattr(self.instance, "package_start", None):
                start_initial = timezone.localtime(self.instance.package_start).date()
            if getattr(self.instance, "package_end", None):
                end_initial = timezone.localtime(self.instance.package_end).date()
            help_text = (
                "Assign a billing plan to auto-calculate the end date from package settings."
            )
            if plan and plan.duration:
                help_text = (
                    f"Auto-updates from the {plan.get_duration_display().lower()} package "
                    "when you change the start date. You can still set a custom end date."
                )
            self.fields["package_start"] = forms.DateField(
                label="Package starts",
                required=True,
                initial=start_initial,
                input_formats=["%Y-%m-%d"],
                widget=forms.DateInput(
                    format="%Y-%m-%d",
                    attrs={
                        "class": "form-control",
                        "type": "date",
                        "id": "id_package_start",
                    },
                ),
            )
            self.fields["package_end"] = forms.DateField(
                label="Package ends",
                required=False,
                initial=end_initial,
                input_formats=["%Y-%m-%d"],
                widget=forms.DateInput(
                    format="%Y-%m-%d",
                    attrs={
                        "class": "form-control",
                        "type": "date",
                        "id": "id_package_end",
                    },
                ),
                help_text=help_text,
            )

    def _combine_time(self, value, *, base_day: date | None = None):
        """Turn a time into a local datetime on today (or an explicit day)."""
        if value is None:
            return None
        if isinstance(value, datetime):
            return value if timezone.is_aware(value) else timezone.make_aware(
                value, timezone.get_current_timezone()
            )
        if isinstance(value, time):
            # Hourly packages are always for the current local day when set via the clock.
            day = base_day or timezone.localdate()
            return timezone.make_aware(
                datetime.combine(day, value),
                timezone.get_current_timezone(),
            )
        if isinstance(value, date):
            return timezone.make_aware(
                datetime.combine(value, time.min),
                timezone.get_current_timezone(),
            )
        return value

    def _combine_date(self, value):
        """Turn a date (or datetime) into a local datetime at midnight."""
        if value is None:
            return None
        if isinstance(value, datetime):
            local = value if timezone.is_aware(value) else timezone.make_aware(
                value, timezone.get_current_timezone()
            )
            local = timezone.localtime(local)
            return timezone.make_aware(
                datetime.combine(local.date(), time.min),
                timezone.get_current_timezone(),
            )
        if isinstance(value, date):
            return timezone.make_aware(
                datetime.combine(value, time.min),
                timezone.get_current_timezone(),
            )
        return value

    def clean_package_start(self):
        start = self.cleaned_data.get("package_start")
        if not start:
            raise forms.ValidationError(
                "Enter when the package starts." if not self.is_hourly else "Enter the start time."
            )
        return self._combine_time(start) if self.is_hourly else self._combine_date(start)

    def clean_package_end(self):
        end = self.cleaned_data.get("package_end")
        if end is None or end == "":
            return None
        if self.is_hourly:
            start = self.cleaned_data.get("package_start")
            base_day = timezone.localtime(start).date() if isinstance(start, datetime) else timezone.localdate()
            combined = self._combine_time(end, base_day=base_day)
            # If end time is earlier than start (e.g. 23:00 → 00:00), roll to next day.
            if combined and isinstance(start, datetime) and combined < start:
                combined = combined + timedelta(days=1)
            return combined
        return self._combine_date(end)

    def clean(self):
        cleaned = super().clean()
        start = cleaned.get("package_start")
        end = cleaned.get("package_end")
        plan = getattr(self.instance, "plan", None)

        if start and plan and end is None:
            computed = compute_package_end(start, plan)
            if computed is not None:
                cleaned["package_end"] = computed
                end = computed

        if start and end and end < start:
            self.add_error(
                "package_end",
                "End time cannot be before the start time."
                if self.is_hourly
                else "End date cannot be before the start date.",
            )
        return cleaned

    def save(self, commit=True):
        customer = super().save(commit=False)
        if customer.package_start and customer.plan_id and not customer.package_end:
            customer.package_end = compute_package_end(
                customer.package_start,
                customer.plan,
            )
        if commit:
            customer.save()
        return customer


class CustomerPackagePeriodForm(forms.ModelForm):
    """Legacy combined form kept for compatibility."""

    class Meta:
        model = Customer
        fields = ["plan", "package_start", "package_end"]
        widgets = {
            "plan": forms.Select(attrs={"class": "form-control", "id": "id_package_plan"}),
            "package_start": forms.DateInput(
                format="%Y-%m-%d",
                attrs={
                    "class": "form-control",
                    "type": "date",
                    "id": "id_package_start",
                },
            ),
            "package_end": forms.DateInput(
                format="%Y-%m-%d",
                attrs={
                    "class": "form-control",
                    "type": "date",
                    "id": "id_package_end",
                },
            ),
        }
        labels = {
            "plan": "Package / plan",
            "package_start": "Package starts",
            "package_end": "Package ends",
        }

    def __init__(self, *args, organization=None, **kwargs):
        self.organization = organization
        super().__init__(*args, **kwargs)
        self.fields["plan"].required = False
        self.fields["plan"].empty_label = "No plan"
        if self.organization:
            self.fields["plan"].queryset = BillingPlan.objects.filter(
                organization=self.organization, is_active=True,
            )
        else:
            self.fields["plan"].queryset = BillingPlan.objects.none()
        self.fields["package_start"].required = True
        self.fields["package_end"].required = False
        self.fields["package_start"].input_formats = ["%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S"]
        self.fields["package_end"].input_formats = ["%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S"]
        plan = getattr(self.instance, "plan", None)
        if plan and plan.duration:
            self.fields["package_end"].help_text = (
                f"Auto-updates from the {plan.get_duration_display().lower()} package "
                "when you change the start date. You can still set a custom end date."
            )
        else:
            self.fields["package_end"].help_text = (
                "Assign a billing plan to auto-calculate the end date from package settings."
            )

    def clean_package_start(self):
        start = self.cleaned_data.get("package_start")
        if not start:
            raise forms.ValidationError("Enter when the package starts.")
        return start

    def clean(self):
        cleaned = super().clean()
        start = cleaned.get("package_start")
        end = cleaned.get("package_end")
        plan = cleaned.get("plan")

        if start and plan and end is None:
            computed = compute_package_end(start, plan)
            if computed is not None:
                cleaned["package_end"] = computed
                end = computed

        if start and end and end < start:
            self.add_error("package_end", "End date cannot be before the start date.")
        return cleaned

    def save(self, commit=True):
        customer = super().save(commit=False)
        if customer.package_start and customer.plan_id and not customer.package_end:
            customer.package_end = compute_package_end(
                customer.package_start,
                customer.plan,
            )
        if commit:
            customer.save()
        return customer


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
