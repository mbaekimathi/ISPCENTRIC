from datetime import date, datetime, time, timedelta

from django import forms
from django.utils import timezone

from accounts.countries import DEFAULT_COUNTRY, country_choices, get_country_options, option_for_value
from accounts.forms import national_phone_length, validate_and_normalize_phone
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
            "router",
            "address",
            "house_number",
            "plan",
            "pppoe_username",
            "pppoe_password",
            "cpe_username",
            "cpe_password",
        ]
        widgets = {
            "full_name": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "Full name",
                    "autocomplete": "name",
                }
            ),
            "phone": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
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
            "router": forms.Select(attrs={"class": "form-control", "id": "id_pppoe_router"}),
            "address": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "Install address (optional)",
                    "autocomplete": "street-address",
                }
            ),
            "house_number": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "House / unit number",
                    "autocomplete": "address-line2",
                }
            ),
            "plan": forms.Select(attrs={"class": "form-control"}),
            "pppoe_username": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
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
            "router": "MikroTik router",
            "address": "Address",
            "house_number": "House number",
            "plan": "Billing plan",
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
        self.fields["house_number"].required = False
        self.fields["plan"].required = False
        self.fields["cpe_username"].required = False
        self.fields["cpe_password"].required = False
        self.fields["pppoe_username"].required = False
        # Router is required so the PPPoE secret can be installed on the NAS.
        self.fields["router"].required = True
        self.fields["plan"].empty_label = "No plan yet"
        self.fields["router"].empty_label = "Select MikroTik router"
        if not self.is_bound and not (self.initial.get("cpe_username") or getattr(self.instance, "cpe_username", "")):
            self.fields["cpe_username"].initial = "admin"
        if organization is not None:
            from billing.services import plans_for_router

            router = None
            if self.is_bound:
                raw_router = self.data.get("router")
                if raw_router:
                    router = (
                        MikroTikRouter.objects.filter(
                            pk=raw_router, organization=organization
                        ).first()
                    )
            elif self.initial.get("router"):
                router = self.initial.get("router")
            elif getattr(self.instance, "router_id", None):
                router = self.instance.router
            self.fields["plan"].queryset = plans_for_router(organization, router)
            self.fields["router"].queryset = MikroTikRouter.objects.filter(
                organization=organization,
            ).order_by("name")
        else:
            self.fields["plan"].queryset = BillingPlan.objects.none()
            self.fields["router"].queryset = MikroTikRouter.objects.none()

    def clean_full_name(self):
        name = (self.cleaned_data.get("full_name") or "").strip().upper()
        if not name:
            raise forms.ValidationError("Enter the client’s full name.")
        return name

    def clean_phone(self):
        phone = (self.cleaned_data.get("phone") or "").strip().upper()
        if not phone:
            raise forms.ValidationError("Enter a phone number.")
        return phone

    def clean_email(self):
        return (self.cleaned_data.get("email") or "").strip().lower()

    def clean_address(self):
        return (self.cleaned_data.get("address") or "").strip().upper()

    def clean_house_number(self):
        return (self.cleaned_data.get("house_number") or "").strip().upper()

    def clean_pppoe_username(self):
        return (self.cleaned_data.get("pppoe_username") or "").strip().upper()

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

    def clean(self):
        cleaned = super().clean()
        phone = (cleaned.get("phone") or "").strip().upper()
        username = (cleaned.get("pppoe_username") or "").strip().upper()
        if not username and phone:
            username = phone
        cleaned["pppoe_username"] = username
        if not username:
            self.add_error("pppoe_username", "Enter the PPPoE username.")
        elif self.organization:
            qs = Customer.objects.filter(
                organization=self.organization,
                service_type=Customer.ServiceType.PPPOE,
                pppoe_username__iexact=username,
            )
            if self.instance and self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                self.add_error("pppoe_username", "That PPPoE username is already registered.")
        plan = cleaned.get("plan")
        router = cleaned.get("router")
        if plan and router and not plan.is_available_on_router(router):
            self.add_error(
                "plan",
                "That package is not linked to the selected MikroTik.",
            )
        return cleaned

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
            from billing.services import generate_account_number_from_phone

            customer.account_number = generate_account_number_from_phone(
                customer.phone,
                organization=self.organization,
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


class SalesClientRegisterForm(forms.ModelForm):
    """Sales registration of a personal client (contact + map location)."""

    place_id = forms.CharField(
        required=False,
        widget=forms.HiddenInput(attrs={"id": "id_client_place_id"}),
    )
    location_lat = forms.DecimalField(
        required=False,
        max_digits=9,
        decimal_places=6,
        widget=forms.HiddenInput(attrs={"id": "id_client_location_lat"}),
    )
    location_lng = forms.DecimalField(
        required=False,
        max_digits=9,
        decimal_places=6,
        widget=forms.HiddenInput(attrs={"id": "id_client_location_lng"}),
    )
    country_code = forms.ChoiceField(
        label="Country",
        choices=country_choices,
        initial=DEFAULT_COUNTRY,
        widget=forms.HiddenInput(attrs={"id": "id_client_country_code"}),
    )

    class Meta:
        model = Customer
        fields = [
            "organization",
            "full_name",
            "phone",
            "email",
            "address",
            "location_lat",
            "location_lng",
            "building_name",
            "house_number",
        ]
        widgets = {
            "organization": forms.Select(
                attrs={
                    "class": "form-control",
                    "id": "id_client_organization",
                }
            ),
            "full_name": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "FULL NAME",
                    "autocomplete": "name",
                    "autocapitalize": "characters",
                }
            ),
            "phone": forms.TextInput(
                attrs={
                    "class": "form-control text-upper phone-local",
                    "placeholder": "7XX XXX XXX",
                    "autocomplete": "tel-national",
                    "inputmode": "tel",
                    "id": "id_client_phone",
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
            "address": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "START TYPING A PLACE OR ADDRESS…",
                    "autocomplete": "off",
                    "autocapitalize": "characters",
                    "spellcheck": "false",
                    "id": "id_client_location",
                    "role": "combobox",
                    "aria-autocomplete": "list",
                    "aria-controls": "client-location-suggest",
                }
            ),
            "building_name": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "BUILDING NAME",
                    "autocomplete": "organization",
                    "autocapitalize": "characters",
                    "id": "id_client_building_name",
                }
            ),
            "house_number": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "HOUSE / UNIT NUMBER (OPTIONAL)",
                    "autocomplete": "address-line2",
                    "autocapitalize": "characters",
                    "id": "id_client_house_number",
                }
            ),
        }
        labels = {
            "organization": "ISP provider",
            "full_name": "Full name",
            "phone": "Phone number",
            "email": "Email",
            "address": "Location",
            "building_name": "Building name",
            "house_number": "House number",
        }

    def __init__(self, *args, organization=None, organizations=None, **kwargs):
        from core.forms import CoordinateField

        super().__init__(*args, **kwargs)
        self.organization = organization

        from accounts.models import Organization

        self.fields["location_lat"] = CoordinateField(
            widget=forms.HiddenInput(attrs={"id": "id_client_location_lat"})
        )
        self.fields["location_lng"] = CoordinateField(
            widget=forms.HiddenInput(attrs={"id": "id_client_location_lng"})
        )

        org_qs = organizations
        if org_qs is None:
            org_qs = Organization.objects.order_by("name")
        self.fields["organization"].queryset = org_qs
        self.fields["organization"].required = False
        self.fields["organization"].empty_label = "— No specific ISP provider —"
        self.fields["email"].required = False
        self.fields["address"].required = True
        self.fields["building_name"].required = True
        self.fields["house_number"].required = False
        self.country_options = get_country_options()
        selected = DEFAULT_COUNTRY
        if self.is_bound:
            selected = self.data.get(self.add_prefix("country_code")) or selected
        elif self.fields["country_code"].initial:
            selected = self.fields["country_code"].initial
        self.selected_country = option_for_value(selected or DEFAULT_COUNTRY)
        self.phone_national_length = national_phone_length(selected or DEFAULT_COUNTRY)

    def clean_full_name(self):
        name = (self.cleaned_data.get("full_name") or "").strip().upper()
        if not name:
            raise forms.ValidationError("Enter the client’s full name.")
        return name

    def clean_email(self):
        return (self.cleaned_data.get("email") or "").strip().lower()

    def clean_address(self):
        return (self.cleaned_data.get("address") or "").strip().upper()

    def clean_building_name(self):
        name = (self.cleaned_data.get("building_name") or "").strip().upper()
        if not name:
            raise forms.ValidationError("Enter the building name.")
        return name

    def clean_house_number(self):
        return (self.cleaned_data.get("house_number") or "").strip().upper()

    def clean(self):
        from core.places import apply_resolved_coords

        cleaned = super().clean()
        self.organization = cleaned.get("organization")

        country = cleaned.get("country_code") or DEFAULT_COUNTRY
        try:
            cleaned["phone"] = validate_and_normalize_phone(
                country, cleaned.get("phone") or "", required=True
            )
        except forms.ValidationError as exc:
            self.add_error("phone", exc)

        location = cleaned.get("address") or ""
        if not location:
            self.add_error("address", "Enter and select a location.")
            return cleaned

        label, lat, lng = apply_resolved_coords(
            location,
            cleaned.get("location_lat"),
            cleaned.get("location_lng"),
            place_id=cleaned.get("place_id") or "",
        )
        cleaned["address"] = (label or "").strip().upper()
        cleaned["location_lat"] = lat
        cleaned["location_lng"] = lng
        if lat is None or lng is None:
            self.add_error(
                "address",
                "Choose a suggested location so latitude and longitude can be saved.",
            )
        return cleaned

    def save(self, commit=True, *, registered_by=None):
        customer = super().save(commit=False)
        customer.organization = self.cleaned_data.get("organization")
        self.organization = customer.organization
        customer.service_type = Customer.ServiceType.PPPOE
        customer.status = (
            Customer.Status.ALLOCATED
            if customer.organization_id
            else Customer.Status.NEW
        )
        if registered_by is not None:
            customer.registered_by = registered_by
        if not customer.account_number:
            from billing.services import generate_account_number_from_phone

            customer.account_number = generate_account_number_from_phone(
                customer.phone,
                organization=customer.organization,
            )
        if not customer.sales_ticket_number:
            from billing.services import generate_sales_ticket_number

            customer.sales_ticket_number = generate_sales_ticket_number(
                customer.organization
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
            from billing.services import plans_for_router

            router = getattr(self.instance, "router", None)
            self.fields["plan"].queryset = plans_for_router(self.organization, router)
        else:
            self.fields["plan"].queryset = BillingPlan.objects.none()

    def clean_plan(self):
        plan = self.cleaned_data.get("plan")
        if not plan:
            raise forms.ValidationError("Select a billing plan.")
        router = getattr(self.instance, "router", None)
        if plan and router and not plan.is_available_on_router(router):
            raise forms.ValidationError(
                "That package is not linked to this client’s MikroTik."
            )
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
    """Set plan and package window together.

    Hourly plans use clock fields; other durations use date fields.
    The template shows the matching pair based on the selected plan.
    """

    start_date = forms.DateField(
        label="Package starts",
        required=False,
        input_formats=["%Y-%m-%d"],
        widget=forms.DateInput(
            format="%Y-%m-%d",
            attrs={
                "class": "form-control",
                "type": "date",
                "id": "id_package_start_date",
            },
        ),
    )
    end_date = forms.DateField(
        label="Package ends",
        required=False,
        input_formats=["%Y-%m-%d"],
        widget=forms.DateInput(
            format="%Y-%m-%d",
            attrs={
                "class": "form-control",
                "type": "date",
                "id": "id_package_end_date",
                "readonly": "readonly",
            },
        ),
        help_text="Auto-fills from the selected package period when you change the start date.",
    )
    start_time = forms.TimeField(
        label="Starts at",
        required=False,
        input_formats=["%H:%M", "%H:%M:%S"],
        widget=forms.TimeInput(
            format="%H:%M",
            attrs={
                "class": "form-control",
                "type": "time",
                "id": "id_package_start_time",
            },
        ),
    )
    end_time = forms.TimeField(
        label="Ends at",
        required=False,
        input_formats=["%H:%M", "%H:%M:%S"],
        widget=forms.TimeInput(
            format="%H:%M",
            attrs={
                "class": "form-control",
                "type": "time",
                "id": "id_package_end_time",
                "readonly": "readonly",
            },
        ),
        help_text="Auto-fills one hour after the start time for hourly packages.",
    )
    service_day = forms.DateField(
        label="Day",
        required=False,
        input_formats=["%Y-%m-%d"],
        widget=forms.DateInput(
            format="%Y-%m-%d",
            attrs={
                "class": "form-control",
                "type": "date",
                "id": "id_package_service_day",
            },
        ),
        help_text="Which calendar day this hourly package applies to.",
    )

    class Meta:
        model = Customer
        fields = ["plan"]
        labels = {
            "plan": "Package / plan",
        }

    def __init__(self, *args, organization=None, **kwargs):
        self.organization = organization
        super().__init__(*args, **kwargs)

        self.fields["plan"].required = True
        self.fields["plan"].empty_label = "Select a plan"
        self.fields["plan"].widget.attrs.update({
            "class": "form-control",
            "id": "id_package_plan",
        })
        if self.organization:
            from billing.services import plans_for_router

            router = getattr(self.instance, "router", None)
            self.fields["plan"].queryset = plans_for_router(self.organization, router)
        else:
            self.fields["plan"].queryset = BillingPlan.objects.none()

        plan = self._resolve_plan()
        self.is_hourly = bool(
            plan and getattr(plan, "duration", "") == BillingPlan.Duration.HOURLY
        )

        start = getattr(self.instance, "package_start", None)
        end = getattr(self.instance, "package_end", None)
        today = timezone.localdate()
        if start:
            local_start = timezone.localtime(start)
            self.fields["start_date"].initial = local_start.date()
            self.fields["start_time"].initial = local_start.time().replace(
                second=0, microsecond=0
            )
            self.fields["service_day"].initial = local_start.date()
        else:
            self.fields["service_day"].initial = today
        if end:
            local_end = timezone.localtime(end)
            self.fields["end_date"].initial = local_end.date()
            self.fields["end_time"].initial = local_end.time().replace(
                second=0, microsecond=0
            )

        if plan and plan.duration == BillingPlan.Duration.HOURLY:
            self.fields["service_day"].help_text = (
                "Defaults to today. Pick another day if this hourly package should run then."
            )
        elif plan and plan.duration:
            self.fields["end_date"].help_text = (
                f"Auto-fills from the {plan.get_duration_display().lower()} package "
                "when you change the plan or start date."
            )

    def _resolve_plan(self):
        data = getattr(self, "data", None)
        if data is not None:
            raw = data.get("plan")
            if raw:
                try:
                    return self.fields["plan"].queryset.filter(pk=raw).first()
                except (TypeError, ValueError):
                    pass
        return getattr(self.instance, "plan", None)

    def _combine_time(self, value, *, base_day: date | None = None):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value if timezone.is_aware(value) else timezone.make_aware(
                value, timezone.get_current_timezone()
            )
        if isinstance(value, time):
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

    def clean_plan(self):
        plan = self.cleaned_data.get("plan")
        if not plan:
            raise forms.ValidationError("Select a billing plan.")
        router = getattr(self.instance, "router", None)
        if plan and router and not plan.is_available_on_router(router):
            raise forms.ValidationError(
                "That package is not linked to this client’s MikroTik."
            )
        return plan

    def clean(self):
        cleaned = super().clean()
        plan = cleaned.get("plan")
        is_hourly = bool(
            plan and getattr(plan, "duration", "") == BillingPlan.Duration.HOURLY
        )
        self.is_hourly = is_hourly

        if is_hourly:
            day = cleaned.get("service_day")
            start_raw = cleaned.get("start_time")
            end_raw = cleaned.get("end_time")
            if not day:
                self.add_error("service_day", "Select the day.")
                return cleaned
            if not start_raw:
                self.add_error("start_time", "Enter the start time.")
                return cleaned
            start = self._combine_time(start_raw, base_day=day)
            end = None
            if end_raw not in (None, ""):
                end = self._combine_time(end_raw, base_day=day)
                if end and isinstance(start, datetime) and end < start:
                    end = end + timedelta(days=1)
        else:
            start_raw = cleaned.get("start_date")
            end_raw = cleaned.get("end_date")
            if not start_raw:
                self.add_error("start_date", "Enter when the package starts.")
                return cleaned
            start = self._combine_date(start_raw)
            end = self._combine_date(end_raw) if end_raw not in (None, "") else None

        if start and plan:
            computed = compute_package_end(start, plan)
            if computed is not None:
                end = computed

        if start and end and end < start:
            field = "end_time" if is_hourly else "end_date"
            self.add_error(
                field,
                "End time cannot be before the start time."
                if is_hourly
                else "End date cannot be before the start date.",
            )

        cleaned["package_start"] = start
        cleaned["package_end"] = end
        return cleaned

    def save(self, commit=True):
        customer = super().save(commit=False)
        customer.package_start = self.cleaned_data.get("package_start")
        customer.package_end = self.cleaned_data.get("package_end")
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

    routers = forms.ModelMultipleChoiceField(
        label="MikroTik routers",
        required=False,
        queryset=MikroTikRouter.objects.none(),
        widget=forms.CheckboxSelectMultiple,
        help_text="Optional. Leave unchecked to use this package on all MikroTiks.",
    )

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
            "routers",
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
            "routers": "MikroTik routers",
        }

    def __init__(self, *args, organization=None, id_prefix="package", **kwargs):
        self.organization = organization
        self.id_prefix = id_prefix or "package"
        super().__init__(*args, **kwargs)
        self.fields["description"].required = False
        self.fields["image"].required = False
        self.fields["is_active"].required = False
        self.fields["routers"].required = False
        # Default Active only for new packages — keep the saved value when editing.
        if not self.is_bound and not getattr(self.instance, "pk", None):
            self.fields["is_active"].initial = True
        if self.organization is not None:
            self.fields["routers"].queryset = MikroTikRouter.objects.filter(
                organization=self.organization,
            ).order_by("name")
        else:
            self.fields["routers"].queryset = MikroTikRouter.objects.none()
        id_map = {
            "name": f"id_{self.id_prefix}_name",
            "description": f"id_{self.id_prefix}_description",
            "price": f"id_{self.id_prefix}_price",
            "download_speed_mbps": f"id_{self.id_prefix}_download_speed",
            "upload_speed_mbps": f"id_{self.id_prefix}_upload_speed",
            "duration": f"id_{self.id_prefix}_duration",
            "image": f"id_{self.id_prefix}_image",
            "is_active": f"id_{self.id_prefix}_is_active",
            "routers": f"id_{self.id_prefix}_routers",
        }
        for field_name, field_id in id_map.items():
            if field_name in self.fields:
                self.fields[field_name].widget.attrs["id"] = field_id
        # CheckboxSelectMultiple renders one id per option; keep a stable container id.
        self.fields["routers"].widget.attrs["class"] = "package-router-checks"

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
        # Empty upload on edit should keep the current image (FileInput clears otherwise).
        if image in (None, False):
            if self.instance and getattr(self.instance, "pk", None) and self.instance.image:
                return self.instance.image
            return None
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

    def clean_routers(self):
        routers = self.cleaned_data.get("routers")
        if not routers:
            return routers
        if self.organization is None:
            return routers
        invalid = [r for r in routers if r.organization_id != self.organization.pk]
        if invalid:
            raise forms.ValidationError("Choose MikroTiks from this organization only.")
        return routers

    def save(self, commit=True):
        plan = super().save(commit=False)
        plan.organization = self.organization
        if self.cleaned_data.get("is_active") is None:
            plan.is_active = True
        plan.sync_general_speed()
        if commit:
            plan.save()
            self.save_m2m()
        return plan
