from datetime import date, datetime, time, timedelta
from decimal import Decimal, InvalidOperation

from django import forms
from django.db.models import Q
from django.utils import timezone

from accounts.countries import DEFAULT_COUNTRY, country_choices, get_country_options, option_for_value
from accounts.forms import national_phone_length, validate_and_normalize_phone
from billing.models import BillingPlan, Customer
from billing.services import (
    PHONE_ALREADY_REGISTERED,
    clear_customer_package_pause,
    compute_package_end,
    customer_phone_is_taken,
    plan_uses_clock_time,
    plans_for_router,
)
from core.models import MikroTikRouter


def _default_client_password(length: int = 10) -> str:
    import secrets

    alphabet = "abcdefghjkmnpqrstuvwxyz23456789ACDEFGHJKLMNPQRSTUVWXYZ"
    return "".join(secrets.choice(alphabet) for _ in range(length))


class PppoeClientRegisterForm(forms.ModelForm):
    """Register a new PPPoE subscriber for an organization."""

    activate_account = forms.TypedChoiceField(
        label="Activate PPPoE account",
        choices=(
            ("1", "Activate"),
            ("0", "Do not activate"),
        ),
        coerce=lambda value: str(value).strip().lower() in {"1", "true", "yes", "on"},
        widget=forms.Select(
            attrs={
                "class": "form-control",
                "id": "id_pppoe_activate",
                "data-pppoe-activate": "1",
            }
        ),
        help_text=(
            "Active accounts can surf when a package is running. "
            "Inactive accounts can dial in but stay on the blocked profile until activation."
        ),
    )
    activation_date = forms.DateField(
        label="Activate from",
        required=False,
        widget=forms.DateInput(
            attrs={
                "type": "date",
                "class": "form-control",
                "id": "id_pppoe_activation_date",
                "data-pppoe-activation-date": "1",
            }
        ),
        help_text="Package period starts on this date.",
    )

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
                    "placeholder": "Email",
                    "autocomplete": "email",
                }
            ),
            "router": forms.Select(attrs={"class": "form-control", "id": "id_pppoe_router"}),
            "address": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "Address",
                    "autocomplete": "street-address",
                    "id": "id_pppoe_address",
                }
            ),
            "house_number": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "House / unit",
                    "autocomplete": "address-line2",
                }
            ),
            "plan": forms.Select(attrs={"class": "form-control"}),
            "pppoe_username": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "Username",
                    "autocomplete": "off",
                    "id": "id_pppoe_username",
                }
            ),
            "pppoe_password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "Password",
                    "autocomplete": "new-password",
                    "id": "id_pppoe_password",
                },
                render_value=True,
            ),
            "cpe_username": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "admin",
                    "autocomplete": "username",
                    "id": "id_pppoe_cpe_username",
                }
            ),
            "cpe_password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "Router password",
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
            "router": "MikroTik",
            "address": "Address",
            "house_number": "House number",
            "plan": "Plan",
            "pppoe_username": "Username",
            "pppoe_password": "Password",
            "cpe_username": "Username",
            "cpe_password": "Password",
        }

    def __init__(
        self,
        *args,
        organization=None,
        organizations=None,
        default_activate=True,
        allow_activate=True,
        require_serials=False,
        **kwargs,
    ):
        self.organization = organization
        self.organizations = organizations
        self.allow_activate = bool(allow_activate)
        # Technicians must record installed gear serials; other roles may skip.
        self.require_serials = bool(require_serials)
        # Technicians (and other non-activators) must register pending only.
        if not self.allow_activate:
            default_activate = False
        self.default_activate = bool(default_activate)
        super().__init__(*args, **kwargs)
        self.fields["email"].required = False
        self.fields["address"].required = False
        self.fields["house_number"].required = False
        self.fields["plan"].required = False
        self.fields["cpe_username"].required = False
        self.fields["cpe_password"].required = False
        self.fields["cpe_password"].help_text = (
            "Uses the default client-router login saved on the selected MikroTik. "
            "Change only if this CPE uses different credentials."
        )
        self.fields["pppoe_username"].required = False
        # Router is required so the PPPoE secret can be installed on the NAS.
        self.fields["router"].required = True
        self.fields["plan"].empty_label = "No plan yet"
        self.fields["router"].empty_label = "Select MikroTik"
        # Bound field used only for validation errors; inputs are rendered manually.
        self.fields["equipment_serials"] = forms.CharField(
            label="Equipment serials",
            required=False,
            widget=forms.HiddenInput(),
        )
        activate_initial = "1" if self.default_activate else "0"
        self.fields["activate_account"].initial = activate_initial
        if not self.allow_activate:
            self.fields["activate_account"].widget = forms.HiddenInput()
            self.fields["activate_account"].help_text = (
                "Technician registrations stay pending. An ISP client must activate the account."
            )
            self.fields["activation_date"].required = False
            self.fields["activation_date"].widget = forms.HiddenInput()

        org_qs = None
        if organizations is not None:
            from accounts.models import Organization

            if hasattr(organizations, "all"):
                org_qs = organizations
            else:
                org_ids = [
                    getattr(item, "pk", item) for item in organizations if item is not None
                ]
                org_qs = Organization.objects.filter(pk__in=org_ids).order_by("name")
            self.fields["organization"] = forms.ModelChoiceField(
                label="ISP client",
                queryset=org_qs,
                required=True,
                empty_label="Select ISP client",
                widget=forms.Select(
                    attrs={
                        "class": "form-control",
                        "id": "id_pppoe_organization",
                        "data-pppoe-organization": "1",
                    }
                ),
            )
            selected_org = organization
            if self.is_bound:
                raw_org = (self.data.get("organization") or "").strip()
                selected_org = org_qs.filter(pk=raw_org).first() if raw_org else None
            elif self.initial.get("organization"):
                candidate = self.initial.get("organization")
                if isinstance(candidate, Organization):
                    selected_org = candidate
                else:
                    selected_org = org_qs.filter(pk=candidate).first()
            self.organization = selected_org
            if selected_org is not None and not self.is_bound:
                self.initial.setdefault("organization", selected_org.pk)
            self.order_fields(
                [
                    "organization",
                    "full_name",
                    "phone",
                    "email",
                    "router",
                    "address",
                    "house_number",
                    "plan",
                    "activate_account",
                    "activation_date",
                    "pppoe_username",
                    "pppoe_password",
                    "cpe_username",
                    "cpe_password",
                    "equipment_serials",
                ]
            )

        self.serial_values = self._serial_values_for_display()

        today = timezone.localdate()
        if not self.is_bound:
            self.initial.setdefault("activate_account", activate_initial)
            self.initial.setdefault("activation_date", today)
            default_password = self.initial.get("pppoe_password") or _default_client_password()
            self.initial.setdefault("pppoe_password", default_password)
            router = self._selected_router()
            cpe_user, cpe_pass = self._cpe_defaults_for_router(router)
            if not (self.initial.get("cpe_username") or getattr(self.instance, "cpe_username", "")):
                self.initial.setdefault("cpe_username", cpe_user)
            if not self.initial.get("cpe_password"):
                self.initial.setdefault("cpe_password", cpe_pass)
            if not (self.initial.get("address") or getattr(self.instance, "address", "")):
                address = self._address_default_for_router(router)
                if address:
                    self.initial.setdefault("address", address)
        else:
            if not self.data.get("activation_date"):
                self.fields["activation_date"].initial = today
            if not (self.initial.get("cpe_username") or getattr(self.instance, "cpe_username", "")):
                self.fields["cpe_username"].initial = "admin"
        if self.organization is not None:
            from billing.services import plans_for_router

            self.fields["plan"].queryset = plans_for_router(
                self.organization,
                self._selected_router(),
                service_type=Customer.ServiceType.PPPOE,
            )
            self.fields["router"].queryset = MikroTikRouter.objects.filter(
                organization=self.organization,
            ).order_by("name")
        elif org_qs is not None:
            # Multi-ISP registration: MikroTiks/plans are filled from JS maps
            # until an ISP client is chosen. On POST without a valid ISP, keep
            # allowed routers so validation errors can still redisplay.
            if self.is_bound:
                self.fields["router"].queryset = MikroTikRouter.objects.filter(
                    organization__in=org_qs,
                ).order_by("name")
                self.fields["plan"].queryset = BillingPlan.objects.filter(
                    organization__in=org_qs,
                    is_active=True,
                    service_type=Customer.ServiceType.PPPOE,
                ).order_by("price", "name")
            else:
                self.fields["router"].queryset = MikroTikRouter.objects.none()
                self.fields["plan"].queryset = BillingPlan.objects.none()
        else:
            self.fields["plan"].queryset = BillingPlan.objects.none()
            self.fields["router"].queryset = MikroTikRouter.objects.none()

    @staticmethod
    def _normalize_equipment_serials(raw_values) -> list[str]:
        """Uppercase, strip, and de-dupe serials while preserving order."""
        serials: list[str] = []
        seen: set[str] = set()
        for raw in raw_values or []:
            value = (raw or "").strip().upper()
            if not value or value in seen:
                continue
            seen.add(value)
            serials.append(value)
        return serials

    def _posted_equipment_serials(self) -> list[str]:
        if not self.is_bound:
            return []
        data = self.data
        if hasattr(data, "getlist"):
            raw = data.getlist("equipment_serial")
        else:
            single = data.get("equipment_serial")
            if single is None:
                raw = []
            elif isinstance(single, (list, tuple)):
                raw = list(single)
            else:
                raw = [single]
        return self._normalize_equipment_serials(raw)

    def _serial_values_for_display(self) -> list[str]:
        if self.is_bound:
            values = self._posted_equipment_serials()
            return values or [""]
        initial = self.initial.get("equipment_serials")
        if initial is None and getattr(self.instance, "pk", None):
            initial = getattr(self.instance, "equipment_serials", None) or []
        values = self._normalize_equipment_serials(initial or [])
        return values or [""]

    def _selected_router(self):
        router = None
        if self.organization is None:
            return None
        if self.is_bound:
            raw_router = self.data.get("router")
            if raw_router:
                router = MikroTikRouter.objects.filter(
                    pk=raw_router, organization=self.organization
                ).first()
        elif self.initial.get("router"):
            candidate = self.initial.get("router")
            if isinstance(candidate, MikroTikRouter):
                router = candidate
            else:
                router = MikroTikRouter.objects.filter(
                    pk=candidate, organization=self.organization
                ).first()
        elif getattr(self.instance, "router_id", None):
            router = self.instance.router
        return router

    @staticmethod
    def _address_default_for_router(router) -> str:
        if router is None:
            return ""
        return (getattr(router, "location", None) or "").strip()

    @staticmethod
    def _cpe_defaults_for_router(router, fallback_password: str = "") -> tuple[str, str]:
        """Return MikroTik default CPE login. Never invent a password from PPPoE."""
        if router is None:
            return "admin", ""
        username = (getattr(router, "default_cpe_username", None) or "").strip() or "admin"
        password = getattr(router, "default_cpe_password", None) or ""
        return username, password

    @staticmethod
    def _activation_datetime(day: date):
        now = timezone.localtime()
        if day == now.date():
            return now
        return timezone.make_aware(
            datetime.combine(day, time.min),
            timezone.get_current_timezone(),
        )

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
        username = (self.cleaned_data.get("pppoe_username") or "").strip().upper()
        if not username:
            phone = (self.data.get("phone") or "").strip().upper()
            if phone:
                return phone
        return username

    def clean_pppoe_password(self):
        password = self.cleaned_data.get("pppoe_password") or ""
        if not password:
            raise forms.ValidationError("Enter the PPPoE password.")
        if len(password) < 4:
            raise forms.ValidationError("PPPoE password must be at least 4 characters.")
        return password

    def clean_cpe_username(self):
        username = (self.cleaned_data.get("cpe_username") or "").strip()
        if username:
            return username
        router = self._selected_router()
        cpe_user, _ = self._cpe_defaults_for_router(router)
        return cpe_user or "admin"

    def clean_cpe_password(self):
        password = self.cleaned_data.get("cpe_password") or ""
        if password:
            return password
        router = self._selected_router()
        _, router_password = self._cpe_defaults_for_router(router)
        return router_password or ""
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
        phone = cleaned.get("phone") or ""
        if phone and self.organization and customer_phone_is_taken(
            self.organization,
            phone,
            exclude_pk=getattr(self.instance, "pk", None),
        ):
            self.add_error("phone", PHONE_ALREADY_REGISTERED)
        plan = cleaned.get("plan")
        router = cleaned.get("router")
        if plan and plan.service_type != BillingPlan.ServiceType.PPPOE:
            self.add_error("plan", "Choose a PPPoE package for this client.")
        if plan and router and not plan.is_available_on_router(router):
            self.add_error(
                "plan",
                "That package is not linked to the selected MikroTik.",
            )
        serials = self._posted_equipment_serials()
        cleaned["equipment_serials"] = serials
        if self.require_serials and not serials:
            self.add_error(
                "equipment_serials",
                "Enter at least one equipment serial number.",
            )
        if not self.allow_activate:
            cleaned["activate_account"] = False
            cleaned["activation_date"] = None
            return cleaned
        activate = bool(cleaned.get("activate_account"))
        activation_date = cleaned.get("activation_date")
        if activate and not activation_date:
            self.add_error("activation_date", "Choose the activation date.")
        if not activate:
            cleaned["activation_date"] = None
        return cleaned

    def clean_equipment_serials(self):
        # Value comes from POST getlist("equipment_serial"), not this hidden input.
        return self._posted_equipment_serials()

    def clean_organization(self):
        org = self.cleaned_data.get("organization")
        if self.organizations is None:
            return org
        if not org:
            raise forms.ValidationError("Select the ISP client this subscriber belongs to.")
        self.organization = org
        return org

    def clean_router(self):
        router = self.cleaned_data.get("router")
        if not router:
            raise forms.ValidationError(
                "Select the MikroTik this client dials into so the PPPoE login can be installed."
            )
        if self.organization and router.organization_id != self.organization.pk:
            raise forms.ValidationError(
                "Choose a MikroTik that belongs to the selected ISP client."
            )
        return router

    def save(self, commit=True):
        customer = super().save(commit=False)
        if self.organizations is not None and not self.organization:
            self.organization = self.cleaned_data.get("organization")
        customer.organization = self.organization
        customer.service_type = Customer.ServiceType.PPPOE
        activate = bool(self.cleaned_data.get("activate_account"))
        activation_date = self.cleaned_data.get("activation_date")
        if activate:
            customer.status = Customer.Status.ACTIVE
            start = self._activation_datetime(activation_date or timezone.localdate())
            customer.package_start = start
            if customer.plan_id:
                customer.package_end = compute_package_end(start, customer.plan)
            else:
                customer.package_end = None
        else:
            customer.status = Customer.Status.INACTIVE
            customer.package_start = None
            customer.package_end = None
        customer.equipment_serials = list(
            self.cleaned_data.get("equipment_serials") or []
        )
        if not customer.account_number:
            from billing.services import generate_account_number_from_phone

            customer.account_number = generate_account_number_from_phone(
                customer.phone,
                organization=self.organization,
            )
        if commit:
            customer.save()
        return customer


class CustomerDetailsEditForm(forms.ModelForm):
    """Edit subscriber name, MikroTik router, and connection details from the client detail page."""

    class Meta:
        model = Customer
        fields = [
            "full_name",
            "router",
            "pppoe_username",
            "pppoe_password",
            "cpe_username",
            "cpe_password",
            "cpe_ip",
            "cpe_mac",
        ]
        widgets = {
            "full_name": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "Full name",
                    "autocomplete": "name",
                    "id": "id_edit_full_name",
                }
            ),
            "router": forms.Select(
                attrs={"class": "form-control", "id": "id_edit_router"}
            ),
            "pppoe_username": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
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
            "cpe_username": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "admin",
                    "autocomplete": "username",
                    "id": "id_edit_cpe_username",
                }
            ),
            "cpe_password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "Client router admin password",
                    "autocomplete": "new-password",
                    "id": "id_edit_cpe_password",
                },
                render_value=True,
            ),
            "cpe_ip": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "192.168.88.50",
                    "autocomplete": "off",
                    "id": "id_edit_cpe_ip",
                }
            ),
            "cpe_mac": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "AA:BB:CC:DD:EE:FF",
                    "autocomplete": "off",
                    "id": "id_edit_cpe_mac",
                }
            ),
        }
        labels = {
            "full_name": "Client name",
            "router": "MikroTik router",
            "pppoe_username": "PPPoE username",
            "pppoe_password": "PPPoE password",
            "cpe_username": "Client router username",
            "cpe_password": "Client router password",
            "cpe_ip": "Router IP (static)",
            "cpe_mac": "Router MAC (DHCP)",
        }

    def __init__(self, *args, organization=None, **kwargs):
        self.organization = organization
        super().__init__(*args, **kwargs)
        service_type = getattr(self.instance, "service_type", "")
        is_pppoe = service_type == Customer.ServiceType.PPPOE
        is_static = service_type == Customer.ServiceType.STATIC
        if self.organization:
            self.fields["router"].queryset = MikroTikRouter.objects.filter(
                organization=self.organization
            ).order_by("name")
        else:
            self.fields["router"].queryset = MikroTikRouter.objects.none()
        self.fields["router"].empty_label = "Select MikroTik router"
        self.fields["router"].required = is_pppoe or is_static
        if not is_pppoe:
            self.fields.pop("pppoe_username", None)
            self.fields.pop("pppoe_password", None)
        if not is_static:
            self.fields.pop("cpe_ip", None)
            self.fields.pop("cpe_mac", None)
        if not (is_pppoe or is_static):
            self.fields.pop("cpe_username", None)
            self.fields.pop("cpe_password", None)
        elif is_pppoe or is_static:
            self.fields["cpe_username"].required = False
            self.fields["cpe_password"].required = False
            self.fields["cpe_password"].help_text = (
                "For remote router access — leave blank to keep the saved password."
            )
        if is_pppoe and "pppoe_password" in self.fields:
            self.fields["pppoe_password"].required = False
            self.fields["pppoe_password"].help_text = (
                "Current password shown — change only to update."
            )
        if is_static:
            self.fields["cpe_ip"].required = False
            self.fields["cpe_mac"].required = False
            self.fields["cpe_ip"].help_text = (
                "Fixed LAN IP — saved to the MikroTik as a static DHCP lease when MAC is set too."
            )
            self.fields["cpe_mac"].help_text = (
                "Router MAC for dynamic DHCP — IP is resolved from the NAS."
            )
        self._prefill_edit_credentials()

    def _prefill_edit_credentials(self):
        if self.is_bound or not (self.instance and self.instance.pk):
            return
        values = {
            "pppoe_username": (self.instance.pppoe_username or "").strip(),
            "pppoe_password": self.instance.pppoe_password or "",
            "cpe_username": (self.instance.cpe_username or "").strip() or "admin",
            "cpe_password": self.instance.cpe_password or "",
        }
        for name, value in values.items():
            if name not in self.fields:
                continue
            self.initial[name] = value
            self.fields[name].initial = value
            if name.endswith("_password"):
                widget = self.fields[name].widget
                attrs = dict(getattr(widget, "attrs", {}))
                attrs.setdefault("class", "form-control password-input")
                attrs["autocomplete"] = "off"
                self.fields[name].widget = forms.TextInput(attrs=attrs)
                if value:
                    self.fields[name].help_text = (
                        "Current password shown — change only to update."
                    )

    def clean_full_name(self):
        name = (self.cleaned_data.get("full_name") or "").strip().upper()
        if not name:
            raise forms.ValidationError("Enter the client’s full name.")
        return name

    def clean_pppoe_username(self):
        username = (self.cleaned_data.get("pppoe_username") or "").strip().upper()
        if not username and self.instance and self.instance.pk:
            return (self.instance.pppoe_username or "").strip().upper()
        return username

    def clean_pppoe_password(self):
        password = self.cleaned_data.get("pppoe_password") or ""
        if not password and self.instance and self.instance.pk:
            return self.instance.pppoe_password or ""
        if not password:
            raise forms.ValidationError("Enter the PPPoE password.")
        if len(password) < 4:
            raise forms.ValidationError("PPPoE password must be at least 4 characters.")
        return password

    def clean_cpe_username(self):
        username = (self.cleaned_data.get("cpe_username") or "").strip()
        if not username and self.instance and self.instance.pk:
            return (self.instance.cpe_username or "").strip() or "admin"
        return username or "admin"

    def clean_cpe_password(self):
        password = self.cleaned_data.get("cpe_password") or ""
        if not password and self.instance and self.instance.pk:
            return self.instance.cpe_password or ""
        return password

    def clean_router(self):
        router = self.cleaned_data.get("router")
        if not router:
            return router
        if self.organization and router.organization_id != self.organization.pk:
            raise forms.ValidationError("Choose a router from this organization.")
        return router

    def clean_cpe_ip(self):
        ip = (self.cleaned_data.get("cpe_ip") or "").strip()
        if ip:
            import ipaddress

            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise forms.ValidationError("Enter a valid IPv4 or IPv6 address.") from exc
        return ip

    def clean_cpe_mac(self):
        return (self.cleaned_data.get("cpe_mac") or "").strip().upper()

    def clean(self):
        cleaned = super().clean()
        router = cleaned.get("router")
        plan = getattr(self.instance, "plan", None)
        if plan and router and not plan.is_available_on_router(router):
            self.add_error(
                "router",
                "This plan is not available on the selected MikroTik.",
            )
        if "pppoe_username" not in self.fields:
            return cleaned
        username = (cleaned.get("pppoe_username") or "").strip().upper()
        cleaned["pppoe_username"] = username
        if not username:
            existing = (
                (self.instance.pppoe_username or "").strip().upper()
                if self.instance and self.instance.pk
                else ""
            )
            if existing:
                cleaned["pppoe_username"] = existing
                username = existing
            else:
                self.add_error("pppoe_username", "Enter the PPPoE username.")
        if username and self.organization:
            qs = Customer.objects.filter(
                organization=self.organization,
                service_type=Customer.ServiceType.PPPOE,
                pppoe_username__iexact=username,
            )
            if self.instance and self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                self.add_error(
                    "pppoe_username",
                    "That PPPoE username is already registered.",
                )
        return cleaned


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
        phone = cleaned.get("phone") or ""
        org = cleaned.get("organization")
        if phone and org and customer_phone_is_taken(org, phone):
            self.add_error("phone", PHONE_ALREADY_REGISTERED)
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
            self.fields["plan"].queryset = plans_for_router(
                self.organization,
                router,
                service_type=getattr(self.instance, "service_type", None) or None,
            )
        else:
            self.fields["plan"].queryset = BillingPlan.objects.none()

    def clean_plan(self):
        plan = self.cleaned_data.get("plan")
        if not plan:
            raise forms.ValidationError("Select a billing plan.")
        customer_service = getattr(self.instance, "service_type", None) or ""
        if customer_service and plan.service_type != customer_service:
            raise forms.ValidationError(
                f"Choose a {self.instance.get_service_type_display()} package for this client."
            )
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
        self.is_hourly = plan_uses_clock_time(plan)

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
            customer_service = getattr(self.instance, "service_type", None) or None
            qs = plans_for_router(
                self.organization,
                router,
                service_type=customer_service,
            )
            # Keep the client's current plan selectable even if it was later
            # deactivated or unlinked from this router / service type.
            current_plan_id = getattr(self.instance, "plan_id", None)
            if current_plan_id and not qs.filter(pk=current_plan_id).exists():
                qs = (
                    BillingPlan.objects.filter(organization=self.organization)
                    .filter(Q(pk=current_plan_id) | Q(pk__in=qs.values("pk")))
                    .distinct()
                    .order_by("price", "name")
                )
            self.fields["plan"].queryset = qs
        else:
            self.fields["plan"].queryset = BillingPlan.objects.none()

        plan = self._resolve_plan()
        self.is_hourly = plan_uses_clock_time(plan)
        if plan:
            # ModelChoiceField only selects the instance value when it is in
            # the queryset; re-assert after the queryset is finalized.
            self.initial.setdefault("plan", plan.pk)
            self.fields["plan"].initial = plan.pk

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

        if plan_uses_clock_time(plan):
            self.fields["service_day"].help_text = (
                "Defaults to today. Pick another day if this timed package should run then."
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
        customer_service = getattr(self.instance, "service_type", None) or ""
        if customer_service and plan.service_type != customer_service:
            raise forms.ValidationError(
                f"Choose a {self.instance.get_service_type_display()} package for this client."
            )
        router = getattr(self.instance, "router", None)
        if plan and router and not plan.is_available_on_router(router):
            raise forms.ValidationError(
                "That package is not linked to this client’s MikroTik."
            )
        return plan

    def clean(self):
        cleaned = super().clean()
        plan = cleaned.get("plan")
        is_hourly = plan_uses_clock_time(plan)
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
        # A freshly assigned period replaces any frozen pause state.
        clear_customer_package_pause(customer, save=False)
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
            "service_type",
            "price",
            "download_speed_mbps",
            "upload_speed_mbps",
            "duration",
            "max_devices",
            "offer_enabled",
            "offer_pay_count",
            "image",
            "is_active",
            "routers",
        ]
        widgets = {
            "name": forms.TextInput(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": 'e.g. "HOME 10 MBPS"',
                    "autocomplete": "off",
                    "id": "id_package_name",
                }
            ),
            "description": forms.Textarea(
                attrs={
                    "class": "form-control text-upper",
                    "placeholder": "OPTIONAL PACKAGE DETAILS",
                    "rows": 3,
                    "id": "id_package_description",
                }
            ),
            "service_type": forms.RadioSelect(
                attrs={
                    "class": "package-service-type-radios",
                    "id": "id_package_service_type",
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
            "max_devices": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Unlimited",
                    "min": "1",
                    "max": "50",
                    "id": "id_package_max_devices",
                }
            ),
            "offer_enabled": forms.CheckboxInput(
                attrs={
                    "id": "id_package_offer_enabled",
                    "class": "package-offer-toggle",
                }
            ),
            "offer_pay_count": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "5",
                    "min": "1",
                    "max": "100",
                    "id": "id_package_offer_pay_count",
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
            "service_type": "Service type",
            "price": "Price",
            "download_speed_mbps": "Download speed (Mbps)",
            "upload_speed_mbps": "Upload speed (Mbps)",
            "duration": "Billing period",
            "max_devices": "Max devices",
            "offer_enabled": "Enable buy-X-get-1-free offer",
            "offer_pay_count": "Paid sessions before free one",
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
        self.fields["service_type"].required = True
        self.fields["max_devices"].required = False
        self.fields["max_devices"].help_text = (
            "Leave blank for unlimited Hotspot devices. "
            "Hotspot: number of phones/laptops; payment creates one one-time voucher per device. "
            "PPPoE: always 1 concurrent dial (one CPE). Devices on Wi‑Fi/LAN behind that CPE "
            "are already unlimited — this field does not add extra PPPoE sessions."
        )
        self.fields["offer_enabled"].required = False
        self.fields["offer_pay_count"].required = False
        self.fields["offer_pay_count"].help_text = (
            "Example: 5 means after every 5 paid sessions the customer gets one extra session free."
        )
        self.fields["duration"].choices = BillingPlan.Duration.choices
        # Default Active only for new packages — keep the saved value when editing.
        if not self.is_bound and not getattr(self.instance, "pk", None):
            self.fields["is_active"].initial = True
            self.fields["service_type"].initial = BillingPlan.ServiceType.PPPOE
        if int(getattr(self.instance, "max_devices", 0) or 0) <= 0:
            self.initial["max_devices"] = None
        if self.organization is not None:
            self.fields["routers"].queryset = MikroTikRouter.objects.filter(
                organization=self.organization,
            ).order_by("name")
        else:
            self.fields["routers"].queryset = MikroTikRouter.objects.none()
        id_map = {
            "name": f"id_{self.id_prefix}_name",
            "description": f"id_{self.id_prefix}_description",
            "service_type": f"id_{self.id_prefix}_service_type",
            "price": f"id_{self.id_prefix}_price",
            "download_speed_mbps": f"id_{self.id_prefix}_download_speed",
            "upload_speed_mbps": f"id_{self.id_prefix}_upload_speed",
            "duration": f"id_{self.id_prefix}_duration",
            "max_devices": f"id_{self.id_prefix}_max_devices",
            "offer_enabled": f"id_{self.id_prefix}_offer_enabled",
            "offer_pay_count": f"id_{self.id_prefix}_offer_pay_count",
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
        name = (self.cleaned_data.get("name") or "").strip().upper()
        if not name:
            raise forms.ValidationError("Enter a package name.")
        return name

    def clean(self):
        cleaned = super().clean()
        name = cleaned.get("name")
        service_type = cleaned.get("service_type")
        if name and self.organization:
            qs = BillingPlan.objects.filter(
                organization=self.organization,
                name__iexact=name,
            )
            if service_type:
                qs = qs.filter(service_type=service_type)
            if self.instance and self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                self.add_error(
                    "name",
                    "A package with that name already exists for this service type.",
                )
        offer_enabled = bool(cleaned.get("offer_enabled"))
        offer_pay_count = cleaned.get("offer_pay_count")
        if offer_enabled:
            if offer_pay_count in (None, ""):
                self.add_error(
                    "offer_pay_count",
                    "Enter how many paid sessions unlock a free one.",
                )
            elif int(offer_pay_count) < 1:
                self.add_error(
                    "offer_pay_count",
                    "Enter at least 1 paid session before the free one.",
                )
        else:
            cleaned["offer_pay_count"] = int(
                offer_pay_count or getattr(self.instance, "offer_pay_count", None) or 5
            )
        return cleaned

    def clean_description(self):
        return (self.cleaned_data.get("description") or "").strip().upper()

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

    def clean_max_devices(self):
        count = self.cleaned_data.get("max_devices")
        if count in (None, "") or count == 0:
            return 0
        if count < 1:
            raise forms.ValidationError(
                "Enter at least 1 device, or leave blank for unlimited."
            )
        if count > 50:
            raise forms.ValidationError("Max devices cannot exceed 50.")
        return count

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


class CustomerCashRechargeForm(forms.Form):
    """Staff cash recharge: start date + cash amount → purchased duration.

    Active clients keep remaining paid time (server stacks the duration).
    Expired clients get the absolute start→end window.
    """

    plan = forms.ModelChoiceField(
        label="Package / plan",
        queryset=BillingPlan.objects.none(),
        empty_label="Select a plan",
        widget=forms.Select(
            attrs={
                "class": "form-control",
                "id": "id_recharge_plan",
            },
        ),
    )
    period_from = forms.DateField(
        label="Start date",
        required=True,
        input_formats=["%Y-%m-%d"],
        widget=forms.DateInput(
            format="%Y-%m-%d",
            attrs={
                "class": "form-control",
                "type": "date",
                "id": "id_recharge_period_from",
            },
        ),
    )
    amount = forms.DecimalField(
        label="Amount (KES)",
        min_value=Decimal("0.01"),
        max_digits=12,
        decimal_places=2,
        widget=forms.NumberInput(
            attrs={
                "class": "form-control",
                "id": "id_recharge_amount",
                "step": "0.01",
                "min": "0.01",
                "inputmode": "decimal",
            },
        ),
    )
    period_to = forms.DateField(
        label="End date",
        required=False,
        input_formats=["%Y-%m-%d"],
        widget=forms.DateInput(
            format="%Y-%m-%d",
            attrs={
                "class": "form-control",
                "type": "date",
                "id": "id_recharge_period_to",
                "readonly": True,
            },
        ),
    )
    reference = forms.CharField(
        label="Reference",
        required=False,
        max_length=100,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "id_recharge_reference",
                "placeholder": "Optional receipt / note",
                "autocomplete": "off",
            },
        ),
    )

    def __init__(self, *args, organization=None, customer=None, **kwargs):
        self.organization = organization
        self.customer = customer
        super().__init__(*args, **kwargs)

        qs = BillingPlan.objects.none()
        if self.organization and self.customer is not None:
            router = getattr(self.customer, "router", None)
            customer_service = getattr(self.customer, "service_type", None) or None
            qs = plans_for_router(
                self.organization,
                router,
                service_type=customer_service,
            )
            current_plan_id = getattr(self.customer, "plan_id", None)
            if current_plan_id and not qs.filter(pk=current_plan_id).exists():
                qs = (
                    BillingPlan.objects.filter(organization=self.organization)
                    .filter(Q(pk=current_plan_id) | Q(pk__in=qs.values("pk")))
                    .distinct()
                    .order_by("price", "name")
                )
        elif self.organization:
            qs = BillingPlan.objects.filter(
                organization=self.organization,
                is_active=True,
            ).order_by("price", "name")

        self.fields["plan"].queryset = qs
        today = timezone.localdate()
        self.fields["period_from"].initial = today
        self.fields["period_to"].initial = today
        current_plan = getattr(self.customer, "plan", None) if self.customer else None
        if current_plan and qs.filter(pk=current_plan.pk).exists():
            self.fields["plan"].initial = current_plan.pk
            if "amount" not in self.data:
                self.fields["amount"].initial = current_plan.price
        elif qs.exists() and "amount" not in self.data:
            first = qs.first()
            self.fields["plan"].initial = first.pk
            self.fields["amount"].initial = first.price

    def clean_amount(self):
        amount = self.cleaned_data.get("amount")
        if amount is None:
            raise forms.ValidationError("Enter the cash amount received.")
        try:
            amount = Decimal(amount)
        except (InvalidOperation, TypeError):
            raise forms.ValidationError("Enter a valid amount.")
        if amount <= 0:
            raise forms.ValidationError("Amount must be greater than zero.")
        return amount

    def clean_plan(self):
        plan = self.cleaned_data.get("plan")
        if plan is None:
            raise forms.ValidationError("Select a package to recharge.")
        if self.organization and plan.organization_id != self.organization.pk:
            raise forms.ValidationError("Choose a plan from this organization.")
        return plan

    def clean(self):
        from billing.services import (
            compute_partial_to_date_from_amount,
            partial_recharge_window,
        )

        cleaned = super().clean()
        plan = cleaned.get("plan")
        period_from = cleaned.get("period_from")
        amount = cleaned.get("amount")
        if period_from is None:
            self.add_error("period_from", "Select the start date.")
            return cleaned
        if plan is None or amount is None:
            return cleaned
        try:
            period_to = compute_partial_to_date_from_amount(plan, period_from, amount)
            start, end = partial_recharge_window(period_from, period_to, plan)
        except ValueError as exc:
            self.add_error(None, str(exc))
            return cleaned
        cleaned["period_to"] = period_to
        cleaned["period_start"] = start
        cleaned["period_end"] = end
        return cleaned
