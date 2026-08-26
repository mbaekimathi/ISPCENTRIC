from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

from django import forms

from .models import MikroTikRouter
from .places import apply_resolved_coords


class CoordinateField(forms.DecimalField):
    """Accept map coords with extra precision, then store at 6 decimal places."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("max_digits", 9)
        kwargs.setdefault("decimal_places", 6)
        kwargs.setdefault("required", False)
        super().__init__(*args, **kwargs)

    def to_python(self, value):
        if value in self.empty_values:
            return None
        try:
            dec = Decimal(str(value).strip())
        except (InvalidOperation, AttributeError, TypeError, ValueError):
            raise forms.ValidationError(self.error_messages["invalid"], code="invalid")
        return dec.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)


class MikroTikOnboardForm(forms.ModelForm):
    place_id = forms.CharField(required=False, widget=forms.HiddenInput(attrs={"id": "id_mikrotik_place_id"}))
    location_lat = CoordinateField(widget=forms.HiddenInput(attrs={"id": "id_mikrotik_location_lat"}))
    location_lng = CoordinateField(widget=forms.HiddenInput(attrs={"id": "id_mikrotik_location_lng"}))

    class Meta:
        model = MikroTikRouter
        fields = [
            "name",
            "model",
            "location",
            "location_lat",
            "location_lng",
            "host",
            "username",
            "password",
            "wifi_ssid",
            "wifi_password",
            "default_cpe_username",
            "default_cpe_password",
        ]
        widgets = {
            "name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": 'e.g. "ISP CENTRIC Router"',
                    "autocomplete": "off",
                }
            ),
            "model": forms.Select(
                attrs={
                    "class": "form-control mikrotik-model-select",
                    "id": "id_mikrotik_model",
                }
            ),
            "location": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Start typing a place or address…",
                    "autocomplete": "off",
                    "autocapitalize": "off",
                    "spellcheck": "false",
                    "id": "id_mikrotik_location",
                    "role": "combobox",
                    "aria-autocomplete": "list",
                    "aria-controls": "mikrotik-location-suggest",
                }
            ),
            "host": forms.TextInput(
                attrs={
                    "class": "form-control mikrotik-host-input",
                    "placeholder": "Select a found router or type an IP…",
                    "autocomplete": "off",
                    "id": "id_mikrotik_host",
                    "role": "combobox",
                    "aria-autocomplete": "list",
                    "aria-controls": "mikrotik-host-picker",
                    "aria-expanded": "false",
                }
            ),
            "username": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "admin",
                    "autocomplete": "username",
                    "id": "id_mikrotik_username",
                }
            ),
            "password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "Router password",
                    "autocomplete": "new-password",
                    "id": "id_mikrotik_password",
                }
            ),
            "wifi_ssid": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Current Wi‑Fi name",
                    "autocomplete": "off",
                    "maxlength": "32",
                    "id": "id_mikrotik_wifi_ssid",
                }
            ),
            "wifi_password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "Current Wi‑Fi password",
                    "autocomplete": "new-password",
                    "id": "id_mikrotik_wifi_password",
                },
                render_value=True,
            ),
            "default_cpe_username": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "admin",
                    "autocomplete": "username",
                    "id": "id_mikrotik_default_cpe_username",
                }
            ),
            "default_cpe_password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "Client router admin password",
                    "autocomplete": "new-password",
                    "id": "id_mikrotik_default_cpe_password",
                },
                render_value=True,
            ),
        }
        labels = {
            "name": "Name your MikroTik",
            "model": "Model",
            "location": "Set location",
            "host": "MikroTik IP",
            "username": "Username",
            "password": "Password",
            "wifi_ssid": "Wi‑Fi name",
            "wifi_password": "Wi‑Fi password",
            "default_cpe_username": "Client router username",
            "default_cpe_password": "Client router password",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["default_cpe_username"].required = False
        self.fields["default_cpe_password"].required = False
        if not self.is_bound and not (self.initial.get("default_cpe_username") or "").strip():
            self.initial.setdefault("default_cpe_username", "admin")

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip()

    def clean_host(self):
        from core.mikrotik_connect import (
            is_factory_default_mikrotik_ip,
            normalize_mikrotik_host,
        )

        host = normalize_mikrotik_host(self.cleaned_data.get("host") or "")
        if not host:
            raise forms.ValidationError("Enter the MikroTik IP address or hostname.")
        if is_factory_default_mikrotik_ip(host):
            raise forms.ValidationError(
                "Change the MikroTik LAN IP away from the factory default "
                "192.168.88.1 before onboarding — keeping it causes collisions "
                "with other MikroTik routers."
            )
        return host

    def clean_username(self):
        username = (self.cleaned_data.get("username") or "").strip()
        if not username:
            raise forms.ValidationError("Enter the router username.")
        return username

    def clean_location(self):
        return (self.cleaned_data.get("location") or "").strip()

    def clean_wifi_ssid(self):
        return (self.cleaned_data.get("wifi_ssid") or "").strip()

    def clean_wifi_password(self):
        return self.cleaned_data.get("wifi_password") or ""

    def clean_default_cpe_username(self):
        return (self.cleaned_data.get("default_cpe_username") or "").strip() or "admin"

    def clean_default_cpe_password(self):
        return self.cleaned_data.get("default_cpe_password") or ""

    def clean(self):
        cleaned = super().clean()
        location = cleaned.get("location") or ""
        wifi_ssid = cleaned.get("wifi_ssid") or ""
        wifi_password = cleaned.get("wifi_password") or ""

        if wifi_password and len(wifi_password) < 8:
            self.add_error("wifi_password", "Wi‑Fi password must be at least 8 characters.")
        if wifi_password and not wifi_ssid:
            self.add_error("wifi_ssid", "Enter a Wi‑Fi name when setting a Wi‑Fi password.")

        if not location:
            return cleaned

        label, lat, lng = apply_resolved_coords(
            location,
            cleaned.get("location_lat"),
            cleaned.get("location_lng"),
            place_id=cleaned.get("place_id") or "",
        )
        cleaned["location"] = label
        cleaned["location_lat"] = lat
        cleaned["location_lng"] = lng

        if lat is None or lng is None:
            self.add_error(
                "location",
                "Choose a suggested location so latitude and longitude can be saved.",
            )
        return cleaned


class MikroTikEditDetailsForm(forms.ModelForm):
    """Edit router details, API login credentials, and default client-router credentials."""

    place_id = forms.CharField(
        required=False,
        widget=forms.HiddenInput(attrs={"id": "id_edit_mikrotik_place_id"}),
    )
    location_lat = CoordinateField(
        widget=forms.HiddenInput(attrs={"id": "id_edit_mikrotik_location_lat"})
    )
    location_lng = CoordinateField(
        widget=forms.HiddenInput(attrs={"id": "id_edit_mikrotik_location_lng"})
    )

    class Meta:
        model = MikroTikRouter
        fields = [
            "name",
            "model",
            "location",
            "location_lat",
            "location_lng",
            "host",
            "username",
            "password",
            "default_cpe_username",
            "default_cpe_password",
        ]
        widgets = {
            "name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": 'e.g. "ISP CENTRIC Router"',
                    "autocomplete": "off",
                    "id": "id_edit_mikrotik_name",
                }
            ),
            "model": forms.Select(
                attrs={
                    "class": "form-control",
                    "id": "id_edit_mikrotik_model",
                }
            ),
            "location": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Start typing a place or address…",
                    "autocomplete": "off",
                    "id": "id_edit_mikrotik_location",
                }
            ),
            "host": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "192.168.88.1",
                    "autocomplete": "off",
                    "id": "id_edit_mikrotik_host",
                }
            ),
            "username": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "admin",
                    "autocomplete": "username",
                    "id": "id_edit_mikrotik_username",
                }
            ),
            "password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "Router password",
                    "autocomplete": "new-password",
                    "id": "id_edit_mikrotik_password",
                },
                render_value=True,
            ),
            "default_cpe_username": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "admin",
                    "autocomplete": "username",
                    "id": "id_edit_mikrotik_default_cpe_username",
                }
            ),
            "default_cpe_password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "Client router admin password",
                    "autocomplete": "new-password",
                    "id": "id_edit_mikrotik_default_cpe_password",
                },
                render_value=True,
            ),
        }
        labels = {
            "name": "Name",
            "model": "Model",
            "location": "Location",
            "host": "IP / Host",
            "username": "Username",
            "password": "Password",
            "default_cpe_username": "Client router username",
            "default_cpe_password": "Client router password",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["default_cpe_username"].required = False
        self.fields["default_cpe_password"].required = False
        self.unlisted_model = self._keep_current_model_selectable()

    def clean_host(self):
        host = (self.cleaned_data.get("host") or "").strip()
        if not host:
            raise forms.ValidationError("Enter the MikroTik IP address or hostname.")
        return host

    def clean_username(self):
        username = (self.cleaned_data.get("username") or "").strip()
        if not username:
            raise forms.ValidationError("Enter the router username.")
        return username

    def clean_password(self):
        password = self.cleaned_data.get("password") or ""
        if not password:
            raise forms.ValidationError("Enter the router password.")
        return password

    def _keep_current_model_selectable(self) -> str:
        """Show the stored model even when it predates the current catalog.

        A value the dropdown does not offer renders with nothing selected, so the
        browser shows the first option and saving silently rewrites the model.
        """
        current = (getattr(self.instance, "model", "") or "").strip()
        if not current:
            return ""
        field = self.fields["model"]
        if any(current == value for value, _ in field.choices):
            return ""
        label = current.replace("_", " ").upper()
        field.choices = [(current, label), *field.choices]
        return current

    def _get_validation_exclusions(self):
        exclude = super()._get_validation_exclusions()
        if self.unlisted_model and self.data.get("model") == self.unlisted_model:
            # The model field still validates against the catalog, so keeping a
            # legacy value would otherwise block every edit to this router.
            exclude.add("model")
        return exclude

    def clean_name(self):
        name = (self.cleaned_data.get("name") or "").strip()
        if not name:
            raise forms.ValidationError("Enter a name for this MikroTik.")
        return name

    def clean_location(self):
        return (self.cleaned_data.get("location") or "").strip()

    def clean_default_cpe_username(self):
        return (self.cleaned_data.get("default_cpe_username") or "").strip() or "admin"

    def clean_default_cpe_password(self):
        return self.cleaned_data.get("default_cpe_password") or ""

    def clean(self):
        cleaned = super().clean()
        location = cleaned.get("location") or ""

        if not location:
            cleaned["location_lat"] = None
            cleaned["location_lng"] = None
            return cleaned

        label, lat, lng = apply_resolved_coords(
            location,
            cleaned.get("location_lat"),
            cleaned.get("location_lng"),
            place_id=cleaned.get("place_id") or "",
        )
        cleaned["location"] = label
        cleaned["location_lat"] = lat
        cleaned["location_lng"] = lng
        if lat is None or lng is None:
            # Keep existing coords when the label did not change and coords already exist.
            if self.instance and self.instance.pk:
                if (self.instance.location or "") == location and self.instance.location_lat is not None:
                    cleaned["location_lat"] = self.instance.location_lat
                    cleaned["location_lng"] = self.instance.location_lng
                else:
                    self.add_error(
                        "location",
                        "Choose a suggested location so latitude and longitude can be saved.",
                    )
        return cleaned


class MikroTikCredentialsForm(forms.ModelForm):
    """Update Wi‑Fi name and password on the router."""

    class Meta:
        model = MikroTikRouter
        fields = ["wifi_ssid", "wifi_password"]
        widgets = {
            "wifi_ssid": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Wi‑Fi name",
                    "autocomplete": "off",
                    "maxlength": "32",
                    "id": "id_cred_mikrotik_wifi_ssid",
                }
            ),
            "wifi_password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "Wi‑Fi password",
                    "autocomplete": "new-password",
                    "id": "id_cred_mikrotik_wifi_password",
                },
                render_value=True,
            ),
        }
        labels = {
            "wifi_ssid": "Wi‑Fi name",
            "wifi_password": "Wi‑Fi password",
        }

    def clean_wifi_ssid(self):
        return (self.cleaned_data.get("wifi_ssid") or "").strip()

    def clean_wifi_password(self):
        return self.cleaned_data.get("wifi_password") or ""

    def clean(self):
        cleaned = super().clean()
        wifi_ssid = cleaned.get("wifi_ssid") or ""
        wifi_password = cleaned.get("wifi_password") or ""
        if wifi_password and len(wifi_password) < 8:
            self.add_error("wifi_password", "Wi‑Fi password must be at least 8 characters.")
        if wifi_password and not wifi_ssid:
            self.add_error("wifi_ssid", "Enter a Wi‑Fi name when setting a Wi‑Fi password.")
        return cleaned


class MikroTikSuspendForm(forms.Form):
    """Confirm suspending or reactivating a MikroTik account."""

    confirm = forms.BooleanField(
        required=True,
        error_messages={"required": "Confirm to continue."},
        widget=forms.CheckboxInput(attrs={"id": "id_suspend_mikrotik_confirm"}),
    )


class MikroTikWifiSettingsForm(forms.Form):
    """Update Wi‑Fi name and password on a client's CPE router."""

    wifi_ssid = forms.CharField(
        required=False,
        max_length=64,
        label="Wi‑Fi name",
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "e.g. Home-WiFi",
                "id": "id_client_wifi_ssid",
                "autocomplete": "off",
            }
        ),
    )
    wifi_password = forms.CharField(
        required=False,
        max_length=128,
        label="Wi‑Fi password",
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control password-input",
                "placeholder": "Leave blank to keep current password",
                "autocomplete": "new-password",
                "id": "id_client_wifi_password",
            },
            render_value=True,
        ),
    )

    def clean_wifi_ssid(self):
        return (self.cleaned_data.get("wifi_ssid") or "").strip()

    def clean_wifi_password(self):
        return self.cleaned_data.get("wifi_password") or ""

    def clean(self):
        cleaned = super().clean()
        wifi_ssid = cleaned.get("wifi_ssid") or ""
        wifi_password = cleaned.get("wifi_password") or ""
        if wifi_password and len(wifi_password) < 8:
            self.add_error("wifi_password", "Wi‑Fi password must be at least 8 characters.")
        if wifi_password and not wifi_ssid:
            self.add_error("wifi_ssid", "Enter a Wi‑Fi name when setting a Wi‑Fi password.")
        if not wifi_ssid and not wifi_password:
            self.add_error(None, "Enter a Wi‑Fi name or password to update.")
        return cleaned


class CustomerCpeAccessForm(forms.Form):
    """Save Winbox/API credentials for the subscriber's CPE router."""

    cpe_username = forms.CharField(
        max_length=64,
        label="CPE username",
        initial="admin",
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "admin",
                "id": "id_client_cpe_username",
                "autocomplete": "username",
            }
        ),
    )
    cpe_password = forms.CharField(
        required=False,
        max_length=128,
        label="CPE password",
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control password-input",
                "placeholder": "CPE Winbox password",
                "autocomplete": "new-password",
                "id": "id_client_cpe_password",
            },
            render_value=True,
        ),
    )

    def clean_cpe_username(self):
        username = (self.cleaned_data.get("cpe_username") or "").strip() or "admin"
        return username

    def clean_cpe_password(self):
        return self.cleaned_data.get("cpe_password") or ""


class MikroTikWifiToggleForm(forms.Form):
    """Confirm activating or deactivating MikroTik Wi‑Fi."""

    confirm = forms.BooleanField(
        required=True,
        error_messages={"required": "Confirm to continue."},
        widget=forms.CheckboxInput(attrs={"id": "id_wifi_mikrotik_confirm"}),
    )


class MikroTikCleanUplinkForm(forms.Form):
    """Enable/disable clean uplink (bypass or behind provider) on a MikroTik."""

    mode = forms.ChoiceField(
        choices=[
            (
                "bypass",
                "Modem bypass",
            ),
            (
                "behind",
                "Behind provider",
            ),
        ],
        widget=forms.RadioSelect(attrs={"class": "mikrotik-clean-mode-list"}),
    )
    wan_interface = forms.CharField(
        max_length=64,
        widget=forms.TextInput(
            attrs={
                "class": "input",
                "placeholder": "ether1",
                "id": "id_clean_uplink_wan",
                "autocomplete": "off",
            }
        ),
        label="WAN interface",
    )
    lan_bridge = forms.CharField(
        max_length=64,
        widget=forms.TextInput(
            attrs={
                "class": "input",
                "placeholder": "bridgeLocal",
                "id": "id_clean_uplink_lan",
                "autocomplete": "off",
            }
        ),
        label="LAN bridge",
    )
    provider_gateway = forms.CharField(
        required=False,
        max_length=255,
        widget=forms.TextInput(
            attrs={
                "class": "input",
                "placeholder": "192.168.1.1 or 192.168.100.1",
                "id": "id_clean_uplink_gateway",
                "autocomplete": "off",
            }
        ),
        label="Provider gateway IP",
        help_text=(
            "Behind-provider mode: modem/ONT admin IP. "
            "Comma-separate several (e.g. 192.168.1.1, 192.168.100.1)."
        ),
    )
    separate_wan = forms.BooleanField(
        required=False,
        initial=False,
        label="Separate WAN from bridge",
        help_text=(
            "Only enable if your PC is plugged into a LAN port (ether2–ether5). "
            "If you manage the MikroTik through the ISP modem / ether1, leave this OFF "
            "or you may lose access."
        ),
        widget=forms.CheckboxInput(attrs={"id": "id_clean_uplink_separate_wan"}),
    )
    confirm = forms.BooleanField(
        required=True,
        error_messages={"required": "Confirm to continue."},
        widget=forms.CheckboxInput(attrs={"id": "id_clean_uplink_confirm"}),
    )

    def clean_wan_interface(self):
        return (self.cleaned_data.get("wan_interface") or "").strip()

    def clean_lan_bridge(self):
        return (self.cleaned_data.get("lan_bridge") or "").strip()

    def clean_provider_gateway(self):
        raw = (self.cleaned_data.get("provider_gateway") or "").strip()
        if not raw:
            return ""
        from core.mikrotik_connect import parse_provider_gateways

        try:
            return ", ".join(parse_provider_gateways(raw))
        except ValueError as exc:
            raise forms.ValidationError(str(exc)) from exc

    def clean(self):
        cleaned = super().clean()
        mode = cleaned.get("mode") or "bypass"
        gateway = cleaned.get("provider_gateway") or ""
        if mode == "behind" and not gateway:
            self.add_error(
                "provider_gateway",
                "Enter the provider gateway IP (e.g. 192.168.1.1, 192.168.0.1, or 192.168.100.1).",
            )
        if not cleaned.get("wan_interface"):
            self.add_error("wan_interface", "Enter the WAN interface name.")
        if not cleaned.get("lan_bridge"):
            self.add_error("lan_bridge", "Enter the LAN bridge name.")
        return cleaned
