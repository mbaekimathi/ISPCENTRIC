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
        }

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip()

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

    def clean_location(self):
        return (self.cleaned_data.get("location") or "").strip()

    def clean_wifi_ssid(self):
        return (self.cleaned_data.get("wifi_ssid") or "").strip()

    def clean_wifi_password(self):
        return self.cleaned_data.get("wifi_password") or ""

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
    """Edit name, model, and location without touching login credentials or Wi‑Fi."""

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
            "internet_provider",
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
            "internet_provider": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "e.g. Safaricom, Starlink, Liquid",
                    "autocomplete": "organization",
                    "id": "id_edit_mikrotik_internet_provider",
                }
            ),
        }
        labels = {
            "name": "Name",
            "model": "Model",
            "location": "Location",
            "internet_provider": "Internet company",
        }

    def clean_name(self):
        name = (self.cleaned_data.get("name") or "").strip()
        if not name:
            raise forms.ValidationError("Enter a name for this MikroTik.")
        return name

    def clean_location(self):
        return (self.cleaned_data.get("location") or "").strip()

    def clean_internet_provider(self):
        return (self.cleaned_data.get("internet_provider") or "").strip()

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
    """Update host / username / password and Wi‑Fi credentials."""

    class Meta:
        model = MikroTikRouter
        fields = ["host", "username", "password", "wifi_ssid", "wifi_password"]
        widgets = {
            "host": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "192.168.88.1",
                    "autocomplete": "off",
                    "id": "id_cred_mikrotik_host",
                }
            ),
            "username": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "admin",
                    "autocomplete": "username",
                    "id": "id_cred_mikrotik_username",
                }
            ),
            "password": forms.PasswordInput(
                attrs={
                    "class": "form-control password-input",
                    "placeholder": "Router password",
                    "autocomplete": "new-password",
                    "id": "id_cred_mikrotik_password",
                },
                render_value=True,
            ),
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
            "host": "IP / Host",
            "username": "Username",
            "password": "Password",
            "wifi_ssid": "Wi‑Fi name",
            "wifi_password": "Wi‑Fi password",
        }

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


class MikroTikWifiToggleForm(forms.Form):
    """Confirm activating or deactivating MikroTik Wi‑Fi."""

    confirm = forms.BooleanField(
        required=True,
        error_messages={"required": "Confirm to continue."},
        widget=forms.CheckboxInput(attrs={"id": "id_wifi_mikrotik_confirm"}),
    )
