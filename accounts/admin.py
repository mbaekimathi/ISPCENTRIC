from django import forms
from django.contrib import admin

from .models import (
    CompanyProfile,
    Employee,
    Lead,
    NetworkEquipment,
    Organization,
    PaymentGateway,
    RoleCommission,
)


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "status",
        "join_code",
        "owner",
        "phone",
        "daraja_enabled",
        "mpesa_payment_type",
        "mpesa_number",
        "created_at",
    )
    list_filter = ("status", "daraja_enabled", "mpesa_payment_type", "daraja_environment")
    search_fields = ("name", "join_code", "owner__username", "phone", "mpesa_number")
    list_editable = ("status",)
    readonly_fields = ("join_code", "created_at")


@admin.register(PaymentGateway)
class PaymentGatewayAdmin(admin.ModelAdmin):
    list_display = ("provider", "enabled", "environment", "payment_type", "shortcode", "updated_at")
    readonly_fields = ("updated_at",)
    fields = (
        "enabled",
        "provider",
        "environment",
        "payment_type",
        "shortcode",
        "consumer_key",
        "consumer_secret",
        "passkey",
        "callback_url",
        "updated_at",
    )

    def has_add_permission(self, request):
        return not PaymentGateway.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(CompanyProfile)
class CompanyProfileAdmin(admin.ModelAdmin):
    list_display = ("app_name", "email", "phone", "whatsapp", "updated_at")
    readonly_fields = ("updated_at",)
    fields = ("app_name", "email", "phone", "whatsapp", "logo", "updated_at")

    def has_add_permission(self, request):
        return not CompanyProfile.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(RoleCommission)
class RoleCommissionAdmin(admin.ModelAdmin):
    list_display = ("role", "enabled", "rate_type", "rate_value", "updated_at")
    list_filter = ("enabled", "rate_type", "role")
    search_fields = ("role", "notes")
    readonly_fields = ("updated_at",)
    fields = ("role", "enabled", "rate_type", "rate_value", "notes", "updated_at")


class EmployeeAdminForm(forms.ModelForm):
    class Meta:
        model = Employee
        fields = "__all__"
        widgets = {
            "status": forms.Select,
            "role": forms.Select,
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["status"] = forms.ChoiceField(
            choices=Employee.Status.choices,
            widget=forms.Select(attrs={"class": "vTextField"}),
        )
        self.fields["role"] = forms.ChoiceField(
            choices=Employee.Role.choices,
            widget=forms.Select(attrs={"class": "vTextField"}),
        )


@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    form = EmployeeAdminForm
    list_display = ("user", "login_code", "organization", "status", "role", "phone", "created_at")
    list_filter = ("status", "role", "organization")
    search_fields = ("user__username", "login_code", "organization__name", "phone", "user__first_name", "user__last_name")
    list_editable = ("status", "role")
    readonly_fields = ("created_at", "updated_at")
    fields = (
        "user",
        "organization",
        "login_code",
        "phone",
        "profile_photo",
        "status",
        "role",
        "created_at",
        "updated_at",
    )


@admin.register(Lead)
class LeadAdmin(admin.ModelAdmin):
    list_display = (
        "lead_number",
        "full_name",
        "phone",
        "customer_category",
        "service_type",
        "preferred_installation_date",
        "status",
        "organization",
        "created_at",
    )
    list_filter = ("status", "customer_category", "service_type", "lead_source", "organization")
    search_fields = ("lead_number", "full_name", "phone", "email", "location")
    readonly_fields = ("lead_number", "created_at", "updated_at")
    raw_id_fields = ("preferred_package", "preferred_isp", "organization", "created_by")


@admin.register(NetworkEquipment)
class NetworkEquipmentAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "equipment_type",
        "quantity",
        "created_by",
        "created_at",
    )
    list_filter = ("equipment_type",)
    search_fields = ("name",)
    readonly_fields = ("created_at", "updated_at")
    raw_id_fields = ("created_by",)
