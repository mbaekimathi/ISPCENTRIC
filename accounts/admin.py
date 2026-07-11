from django import forms
from django.contrib import admin

from .models import Employee, Organization


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "status", "join_code", "owner", "phone", "created_at")
    list_filter = ("status",)
    search_fields = ("name", "join_code", "owner__username", "phone")
    list_editable = ("status",)
    readonly_fields = ("join_code", "created_at")


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
