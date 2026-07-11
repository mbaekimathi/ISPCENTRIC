import secrets

from django.contrib.auth.models import User
from django.db import models

from .image_utils import maybe_optimize_image_field


class Organization(models.Model):
    """ISP / company account created at registration."""

    class Status(models.TextChoices):
        REGISTERED = "registered", "Registered"
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"

    name = models.CharField(max_length=150)
    owner = models.OneToOneField(User, on_delete=models.CASCADE, related_name="organization")
    phone = models.CharField(max_length=30, blank=True)
    join_code = models.CharField(
        max_length=6,
        unique=True,
        db_index=True,
        help_text="6-digit code employees use to join this company",
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.REGISTERED,
        db_index=True,
        help_text="Set to Registered when the organization submits registration details",
    )
    profile_photo = models.ImageField(
        upload_to="profiles/%Y/%m/",
        blank=True,
        null=True,
        help_text="Optional profile photo",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "accounts_organization"

    @staticmethod
    def generate_join_code():
        while True:
            code = f"{secrets.randbelow(1_000_000):06d}"
            if not Organization.objects.filter(join_code=code).exists():
                return code

    def save(self, *args, **kwargs):
        if not self.join_code:
            self.join_code = Organization.generate_join_code()
        self.profile_photo = maybe_optimize_image_field(self.profile_photo)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class Employee(models.Model):
    """Staff member belonging to an ISP organization."""

    class Status(models.TextChoices):
        PENDING_APPROVAL = "pending_approval", "Pending approval"
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"
        BURNED = "burned", "Burned"

    class Role(models.TextChoices):
        PENDING = "pending", "Pending role allocation"
        SUPER_ADMIN = "super_admin", "Super admin"
        ADMINISTRATOR = "administrator", "Administrator"
        MANAGER = "manager", "Manager"
        IT_SUPPORT = "it_support", "IT support"
        SALES = "sales", "Sales"
        TECHNICIAN = "technician", "Technician"

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="employee_profile")
    organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        related_name="employees",
        null=True,
        blank=True,
    )
    phone = models.CharField(max_length=30, blank=True)
    login_code = models.CharField(
        max_length=6,
        unique=True,
        db_index=True,
        help_text="6-digit code the employee uses to log in",
    )
    profile_photo = models.ImageField(
        upload_to="employees/%Y/%m/",
        blank=True,
        null=True,
        help_text="Optional profile photo",
    )
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.PENDING_APPROVAL,
        db_index=True,
        help_text="Employee account status",
    )
    role = models.CharField(
        max_length=32,
        choices=Role.choices,
        default=Role.PENDING,
        db_index=True,
        help_text="Assigned employee role",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "accounts_employee"

    @property
    def is_pending(self):
        return self.status == self.Status.PENDING_APPROVAL or self.role == self.Role.PENDING

    @property
    def can_access_workspace(self):
        return self.status == self.Status.ACTIVE and self.role != self.Role.PENDING

    def save(self, *args, **kwargs):
        self.profile_photo = maybe_optimize_image_field(self.profile_photo)
        super().save(*args, **kwargs)

    def __str__(self):
        if self.organization_id:
            return f"{self.user.username} @ {self.organization.name}"
        return self.user.username
