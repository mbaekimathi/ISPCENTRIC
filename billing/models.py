from decimal import Decimal

from django.conf import settings
from django.db import models
from django.utils import timezone

from accounts.image_utils import maybe_optimize_image_field


class BillingPlan(models.Model):
    class Duration(models.TextChoices):
        HOURLY = "hourly", "Per hour"
        DAILY = "daily", "Daily"
        WEEKLY = "weekly", "Weekly"
        MONTHLY = "monthly", "Monthly"
        YEARLY = "yearly", "Yearly"

    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="plans",
    )
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    price = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))
    download_speed_mbps = models.PositiveIntegerField("Download speed (Mbps)", default=10)
    upload_speed_mbps = models.PositiveIntegerField("Upload speed (Mbps)", default=5)
    speed_mbps = models.PositiveIntegerField(
        "General speed (Mbps)",
        default=10,
        help_text="Derived from download/upload speeds for summaries and legacy displays.",
    )
    duration = models.CharField(max_length=20, choices=Duration.choices, default=Duration.MONTHLY)
    image = models.ImageField(
        "Package image",
        upload_to="billing/packages/%Y/%m/",
        blank=True,
        null=True,
        help_text="Optional package image shown on billing screens.",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "billing_plan"
        ordering = ["price"]

    def __str__(self):
        return f"{self.name} ({self.price})"

    @property
    def speed_label(self) -> str:
        down = self.download_speed_mbps or self.speed_mbps or 0
        up = self.upload_speed_mbps or 0
        if down and up:
            return f"{down}/{up} Mbps"
        if down:
            return f"{down} Mbps"
        return "—"

    def sync_general_speed(self) -> None:
        """General speed follows the package download rate."""
        self.speed_mbps = self.download_speed_mbps or self.upload_speed_mbps or self.speed_mbps or 1

    def save(self, *args, **kwargs):
        self.sync_general_speed()
        self.image = maybe_optimize_image_field(self.image)
        super().save(*args, **kwargs)


class Customer(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        PAUSED = "paused", "Paused"
        SUSPENDED = "suspended", "Suspended"
        INACTIVE = "inactive", "Inactive"

    class ServiceType(models.TextChoices):
        PPPOE = "pppoe", "PPPoE"
        STATIC = "static", "Static"
        HOTSPOT = "hotspot", "Hotspot"

    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="customers",
    )
    full_name = models.CharField(max_length=150)
    phone = models.CharField(max_length=30)
    email = models.EmailField(blank=True)
    address = models.CharField(max_length=255, blank=True)
    account_number = models.CharField(max_length=40, unique=True)
    service_type = models.CharField(
        max_length=20,
        choices=ServiceType.choices,
        default=ServiceType.PPPOE,
        db_index=True,
    )
    pppoe_username = models.CharField("PPPoE username", max_length=64, blank=True)
    pppoe_password = models.CharField("PPPoE password", max_length=128, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    plan = models.ForeignKey(
        BillingPlan,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="customers",
    )
    router = models.ForeignKey(
        "core.MikroTikRouter",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="customers",
        help_text="MikroTik this client is provisioned on.",
    )
    service_start = models.DateField(
        "Service start",
        null=True,
        blank=True,
        help_text="First day of the current paid surfing period.",
    )
    service_until = models.DateField(
        "Service until",
        null=True,
        blank=True,
        help_text="Last day of the current paid surfing period.",
    )
    paused_days_remaining = models.PositiveIntegerField(
        "Paused days remaining",
        null=True,
        blank=True,
        help_text="Inclusive paid days frozen while the subscription is paused.",
    )
    paused_at = models.DateField(
        "Paused on",
        null=True,
        blank=True,
        help_text="Date the subscription was paused.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "billing_customer"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["organization", "status"], name="bill_cust_org_status_idx"),
            models.Index(
                fields=["organization", "service_type"],
                name="bill_cust_org_svc_idx",
            ),
        ]

    def __str__(self):
        return f"{self.full_name} ({self.account_number})"


class Invoice(models.Model):
    class Status(models.TextChoices):
        DRAFT = "draft", "Draft"
        PENDING = "pending", "Pending"
        PAID = "paid", "Paid"
        OVERDUE = "overdue", "Overdue"
        CANCELLED = "cancelled", "Cancelled"

    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="invoices",
    )
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name="invoices")
    invoice_number = models.CharField(max_length=40, unique=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    due_date = models.DateField()
    period_start = models.DateField(
        "Billing period start",
        null=True,
        blank=True,
        help_text="First day of the billed surfing cycle.",
    )
    period_end = models.DateField(
        "Billing period end",
        null=True,
        blank=True,
        help_text="Last day of the billed surfing cycle.",
    )
    issued_at = models.DateTimeField(default=timezone.now)
    paid_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        db_table = "billing_invoice"
        ordering = ["-issued_at"]
        indexes = [
            models.Index(fields=["organization", "status"], name="bill_inv_org_status_idx"),
            models.Index(
                fields=["customer", "period_start", "period_end"],
                name="bill_inv_cust_period_idx",
            ),
        ]

    def __str__(self):
        return self.invoice_number


class Payment(models.Model):
    class Method(models.TextChoices):
        MPESA = "mpesa", "M-Pesa"
        CASH = "cash", "Cash"
        BANK = "bank", "Bank Transfer"
        CARD = "card", "Card"
        OTHER = "other", "Other"

    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="payments",
    )
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name="payments")
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    method = models.CharField(max_length=20, choices=Method.choices, default=Method.MPESA)
    reference = models.CharField(max_length=100, blank=True)
    received_at = models.DateTimeField(default=timezone.now)
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="recorded_payments",
    )

    class Meta:
        db_table = "billing_payment"
        ordering = ["-received_at"]

    def __str__(self):
        return f"{self.reference or self.pk} — {self.amount}"
