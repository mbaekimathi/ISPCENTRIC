from decimal import Decimal

from django.conf import settings
from django.db import models
from django.utils import timezone


class BillingPlan(models.Model):
    class Duration(models.TextChoices):
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
    speed_mbps = models.PositiveIntegerField(default=10)
    duration = models.CharField(max_length=20, choices=Duration.choices, default=Duration.MONTHLY)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "billing_plan"
        ordering = ["price"]

    def __str__(self):
        return f"{self.name} ({self.price})"


class Customer(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"
        INACTIVE = "inactive", "Inactive"

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
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    plan = models.ForeignKey(
        BillingPlan,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="customers",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "billing_customer"
        ordering = ["-created_at"]

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
    issued_at = models.DateTimeField(default=timezone.now)
    paid_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        db_table = "billing_invoice"
        ordering = ["-issued_at"]

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
