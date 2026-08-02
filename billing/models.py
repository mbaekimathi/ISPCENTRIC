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
    routers = models.ManyToManyField(
        "core.MikroTikRouter",
        blank=True,
        related_name="billing_plans",
        help_text="Optional. Leave empty to offer this package on all MikroTiks; "
        "select specific routers to limit where it can be used.",
    )
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

    @property
    def router_scope_label(self) -> str:
        """Short label for package tables: All MikroTiks vs linked names."""
        # Prefer prefetched cache when available (dashboard/packages lists).
        prefetched = getattr(self, "_prefetched_objects_cache", {})
        if "routers" in prefetched:
            linked = list(prefetched["routers"])
        else:
            linked = list(self.routers.all())
        if not linked:
            return "All MikroTiks"
        names = [r.name for r in linked[:3]]
        extra = len(linked) - len(names)
        label = ", ".join(names)
        if extra > 0:
            label = f"{label} +{extra}"
        return label

    def is_available_on_router(self, router) -> bool:
        """True when unlinked (all routers) or explicitly linked to this router."""
        if router is None:
            return True
        router_id = getattr(router, "pk", router)
        if not router_id:
            return True
        if not self.routers.exists():
            return True
        return self.routers.filter(pk=router_id).exists()

    def sync_general_speed(self) -> None:
        """General speed follows the package download rate."""
        self.speed_mbps = self.download_speed_mbps or self.upload_speed_mbps or self.speed_mbps or 1

    def save(self, *args, **kwargs):
        self.sync_general_speed()
        self.image = maybe_optimize_image_field(self.image)
        super().save(*args, **kwargs)


class Customer(models.Model):
    class Status(models.TextChoices):
        NEW = "new", "New"
        ALLOCATED = "allocated", "Allocated"
        ALLOCATED_OPEN = "allocated_open", "Allocated — open"
        ALLOCATED_CLOSED = "allocated_closed", "Allocated — closed"
        ACCEPTED = "accepted", "Accepted"
        NOT_INTERESTED = "not_interested", "Not interested"
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"
        INACTIVE = "inactive", "Inactive"

    ALLOCATED_STATUSES = (
        Status.ALLOCATED,
        Status.ALLOCATED_OPEN,
        Status.ALLOCATED_CLOSED,
    )

    class ServiceType(models.TextChoices):
        PPPOE = "pppoe", "PPPoE"
        STATIC = "static", "Static"
        HOTSPOT = "hotspot", "Hotspot"

    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="customers",
        null=True,
        blank=True,
        help_text="ISP this client belongs to. Optional until a specific provider is assigned.",
    )
    full_name = models.CharField(max_length=150)
    phone = models.CharField(max_length=30)
    email = models.EmailField(blank=True)
    address = models.CharField(
        "Location",
        max_length=255,
        blank=True,
        help_text="Map place name selected during registration.",
    )
    location_lat = models.DecimalField(
        max_digits=9, decimal_places=6, null=True, blank=True
    )
    location_lng = models.DecimalField(
        max_digits=9, decimal_places=6, null=True, blank=True
    )
    building_name = models.CharField(max_length=150, blank=True)
    house_number = models.CharField(max_length=60, blank=True)
    account_number = models.CharField(max_length=40, unique=True)
    sales_ticket_number = models.CharField(
        "Sales ticket number",
        max_length=40,
        unique=True,
        null=True,
        blank=True,
        db_index=True,
        help_text="Generated when sales registers this client.",
    )
    service_type = models.CharField(
        max_length=20,
        choices=ServiceType.choices,
        default=ServiceType.PPPOE,
        db_index=True,
    )
    pppoe_username = models.CharField("PPPoE username", max_length=64, blank=True)
    pppoe_password = models.CharField("PPPoE password", max_length=128, blank=True)
    hotspot_mac = models.CharField(
        "Hotspot device MAC",
        max_length=17,
        blank=True,
        null=True,
        default=None,
        db_index=True,
        help_text="Device authorized automatically after a successful Hotspot payment.",
    )
    # CPE = the subscriber's own router that dials PPPoE into the ISP MikroTik.
    cpe_username = models.CharField(
        "CPE username",
        max_length=64,
        blank=True,
        default="admin",
        help_text="RouterOS / Winbox username on the client's CPE router.",
    )
    cpe_password = models.CharField(
        "CPE password",
        max_length=128,
        blank=True,
        help_text="RouterOS / Winbox password on the client's CPE router.",
    )
    cpe_wifi_ssid = models.CharField("CPE Wi‑Fi name", max_length=64, blank=True)
    cpe_wifi_password = models.CharField("CPE Wi‑Fi password", max_length=128, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    plan = models.ForeignKey(
        BillingPlan,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="customers",
    )
    package_start = models.DateTimeField(
        "Package start",
        null=True,
        blank=True,
        help_text="When this client's current package period began.",
    )
    package_end = models.DateTimeField(
        "Package end",
        null=True,
        blank=True,
        help_text="When this client's current package period ends (from plan duration or manual override).",
    )
    router = models.ForeignKey(
        "core.MikroTikRouter",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="customers",
        help_text="MikroTik this client is provisioned on.",
    )
    registered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="registered_customers",
        null=True,
        blank=True,
        help_text="Sales staff (or other user) who registered this client.",
    )
    assigned_technician = models.ForeignKey(
        "accounts.Employee",
        on_delete=models.SET_NULL,
        related_name="assigned_customers",
        null=True,
        blank=True,
        help_text="Technician assigned when this lead was allocated (closed assignment).",
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
        constraints = [
            # NULL MACs are distinct in MySQL/MariaDB unique indexes, so PPPoE
            # rows without a device MAC do not collide. Hotspot rows store a
            # concrete MAC and cannot duplicate within an organization.
            models.UniqueConstraint(
                fields=["organization", "hotspot_mac"],
                name="bill_cust_org_hotspot_mac_uniq",
            ),
        ]

    def save(self, *args, **kwargs):
        mac = (self.hotspot_mac or "").strip()
        self.hotspot_mac = mac or None
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.full_name} ({self.account_number})"


class InstallationDecline(models.Model):
    """Per-technician hide of an installation ticket with a reason."""

    class Reason(models.TextChoices):
        TOO_FAR = "too_far", "Too far / wrong location"
        NO_CAPACITY = "no_capacity", "No capacity / too busy"
        SITE_NOT_READY = "site_not_ready", "Site not ready"
        ACCESS_ISSUE = "access_issue", "Access / security issue"
        OTHER = "other", "Other reason"

    DETAIL_REQUIRED = {Reason.OTHER}

    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name="installation_declines",
    )
    technician = models.ForeignKey(
        "accounts.Employee",
        on_delete=models.CASCADE,
        related_name="installation_declines",
    )
    reason_category = models.CharField(max_length=40, choices=Reason.choices)
    reason = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "billing_installation_decline"
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["customer", "technician"],
                name="bill_inst_decline_cust_tech_uniq",
            ),
        ]

    def __str__(self):
        return f"{self.customer_id} declined by {self.technician_id}: {self.reason}"


class InstallationReject(models.Model):
    """Reason logged when a technician returns a ticket to allocated-open."""

    class Reason(models.TextChoices):
        TOO_FAR = "too_far", "Too far / wrong location"
        NO_CAPACITY = "no_capacity", "No capacity / too busy"
        SITE_NOT_READY = "site_not_ready", "Site not ready"
        ACCESS_ISSUE = "access_issue", "Access / security issue"
        CLIENT_UNAVAILABLE = "client_unavailable", "Client unavailable"
        OTHER = "other", "Other reason"

    DETAIL_REQUIRED = {Reason.OTHER, Reason.CLIENT_UNAVAILABLE}

    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name="installation_rejects",
    )
    technician = models.ForeignKey(
        "accounts.Employee",
        on_delete=models.CASCADE,
        related_name="installation_rejects",
    )
    reason_category = models.CharField(max_length=40, choices=Reason.choices)
    reason = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "billing_installation_reject"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.customer_id} rejected by {self.technician_id}: {self.reason}"


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
        indexes = [
            models.Index(fields=["organization", "status"], name="bill_inv_org_status_idx"),
            models.Index(fields=["customer", "-issued_at"], name="bill_inv_cust_issued_idx"),
            models.Index(fields=["organization", "customer"], name="bill_inv_org_cust_idx"),
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
        indexes = [
            models.Index(fields=["organization", "received_at"], name="bill_pay_org_recv_idx"),
        ]

    def __str__(self):
        return f"{self.reference or self.pk} — {self.amount}"


class StkPushRequest(models.Model):
    """Tracks an M-Pesa STK Push attempt for subscription payment."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    class Purpose(models.TextChoices):
        SUBSCRIPTION = "subscription", "Subscription renewal"
        LEAD_ALLOCATION = "lead_allocation", "Lead allocation"

    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="stk_push_requests",
    )
    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name="stk_push_requests",
    )
    plan = models.ForeignKey(
        BillingPlan,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="stk_push_requests",
        help_text="Package selected and priced when this payment attempt began.",
    )
    purpose = models.CharField(
        max_length=32,
        choices=Purpose.choices,
        default=Purpose.SUBSCRIPTION,
        db_index=True,
    )
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    phone = models.CharField(max_length=20)
    account_reference = models.CharField(max_length=64)
    merchant_request_id = models.CharField(max_length=64, blank=True)
    checkout_request_id = models.CharField(max_length=64, blank=True, db_index=True)
    mpesa_receipt = models.CharField(max_length=64, blank=True)
    result_code = models.IntegerField(null=True, blank=True)
    result_desc = models.CharField(max_length=255, blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    invoice = models.ForeignKey(
        Invoice,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="stk_push_requests",
    )
    payment = models.ForeignKey(
        Payment,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="stk_push_requests",
    )
    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="initiated_stk_pushes",
    )
    subscription_applied = models.BooleanField(default=False)
    raw_callback = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "billing_stk_push_request"
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["organization", "status", "-created_at"],
                name="bill_stk_org_status_idx",
            ),
            models.Index(
                fields=["customer", "-created_at"],
                name="bill_stk_cust_created_idx",
            ),
        ]

    def __str__(self):
        return f"STK {self.checkout_request_id or self.pk} ({self.status})"


class CustomerUsageSample(models.Model):
    """Time-series snapshot of a PPPoE client's live session metrics."""

    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name="usage_samples",
    )
    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="customer_usage_samples",
    )
    sampled_at = models.DateTimeField(db_index=True)
    session_active = models.BooleanField(default=False)
    uptime_seconds = models.PositiveIntegerField(default=0)
    download_bps = models.BigIntegerField(default=0)
    upload_bps = models.BigIntegerField(default=0)
    bytes_in = models.BigIntegerField(default=0)
    bytes_out = models.BigIntegerField(default=0)
    address = models.CharField(max_length=64, blank=True)

    class Meta:
        db_table = "billing_customer_usage_sample"
        ordering = ["sampled_at"]
        indexes = [
            models.Index(
                fields=["customer", "sampled_at"],
                name="bill_usage_cust_sampled_idx",
            ),
            models.Index(
                fields=["organization", "sampled_at"],
                name="bill_usage_org_sampled_idx",
            ),
        ]

    def __str__(self):
        return f"Usage sample {self.customer_id} @ {self.sampled_at}"
