from decimal import Decimal

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone

from accounts.image_utils import maybe_optimize_image_field


class BillingPlan(models.Model):
    class Duration(models.TextChoices):
        HOURLY = "hourly", "Per hour"
        SIX_HOURS = "six_hours", "Per 6 hours"
        DAILY = "daily", "Daily"
        WEEKLY = "weekly", "Weekly"
        MONTHLY = "monthly", "Monthly"
        QUARTERLY = "quarterly", "Quarterly"
        SEMI_ANNUAL = "semi_annual", "Semi-annual"
        YEARLY = "yearly", "Yearly"

    class ServiceType(models.TextChoices):
        PPPOE = "pppoe", "PPPoE"
        HOTSPOT = "hotspot", "Hotspot"

    # Durations that use clock time (start/end times) instead of calendar days.
    CLOCK_TIME_DURATIONS = frozenset({Duration.HOURLY, Duration.SIX_HOURS})

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
    service_type = models.CharField(
        max_length=20,
        choices=ServiceType.choices,
        default=ServiceType.PPPOE,
        db_index=True,
        help_text="Whether this package is for Hotspot or PPPoE customers.",
    )
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
    max_devices = models.PositiveIntegerField(
        "Max devices",
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(50)],
        help_text=(
            "How many Hotspot devices this package allows. 0 / blank = unlimited. "
            "Hotspot: phones/laptops on one paid account. "
            "PPPoE always enforces 1 concurrent dial (one CPE); LAN behind it is unlimited."
        ),
    )
    offer_enabled = models.BooleanField(
        "Package offer enabled",
        default=False,
        help_text="When enabled, repeat payers earn a free session after the set number of payments.",
    )
    offer_pay_count = models.PositiveSmallIntegerField(
        "Payments before free session",
        default=5,
        validators=[MinValueValidator(1), MaxValueValidator(100)],
        help_text="Buy X get 1 free — e.g. 5 means every 5 paid sessions grants one extra session.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "billing_plan"
        ordering = ["price"]

    def __str__(self):
        return f"{self.name} ({self.price})"

    @property
    def uses_clock_time(self) -> bool:
        """True when package windows are measured in hours (not calendar days)."""
        return self.duration in self.CLOCK_TIME_DURATIONS

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
    def max_devices_label(self) -> str:
        n = int(self.max_devices or 0)
        if self.service_type == self.ServiceType.PPPOE:
            # MikroTik only-one=yes — one CPE dial; LAN behind it is unlimited.
            return "1 CPE · unlimited LAN"
        if n <= 0:
            return "Unlimited devices"
        if self.service_type == self.ServiceType.HOTSPOT:
            if n == 1:
                return "1 device · 1 voucher"
            return f"{n} devices · {n} vouchers"
        return "1 device" if n == 1 else f"{n} devices"

    @property
    def offer_display_label(self) -> str:
        """Short label for admin tables and pay portals."""
        if not self.offer_enabled:
            return ""
        count = int(self.offer_pay_count or 0)
        if count < 1:
            return ""
        return f"Buy {count} get 1 free"

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
    phone_normalized = models.CharField(
        max_length=20,
        blank=True,
        default="",
        db_index=True,
        help_text="Digits-only phone key used to enforce one account per number.",
    )
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
    cpe_ip = models.CharField(
        "CPE IP address",
        max_length=45,
        blank=True,
        help_text="Fixed LAN IP for static clients (used for remote router access).",
    )
    cpe_mac = models.CharField(
        "CPE MAC address",
        max_length=17,
        blank=True,
        help_text="Router MAC for dynamic DHCP clients — IP is resolved from the NAS lease.",
    )
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
    package_paused_at = models.DateTimeField(
        "Package paused at",
        null=True,
        blank=True,
        help_text=(
            "When set, the package clock is frozen: surfing is blocked and the "
            "remaining period is preserved until resume."
        ),
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
            models.UniqueConstraint(
                fields=["organization", "phone_normalized"],
                condition=models.Q(phone_normalized__gt=""),
                name="bill_cust_org_phone_uniq",
            ),
        ]

    def save(self, *args, **kwargs):
        from billing.services import normalize_customer_phone_key

        mac = (self.hotspot_mac or "").strip()
        self.hotspot_mac = mac or None
        self.phone_normalized = normalize_customer_phone_key(self.phone)
        update_fields = kwargs.get("update_fields")
        if update_fields is not None and "phone_normalized" not in update_fields:
            if "phone" in update_fields or "hotspot_mac" in update_fields:
                kwargs["update_fields"] = list(update_fields) + ["phone_normalized"]
        super().save(*args, **kwargs)
        mac = (self.hotspot_mac or "").strip()
        if mac and self.pk and self.organization_id:
            from billing.devices import ensure_customer_device

            ensure_customer_device(self, mac)

    def __str__(self):
        return f"{self.full_name} ({self.account_number})"


class CustomerDevice(models.Model):
    """A Hotspot MAC authorized on a Customer, up to BillingPlan.max_devices."""

    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="customer_devices",
    )
    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name="devices",
    )
    mac = models.CharField("Device MAC", max_length=17, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "billing_customer_device"
        ordering = ["id"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "mac"],
                name="bill_cust_dev_org_mac_uniq",
            ),
        ]
        indexes = [
            models.Index(fields=["customer", "mac"], name="bill_cust_dev_cust_mac_idx"),
        ]

    def save(self, *args, **kwargs):
        from billing.devices import normalize_device_mac

        self.mac = normalize_device_mac(self.mac)
        if self.organization_id is None and self.customer_id:
            org_id = getattr(self.customer, "organization_id", None)
            if org_id is None:
                org_id = (
                    Customer.objects.filter(pk=self.customer_id)
                    .values_list("organization_id", flat=True)
                    .first()
                )
            self.organization_id = org_id
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.mac} ({self.customer_id})"


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
        MIKROTIK_ONBOARDING = "mikrotik_onboarding", "MikroTik onboarding"

    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="stk_push_requests",
    )
    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name="stk_push_requests",
        null=True,
        blank=True,
        help_text="Optional for platform fees such as MikroTik onboarding.",
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


class PackageOfferProgress(models.Model):
    """Tracks paid renewals toward a package buy-X-get-1-free offer."""

    customer = models.ForeignKey(
        "Customer",
        on_delete=models.CASCADE,
        related_name="package_offer_progress",
    )
    plan = models.ForeignKey(
        BillingPlan,
        on_delete=models.CASCADE,
        related_name="offer_progress",
    )
    paid_count = models.PositiveSmallIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "billing_package_offer_progress"
        constraints = [
            models.UniqueConstraint(
                fields=["customer", "plan"],
                name="billing_offer_progress_customer_plan_uniq",
            ),
        ]

    def __str__(self):
        return f"Offer progress {self.customer_id}/{self.plan_id}: {self.paid_count}"


class AccessVoucher(models.Model):
    """
    One-time activation code created after a successful subscription payment.

    Hotspot packages with max_devices = N issue N vouchers (one per device).
    PPPoE payments issue a single voucher.

    Lifecycle:
      valid   — paid; unused; redeemable
      expired — legacy “used” (redeemed once); cannot activate again
      invalid — used / burned; code can never activate again

    Transitions:
      payment success → valid (N codes for a Hotspot device package)
      redeem or successful auto-connect → invalid (this device only)
      surfing while valid → invalid for that device’s voucher only
      unused sibling vouchers stay valid for other devices
    """

    class Status(models.TextChoices):
        VALID = "valid", "Valid"
        EXPIRED = "expired", "Used"
        INVALID = "invalid", "Invalid"

    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="access_vouchers",
    )
    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name="access_vouchers",
    )
    plan = models.ForeignKey(
        BillingPlan,
        on_delete=models.PROTECT,
        related_name="access_vouchers",
    )
    stk_request = models.ForeignKey(
        StkPushRequest,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="access_vouchers",
    )
    payment = models.ForeignKey(
        "Payment",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="access_vouchers",
        help_text="Cash/bank recharge that issued this voucher batch (when no STK).",
    )
    subscription_applied = models.BooleanField(
        default=False,
        help_text="True when the paid package for this voucher was already extended (cash recharge or STK activate).",
    )
    code = models.CharField(max_length=24, db_index=True)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.VALID,
        db_index=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    redeemed_at = models.DateTimeField(null=True, blank=True)
    invalidated_at = models.DateTimeField(null=True, blank=True)
    redeemed_mac = models.CharField(max_length=17, blank=True)

    class Meta:
        db_table = "billing_access_voucher"
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "code"],
                name="bill_voucher_org_code_uniq",
            ),
        ]
        indexes = [
            models.Index(
                fields=["organization", "status", "-created_at"],
                name="bill_voucher_org_status_idx",
            ),
            models.Index(
                fields=["customer", "status"],
                name="bill_voucher_cust_status_idx",
            ),
            models.Index(
                fields=["stk_request", "status"],
                name="bill_voucher_stk_status_idx",
            ),
            models.Index(
                fields=["payment", "status"],
                name="bill_voucher_pay_status_idx",
            ),
        ]

    def __str__(self):
        return f"Voucher {self.code} ({self.status})"

    @property
    def is_redeemable(self) -> bool:
        return self.status == self.Status.VALID
