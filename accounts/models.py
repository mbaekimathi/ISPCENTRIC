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
    pppoe_compulsory = models.BooleanField(
        "PPPoE enforcement",
        default=False,
        help_text=(
            "When enabled, free LAN browsing is blocked. Paid PPPoE clients "
            "surf automatically; other devices fall back to the Hotspot "
            "payment portal."
        ),
    )
    hotspot_enabled = models.BooleanField(
        "Enable Hotspot",
        default=False,
        help_text=(
            "Allow Hotspot portals and voucher access for this organization. "
            "Enabled automatically as fallback when PPPoE enforcement is on."
        ),
    )
    hotspot_portal_title = models.CharField(
        "Portal title",
        max_length=120,
        blank=True,
        default="",
        help_text="Title shown on the Hotspot login page.",
    )
    hotspot_login_message = models.TextField(
        "Login message",
        blank=True,
        default="",
        help_text="Welcome text shown on the Hotspot login page.",
    )
    hotspot_redirect_url = models.URLField(
        "Redirect URL after login",
        max_length=500,
        blank=True,
        default="",
        help_text="URL clients open after a successful Hotspot login.",
    )
    hotspot_use_welcome_page = models.BooleanField(
        "Use ISPCENTRIC welcome page",
        default=True,
        help_text="After login, send clients to your customizable Hotspot welcome page.",
    )
    hotspot_welcome_title = models.CharField(
        "Welcome page title",
        max_length=120,
        blank=True,
        default="",
        help_text="Headline on the post-login welcome page.",
    )
    hotspot_welcome_message = models.TextField(
        "Welcome page message",
        blank=True,
        default="",
        help_text="Body text on the post-login welcome page.",
    )
    hotspot_welcome_button_label = models.CharField(
        "Welcome button label",
        max_length=80,
        blank=True,
        default="",
        help_text="Label for the main button on the welcome page.",
    )
    hotspot_welcome_button_url = models.URLField(
        "Welcome button link",
        max_length=500,
        blank=True,
        default="",
        help_text="Optional link for the welcome page button (e.g. your website).",
    )
    hotspot_voucher_validity_hours = models.PositiveIntegerField(
        "Default voucher validity (hours)",
        default=24,
        help_text="Default lifetime for new Hotspot vouchers.",
    )
    hotspot_default_download_mbps = models.PositiveIntegerField(
        "Default download (Mbps)",
        default=10,
        help_text="Default download speed for new Hotspot vouchers.",
    )
    hotspot_default_upload_mbps = models.PositiveIntegerField(
        "Default upload (Mbps)",
        default=5,
        help_text="Default upload speed for new Hotspot vouchers.",
    )
    hotspot_idle_timeout_minutes = models.PositiveIntegerField(
        "Idle timeout (minutes)",
        default=15,
        help_text="Disconnect idle Hotspot sessions after this many minutes. Use 0 for no idle timeout.",
    )

    class MpesaPaymentType(models.TextChoices):
        NONE = "", "Not set"
        PAYBILL = "paybill", "Paybill"
        TILL = "till", "Buy Goods Till"

    mpesa_payment_type = models.CharField(
        "M-Pesa payment type",
        max_length=20,
        choices=MpesaPaymentType.choices,
        blank=True,
        default="",
        help_text="How subscribers pay for packages: Paybill or Buy Goods Till.",
    )
    mpesa_number = models.CharField(
        "M-Pesa number",
        max_length=20,
        blank=True,
        help_text="Paybill number or Buy Goods Till number.",
    )
    mpesa_account = models.CharField(
        "Paybill account",
        max_length=64,
        blank=True,
        help_text="Optional Paybill account / reference clients should enter.",
    )
    class DarajaEnvironment(models.TextChoices):
        SANDBOX = "sandbox", "Sandbox"
        PRODUCTION = "production", "Production"

    daraja_enabled = models.BooleanField(
        "Enable Daraja API",
        default=False,
        help_text="Receive subscription payments via M-Pesa Daraja STK Push.",
    )
    daraja_environment = models.CharField(
        "Daraja environment",
        max_length=20,
        choices=DarajaEnvironment.choices,
        default=DarajaEnvironment.SANDBOX,
    )
    daraja_consumer_key = models.CharField(
        "Daraja consumer key",
        max_length=255,
        blank=True,
    )
    daraja_consumer_secret = models.CharField(
        "Daraja consumer secret",
        max_length=255,
        blank=True,
    )
    daraja_passkey = models.CharField(
        "Lipa Na M-Pesa passkey",
        max_length=255,
        blank=True,
        help_text="Passkey for your Paybill or Till Lipa Na M-Pesa Online shortcode.",
    )
    registered_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        related_name="registered_organizations",
        null=True,
        blank=True,
        help_text="Sales staff (or other user) who registered this ISP / business.",
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
        from accounts.routing import invalidate_switchable_clients_cache

        invalidate_switchable_clients_cache()

    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)
        from accounts.routing import invalidate_switchable_clients_cache

        invalidate_switchable_clients_cache()

    def __str__(self):
        return self.name

    @property
    def receives_via_label(self) -> str:
        if self.mpesa_payment_type == self.MpesaPaymentType.PAYBILL and self.mpesa_number:
            return f"Paybill {self.mpesa_number}"
        if self.mpesa_payment_type == self.MpesaPaymentType.TILL and self.mpesa_number:
            return f"Till {self.mpesa_number}"
        return "Not set"

    def uses_platform_daraja_credentials(self) -> bool:
        """Sandbox / testing uses IT Support Payment Gateway credentials."""
        env = (self.daraja_environment or self.DarajaEnvironment.SANDBOX).strip().lower()
        return env != self.DarajaEnvironment.PRODUCTION

    def effective_daraja_credentials(self) -> dict:
        """
        Credentials used for STK Push.

        Testing (sandbox): IT Support Payment Gateway settings.
        Production: this organization's own Daraja fields + Paybill/Till.
        """
        payment_type = (self.mpesa_payment_type or "").strip()
        shortcode = (self.mpesa_number or "").strip()
        environment = self.daraja_environment or self.DarajaEnvironment.SANDBOX

        if not self.daraja_enabled:
            return {
                "enabled": False,
                "ready": False,
                "source": "none",
                "source_label": "Off",
                "environment": environment,
                "payment_type": payment_type,
                "shortcode": shortcode,
                "consumer_key": "",
                "consumer_secret": "",
                "passkey": "",
                "callback_url": "",
                "message": "Daraja API is turned off.",
            }

        if not payment_type or not shortcode:
            return {
                "enabled": True,
                "ready": False,
                "source": "incomplete",
                "source_label": "Incomplete",
                "environment": environment,
                "payment_type": payment_type,
                "shortcode": shortcode,
                "consumer_key": "",
                "consumer_secret": "",
                "passkey": "",
                "callback_url": "",
                "message": "Choose Paybill or Till and enter the number first.",
            }

        if self.uses_platform_daraja_credentials():
            gateway = PaymentGateway.get_solo()
            ready = gateway.is_stk_ready()
            # STK BusinessShortCode/passkey must match the Daraja app on the gateway.
            # Org Paybill/Till is the receive method shown to clients; the Lipa Na
            # M-Pesa Online shortcode comes from IT Support Payment Gateway.
            gw_shortcode = (gateway.shortcode or "").strip() or shortcode
            gw_payment_type = (gateway.payment_type or "").strip() or payment_type
            gw_environment = (
                gateway.environment or PaymentGateway.Environment.SANDBOX
            ).strip().lower()
            # Live Paybill/Till shortcodes must hit api.safaricom.co.ke.
            # Sandbox host only works with Safaricom's test shortcode 174379.
            if gw_shortcode and gw_shortcode != "174379":
                gw_environment = PaymentGateway.Environment.PRODUCTION
            return {
                "enabled": True,
                "ready": ready,
                "source": "it_support",
                "source_label": "IT Support Payment Gateway",
                "environment": gw_environment,
                "payment_type": gw_payment_type,
                "shortcode": gw_shortcode,
                "consumer_key": (gateway.consumer_key or "").strip(),
                "consumer_secret": (gateway.consumer_secret or "").strip(),
                "passkey": (gateway.passkey or "").strip(),
                "callback_url": gateway.resolved_callback_url(),
                "message": (
                    f"Using IT Support Daraja credentials ({gw_environment}) "
                    f"with shortcode {gw_shortcode}."
                    if ready
                    else "IT Support Payment Gateway is not ready for STK Push."
                ),
            }

        key = (self.daraja_consumer_key or "").strip()
        secret = (self.daraja_consumer_secret or "").strip()
        passkey = (self.daraja_passkey or "").strip()
        ready = bool(key and secret and passkey)
        return {
            "enabled": True,
            "ready": ready,
            "source": "organization",
            "source_label": "Organization credentials",
            "environment": self.DarajaEnvironment.PRODUCTION,
            "payment_type": payment_type,
            "shortcode": shortcode,
            "consumer_key": key,
            "consumer_secret": secret,
            "passkey": passkey,
            "callback_url": "",
            "message": (
                "Using this organization's production Daraja credentials."
                if ready
                else "Add production consumer key, secret, and passkey."
            ),
        }


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
        MANAGER = "manager", "Customer support"
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


class Lead(models.Model):
    """Sales lead captured by the sales team."""

    class CustomerCategory(models.TextChoices):
        HOME = "home", "Home internet"
        BUSINESS = "business", "Business internet"
        ISP_CLIENT = "isp_client", "ISP client"
        HOTSPOT_CLIENT = "hotspot_client", "Hotspot client"

    class ServiceType(models.TextChoices):
        HOME_INTERNET = "home_internet", "Home internet"
        BUSINESS_INTERNET = "business_internet", "Business internet"
        DEDICATED_LINK = "dedicated_link", "Dedicated link"
        STARLINK_INSTALLATION = "starlink_installation", "Starlink installation"
        HOTSPOT = "hotspot", "Hotspot"

    class LeadSource(models.TextChoices):
        WALK_IN = "walk_in", "Walk-in"
        PHONE_CALL = "phone_call", "Phone call"
        REFERRAL = "referral", "Referral"
        WEBSITE = "website", "Website"
        SOCIAL_MEDIA = "social_media", "Social media"
        FIELD_VISIT = "field_visit", "Field visit"
        OTHER = "other", "Other"

    class Status(models.TextChoices):
        NEW = "new", "New"
        CONTACTED = "contacted", "Contacted"
        QUALIFIED = "qualified", "Qualified"
        CONVERTED = "converted", "Converted"
        LOST = "lost", "Lost"

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="leads",
        null=True,
        blank=True,
        help_text="Sales organization that owns this lead (optional until an ISP is chosen).",
    )
    lead_number = models.CharField(max_length=40, unique=True, db_index=True)
    customer_category = models.CharField(
        max_length=20,
        choices=CustomerCategory.choices,
        default=CustomerCategory.HOME,
        db_index=True,
    )
    full_name = models.CharField("Full name / company name", max_length=150)
    phone = models.CharField("Phone / company number", max_length=30)
    alternative_phone = models.CharField(
        "Alternative phone / company number",
        max_length=30,
        blank=True,
    )
    email = models.EmailField(blank=True)
    location = models.CharField(max_length=255, blank=True)
    location_lat = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    location_lng = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    service_type = models.CharField(
        max_length=32,
        choices=ServiceType.choices,
        default=ServiceType.HOME_INTERNET,
        db_index=True,
    )
    preferred_package = models.ForeignKey(
        "billing.BillingPlan",
        on_delete=models.SET_NULL,
        related_name="leads",
        null=True,
        blank=True,
    )
    preferred_isp = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        related_name="preferred_leads",
        null=True,
        blank=True,
        help_text="Optional preferred ISP from registered organizations",
    )
    lead_source = models.CharField(
        max_length=32,
        choices=LeadSource.choices,
        default=LeadSource.WALK_IN,
    )
    preferred_installation_date = models.DateField(
        "Preferred installation date",
        null=True,
        blank=True,
    )
    customer_requirements = models.TextField(blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.NEW,
        db_index=True,
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        related_name="created_leads",
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "accounts_lead"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.lead_number} — {self.full_name}"

    @classmethod
    def generate_lead_number(cls, organization) -> str:
        org_id = getattr(organization, "pk", None) or 0
        for _ in range(40):
            candidate = f"LD-{org_id:04d}-{secrets.token_hex(3).upper()}"
            if not cls.objects.filter(lead_number=candidate).exists():
                return candidate
        raise RuntimeError("Could not generate a unique lead number.")


class PaymentGateway(models.Model):
    """Platform-wide payment gateway settings (singleton, managed by IT Support)."""

    class Provider(models.TextChoices):
        MPESA = "mpesa", "M-Pesa"

    class Environment(models.TextChoices):
        SANDBOX = "sandbox", "Sandbox"
        PRODUCTION = "production", "Production"

    class PaymentType(models.TextChoices):
        NONE = "", "Not set"
        PAYBILL = "paybill", "Paybill"
        TILL = "till", "Buy Goods Till"

    enabled = models.BooleanField(
        "Activate STK Push",
        default=False,
        help_text="Turn on M-Pesa Daraja Lipa Na M-Pesa Online (STK Push) for collections.",
    )
    provider = models.CharField(
        "Provider",
        max_length=20,
        choices=Provider.choices,
        default=Provider.MPESA,
    )
    environment = models.CharField(
        "Environment",
        max_length=20,
        choices=Environment.choices,
        default=Environment.SANDBOX,
    )
    payment_type = models.CharField(
        "Payment type",
        max_length=20,
        choices=PaymentType.choices,
        blank=True,
        default="",
        help_text="Paybill (CustomerPayBillOnline) or Till (CustomerBuyGoodsOnline).",
    )
    shortcode = models.CharField(
        "Business shortcode",
        max_length=20,
        blank=True,
        help_text="Lipa Na M-Pesa Online shortcode (Paybill or Till).",
    )
    account_reference = models.CharField(
        "Account reference",
        max_length=64,
        blank=True,
        help_text="Unused. STK Push AccountReference is always the client's account number.",
    )
    consumer_key = models.CharField("Consumer key", max_length=255, blank=True)
    consumer_secret = models.CharField("Consumer secret", max_length=255, blank=True)
    passkey = models.CharField(
        "Lipa Na M-Pesa passkey",
        max_length=255,
        blank=True,
        help_text="Passkey for the Lipa Na M-Pesa Online shortcode.",
    )
    callback_url = models.URLField(
        "Callback URL",
        max_length=500,
        blank=True,
        help_text=(
            "URL Safaricom calls with STK Push results. "
            "Sandbox may use http://localhost:8000; production requires HTTPS."
        ),
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "accounts_payment_gateway"
        verbose_name = "Payment gateway"
        verbose_name_plural = "Payment gateway"

    STK_CALLBACK_PATH = "/api/mpesa/stk-callback/"
    SANDBOX_BASE_URL = "http://localhost:8000"

    def save(self, *args, **kwargs):
        self.pk = 1
        # Live shortcodes cannot use the sandbox API host.
        shortcode = (self.shortcode or "").strip()
        if shortcode and shortcode != "174379":
            self.environment = self.Environment.PRODUCTION
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        pass

    @classmethod
    def get_solo(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def is_stk_ready(self) -> bool:
        """True when STK Push is activated with usable Daraja credentials."""
        return bool(
            self.enabled
            and (self.consumer_key or "").strip()
            and (self.consumer_secret or "").strip()
            and (self.passkey or "").strip()
            and (self.shortcode or "").strip()
        )

    @classmethod
    def sandbox_base_url(cls) -> str:
        from django.conf import settings

        base = (getattr(settings, "PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
        if base.startswith("http://localhost") or base.startswith("http://127.0.0.1"):
            return base
        return cls.SANDBOX_BASE_URL

    @classmethod
    def default_callback_url(cls, environment: str = "") -> str:
        env = (environment or "").strip().lower()
        if env == cls.Environment.SANDBOX or not env:
            return f"{cls.sandbox_base_url()}{cls.STK_CALLBACK_PATH}"
        from django.conf import settings

        base = (getattr(settings, "PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
        if base:
            return f"{base}{cls.STK_CALLBACK_PATH}"
        return ""

    def resolved_callback_url(self) -> str:
        url = (self.callback_url or "").strip()
        if url:
            return self.normalize_callback_url(url)
        shortcode = (self.shortcode or "").strip()
        env = self.environment
        if shortcode and shortcode != "174379":
            env = self.Environment.PRODUCTION
        return self.default_callback_url(env)

    @classmethod
    def normalize_callback_url(cls, url: str) -> str:
        """Ensure a callback base like http://localhost:8000 includes the STK path."""
        raw = (url or "").strip()
        if not raw:
            return ""
        path = cls.STK_CALLBACK_PATH
        path_noslash = path.rstrip("/")
        if path_noslash in raw:
            return raw
        return f"{raw.rstrip('/')}{path}"

    @staticmethod
    def account_reference_for_client(customer) -> str:
        """STK Push AccountReference is always the client's account number."""
        return (getattr(customer, "account_number", None) or "").strip()

    def __str__(self):
        status = "enabled" if self.enabled else "disabled"
        return f"{self.get_provider_display()} ({status})"


class CompanyProfile(models.Model):
    """Platform company / app profile (singleton, managed by IT Support)."""

    app_name = models.CharField(
        "App name",
        max_length=120,
        default="ISPCENTRIC",
        help_text="Brand name shown across the platform.",
    )
    email = models.EmailField("Email", blank=True)
    phone = models.CharField("Phone number", max_length=30, blank=True)
    whatsapp = models.CharField("WhatsApp number", max_length=30, blank=True)
    logo = models.ImageField(
        "Logo",
        upload_to="company/%Y/%m/",
        blank=True,
        null=True,
        help_text="Company logo shown in the workspace.",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "accounts_company_profile"
        verbose_name = "Company profile"
        verbose_name_plural = "Company profile"

    def save(self, *args, **kwargs):
        self.pk = 1
        self.logo = maybe_optimize_image_field(self.logo)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        pass

    @classmethod
    def get_solo(cls):
        obj, _ = cls.objects.get_or_create(
            pk=1,
            defaults={"app_name": "ISPCENTRIC"},
        )
        return obj

    def __str__(self):
        return self.app_name or "Company profile"


class RoleCommission(models.Model):
    """Commission rate settings for an employee role (managed by IT Support)."""

    class RateType(models.TextChoices):
        PERCENT = "percent", "Percentage"
        FLAT = "flat", "Flat amount"
        PER_TICKET = "per_ticket", "Per ticket"
        PER_TICKET_PACKAGE = "per_ticket_package", "Per ticket package %"

    COMMISSIONABLE_ROLES = (
        Employee.Role.SUPER_ADMIN,
        Employee.Role.ADMINISTRATOR,
        Employee.Role.MANAGER,
        Employee.Role.IT_SUPPORT,
        Employee.Role.SALES,
        Employee.Role.TECHNICIAN,
    )

    role = models.CharField(
        "Role",
        max_length=32,
        choices=Employee.Role.choices,
        unique=True,
        db_index=True,
    )
    enabled = models.BooleanField(
        "Enable commissions",
        default=False,
        help_text="Turn on commission tracking for this role.",
    )
    rate_type = models.CharField(
        "Rate type",
        max_length=32,
        choices=RateType.choices,
        default=RateType.PERCENT,
    )
    rate_value = models.DecimalField(
        "Rate value",
        max_digits=10,
        decimal_places=2,
        default=0,
        help_text="Percentage, flat amount, or price per ticket in KES.",
    )
    notes = models.CharField(
        "Notes",
        max_length=255,
        blank=True,
        help_text="Optional note about how this commission is calculated.",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "accounts_role_commission"
        ordering = ["role"]
        verbose_name = "Role commission"
        verbose_name_plural = "Role commissions"

    def __str__(self):
        return f"{self.get_role_display()} commission"

    @property
    def rate_display(self) -> str:
        value = self.rate_value
        if self.rate_type == self.RateType.PERCENT:
            return f"{value}%"
        if self.rate_type == self.RateType.PER_TICKET:
            return f"KES {value} / ticket"
        if self.rate_type == self.RateType.PER_TICKET_PACKAGE:
            return f"{value}% of package"
        return f"KES {value}"

    @classmethod
    def for_role(cls, role: str):
        defaults = {}
        if role == Employee.Role.SALES:
            defaults = {"rate_type": cls.RateType.PER_TICKET}
        obj, _ = cls.objects.get_or_create(role=role, defaults=defaults)
        return obj

    @classmethod
    def commissionable_rows(cls):
        """Return RoleCommission rows for every assignable role, creating missing ones."""
        existing = {row.role: row for row in cls.objects.filter(role__in=cls.COMMISSIONABLE_ROLES)}
        rows = []
        for role in cls.COMMISSIONABLE_ROLES:
            row = existing.get(role)
            if row is None:
                defaults = {}
                if role == Employee.Role.SALES:
                    defaults = {"rate_type": cls.RateType.PER_TICKET}
                row = cls.objects.create(role=role, **defaults)
            rows.append(row)
        return rows


class NetworkEquipment(models.Model):
    """Inventory item used for installs and field repairs."""

    class EquipmentType(models.TextChoices):
        ROUTER = "router", "Router"
        ONU = "onu", "ONU / ONT"
        SWITCH = "switch", "Switch"
        RADIO = "radio", "Radio / antenna"
        CABLE = "cable", "Cable"
        CONNECTOR = "connector", "Connector / splitter"
        POWER = "power", "Power / PoE"
        OTHER = "other", "Other"

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"

    name = models.CharField("Equipment name", max_length=150)
    equipment_type = models.CharField(
        "Type",
        max_length=20,
        choices=EquipmentType.choices,
        default=EquipmentType.ROUTER,
        db_index=True,
    )
    quantity = models.PositiveIntegerField(
        "Stock quantity",
        default=0,
        help_text="Current units in stock.",
    )
    track_serials = models.BooleanField(
        "Track serial numbers",
        default=False,
        help_text="When enabled, stock movements require serial numbers for this equipment.",
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE,
        db_index=True,
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        related_name="registered_network_equipment",
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "accounts_network_equipment"
        ordering = ["-created_at"]
        verbose_name = "Network equipment"
        verbose_name_plural = "Network equipment"

    def __str__(self):
        return self.name

    @property
    def is_suspended(self) -> bool:
        return self.status == self.Status.SUSPENDED


class NetworkEquipmentSerial(models.Model):
    """Tracked serial / barcode unit for network equipment stock."""

    class Status(models.TextChoices):
        IN_STOCK = "in_stock", "In stock"
        ISSUED = "issued", "Issued"

    equipment = models.ForeignKey(
        NetworkEquipment,
        on_delete=models.CASCADE,
        related_name="serials",
    )
    serial_number = models.CharField("Serial number", max_length=120, db_index=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.IN_STOCK,
        db_index=True,
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        related_name="registered_equipment_serials",
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    issued_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "accounts_network_equipment_serial"
        ordering = ["-created_at"]
        verbose_name = "Equipment serial"
        verbose_name_plural = "Equipment serials"
        constraints = [
            models.UniqueConstraint(
                fields=["equipment", "serial_number"],
                name="uniq_equipment_serial_number",
            )
        ]

    def __str__(self):
        return f"{self.serial_number} ({self.equipment.name})"


class NetworkEquipmentAllocation(models.Model):
    """Equipment units currently (or previously) allocated to an employee."""

    equipment = models.ForeignKey(
        NetworkEquipment,
        on_delete=models.CASCADE,
        related_name="allocations",
    )
    employee = models.ForeignKey(
        Employee,
        on_delete=models.CASCADE,
        related_name="equipment_allocations",
    )
    quantity = models.PositiveIntegerField(default=1)
    serial = models.ForeignKey(
        NetworkEquipmentSerial,
        on_delete=models.SET_NULL,
        related_name="allocations",
        null=True,
        blank=True,
    )
    notes = models.CharField(max_length=255, blank=True, default="")
    allocated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        related_name="equipment_allocations_made",
        null=True,
        blank=True,
    )
    allocated_at = models.DateTimeField(auto_now_add=True)
    returned_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "accounts_network_equipment_allocation"
        ordering = ["-allocated_at"]
        verbose_name = "Equipment allocation"
        verbose_name_plural = "Equipment allocations"

    def __str__(self):
        label = self.serial.serial_number if self.serial_id else f"×{self.quantity}"
        return f"{self.equipment.name} {label} → {self.employee}"

    @property
    def is_active(self) -> bool:
        return self.returned_at is None
