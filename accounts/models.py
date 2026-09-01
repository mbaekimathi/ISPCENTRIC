import secrets

from django.contrib.auth.models import User
from django.db import models

from ispcentric.encrypted_fields import EncryptedCharField

from .image_utils import maybe_optimize_image_field


class Organization(models.Model):
    """ISP / company account created at registration."""

    class Status(models.TextChoices):
        REGISTERED = "registered", "Registered"
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"

    name = models.CharField(max_length=150)
    owner = models.OneToOneField(User, on_delete=models.CASCADE, related_name="organization")
    login_code = models.CharField(
        max_length=6,
        unique=True,
        db_index=True,
        blank=True,
        default="",
        help_text="6-digit code the ISP owner uses to log in (separate from staff login codes).",
    )
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
        SANDBOX = "sandbox", "Company Payment Gateway"
        PRODUCTION = "production", "My own Payment Gateway"

    daraja_enabled = models.BooleanField(
        "Enable Daraja API",
        default=False,
        help_text="Receive subscription payments via M-Pesa Daraja STK Push.",
    )
    daraja_environment = models.CharField(
        "STK gateway",
        max_length=20,
        choices=DarajaEnvironment.choices,
        default=DarajaEnvironment.SANDBOX,
    )
    daraja_consumer_key = EncryptedCharField(
        "Daraja consumer key",
        max_length=512,
        blank=True,
    )
    daraja_consumer_secret = EncryptedCharField(
        "Daraja consumer secret",
        max_length=512,
        blank=True,
    )
    daraja_passkey = EncryptedCharField(
        "Lipa Na M-Pesa passkey",
        max_length=512,
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
    class ReferralStatus(models.TextChoices):
        PENDING = "pending", "Pending"
        ACTIVE = "active", "Active"

    referral_code = models.CharField(
        "Referral code",
        max_length=64,
        unique=True,
        null=True,
        blank=True,
        db_index=True,
        help_text="Shareable code — the organization's phone digits.",
    )
    referred_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        related_name="referrals",
        null=True,
        blank=True,
        help_text="ISP that referred this organization via a referral link.",
    )
    referral_status = models.CharField(
        "Referral status",
        max_length=16,
        choices=ReferralStatus.choices,
        blank=True,
        default="",
        db_index=True,
        help_text=(
            "When this org was referred: pending until the first MikroTik "
            "is onboarded, then active."
        ),
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

    @staticmethod
    def generate_login_code():
        """Unique 6-digit ISP client login code (accounts_organization.login_code)."""
        while True:
            code = f"{secrets.randbelow(1_000_000):06d}"
            if not Organization.objects.filter(login_code=code).exists():
                return code

    @staticmethod
    def generate_owner_username():
        """Internal Django username for an ISP owner (not used at sign-in)."""
        while True:
            candidate = f"isp-owner-{secrets.token_hex(8)}"
            if not User.objects.filter(username=candidate).exists():
                return candidate

    @staticmethod
    def normalize_referral_phone(phone: str = "") -> str:
        """Strip to national phone digits used as the referral code."""
        import re

        digits = re.sub(r"\D", "", phone or "")
        if digits.startswith("254") and len(digits) >= 12:
            digits = digits[3:]
        elif digits.startswith("0") and len(digits) >= 10:
            digits = digits.lstrip("0")
        return digits

    @staticmethod
    def generate_referral_code(phone: str = "", *, exclude_pk=None) -> str:
        """Build a unique referral code from phone digits only."""
        base = Organization.normalize_referral_phone(phone)
        if not base:
            base = f"{secrets.randbelow(1_000_000_000):09d}"
        code = base
        n = 1
        qs = Organization.objects.filter(referral_code=code)
        if exclude_pk:
            qs = qs.exclude(pk=exclude_pk)
        while qs.exists():
            n += 1
            code = f"{base}{n}"
            qs = Organization.objects.filter(referral_code=code)
            if exclude_pk:
                qs = qs.exclude(pk=exclude_pk)
        return code

    @classmethod
    def lookup_by_referral_code(cls, raw: str):
        """Resolve a referrer from a typed/pasted phone code."""
        code = (raw or "").strip()
        if not code:
            return None
        org = cls.objects.filter(referral_code__iexact=code).first()
        if org:
            return org
        digits = cls.normalize_referral_phone(code)
        if not digits or digits == code:
            return None
        return cls.objects.filter(referral_code=digits).first()

    def ensure_referral_code(self) -> str:
        """Return a phone-based referral code, upgrading older formats."""
        import re

        phone_code = Organization.generate_referral_code(
            self.phone, exclude_pk=self.pk
        )
        current = (self.referral_code or "").strip()
        # Keep an existing pure phone code when it already matches.
        if current and re.fullmatch(r"\d+", current):
            if not self.phone or current == Organization.normalize_referral_phone(self.phone) or current == phone_code:
                return current
        self.referral_code = phone_code
        if self.pk:
            type(self).objects.filter(pk=self.pk).update(referral_code=self.referral_code)
        return self.referral_code

    def mark_referral_active(self) -> bool:
        """Flip referred org from pending → active. Returns True if changed."""
        if not self.referred_by_id:
            return False
        if self.referral_status == self.ReferralStatus.ACTIVE:
            return False
        type(self).objects.filter(pk=self.pk).update(
            referral_status=self.ReferralStatus.ACTIVE
        )
        self.referral_status = self.ReferralStatus.ACTIVE
        return True

    def save(self, *args, **kwargs):
        if not self.join_code:
            self.join_code = Organization.generate_join_code()
        if not self.login_code:
            self.login_code = Organization.generate_login_code()
        if self.phone and (
            not self.referral_code
            or not str(self.referral_code).isdigit()
        ):
            self.referral_code = Organization.generate_referral_code(
                self.phone, exclude_pk=self.pk
            )
        if self.referred_by_id and not self.referral_status:
            self.referral_status = self.ReferralStatus.PENDING
        self.profile_photo = maybe_optimize_image_field(self.profile_photo)
        super().save(*args, **kwargs)
        from accounts.routing import invalidate_switchable_clients_cache

        invalidate_switchable_clients_cache()

    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)
        from accounts.routing import invalidate_switchable_clients_cache

        invalidate_switchable_clients_cache()

    def purge_account(self, *, actor_user_id=None):
        """Delete this ISP and all of its data without touching other organizations."""
        from django.db import transaction

        from billing.models import AccessVoucher, StkPushRequest

        if not self.pk:
            return

        org_id = self.pk
        owner_id = self.owner_id

        with transaction.atomic():
            type(self).objects.filter(referred_by_id=org_id).update(
                referred_by=None,
                referral_status="",
            )
            # Clear PROTECT blockers that would otherwise stop plan/org deletion.
            AccessVoucher.objects.filter(organization_id=org_id).delete()
            StkPushRequest.objects.filter(organization_id=org_id).delete()

            staff_qs = Employee.objects.filter(organization_id=org_id)
            if actor_user_id:
                staff_qs = staff_qs.exclude(user_id=actor_user_id)
            staff_user_ids = list(staff_qs.values_list("user_id", flat=True))

            self.delete()

            user_ids = {
                uid
                for uid in [owner_id, *staff_user_ids]
                if uid and uid != actor_user_id
            }
            if user_ids:
                User.objects.filter(pk__in=user_ids).delete()

    def deletion_preview(self, *, sample_limit=8):
        """Counts and sample names of data that purge_account will remove."""
        from billing.models import AccessVoucher, Invoice, Payment, StkPushRequest

        limit = max(1, int(sample_limit or 8))
        owner_name = ""
        owner_email = ""
        if self.owner_id and self.owner:
            owner_name = self.owner.get_full_name() or self.owner.username
            owner_email = (self.owner.email or "").strip()

        staff_qs = Employee.objects.filter(organization_id=self.pk).select_related("user")
        staff_names = []
        for member in staff_qs.order_by("user__first_name", "user__username")[:limit]:
            label = member.user.get_full_name() or member.user.username
            if member.get_role_display():
                label = f"{label} · {member.get_role_display()}"
            staff_names.append(label)

        customer_names = list(
            self.customers.order_by("full_name").values_list("full_name", flat=True)[:limit]
        )
        plan_names = list(self.plans.order_by("name").values_list("name", flat=True)[:limit])
        router_names = list(
            self.mikrotik_routers.order_by("name").values_list("name", flat=True)[:limit]
        )
        lead_names = list(
            self.leads.order_by("-created_at").values_list("full_name", flat=True)[:limit]
        )
        has_comms = CommunicationSettings.objects.filter(organization_id=self.pk).exists()

        def item(key, label, count, *, detail="", samples=None):
            return {
                "key": key,
                "label": label,
                "count": int(count or 0),
                "detail": detail,
                "samples": list(samples or []),
            }

        items = [
            item(
                "account",
                "ISP account",
                1,
                detail=self.name,
            ),
            item(
                "owner",
                "Owner login",
                1 if self.owner_id else 0,
                detail=" · ".join(part for part in (owner_name, owner_email) if part),
            ),
            item("staff", "Staff accounts", staff_qs.count(), samples=staff_names),
            item(
                "customers",
                "Subscribers",
                self.customers.count(),
                samples=customer_names,
            ),
            item("packages", "Packages", self.plans.count(), samples=plan_names),
            item(
                "routers",
                "MikroTik routers",
                self.mikrotik_routers.count(),
                samples=router_names,
            ),
            item("leads", "Sales leads", self.leads.count(), samples=lead_names),
            item("invoices", "Invoices", Invoice.objects.filter(organization_id=self.pk).count()),
            item("payments", "Payments", Payment.objects.filter(organization_id=self.pk).count()),
            item(
                "vouchers",
                "Access vouchers",
                AccessVoucher.objects.filter(organization_id=self.pk).count(),
            ),
            item(
                "stk",
                "STK Push requests",
                StkPushRequest.objects.filter(organization_id=self.pk).count(),
            ),
            item(
                "devices",
                "Registered devices",
                self.customer_devices.count(),
            ),
            item(
                "settings",
                "ISP settings",
                1,
                detail="Hotspot, PPPoE, M-Pesa, and Daraja settings for this ISP",
            ),
            item(
                "comms",
                "Communication settings",
                1 if has_comms else 0,
                detail="SMS, email, and WhatsApp credentials for this ISP",
            ),
        ]
        present = [row for row in items if row["count"]]
        return {
            "owner_name": owner_name,
            "owner_email": owner_email,
            "items": items,
            "present_items": present,
            "empty_labels": [row["label"] for row in items if not row["count"]],
            "total_records": sum(row["count"] for row in items),
        }

    def __str__(self):
        return self.name

    @property
    def receives_via_label(self) -> str:
        if self.mpesa_payment_type == self.MpesaPaymentType.PAYBILL and self.mpesa_number:
            return f"Paybill {self.mpesa_number}"
        if self.mpesa_payment_type == self.MpesaPaymentType.TILL and self.mpesa_number:
            return f"Till {self.mpesa_number}"
        return "Not set"

    def has_own_daraja_credentials(self) -> bool:
        """True when this ISP has a complete Daraja app of its own."""
        return bool(
            (self.daraja_consumer_key or "").strip()
            and (self.daraja_consumer_secret or "").strip()
            and (self.daraja_passkey or "").strip()
            and (self.mpesa_payment_type or "").strip()
            and (self.mpesa_number or "").strip()
        )

    def uses_platform_daraja_credentials(self) -> bool:
        """Company Payment Gateway is the default when this ISP has no own Daraja app."""
        if not self.daraja_enabled:
            return False
        env = (self.daraja_environment or self.DarajaEnvironment.SANDBOX).strip().lower()
        if env == self.DarajaEnvironment.PRODUCTION and self.has_own_daraja_credentials():
            return False
        return True

    def effective_daraja_credentials(self) -> dict:
        """
        Credentials used for ISP subscription STK Push.

        Company Payment Gateway is the default when this ISP has no own Daraja app.
        An ISP Payment Gateway uses only this organization's fields.
        The two gateways are never mixed (no company keys + ISP shortcode, or vice versa).
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
                "message": "STK Push is turned off for this ISP.",
            }

        if not self.uses_platform_daraja_credentials():
            key = (self.daraja_consumer_key or "").strip()
            secret = (self.daraja_consumer_secret or "").strip()
            passkey = (self.daraja_passkey or "").strip()
            ready = bool(key and secret and passkey and payment_type and shortcode)
            return {
                "enabled": True,
                "ready": ready,
                "source": "organization",
                "source_label": "ISP Payment Gateway",
                "environment": self.DarajaEnvironment.PRODUCTION,
                "payment_type": payment_type,
                "shortcode": shortcode,
                "consumer_key": key,
                "consumer_secret": secret,
                "passkey": passkey,
                "callback_url": "",
                "message": (
                    f"Using this ISP's Payment Gateway with shortcode {shortcode}."
                    if ready
                    else "Add this ISP's Paybill/Till and Daraja consumer key, secret, and passkey."
                ),
            }

        creds = PaymentGateway.get_solo().as_stk_credentials()
        creds["enabled"] = True
        if creds.get("ready"):
            creds["message"] = (
                f"Using Company Payment Gateway ({creds.get('environment')}) "
                f"with shortcode {creds.get('shortcode')}. "
                "This ISP has no own Payment Gateway yet."
            )
        else:
            creds["message"] = (
                "Company Payment Gateway is the default until this ISP adds its own. "
                "IT Support must activate Payment Gateway first."
            )
        return creds


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
    """
    Company / platform Payment Gateway (singleton, managed by IT Support).

    Default STK gateway for ISPs that have not configured their own Daraja app.
    Also used for platform fees such as MikroTik onboarding. Never mixed with
    an ISP's Paybill/Till or Daraja credentials.
    """

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
        help_text=(
            "Company Daraja STK Push. Default for ISPs without their own Payment Gateway, "
            "and for platform fees such as MikroTik onboarding."
        ),
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
    consumer_key = EncryptedCharField("Consumer key", max_length=512, blank=True)
    consumer_secret = EncryptedCharField("Consumer secret", max_length=512, blank=True)
    passkey = EncryptedCharField(
        "Lipa Na M-Pesa passkey",
        max_length=512,
        blank=True,
        help_text="Passkey for the Lipa Na M-Pesa Online shortcode.",
    )
    callback_url = models.URLField(
        "Callback URL",
        max_length=500,
        blank=True,
        help_text=(
            "URL Safaricom calls with STK Push results. "
            "Sandbox accepts local (http://localhost) or hosted (https://…) URLs. "
            "Production requires HTTPS."
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

    def as_stk_credentials(self) -> dict:
        """Company Payment Gateway fields only — never mixed with ISP Daraja values."""
        shortcode = (self.shortcode or "").strip()
        environment = (self.environment or self.Environment.SANDBOX).strip().lower()
        if shortcode and shortcode != "174379":
            environment = self.Environment.PRODUCTION
        ready = self.is_stk_ready()
        return {
            "enabled": bool(self.enabled),
            "ready": ready,
            "source": "platform",
            "source_label": "Company Payment Gateway",
            "environment": environment,
            "payment_type": (self.payment_type or "").strip(),
            "shortcode": shortcode,
            "consumer_key": (self.consumer_key or "").strip(),
            "consumer_secret": (self.consumer_secret or "").strip(),
            "passkey": (self.passkey or "").strip(),
            "callback_url": self.resolved_callback_url() if ready else "",
            "message": (
                f"Using Company Payment Gateway ({environment}) with shortcode {shortcode}."
                if ready
                else "Activate and complete Company Payment Gateway under IT Support → Payment Gateway."
            ),
        }

    @classmethod
    def sandbox_local_base_url(cls, request=None) -> str:
        """Loopback origin for Daraja sandbox testing on this PC."""
        port = 8000
        try:
            from django.conf import settings

            from core.hotspot_portal import _local_http_port

            port = _local_http_port(
                getattr(settings, "PUBLIC_BASE_URL", "") or "",
                request,
            )
        except Exception:
            pass
        if port in (80, 443):
            return "http://localhost"
        return f"http://localhost:{port}"

    @classmethod
    def sandbox_hosted_base_url(cls, request=None) -> str:
        """Public origin for Daraja sandbox testing on a hosted deploy."""
        try:
            from urllib.parse import urlparse

            from core.hotspot_portal import (
                _host_is_private_ip,
                hosted_fallback_base_url,
                is_loopback_url,
                public_base_url,
            )

            for candidate in (
                (public_base_url(request) or "").strip().rstrip("/"),
                (hosted_fallback_base_url(request) or "").strip().rstrip("/"),
            ):
                if not candidate or is_loopback_url(candidate):
                    continue
                host = (urlparse(candidate).hostname or "").strip().lower()
                if host in {"localhost", "127.0.0.1", "::1"}:
                    continue
                if candidate.startswith("https://"):
                    return candidate
                if candidate.startswith("http://") and not _host_is_private_ip(host):
                    return candidate.replace("http://", "https://", 1)
                if candidate.startswith("http://"):
                    return candidate
        except Exception:
            pass
        try:
            from urllib.parse import urlparse

            from django.conf import settings

            from core.hotspot_portal import is_loopback_url

            configured = (getattr(settings, "PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
            if configured.lower() in {"", "auto", "detect", "lan", "local"}:
                return ""
            if not configured.startswith(("http://", "https://")):
                configured = f"https://{configured}"
            if is_loopback_url(configured):
                return ""
            host = (urlparse(configured).hostname or "").strip().lower()
            if configured.startswith("http://"):
                from core.hotspot_portal import _host_is_private_ip

                if not _host_is_private_ip(host):
                    return configured.replace("http://", "https://", 1)
            return configured
        except Exception:
            return ""
        return ""

    @classmethod
    def sandbox_local_callback_url(cls, request=None) -> str:
        return cls.normalize_callback_url(
            f"{cls.sandbox_local_base_url(request)}{cls.STK_CALLBACK_PATH}"
        )

    @classmethod
    def sandbox_hosted_callback_url(cls, request=None) -> str:
        base = cls.sandbox_hosted_base_url(request)
        if not base:
            return ""
        return cls.normalize_callback_url(f"{base}{cls.STK_CALLBACK_PATH}")

    @classmethod
    def sandbox_callback_options(cls, request=None) -> list[dict]:
        """Local and hosted sandbox callback URLs (both allowed for testing)."""
        options: list[dict] = []
        seen: set[str] = set()
        for label, url, kind in (
            ("Local", cls.sandbox_local_callback_url(request), "local"),
            ("Hosted", cls.sandbox_hosted_callback_url(request), "hosted"),
        ):
            if url and url not in seen:
                seen.add(url)
                options.append({"label": label, "url": url, "kind": kind})
        return options

    @classmethod
    def sandbox_base_url(cls, request=None) -> str:
        """Default sandbox origin: hosted when deployed, localhost when developing."""
        try:
            from django.conf import settings

            from core.hotspot_portal import _is_hosted, is_loopback_url, public_base_url

            if _is_hosted():
                hosted = cls.sandbox_hosted_base_url(request)
                if hosted:
                    return hosted
            base = (public_base_url(request) or "").strip().rstrip("/")
            if base and is_loopback_url(base):
                return base
        except Exception:
            pass
        return cls.sandbox_local_base_url(request)

    @classmethod
    def default_callback_url(cls, environment: str = "", request=None) -> str:
        env = (environment or "").strip().lower()
        if env == cls.Environment.SANDBOX or not env:
            return f"{cls.sandbox_base_url(request)}{cls.STK_CALLBACK_PATH}"
        try:
            from core.hotspot_portal import public_base_url

            base = (public_base_url(request) or "").strip().rstrip("/")
        except Exception:
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


class ClientSettings(models.Model):
    """Platform client-facing switches (singleton, managed by IT Support)."""

    landing_register_enabled = models.BooleanField(
        "Show Register on landing page",
        default=False,
        help_text="When enabled, the public landing page shows Register / Get started links.",
    )
    onboarding_fee_enabled = models.BooleanField(
        "Charge MikroTik onboarding fee",
        default=False,
        help_text=(
            "When enabled, clients must pay via STK Push before a MikroTik "
            "tunnel onboarding script can be generated."
        ),
    )
    onboarding_fee_amount = models.DecimalField(
        "Onboarding fee amount (KES)",
        max_digits=12,
        decimal_places=2,
        default=0,
        help_text="Amount prompted on the phone when onboarding fee is enabled.",
    )
    referral_enabled = models.BooleanField(
        "Enable referrals",
        default=False,
        help_text="When enabled, client referral features are available on the platform.",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "accounts_client_settings"
        verbose_name = "Client settings"
        verbose_name_plural = "Client settings"

    def save(self, *args, **kwargs):
        self.pk = 1
        if not self.onboarding_fee_enabled:
            # Keep amount stored for when the toggle is turned back on.
            pass
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        pass

    @classmethod
    def get_solo(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    @property
    def onboarding_fee_ready(self) -> bool:
        return bool(
            self.onboarding_fee_enabled
            and self.onboarding_fee_amount is not None
            and self.onboarding_fee_amount > 0
        )

    def __str__(self):
        return "Client settings"


class CommunicationCredentialsBase(models.Model):
    """Shared SMS, email, and WhatsApp credential fields."""

    class SmsProvider(models.TextChoices):
        AFRICASTALKING = "africastalking", "Africa's Talking"
        TWILIO = "twilio", "Twilio"
        CUSTOM = "custom", "Custom HTTP API"

    class WhatsAppProvider(models.TextChoices):
        META = "meta", "WhatsApp Cloud API (Meta)"
        TWILIO = "twilio", "Twilio WhatsApp"
        AFRICASTALKING = "africastalking", "Africa's Talking WhatsApp"

    class Meta:
        abstract = True

    sms_enabled = models.BooleanField(
        "Enable SMS",
        default=False,
        help_text="Send SMS notifications to clients using your gateway.",
    )
    sms_provider = models.CharField(
        "SMS provider",
        max_length=32,
        choices=SmsProvider.choices,
        blank=True,
        default=SmsProvider.AFRICASTALKING,
    )
    sms_username = models.CharField(
        "SMS username / Account SID",
        max_length=120,
        blank=True,
        help_text="Africa's Talking username or Twilio Account SID.",
    )
    sms_api_key = EncryptedCharField(
        "SMS API key / Auth token",
        max_length=1024,
        blank=True,
        help_text="Africa's Talking API key, Twilio Auth Token, or custom API key.",
    )
    sms_sender_id = models.CharField(
        "SMS sender ID",
        max_length=32,
        blank=True,
        help_text="Alphanumeric sender ID or shortcode (Africa's Talking / custom).",
    )
    sms_from_number = models.CharField(
        "SMS from number",
        max_length=30,
        blank=True,
        help_text="Twilio phone number that sends SMS, e.g. +2547…",
    )
    sms_base_url = models.URLField(
        "Custom SMS API URL",
        max_length=500,
        blank=True,
        help_text="POST endpoint for a custom SMS gateway.",
    )

    email_enabled = models.BooleanField(
        "Enable email",
        default=False,
        help_text="Send email using your own SMTP account.",
    )
    email_host = models.CharField(
        "SMTP host",
        max_length=255,
        blank=True,
        help_text="e.g. smtp.gmail.com or mail.yourdomain.com",
    )
    email_port = models.PositiveIntegerField(
        "SMTP port",
        default=587,
        help_text="587 for TLS, 465 for SSL, 25 for unencrypted.",
    )
    email_use_tls = models.BooleanField(
        "Use TLS",
        default=True,
        help_text="Turn on for port 587. Port 465 uses SSL automatically.",
    )
    email_host_user = models.CharField(
        "SMTP username",
        max_length=255,
        blank=True,
        help_text="Usually the full email address you sign in with.",
    )
    email_host_password = EncryptedCharField(
        "SMTP password",
        max_length=1024,
        blank=True,
        help_text="App password or mailbox password.",
    )
    email_from_email = models.EmailField(
        "From email",
        blank=True,
        help_text="Address clients see as the sender. Defaults to the SMTP username.",
    )
    email_from_name = models.CharField(
        "From name",
        max_length=120,
        blank=True,
        help_text="Display name, e.g. your ISP name.",
    )

    whatsapp_enabled = models.BooleanField(
        "Enable WhatsApp",
        default=False,
        help_text="Send WhatsApp messages using your Business API.",
    )
    whatsapp_provider = models.CharField(
        "WhatsApp provider",
        max_length=32,
        choices=WhatsAppProvider.choices,
        blank=True,
        default=WhatsAppProvider.META,
    )
    whatsapp_phone_number_id = models.CharField(
        "WhatsApp phone number ID",
        max_length=64,
        blank=True,
        help_text="From Meta WhatsApp Cloud API.",
    )
    whatsapp_access_token = EncryptedCharField(
        "WhatsApp access token",
        max_length=2048,
        blank=True,
        help_text="Permanent or temporary Meta Cloud API token.",
    )
    whatsapp_username = models.CharField(
        "WhatsApp username / Account SID",
        max_length=120,
        blank=True,
        help_text="Twilio Account SID or Africa's Talking username.",
    )
    whatsapp_api_key = EncryptedCharField(
        "WhatsApp API key / Auth token",
        max_length=1024,
        blank=True,
        help_text="Twilio Auth Token or Africa's Talking API key.",
    )
    whatsapp_from_number = models.CharField(
        "WhatsApp from number",
        max_length=30,
        blank=True,
        help_text="Business number that sends WhatsApp, e.g. +2547…",
    )
    updated_at = models.DateTimeField(auto_now=True)

    def sms_status(self) -> dict:
        provider = (self.sms_provider or "").strip()
        label = self.get_sms_provider_display() if provider else "Not set"
        if not self.sms_enabled:
            return {
                "enabled": False,
                "ready": False,
                "provider": provider,
                "provider_label": "Off",
                "message": "SMS is turned off.",
            }
        if provider == self.SmsProvider.AFRICASTALKING:
            ready = bool(
                (self.sms_username or "").strip() and (self.sms_api_key or "").strip()
            )
            message = (
                "Africa's Talking SMS is ready."
                if ready
                else "Add Africa's Talking username and API key."
            )
        elif provider == self.SmsProvider.TWILIO:
            ready = bool(
                (self.sms_username or "").strip()
                and (self.sms_api_key or "").strip()
                and ((self.sms_from_number or "").strip() or (self.sms_sender_id or "").strip())
            )
            message = (
                "Twilio SMS is ready."
                if ready
                else "Add Twilio Account SID, Auth Token, then fetch or enter any from number / sender."
            )
        elif provider == self.SmsProvider.CUSTOM:
            ready = bool(
                (self.sms_base_url or "").strip() and (self.sms_api_key or "").strip()
            )
            message = (
                "Custom SMS API is ready."
                if ready
                else "Add the SMS API URL and API key."
            )
        else:
            ready = False
            message = "Choose an SMS provider."
        return {
            "enabled": True,
            "ready": ready,
            "provider": provider,
            "provider_label": label,
            "message": message,
        }

    def email_status(self) -> dict:
        if not self.email_enabled:
            return {
                "enabled": False,
                "ready": False,
                "provider_label": "Off",
                "message": "Email is turned off.",
            }
        ready = bool(
            (self.email_host or "").strip()
            and (self.email_host_user or "").strip()
            and (self.email_host_password or "").strip()
            and ((self.email_from_email or "").strip() or (self.email_host_user or "").strip())
        )
        return {
            "enabled": True,
            "ready": ready,
            "provider_label": (self.email_host or "").strip() or "SMTP",
            "message": (
                "SMTP email is ready."
                if ready
                else "Add SMTP host, username, password, and from address."
            ),
        }

    def whatsapp_status(self) -> dict:
        provider = (self.whatsapp_provider or "").strip()
        label = self.get_whatsapp_provider_display() if provider else "Not set"
        if not self.whatsapp_enabled:
            return {
                "enabled": False,
                "ready": False,
                "provider": provider,
                "provider_label": "Off",
                "message": "WhatsApp is turned off.",
            }
        if provider == self.WhatsAppProvider.META:
            ready = bool(
                (self.whatsapp_phone_number_id or "").strip()
                and (self.whatsapp_access_token or "").strip()
            )
            message = (
                "WhatsApp Cloud API is ready."
                if ready
                else "Add Meta phone number ID and access token."
            )
        elif provider == self.WhatsAppProvider.TWILIO:
            ready = bool(
                (self.whatsapp_username or "").strip()
                and (self.whatsapp_api_key or "").strip()
                and (self.whatsapp_from_number or "").strip()
            )
            message = (
                "Twilio WhatsApp is ready."
                if ready
                else "Add Twilio Account SID and Auth Token, then fetch or enter any WhatsApp from number."
            )
        elif provider == self.WhatsAppProvider.AFRICASTALKING:
            ready = bool(
                (self.whatsapp_username or "").strip()
                and (self.whatsapp_api_key or "").strip()
                and (self.whatsapp_from_number or "").strip()
            )
            message = (
                "Africa's Talking WhatsApp is ready."
                if ready
                else "Add Africa's Talking username, API key, and from number."
            )
        else:
            ready = False
            message = "Choose a WhatsApp provider."
        return {
            "enabled": True,
            "ready": ready,
            "provider": provider,
            "provider_label": label,
            "message": message,
        }

    def channel_statuses(self) -> dict:
        return {
            "sms": self.sms_status(),
            "email": self.email_status(),
            "whatsapp": self.whatsapp_status(),
        }


class CommunicationSettings(CommunicationCredentialsBase):
    """Per-ISP organization credentials used to message that ISP's subscribers."""

    organization = models.OneToOneField(
        Organization,
        on_delete=models.CASCADE,
        related_name="communications",
    )

    class Meta:
        db_table = "accounts_communication_settings"
        verbose_name = "ISP communication settings"
        verbose_name_plural = "ISP communication settings"

    def __str__(self):
        return f"Communications for {self.organization}"

    @classmethod
    def for_organization(cls, organization):
        if organization is None:
            return None
        obj, _ = cls.objects.get_or_create(organization=organization)
        return obj


class PlatformCommunicationSettings(CommunicationCredentialsBase):
    """ISPCENTRIC platform credentials (IT Support) used to message ISPs and staff."""

    class Meta:
        db_table = "accounts_platform_communication_settings"
        verbose_name = "Platform communication settings"
        verbose_name_plural = "Platform communication settings"

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        pass

    @classmethod
    def get_solo(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def __str__(self):
        return "Platform communications"


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
    image = models.ImageField(
        "Equipment image",
        upload_to="equipment/%Y/%m/",
        blank=True,
        null=True,
        help_text="Optional photo of the equipment item.",
    )
    selling_price = models.DecimalField(
        "Selling price",
        max_digits=12,
        decimal_places=2,
        default=0,
        help_text="Unit selling price in KES.",
    )
    discount_enabled = models.BooleanField(
        "Enable discount",
        default=False,
        help_text="When enabled, the item sells at discount_price instead of selling_price.",
    )
    discount_amount = models.DecimalField(
        "Discount amount",
        max_digits=12,
        decimal_places=2,
        default=0,
        help_text="Calculated savings in KES (selling price minus discount price).",
    )
    discount_price = models.DecimalField(
        "Discount price",
        max_digits=12,
        decimal_places=2,
        default=0,
        help_text="Price to sell at when a discount is enabled.",
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

    @property
    def effective_price(self):
        from decimal import Decimal

        if self.discount_enabled:
            price = self.discount_price or Decimal("0")
        else:
            price = self.selling_price or Decimal("0")
        if price < 0:
            return Decimal("0")
        return price

    @property
    def calculated_discount(self):
        from decimal import Decimal

        if not self.discount_enabled:
            return Decimal("0")
        selling = self.selling_price or Decimal("0")
        discounted = self.discount_price or Decimal("0")
        savings = selling - discounted
        if savings < 0:
            return Decimal("0")
        return savings


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


class SecurityAuditLog(models.Model):
    """Immutable-ish record of privileged and security-sensitive actions."""

    class Action(models.TextChoices):
        ROLE_SWITCH = "role_switch", "Role switch"
        CLIENT_VIEW = "client_view", "Client workspace view"
        RSC_DOWNLOAD = "rsc_download", "WireGuard RSC download"
        STK_RATE_LIMIT = "stk_rate_limit", "STK rate limit hit"
        LOGIN_RATE_LIMIT = "login_rate_limit", "Login rate limit hit"

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    action = models.CharField(max_length=64, db_index=True)
    actor = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="security_audit_logs",
    )
    actor_ip = models.CharField(max_length=64, blank=True, default="")
    target = models.CharField(max_length=255, blank=True, default="")
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "accounts_security_audit_log"
        ordering = ["-created_at"]
        verbose_name = "Security audit log"
        verbose_name_plural = "Security audit logs"

    def __str__(self):
        who = self.actor_id or self.actor_ip or "?"
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.action} by {who}"
