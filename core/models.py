from django.conf import settings
from django.db import models


class MikroTikRouter(models.Model):
    class ModelChoice(models.TextChoices):
        HAP_AX2 = "hap_ax2", "hAP ax²"
        HAP_AX3 = "hap_ax3", "hAP ax³"
        HAP_LITE = "hap_lite", "hAP lite"
        HAP_AC2 = "hap_ac2", "hAP ac²"
        HAP_AC3 = "hap_ac3", "hAP ac³"
        HEX = "rb750gr3", "hEX"
        HEX_S = "rb760igs", "hEX S"
        L009 = "l009", "L009"
        RB2011 = "rb2011", "RB2011"
        RB3011 = "rb3011", "RB3011"
        RB4011 = "rb4011", "RB4011"
        RB5009 = "rb5009", "RB5009"
        CCR2004 = "ccr2004", "CCR2004"
        CCR2116 = "ccr2116", "CCR2116"
        CCR2216 = "ccr2216", "CCR2216"
        CHR = "chr", "CHR"
        AUDIENCE = "audience", "Audience"
        OTHER = "other", "Other"

    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="mikrotik_routers",
    )
    name = models.CharField(max_length=150)
    model = models.CharField(max_length=32, choices=ModelChoice.choices)
    location = models.CharField(max_length=255, blank=True)
    location_lat = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    location_lng = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    host = models.CharField(max_length=255, help_text="MikroTik IP address or hostname")
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=255)
    wifi_ssid = models.CharField("Wi‑Fi name", max_length=32, blank=True)
    wifi_password = models.CharField("Wi‑Fi password", max_length=63, blank=True)
    internet_provider = models.CharField(
        "Internet company",
        max_length=120,
        blank=True,
        help_text="ISP or upstream provider feeding this MikroTik (e.g. Safaricom, Starlink).",
    )

    class AccountStatus(models.TextChoices):
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"

    account_status = models.CharField(
        max_length=20,
        choices=AccountStatus.choices,
        default=AccountStatus.ACTIVE,
        db_index=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "core_mikrotik_router"
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.host})"
