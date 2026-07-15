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
        RB951 = "rb951", "RB951"
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

    class CleanUplinkMode(models.TextChoices):
        BYPASS = "bypass", "Starlink Bypass"
        BEHIND = "behind", "Behind provider router"

    clean_uplink_enabled = models.BooleanField(
        "Clean uplink enabled",
        default=False,
        help_text="When on, ISPCENTRIC pushes firewall/DNS/NAT rules that pass clean internet and block provider settings.",
    )
    clean_uplink_mode = models.CharField(
        "Clean uplink mode",
        max_length=16,
        choices=CleanUplinkMode.choices,
        default=CleanUplinkMode.BYPASS,
    )
    wan_interface = models.CharField(
        "WAN interface",
        max_length=64,
        default="ether1",
        help_text="Port cabled to Starlink / the provider (usually ether1).",
    )
    lan_bridge = models.CharField(
        "LAN bridge",
        max_length=64,
        default="bridgeLocal",
        help_text="Bridge used for customer / LAN ports.",
    )
    provider_gateway = models.CharField(
        "Provider gateway IP",
        max_length=64,
        default="192.168.1.1",
        blank=True,
        help_text="Starlink/ISP admin IP to block when running behind their router.",
    )
    clean_uplink_separate_wan = models.BooleanField(
        "Separate WAN from bridge",
        default=False,
        help_text="Remove the WAN port from the LAN bridge so MikroTik routes instead of switching.",
    )
    clean_uplink_wan_was_bridged = models.BooleanField(
        default=False,
        help_text="Internal: WAN port was a bridge slave when clean uplink was enabled.",
    )

    class PortRole(models.TextChoices):
        NONE = "none", "Unassigned"
        WAN = "wan", "WAN / Internet (primary)"
        WAN_PRIMARY = "wan_primary", "WAN primary (legacy)"
        WAN_BACKUP = "wan_backup", "WAN backup (failover)"
        BOND = "bond", "Bond member (same provider)"
        LAN = "lan", "LAN / Customers"
        UNUSED = "unused", "Unused"

    port_roles = models.JSONField(
        default=dict,
        blank=True,
        help_text="Map of interface name → role (wan, wan_primary, wan_backup, bond, lan, unused, none).",
    )

    class UplinkMode(models.TextChoices):
        SINGLE = "single", "Single WAN"
        BOND = "bond", "Bonded uplinks (same provider)"
        FAILOVER = "failover", "Failover (different providers)"

    uplink_mode = models.CharField(
        "Uplink mode",
        max_length=16,
        choices=UplinkMode.choices,
        default=UplinkMode.SINGLE,
        help_text="Single WAN, bond multiple ports to one provider, or failover across providers.",
    )
    bond_interface = models.CharField(
        "Bond interface",
        max_length=64,
        default="bond-wan",
        blank=True,
        help_text="Name of the bonding interface created for same-provider uplinks.",
    )
    bond_mode = models.CharField(
        "Bond mode",
        max_length=32,
        default="balance-xor",
        blank=True,
        help_text="RouterOS bonding mode (e.g. balance-xor, 802.3ad, active-backup).",
    )
    uplink_ports = models.JSONField(
        default=list,
        blank=True,
        help_text="Ordered port names used for bond (all members) or failover (primary first, then backups).",
    )
    uplink_unbridged = models.JSONField(
        default=list,
        blank=True,
        help_text="Ports removed from a bridge for bond/failover; restored when multi-uplink is cleared.",
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
