from django.conf import settings
from django.db import models


class MikroTikRouter(models.Model):
    class ModelChoice(models.TextChoices):
        HAP_AX2 = "hap_ax2", "hAP ax²"
        HAP_AX3 = "hap_ax3", "hAP ax³"
        HAP_LITE = "hap_lite", "hAP lite"
        HAP_AC2 = "hap_ac2", "hAP ac²"
        HAP_AC3 = "hap_ac3", "hAP ac³"
        RB951UI_2HND = "rb951ui_2hnd", "RB951Ui-2HnD"
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
    serial_number = models.CharField(
        "Serial number",
        max_length=64,
        blank=True,
        db_index=True,
        help_text="RouterBOARD serial from /system/routerboard — unique hardware identity.",
    )
    software_id = models.CharField(
        "Software ID",
        max_length=64,
        blank=True,
        help_text="RouterOS license software-id from /system/license.",
    )
    wifi_ssid = models.CharField("Wi‑Fi name", max_length=32, blank=True)
    wifi_password = models.CharField("Wi‑Fi password", max_length=63, blank=True)
    default_cpe_username = models.CharField(
        "Default client router username",
        max_length=64,
        blank=True,
        default="admin",
        help_text="Pre-filled on new PPPoE clients linked to this MikroTik.",
    )
    default_cpe_password = models.CharField(
        "Default client router password",
        max_length=128,
        blank=True,
        help_text="Pre-filled on new PPPoE clients; used for remote CPE access from ISPCENTRIC.",
    )
    internet_provider = models.CharField(
        "Internet company",
        max_length=120,
        blank=True,
        help_text="ISP or upstream provider feeding this MikroTik (e.g. Safaricom, Starlink).",
    )

    class CleanUplinkMode(models.TextChoices):
        BYPASS = "bypass", "Modem bypass (MikroTik owns WAN)"
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
        help_text="Port cabled to the ISP modem/ONT (usually ether1). PPPoE-out is detected automatically when present.",
    )
    lan_bridge = models.CharField(
        "LAN bridge",
        max_length=64,
        default="bridgeLocal",
        help_text="Bridge used for customer / LAN ports.",
    )
    provider_gateway = models.CharField(
        "Provider gateway IP",
        max_length=255,
        default="192.168.1.1",
        blank=True,
        help_text="ISP modem/ONT admin IP(s) to block in behind-provider mode. Comma-separated allowed (e.g. 192.168.1.1, 192.168.100.1).",
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
        BALANCE = "balance", "Load balance (different providers)"

    uplink_mode = models.CharField(
        "Uplink mode",
        max_length=16,
        choices=UplinkMode.choices,
        default=UplinkMode.SINGLE,
        help_text=(
            "Single WAN, bond multiple ports to one provider, failover across "
            "providers, or PCC load-balance (equal or weighted by Mbps) across providers."
        ),
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
    uplink_weights = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "Per-port uplink capacity in Mbps for weighted PCC load balance "
            "(e.g. {\"ether1\": 100, \"ether4\": 20}). Empty means equal share."
        ),
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

    # WireGuard peer. A hosted billing server is the *client* of the MikroTik
    # API, so it must reach the router — but the router sits on a private LAN.
    # The router dials out to the VPS and the tunnel address becomes the host
    # the app connects to.
    vpn_address = models.GenericIPAddressField(
        "Tunnel address",
        protocol="IPv4",
        null=True,
        blank=True,
        unique=True,
        help_text="Address this router answers on inside the WireGuard tunnel.",
    )
    vpn_public_key = models.CharField(max_length=64, blank=True)
    vpn_private_key = models.CharField(max_length=64, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def api_host(self) -> str:
        """Address the billing server should dial for the API."""
        return (self.vpn_address or "").strip() or (self.host or "").strip()

    class Meta:
        db_table = "core_mikrotik_router"
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "serial_number"],
                condition=~models.Q(serial_number=""),
                name="uniq_org_mikrotik_serial",
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.host})"


class MikroTikStatusSample(models.Model):
    """Time-series health snapshot for one MikroTik (dashboard performance trend)."""

    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="mikrotik_status_samples",
    )
    router = models.ForeignKey(
        MikroTikRouter,
        on_delete=models.CASCADE,
        related_name="status_samples",
    )
    sampled_at = models.DateTimeField(db_index=True)
    status = models.CharField(max_length=32, default="disconnected")
    score = models.PositiveSmallIntegerField(default=0)
    online = models.BooleanField(default=False)

    class Meta:
        db_table = "core_mikrotik_status_sample"
        ordering = ["sampled_at"]
        indexes = [
            models.Index(
                fields=["organization", "sampled_at"],
                name="core_mt_status_org_at_idx",
            ),
            models.Index(
                fields=["router", "sampled_at"],
                name="core_mt_status_router_at_idx",
            ),
        ]

    def __str__(self):
        return f"{self.router_id} {self.status}@{self.sampled_at}"


class WireGuardReservation(models.Model):
    """
    A tunnel peer for a router that has not been onboarded yet.

    Onboarding verifies the API login, which a hosted server cannot do until it
    can reach the router — and it can only reach the router once the tunnel is
    up. Reserving the peer first breaks that circle: bring the tunnel up with
    these keys, then onboard using the reserved address as the router's host.
    """

    label = models.CharField(max_length=150, help_text="Site name, for your reference.")
    address = models.GenericIPAddressField(protocol="IPv4", unique=True)
    public_key = models.CharField(max_length=64)
    private_key = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "core_wireguard_reservation"
        ordering = ["address"]

    def __str__(self):
        return f"{self.label} ({self.address})"
