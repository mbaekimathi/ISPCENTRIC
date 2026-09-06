from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0022_mikrotik_smart_balance"),
    ]

    operations = [
        migrations.AlterField(
            model_name="mikrotikrouter",
            name="clean_uplink_enabled",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "When on, ISPCENTRIC pushes firewall/DNS/NAT rules that pass clean "
                    "internet, isolate WAN from the LAN bridge, and block uplink modem/ONT "
                    "admin pages. Keep this on for customer networks."
                ),
                verbose_name="Clean uplink enabled",
            ),
        ),
        migrations.AlterField(
            model_name="mikrotikrouter",
            name="clean_uplink_separate_wan",
            field=models.BooleanField(
                default=True,
                help_text=(
                    "Always on for clean uplink: remove the WAN port from the LAN bridge "
                    "so MikroTik routes instead of switching. Required so customers cannot "
                    "reach the uplink modem/ONT at layer 2."
                ),
                verbose_name="Separate WAN from bridge",
            ),
        ),
        migrations.AlterField(
            model_name="mikrotikrouter",
            name="provider_gateway",
            field=models.CharField(
                blank=True,
                default="192.168.1.1",
                help_text=(
                    "ISP modem/ONT admin IP(s) to block. Comma-separated allowed "
                    "(e.g. 192.168.1.1, 192.168.100.1). Required for behind-provider mode; "
                    "also used in bypass when the uplink still has a private admin IP."
                ),
                max_length=255,
                verbose_name="Provider gateway IP",
            ),
        ),
    ]
