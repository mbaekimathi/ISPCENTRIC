from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0005_mikrotik_internet_provider"),
    ]

    operations = [
        migrations.AddField(
            model_name="mikrotikrouter",
            name="clean_uplink_enabled",
            field=models.BooleanField(
                default=False,
                help_text="When on, ISPCENTRIC pushes firewall/DNS/NAT rules that pass clean internet and block provider settings.",
                verbose_name="Clean uplink enabled",
            ),
        ),
        migrations.AddField(
            model_name="mikrotikrouter",
            name="clean_uplink_mode",
            field=models.CharField(
                choices=[
                    ("bypass", "Starlink Bypass"),
                    ("behind", "Behind provider router"),
                ],
                default="bypass",
                max_length=16,
                verbose_name="Clean uplink mode",
            ),
        ),
        migrations.AddField(
            model_name="mikrotikrouter",
            name="wan_interface",
            field=models.CharField(
                default="ether1",
                help_text="Port cabled to Starlink / the provider (usually ether1).",
                max_length=64,
                verbose_name="WAN interface",
            ),
        ),
        migrations.AddField(
            model_name="mikrotikrouter",
            name="lan_bridge",
            field=models.CharField(
                default="bridgeLocal",
                help_text="Bridge used for customer / LAN ports.",
                max_length=64,
                verbose_name="LAN bridge",
            ),
        ),
        migrations.AddField(
            model_name="mikrotikrouter",
            name="provider_gateway",
            field=models.CharField(
                blank=True,
                default="192.168.1.1",
                help_text="Starlink/ISP admin IP to block when running behind their router.",
                max_length=64,
                verbose_name="Provider gateway IP",
            ),
        ),
        migrations.AddField(
            model_name="mikrotikrouter",
            name="clean_uplink_separate_wan",
            field=models.BooleanField(
                default=True,
                help_text="Remove the WAN port from the LAN bridge so MikroTik routes instead of switching.",
                verbose_name="Separate WAN from bridge",
            ),
        ),
        migrations.AddField(
            model_name="mikrotikrouter",
            name="clean_uplink_wan_was_bridged",
            field=models.BooleanField(
                default=False,
                help_text="Internal: WAN port was a bridge slave when clean uplink was enabled.",
            ),
        ),
    ]
