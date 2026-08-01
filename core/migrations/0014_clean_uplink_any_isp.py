from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0013_alter_mikrotikrouter_model"),
    ]

    operations = [
        migrations.AlterField(
            model_name="mikrotikrouter",
            name="clean_uplink_mode",
            field=models.CharField(
                choices=[
                    ("bypass", "Modem bypass (MikroTik owns WAN)"),
                    ("behind", "Behind provider router"),
                ],
                default="bypass",
                max_length=16,
                verbose_name="Clean uplink mode",
            ),
        ),
        migrations.AlterField(
            model_name="mikrotikrouter",
            name="wan_interface",
            field=models.CharField(
                default="ether1",
                help_text="Port cabled to the ISP modem/ONT (usually ether1). PPPoE-out is detected automatically when present.",
                max_length=64,
                verbose_name="WAN interface",
            ),
        ),
        migrations.AlterField(
            model_name="mikrotikrouter",
            name="provider_gateway",
            field=models.CharField(
                blank=True,
                default="192.168.1.1",
                help_text="ISP modem/ONT admin IP(s) to block in behind-provider mode. Comma-separated allowed (e.g. 192.168.1.1, 192.168.100.1).",
                max_length=255,
                verbose_name="Provider gateway IP",
            ),
        ),
    ]
