from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0023_clean_uplink_always_isolate_wan"),
    ]

    operations = [
        migrations.AlterField(
            model_name="mikrotikrouter",
            name="clean_uplink_enabled",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "When on, ISPCENTRIC soft-syncs firewall rules that block uplink "
                    "modem/ONT admin pages without unbridging WAN or rewriting LAN/DHCP."
                ),
                verbose_name="Clean uplink enabled",
            ),
        ),
        migrations.AlterField(
            model_name="mikrotikrouter",
            name="clean_uplink_separate_wan",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "Legacy flag. Soft clean uplink never unbridges WAN (avoids disconnects). "
                    "Provider blocks use IP firewall / bridge use-ip-firewall instead."
                ),
                verbose_name="Separate WAN from bridge",
            ),
        ),
    ]
