from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0068_alter_platformcommunicationsettings_enabled_messages"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="hotspot_block_tethering",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "When enabled, MikroTik drops typical USB / Bluetooth / personal-hotspot "
                    "sharing behind a paid Hotspot device (TTL 63 / 127). Does not affect PPPoE."
                ),
                verbose_name="Block Hotspot tethering",
            ),
        ),
    ]
