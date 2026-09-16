from django.db import migrations, models


def enable_tether_block_for_existing(apps, schema_editor):
    Organization = apps.get_model("accounts", "Organization")
    Organization.objects.filter(hotspot_block_tethering=False).update(
        hotspot_block_tethering=True
    )


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0069_organization_hotspot_block_tethering"),
    ]

    operations = [
        migrations.AlterField(
            model_name="organization",
            name="hotspot_block_tethering",
            field=models.BooleanField(
                default=True,
                help_text=(
                    "On by default. MikroTik drops typical USB / Bluetooth / personal-hotspot "
                    "sharing behind a paid Hotspot device (TTL 63 / 127). Turn off to allow sharing. "
                    "Does not affect PPPoE."
                ),
                verbose_name="Block Hotspot tethering",
            ),
        ),
        migrations.RunPython(enable_tether_block_for_existing, migrations.RunPython.noop),
    ]
