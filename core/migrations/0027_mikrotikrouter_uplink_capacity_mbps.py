from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0026_mikrotikrouter_usage_tracking_since"),
    ]

    operations = [
        migrations.AddField(
            model_name="mikrotikrouter",
            name="uplink_capacity_mbps",
            field=models.PositiveIntegerField(
                default=0,
                help_text=(
                    "Total real WAN capacity for this NAS (sold-vs-capacity NOC checks). "
                    "0 = use the sum of uplink_weights when set, otherwise unknown."
                ),
                verbose_name="Uplink capacity (Mbps)",
            ),
        ),
    ]
