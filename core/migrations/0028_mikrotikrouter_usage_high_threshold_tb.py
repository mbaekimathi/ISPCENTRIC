from decimal import Decimal

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0027_mikrotikrouter_uplink_capacity_mbps"),
    ]

    operations = [
        migrations.AddField(
            model_name="mikrotikrouter",
            name="usage_high_threshold_tb",
            field=models.DecimalField(
                decimal_places=2,
                default=Decimal("3.00"),
                help_text=(
                    "Notify the DPO when combined client usage on this MikroTik exceeds "
                    "this amount since the uplink package period start."
                ),
                max_digits=6,
                verbose_name="Usage alert threshold (TB)",
            ),
        ),
    ]
