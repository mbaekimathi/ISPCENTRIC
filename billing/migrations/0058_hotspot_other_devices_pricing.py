from decimal import Decimal

from django.core.validators import MinValueValidator
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0057_hotspot_connection_attempt"),
    ]

    operations = [
        migrations.AddField(
            model_name="billingplan",
            name="hotspot_other_devices_enabled",
            field=models.BooleanField(
                default=True,
                help_text=(
                    "When enabled, the captive pay page offers “Pay for other devices” "
                    "with hourly pricing for multi-device voucher batches."
                ),
                verbose_name="Hotspot other-devices pay",
            ),
        ),
        migrations.AddField(
            model_name="billingplan",
            name="hotspot_other_base_price",
            field=models.DecimalField(
                blank=True,
                decimal_places=2,
                help_text=(
                    "Base fee (KES) added before hourly device top-up. "
                    "Leave blank to use the package price as the base."
                ),
                max_digits=12,
                null=True,
                validators=[MinValueValidator(Decimal("0"))],
                verbose_name="Other devices base price",
            ),
        ),
        migrations.AddField(
            model_name="billingplan",
            name="hotspot_hourly_rate_per_device",
            field=models.DecimalField(
                decimal_places=2,
                default=Decimal("0"),
                help_text=(
                    "KES per hour per device for “Pay for other devices”. "
                    "Total = base + (rate × devices × hours)."
                ),
                max_digits=12,
                validators=[MinValueValidator(Decimal("0"))],
                verbose_name="Hourly rate per device",
            ),
        ),
    ]
