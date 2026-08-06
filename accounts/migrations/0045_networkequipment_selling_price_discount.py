from decimal import Decimal

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0044_networkequipment_image"),
    ]

    operations = [
        migrations.AddField(
            model_name="networkequipment",
            name="selling_price",
            field=models.DecimalField(
                decimal_places=2,
                default=Decimal("0"),
                help_text="Unit selling price in KES.",
                max_digits=12,
                verbose_name="Selling price",
            ),
        ),
        migrations.AddField(
            model_name="networkequipment",
            name="discount_enabled",
            field=models.BooleanField(
                default=False,
                help_text="When enabled, discount_amount is subtracted from the selling price.",
                verbose_name="Enable discount",
            ),
        ),
        migrations.AddField(
            model_name="networkequipment",
            name="discount_amount",
            field=models.DecimalField(
                decimal_places=2,
                default=Decimal("0"),
                help_text="Flat discount in KES when discounts are enabled.",
                max_digits=12,
                verbose_name="Discount amount",
            ),
        ),
    ]
