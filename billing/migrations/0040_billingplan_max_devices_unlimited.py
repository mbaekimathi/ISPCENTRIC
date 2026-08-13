from django.db import migrations, models
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0039_plan_max_devices_and_customer_device"),
    ]

    operations = [
        migrations.AlterField(
            model_name="billingplan",
            name="max_devices",
            field=models.PositiveIntegerField(
                default=0,
                help_text=(
                    "How many devices this package allows. 0 / blank = unlimited. "
                    "Hotspot: phones/laptops on one paid account. PPPoE: CPEs that may dial "
                    "this username (LAN behind one CPE is already unlimited)."
                ),
                validators=[
                    django.core.validators.MinValueValidator(0),
                    django.core.validators.MaxValueValidator(50),
                ],
                verbose_name="Max devices",
            ),
        ),
    ]
