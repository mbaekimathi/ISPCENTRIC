from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0062_accessvoucher_customer_help_text"),
    ]

    operations = [
        migrations.AddField(
            model_name="customer",
            name="fup_enabled",
            field=models.BooleanField(
                default=True,
                help_text=(
                    "When disabled, this client is exempt from the package "
                    "fair-usage policy (no throttle or disconnect even after "
                    "the data cap)."
                ),
                verbose_name="FUP enforcement enabled",
            ),
        ),
    ]
