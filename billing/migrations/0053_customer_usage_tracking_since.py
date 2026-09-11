from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0052_payment_phone"),
    ]

    operations = [
        migrations.AddField(
            model_name="customer",
            name="usage_tracking_since",
            field=models.DateTimeField(
                blank=True,
                help_text=(
                    "When set, data-used totals ignore traffic before this moment "
                    "(package renewal or manual reset). Historical samples are kept."
                ),
                null=True,
                verbose_name="Usage tracking since",
            ),
        ),
    ]
