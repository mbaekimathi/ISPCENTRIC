from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0051_billingplan_custom_duration"),
    ]

    operations = [
        migrations.AddField(
            model_name="payment",
            name="phone",
            field=models.CharField(
                blank=True,
                help_text="MSISDN that completed the M-Pesa payment (STK Push payer).",
                max_length=30,
                verbose_name="M-Pesa paid-from phone",
            ),
        ),
    ]
