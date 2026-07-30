from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0011_organization_pppoe_compulsory"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="mpesa_account",
            field=models.CharField(
                blank=True,
                help_text="Optional Paybill account / reference clients should enter.",
                max_length=64,
                verbose_name="Paybill account",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="mpesa_number",
            field=models.CharField(
                blank=True,
                help_text="Paybill number or Buy Goods Till number.",
                max_length=20,
                verbose_name="M-Pesa number",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="mpesa_payment_type",
            field=models.CharField(
                blank=True,
                choices=[("", "Not set"), ("paybill", "Paybill"), ("till", "Buy Goods Till")],
                default="",
                help_text="How subscribers pay for packages: Paybill or Buy Goods Till.",
                max_length=20,
                verbose_name="M-Pesa payment type",
            ),
        ),
    ]
