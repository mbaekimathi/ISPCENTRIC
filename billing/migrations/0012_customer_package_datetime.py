from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0011_payment_invoice_perf_indexes"),
    ]

    operations = [
        migrations.AlterField(
            model_name="customer",
            name="package_end",
            field=models.DateTimeField(
                blank=True,
                help_text="When this client's current package period ends (from plan duration or manual override).",
                null=True,
                verbose_name="Package end",
            ),
        ),
        migrations.AlterField(
            model_name="customer",
            name="package_start",
            field=models.DateTimeField(
                blank=True,
                help_text="When this client's current package period began.",
                null=True,
                verbose_name="Package start",
            ),
        ),
    ]
