from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0009_customer_cpe_wifi"),
    ]

    operations = [
        migrations.AddField(
            model_name="customer",
            name="package_end",
            field=models.DateField(
                blank=True,
                help_text="Date this client's current package period ends (from plan duration or manual override).",
                null=True,
                verbose_name="Package end",
            ),
        ),
        migrations.AddField(
            model_name="customer",
            name="package_start",
            field=models.DateField(
                blank=True,
                help_text="Date this client's current package period began.",
                null=True,
                verbose_name="Package start",
            ),
        ),
    ]
