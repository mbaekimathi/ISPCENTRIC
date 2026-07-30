from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0008_customer_router"),
    ]

    operations = [
        migrations.AddField(
            model_name="customer",
            name="cpe_password",
            field=models.CharField(
                blank=True,
                help_text="RouterOS / Winbox password on the client's CPE router.",
                max_length=128,
                verbose_name="CPE password",
            ),
        ),
        migrations.AddField(
            model_name="customer",
            name="cpe_username",
            field=models.CharField(
                blank=True,
                default="admin",
                help_text="RouterOS / Winbox username on the client's CPE router.",
                max_length=64,
                verbose_name="CPE username",
            ),
        ),
        migrations.AddField(
            model_name="customer",
            name="cpe_wifi_password",
            field=models.CharField(
                blank=True,
                max_length=128,
                verbose_name="CPE Wi‑Fi password",
            ),
        ),
        migrations.AddField(
            model_name="customer",
            name="cpe_wifi_ssid",
            field=models.CharField(
                blank=True,
                max_length=64,
                verbose_name="CPE Wi‑Fi name",
            ),
        ),
    ]
