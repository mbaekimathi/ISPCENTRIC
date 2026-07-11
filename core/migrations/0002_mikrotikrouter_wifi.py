from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0001_mikrotik_router"),
    ]

    operations = [
        migrations.AddField(
            model_name="mikrotikrouter",
            name="wifi_password",
            field=models.CharField(blank=True, max_length=63, verbose_name="Wi‑Fi password"),
        ),
        migrations.AddField(
            model_name="mikrotikrouter",
            name="wifi_ssid",
            field=models.CharField(blank=True, max_length=32, verbose_name="Wi‑Fi name"),
        ),
    ]
