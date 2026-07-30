from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0013_stk_push_request"),
    ]

    operations = [
        migrations.AddField(
            model_name="customer",
            name="hotspot_mac",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text=(
                    "Device authorized automatically after a successful Hotspot payment."
                ),
                max_length=17,
                verbose_name="Hotspot device MAC",
            ),
        ),
    ]
