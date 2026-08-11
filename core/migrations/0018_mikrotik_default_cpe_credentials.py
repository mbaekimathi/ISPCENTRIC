from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0017_mikrotik_uplink_weights"),
    ]

    operations = [
        migrations.AddField(
            model_name="mikrotikrouter",
            name="default_cpe_username",
            field=models.CharField(
                blank=True,
                default="admin",
                help_text="Pre-filled on new PPPoE clients linked to this MikroTik.",
                max_length=64,
                verbose_name="Default client router username",
            ),
        ),
        migrations.AddField(
            model_name="mikrotikrouter",
            name="default_cpe_password",
            field=models.CharField(
                blank=True,
                help_text="Pre-filled on new PPPoE clients; used for remote CPE access from ISPCENTRIC.",
                max_length=128,
                verbose_name="Default client router password",
            ),
        ),
    ]
