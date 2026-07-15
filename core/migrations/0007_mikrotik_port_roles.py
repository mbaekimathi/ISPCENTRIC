from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0006_mikrotik_clean_uplink"),
    ]

    operations = [
        migrations.AddField(
            model_name="mikrotikrouter",
            name="port_roles",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text="Map of interface name → role (wan, lan, unused, none).",
            ),
        ),
    ]
