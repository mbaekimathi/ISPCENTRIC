from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0008_mikrotik_uplink_bond_failover"),
    ]

    operations = [
        migrations.AddField(
            model_name="mikrotikrouter",
            name="uplink_unbridged",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="Ports removed from a bridge for bond/failover; restored when multi-uplink is cleared.",
            ),
        ),
    ]
