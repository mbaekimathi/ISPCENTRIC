from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0016_mikrotik_uplink_balance"),
    ]

    operations = [
        migrations.AddField(
            model_name="mikrotikrouter",
            name="uplink_weights",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text=(
                    "Per-port uplink capacity in Mbps for weighted PCC load balance "
                    '(e.g. {"ether1": 100, "ether4": 20}). Empty means equal share.'
                ),
            ),
        ),
        migrations.AlterField(
            model_name="mikrotikrouter",
            name="uplink_mode",
            field=models.CharField(
                choices=[
                    ("single", "Single WAN"),
                    ("bond", "Bonded uplinks (same provider)"),
                    ("failover", "Failover (different providers)"),
                    ("balance", "Load balance (different providers)"),
                ],
                default="single",
                help_text=(
                    "Single WAN, bond multiple ports to one provider, failover across "
                    "providers, or PCC load-balance (equal or weighted by Mbps) across providers."
                ),
                max_length=16,
                verbose_name="Uplink mode",
            ),
        ),
    ]
