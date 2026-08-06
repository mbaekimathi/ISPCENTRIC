from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0015_mikrotik_status_sample"),
    ]

    operations = [
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
                    "providers, or PCC load-balance (~50/50) across providers."
                ),
                max_length=16,
                verbose_name="Uplink mode",
            ),
        ),
    ]
