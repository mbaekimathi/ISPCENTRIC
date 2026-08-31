from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0021_wireguard_reservation_lan_address"),
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
                    ("smart_balance", "Smart balance (avoid slow ISPs)"),
                ],
                default="single",
                help_text=(
                    "Single WAN, bond multiple ports to one provider, failover across "
                    "providers, PCC load-balance (equal or weighted by Mbps), or smart "
                    "balance that temporarily avoids slow ISP links."
                ),
                max_length=16,
                verbose_name="Uplink mode",
            ),
        ),
    ]
