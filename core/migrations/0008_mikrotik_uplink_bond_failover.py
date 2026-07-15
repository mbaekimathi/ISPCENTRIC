from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0007_mikrotik_port_roles"),
    ]

    operations = [
        migrations.AddField(
            model_name="mikrotikrouter",
            name="bond_interface",
            field=models.CharField(
                blank=True,
                default="bond-wan",
                help_text="Name of the bonding interface created for same-provider uplinks.",
                max_length=64,
                verbose_name="Bond interface",
            ),
        ),
        migrations.AddField(
            model_name="mikrotikrouter",
            name="bond_mode",
            field=models.CharField(
                blank=True,
                default="balance-xor",
                help_text="RouterOS bonding mode (e.g. balance-xor, 802.3ad, active-backup).",
                max_length=32,
                verbose_name="Bond mode",
            ),
        ),
        migrations.AddField(
            model_name="mikrotikrouter",
            name="uplink_mode",
            field=models.CharField(
                choices=[
                    ("single", "Single WAN"),
                    ("bond", "Bonded uplinks (same provider)"),
                    ("failover", "Failover (different providers)"),
                ],
                default="single",
                help_text="Single WAN, bond multiple ports to one provider, or failover across providers.",
                max_length=16,
                verbose_name="Uplink mode",
            ),
        ),
        migrations.AddField(
            model_name="mikrotikrouter",
            name="uplink_ports",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="Ordered port names used for bond (all members) or failover (primary first, then backups).",
            ),
        ),
        migrations.AlterField(
            model_name="mikrotikrouter",
            name="port_roles",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text="Map of interface name → role (wan, wan_primary, wan_backup, bond, lan, unused, none).",
            ),
        ),
    ]
