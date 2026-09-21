from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0029_client_isp_movement"),
    ]

    operations = [
        migrations.AddField(
            model_name="mikrotikrouter",
            name="smart_auto_balance_enabled",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "When on, ISPCENTRIC may auto-rebalance clients and apply smart-balance "
                    "during live polls and background checks. Manual Switch link always works."
                ),
                verbose_name="Smart auto balance",
            ),
        ),
    ]
