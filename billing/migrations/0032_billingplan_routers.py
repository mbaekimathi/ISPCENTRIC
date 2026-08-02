# Generated manually for BillingPlan ↔ MikroTikRouter linking.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0031_installation_reject_reason"),
        ("core", "0014_clean_uplink_any_isp"),
    ]

    operations = [
        migrations.AddField(
            model_name="billingplan",
            name="routers",
            field=models.ManyToManyField(
                blank=True,
                help_text=(
                    "Optional. Leave empty to offer this package on all MikroTiks; "
                    "select specific routers to limit where it can be used."
                ),
                related_name="billing_plans",
                to="core.mikrotikrouter",
            ),
        ),
    ]
