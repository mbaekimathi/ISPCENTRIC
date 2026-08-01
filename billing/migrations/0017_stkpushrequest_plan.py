from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0016_customer_hotspot_mac_null_unique"),
    ]

    operations = [
        migrations.AddField(
            model_name="stkpushrequest",
            name="plan",
            field=models.ForeignKey(
                blank=True,
                help_text="Package selected and priced when this payment attempt began.",
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="stk_push_requests",
                to="billing.billingplan",
            ),
        ),
    ]
