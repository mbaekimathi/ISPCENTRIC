# Generated manually: one STK payment can issue several Hotspot device vouchers.

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0040_billingplan_max_devices_unlimited"),
    ]

    operations = [
        migrations.AlterField(
            model_name="accessvoucher",
            name="stk_request",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="access_vouchers",
                to="billing.stkpushrequest",
            ),
        ),
        migrations.AddIndex(
            model_name="accessvoucher",
            index=models.Index(
                fields=["stk_request", "status"],
                name="bill_voucher_stk_status_idx",
            ),
        ),
    ]
