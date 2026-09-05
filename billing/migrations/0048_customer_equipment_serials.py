from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0047_customer_status_pending_connection_label"),
    ]

    operations = [
        migrations.AddField(
            model_name="customer",
            name="equipment_serials",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="Serial numbers of CPE / ONU / other gear installed at this subscriber.",
                verbose_name="Equipment serial numbers",
            ),
        ),
    ]
