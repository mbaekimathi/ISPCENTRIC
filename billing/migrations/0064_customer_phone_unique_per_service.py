from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0063_customer_fup_enabled"),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="customer",
            name="bill_cust_org_phone_uniq",
        ),
        migrations.AddConstraint(
            model_name="customer",
            constraint=models.UniqueConstraint(
                condition=models.Q(phone_normalized__gt=""),
                fields=("organization", "service_type", "phone_normalized"),
                name="bill_cust_org_svc_phone_uniq",
            ),
        ),
        migrations.AlterField(
            model_name="customer",
            name="phone_normalized",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text="Digits-only phone key. Unique per organization and service type.",
                max_length=20,
            ),
        ),
    ]
