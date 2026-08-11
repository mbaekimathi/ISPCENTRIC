from django.db import migrations, models


def backfill_phone_normalized(apps, schema_editor):
    Customer = apps.get_model("billing", "Customer")
    from billing.services import normalize_customer_phone_key

    for row in Customer.objects.exclude(phone="").iterator():
        key = normalize_customer_phone_key(row.phone)
        if key and row.phone_normalized != key:
            Customer.objects.filter(pk=row.pk).update(phone_normalized=key)


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0037_customer_cpe_network"),
    ]

    operations = [
        migrations.AddField(
            model_name="customer",
            name="phone_normalized",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text="Digits-only phone key used to enforce one account per number.",
                max_length=20,
            ),
        ),
        migrations.RunPython(backfill_phone_normalized, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="customer",
            constraint=models.UniqueConstraint(
                condition=models.Q(phone_normalized__gt=""),
                fields=("organization", "phone_normalized"),
                name="bill_cust_org_phone_uniq",
            ),
        ),
    ]
