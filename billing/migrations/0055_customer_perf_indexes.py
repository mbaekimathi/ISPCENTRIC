from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0054_customer_delete_keeps_billing"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="customer",
            index=models.Index(
                fields=["organization", "package_end"],
                name="bill_cust_org_pkg_end_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="customer",
            index=models.Index(
                fields=["organization", "service_type", "status", "created_at"],
                name="bill_cust_org_svc_st_cr_idx",
            ),
        ),
    ]
