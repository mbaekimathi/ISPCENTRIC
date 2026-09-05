from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0046_security_hardening_encryption_audit"),
    ]

    operations = [
        migrations.AlterField(
            model_name="customer",
            name="status",
            field=models.CharField(
                choices=[
                    ("new", "Pending connection"),
                    ("allocated", "Allocated"),
                    ("allocated_open", "Allocated — open"),
                    ("allocated_closed", "Allocated — closed"),
                    ("accepted", "Accepted"),
                    ("not_interested", "Not interested"),
                    ("active", "Active"),
                    ("suspended", "Suspended"),
                    ("inactive", "Inactive"),
                ],
                default="active",
                max_length=20,
            ),
        ),
    ]
