from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0048_customer_equipment_serials"),
    ]

    operations = [
        migrations.AlterField(
            model_name="customer",
            name="status",
            field=models.CharField(
                choices=[
                    ("new", "Pending connection"),
                    ("in_progress", "In progress"),
                    ("allocated", "Allocated"),
                    ("allocated_open", "Allocated — open"),
                    ("allocated_closed", "Allocated — closed"),
                    ("accepted", "Accepted"),
                    ("not_interested", "Not interested"),
                    ("active", "Active"),
                    ("suspended", "Suspended"),
                    ("inactive", "Pending activation"),
                ],
                default="active",
                max_length=20,
            ),
        ),
    ]
