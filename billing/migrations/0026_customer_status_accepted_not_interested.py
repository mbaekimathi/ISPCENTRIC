from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0025_reformat_sales_ticket_ppp"),
    ]

    operations = [
        migrations.AlterField(
            model_name="customer",
            name="status",
            field=models.CharField(
                choices=[
                    ("new", "New"),
                    ("allocated", "Allocated"),
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
