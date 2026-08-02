from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0026_customer_status_accepted_not_interested"),
    ]

    operations = [
        migrations.AddField(
            model_name="stkpushrequest",
            name="purpose",
            field=models.CharField(
                choices=[
                    ("subscription", "Subscription renewal"),
                    ("lead_allocation", "Lead allocation"),
                ],
                db_index=True,
                default="subscription",
                max_length=32,
            ),
        ),
    ]
