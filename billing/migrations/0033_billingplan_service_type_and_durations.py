# Generated manually for package periods + Hotspot/PPPoE split

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0032_billingplan_routers"),
    ]

    operations = [
        migrations.AddField(
            model_name="billingplan",
            name="service_type",
            field=models.CharField(
                choices=[("pppoe", "PPPoE"), ("hotspot", "Hotspot")],
                db_index=True,
                default="pppoe",
                help_text="Whether this package is for Hotspot or PPPoE customers.",
                max_length=20,
            ),
        ),
        migrations.AlterField(
            model_name="billingplan",
            name="duration",
            field=models.CharField(
                choices=[
                    ("hourly", "Per hour"),
                    ("six_hours", "Per 6 hours"),
                    ("daily", "Daily"),
                    ("weekly", "Weekly"),
                    ("monthly", "Monthly"),
                    ("quarterly", "Quarterly"),
                    ("semi_annual", "Semi-annual"),
                    ("yearly", "Yearly"),
                ],
                default="monthly",
                max_length=20,
            ),
        ),
    ]
