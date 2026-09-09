# Customizable package billing periods (value + unit)

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models


LEGACY_DURATION_TO_PARTS = {
    "hourly": (1, "hours"),
    "six_hours": (6, "hours"),
    "daily": (1, "days"),
    "weekly": (1, "weeks"),
    "monthly": (1, "months"),
    "quarterly": (3, "months"),
    "semi_annual": (6, "months"),
    "yearly": (1, "years"),
}


def backfill_duration_parts(apps, schema_editor):
    BillingPlan = apps.get_model("billing", "BillingPlan")
    for plan in BillingPlan.objects.all().iterator():
        parts = LEGACY_DURATION_TO_PARTS.get(plan.duration or "", (1, "months"))
        plan.duration_value = parts[0]
        plan.duration_unit = parts[1]
        plan.save(update_fields=["duration_value", "duration_unit"])


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0050_customer_status_linear_lifecycle"),
    ]

    operations = [
        migrations.AddField(
            model_name="billingplan",
            name="duration_value",
            field=models.PositiveIntegerField(
                default=1,
                help_text="How many units (hours, days, weeks, months, or years) this package lasts.",
                validators=[MinValueValidator(1), MaxValueValidator(999)],
                verbose_name="Billing period length",
            ),
        ),
        migrations.AddField(
            model_name="billingplan",
            name="duration_unit",
            field=models.CharField(
                choices=[
                    ("hours", "Hours"),
                    ("days", "Days"),
                    ("weeks", "Weeks"),
                    ("months", "Months"),
                    ("years", "Years"),
                ],
                default="months",
                help_text="Unit for the customizable billing period length.",
                max_length=10,
                verbose_name="Billing period unit",
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
                    ("custom", "Custom"),
                ],
                default="monthly",
                max_length=20,
            ),
        ),
        migrations.RunPython(backfill_duration_parts, migrations.RunPython.noop),
    ]
