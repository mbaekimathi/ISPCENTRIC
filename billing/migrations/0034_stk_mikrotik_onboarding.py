from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0033_billingplan_service_type_and_durations"),
    ]

    operations = [
        migrations.AlterField(
            model_name="stkpushrequest",
            name="purpose",
            field=models.CharField(
                choices=[
                    ("subscription", "Subscription renewal"),
                    ("lead_allocation", "Lead allocation"),
                    ("mikrotik_onboarding", "MikroTik onboarding"),
                ],
                db_index=True,
                default="subscription",
                max_length=32,
            ),
        ),
        migrations.AlterField(
            model_name="stkpushrequest",
            name="customer",
            field=models.ForeignKey(
                blank=True,
                help_text="Optional for platform fees such as MikroTik onboarding.",
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="stk_push_requests",
                to="billing.customer",
            ),
        ),
    ]
