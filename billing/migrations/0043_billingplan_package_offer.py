from django.db import migrations, models
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0042_alter_accessvoucher_status"),
    ]

    operations = [
        migrations.AddField(
            model_name="billingplan",
            name="offer_enabled",
            field=models.BooleanField(
                default=False,
                help_text="When enabled, repeat payers earn a free session after the set number of payments.",
                verbose_name="Package offer enabled",
            ),
        ),
        migrations.AddField(
            model_name="billingplan",
            name="offer_pay_count",
            field=models.PositiveSmallIntegerField(
                default=5,
                help_text="Buy X get 1 free — e.g. 5 means every 5 paid sessions grants one extra session.",
                validators=[
                    django.core.validators.MinValueValidator(1),
                    django.core.validators.MaxValueValidator(100),
                ],
                verbose_name="Payments before free session",
            ),
        ),
        migrations.CreateModel(
            name="PackageOfferProgress",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("paid_count", models.PositiveSmallIntegerField(default=0)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "customer",
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name="package_offer_progress",
                        to="billing.customer",
                    ),
                ),
                (
                    "plan",
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name="offer_progress",
                        to="billing.billingplan",
                    ),
                ),
            ],
            options={
                "db_table": "billing_package_offer_progress",
            },
        ),
        migrations.AddConstraint(
            model_name="packageofferprogress",
            constraint=models.UniqueConstraint(
                fields=("customer", "plan"),
                name="billing_offer_progress_customer_plan_uniq",
            ),
        ),
    ]
