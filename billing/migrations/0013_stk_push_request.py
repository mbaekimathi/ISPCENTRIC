from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("billing", "0012_customer_package_datetime"),
    ]

    operations = [
        migrations.CreateModel(
            name="StkPushRequest",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("amount", models.DecimalField(decimal_places=2, max_digits=12)),
                ("phone", models.CharField(max_length=20)),
                ("account_reference", models.CharField(max_length=64)),
                ("merchant_request_id", models.CharField(blank=True, max_length=64)),
                ("checkout_request_id", models.CharField(blank=True, db_index=True, max_length=64)),
                ("mpesa_receipt", models.CharField(blank=True, max_length=64)),
                ("result_code", models.IntegerField(blank=True, null=True)),
                ("result_desc", models.CharField(blank=True, max_length=255)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("success", "Success"),
                            ("failed", "Failed"),
                            ("cancelled", "Cancelled"),
                        ],
                        db_index=True,
                        default="pending",
                        max_length=20,
                    ),
                ),
                ("subscription_applied", models.BooleanField(default=False)),
                ("raw_callback", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "customer",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="stk_push_requests",
                        to="billing.customer",
                    ),
                ),
                (
                    "initiated_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="initiated_stk_pushes",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "invoice",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="stk_push_requests",
                        to="billing.invoice",
                    ),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="stk_push_requests",
                        to="accounts.organization",
                    ),
                ),
                (
                    "payment",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="stk_push_requests",
                        to="billing.payment",
                    ),
                ),
            ],
            options={
                "db_table": "billing_stk_push_request",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="stkpushrequest",
            index=models.Index(fields=["organization", "status", "-created_at"], name="bill_stk_org_status_idx"),
        ),
        migrations.AddIndex(
            model_name="stkpushrequest",
            index=models.Index(fields=["customer", "-created_at"], name="bill_stk_cust_created_idx"),
        ),
    ]
