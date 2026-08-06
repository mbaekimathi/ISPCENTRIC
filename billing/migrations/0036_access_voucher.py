# Generated manually for AccessVoucher

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0046_networkequipment_discount_price"),
        ("billing", "0035_customer_package_paused_at"),
    ]

    operations = [
        migrations.CreateModel(
            name="AccessVoucher",
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
                ("code", models.CharField(db_index=True, max_length=24)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("valid", "Valid"),
                            ("expired", "Expired"),
                            ("invalid", "Invalid"),
                        ],
                        db_index=True,
                        default="valid",
                        max_length=16,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("redeemed_at", models.DateTimeField(blank=True, null=True)),
                ("invalidated_at", models.DateTimeField(blank=True, null=True)),
                ("redeemed_mac", models.CharField(blank=True, max_length=17)),
                (
                    "customer",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="access_vouchers",
                        to="billing.customer",
                    ),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="access_vouchers",
                        to="accounts.organization",
                    ),
                ),
                (
                    "plan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="access_vouchers",
                        to="billing.billingplan",
                    ),
                ),
                (
                    "stk_request",
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="access_voucher",
                        to="billing.stkpushrequest",
                    ),
                ),
            ],
            options={
                "db_table": "billing_access_voucher",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="accessvoucher",
            index=models.Index(
                fields=["organization", "status", "-created_at"],
                name="bill_voucher_org_status_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="accessvoucher",
            index=models.Index(
                fields=["customer", "status"],
                name="bill_voucher_cust_status_idx",
            ),
        ),
        migrations.AddConstraint(
            model_name="accessvoucher",
            constraint=models.UniqueConstraint(
                fields=("organization", "code"),
                name="bill_voucher_org_code_uniq",
            ),
        ),
    ]
