from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0057_hotspot_connection_attempt"),
        ("core", "0028_mikrotikrouter_usage_high_threshold_tb"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ClientIspMovement",
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
                ("customer_name", models.CharField(blank=True, max_length=255)),
                ("client_ip", models.CharField(blank=True, max_length=45)),
                ("from_isp_port", models.CharField(blank=True, max_length=64)),
                ("to_isp_port", models.CharField(blank=True, max_length=64)),
                (
                    "source",
                    models.CharField(
                        choices=[
                            ("manual", "Manual"),
                            ("auto_rebalance", "Auto balance"),
                            ("background", "Background monitor"),
                        ],
                        db_index=True,
                        default="manual",
                        max_length=32,
                    ),
                ),
                (
                    "seamless",
                    models.BooleanField(
                        default=True,
                        help_text="True when existing sessions were left connected.",
                    ),
                ),
                ("imbalance_reason", models.CharField(blank=True, max_length=32)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="client_isp_movements",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "customer",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="isp_movements",
                        to="billing.customer",
                    ),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="client_isp_movements",
                        to="accounts.organization",
                    ),
                ),
                (
                    "router",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="client_isp_movements",
                        to="core.mikrotikrouter",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(
                        fields=["router", "-created_at"],
                        name="core_clien_router__8a4f21_idx",
                    ),
                    models.Index(
                        fields=["organization", "-created_at"],
                        name="core_clien_organiz_91b2c3_idx",
                    ),
                ],
            },
        ),
    ]
