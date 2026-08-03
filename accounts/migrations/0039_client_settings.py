from decimal import Decimal

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0038_network_equipment_allocation"),
    ]

    operations = [
        migrations.CreateModel(
            name="ClientSettings",
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
                (
                    "landing_sign_uplink_enabled",
                    models.BooleanField(
                        default=False,
                        help_text="When enabled, the public landing page shows a Sign uplink call-to-action.",
                        verbose_name="Show Sign uplink on landing page",
                    ),
                ),
                (
                    "onboarding_fee_enabled",
                    models.BooleanField(
                        default=False,
                        help_text=(
                            "When enabled, clients must pay via STK Push before a MikroTik "
                            "tunnel onboarding script can be generated."
                        ),
                        verbose_name="Charge MikroTik onboarding fee",
                    ),
                ),
                (
                    "onboarding_fee_amount",
                    models.DecimalField(
                        decimal_places=2,
                        default=Decimal("0"),
                        help_text="Amount prompted on the phone when onboarding fee is enabled.",
                        max_digits=12,
                        verbose_name="Onboarding fee amount (KES)",
                    ),
                ),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Client settings",
                "verbose_name_plural": "Client settings",
                "db_table": "accounts_client_settings",
            },
        ),
    ]
