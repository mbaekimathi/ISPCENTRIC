# Generated manually for MikroTik onboarding session model.

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

import ispcentric.encrypted_fields


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("accounts", "0001_initial"),
        ("core", "0031_wireguard_reservation_organization"),
    ]

    operations = [
        migrations.CreateModel(
            name="MikroTikOnboardingSession",
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
                ("label", models.CharField(blank=True, max_length=150)),
                (
                    "tunnel_address",
                    models.GenericIPAddressField(blank=True, null=True, protocol="IPv4"),
                ),
                (
                    "planned_lan",
                    models.GenericIPAddressField(blank=True, null=True, protocol="IPv4"),
                ),
                (
                    "discovered_lan",
                    models.GenericIPAddressField(blank=True, null=True, protocol="IPv4"),
                ),
                (
                    "verified_dial_host",
                    models.GenericIPAddressField(blank=True, null=True, protocol="IPv4"),
                ),
                (
                    "management_host",
                    models.GenericIPAddressField(blank=True, null=True, protocol="IPv4"),
                ),
                ("username", models.CharField(blank=True, max_length=120)),
                (
                    "password",
                    ispcentric.encrypted_fields.EncryptedCharField(
                        blank=True, max_length=512
                    ),
                ),
                ("serial_number", models.CharField(blank=True, max_length=64)),
                ("software_id", models.CharField(blank=True, max_length=64)),
                ("board_name", models.CharField(blank=True, max_length=120)),
                ("routeros_version", models.CharField(blank=True, max_length=64)),
                ("lan_ip_applied_at_connect", models.BooleanField(default=False)),
                (
                    "phase",
                    models.CharField(
                        choices=[
                            ("prepared", "Script generated"),
                            ("tunnel_ready", "Tunnel verified"),
                            ("authenticated", "API login verified"),
                            ("committed", "Router saved"),
                            ("cancelled", "Cancelled"),
                        ],
                        default="prepared",
                        max_length=20,
                    ),
                ),
                ("tunnel_verified_at", models.DateTimeField(blank=True, null=True)),
                ("authenticated_at", models.DateTimeField(blank=True, null=True)),
                ("committed_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("expires_at", models.DateTimeField()),
                (
                    "initiated_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="mikrotik_onboarding_sessions",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="mikrotik_onboarding_sessions",
                        to="accounts.organization",
                    ),
                ),
                (
                    "reservation",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="onboarding_sessions",
                        to="core.wireguardreservation",
                    ),
                ),
                (
                    "router",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="onboarding_sessions",
                        to="core.mikrotikrouter",
                    ),
                ),
            ],
            options={
                "db_table": "core_mikrotik_onboarding_session",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="mikrotikonboardingsession",
            index=models.Index(
                fields=["organization", "phase", "-created_at"],
                name="core_mik_onb_org_phase_idx",
            ),
        ),
    ]
