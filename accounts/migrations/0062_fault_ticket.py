# Generated manually for FaultTicket.

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0061_network_equipment_sold_status"),
        ("billing", "0050_customer_status_linear_lifecycle"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="FaultTicket",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("ticket_number", models.CharField(db_index=True, max_length=32, unique=True)),
                (
                    "issue",
                    models.CharField(
                        choices=[
                            ("no_connectivity", "No connectivity"),
                            ("slow_speed", "Slow speed"),
                            ("intermittent", "Intermittent connection"),
                            ("equipment_fault", "Equipment fault"),
                            ("cable_damage", "Cable / fibre damage"),
                            ("power_issue", "Power / UPS issue"),
                            ("wifi_issue", "Wi‑Fi issue"),
                            ("other", "Other"),
                        ],
                        db_index=True,
                        max_length=32,
                    ),
                ),
                ("notes", models.TextField(blank=True, default="")),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("open", "Open"),
                            ("assigned", "Assigned"),
                            ("in_progress", "In progress"),
                            ("resolved", "Resolved"),
                            ("closed", "Closed"),
                        ],
                        db_index=True,
                        default="open",
                        max_length=20,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "assigned_technician",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="fault_tickets",
                        to="accounts.employee",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="raised_fault_tickets",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "customer",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="fault_tickets",
                        to="billing.customer",
                    ),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="fault_tickets",
                        to="accounts.organization",
                    ),
                ),
            ],
            options={
                "verbose_name": "Fault ticket",
                "verbose_name_plural": "Fault tickets",
                "db_table": "accounts_fault_ticket",
                "ordering": ["-created_at", "-id"],
            },
        ),
    ]
