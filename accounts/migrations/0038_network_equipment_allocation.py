from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("accounts", "0037_networkequipment_track_serials"),
    ]

    operations = [
        migrations.CreateModel(
            name="NetworkEquipmentAllocation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("quantity", models.PositiveIntegerField(default=1)),
                ("notes", models.CharField(blank=True, default="", max_length=255)),
                ("allocated_at", models.DateTimeField(auto_now_add=True)),
                ("returned_at", models.DateTimeField(blank=True, null=True)),
                (
                    "allocated_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="equipment_allocations_made",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "employee",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="equipment_allocations",
                        to="accounts.employee",
                    ),
                ),
                (
                    "equipment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="allocations",
                        to="accounts.networkequipment",
                    ),
                ),
                (
                    "serial",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="allocations",
                        to="accounts.networkequipmentserial",
                    ),
                ),
            ],
            options={
                "verbose_name": "Equipment allocation",
                "verbose_name_plural": "Equipment allocations",
                "db_table": "accounts_network_equipment_allocation",
                "ordering": ["-allocated_at"],
            },
        ),
    ]
