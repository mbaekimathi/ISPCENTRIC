# Generated manually for sold stock movements / serial status.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0060_network_equipment_stock_movement"),
    ]

    operations = [
        migrations.AlterField(
            model_name="networkequipmentserial",
            name="status",
            field=models.CharField(
                choices=[
                    ("in_stock", "In stock"),
                    ("issued", "Issued"),
                    ("sold", "Sold"),
                ],
                db_index=True,
                default="in_stock",
                max_length=20,
            ),
        ),
        migrations.AlterField(
            model_name="networkequipmentstockmovement",
            name="movement_type",
            field=models.CharField(
                choices=[
                    ("stock_in", "Stock in"),
                    ("stock_out", "Stock out"),
                    ("allocate", "Allocated"),
                    ("return", "Returned"),
                    ("sold", "Sold"),
                ],
                db_index=True,
                max_length=20,
            ),
        ),
    ]
