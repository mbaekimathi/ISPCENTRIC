from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0036_network_equipment_serial"),
    ]

    operations = [
        migrations.AddField(
            model_name="networkequipment",
            name="track_serials",
            field=models.BooleanField(
                default=False,
                help_text="When enabled, stock movements require serial numbers for this equipment.",
                verbose_name="Track serial numbers",
            ),
        ),
    ]
