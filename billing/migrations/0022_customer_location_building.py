from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0021_customer_status_new_allocated"),
    ]

    operations = [
        migrations.AlterField(
            model_name="customer",
            name="address",
            field=models.CharField(
                blank=True,
                help_text="Map place name selected during registration.",
                max_length=255,
                verbose_name="Location",
            ),
        ),
        migrations.AddField(
            model_name="customer",
            name="location_lat",
            field=models.DecimalField(
                blank=True, decimal_places=6, max_digits=9, null=True
            ),
        ),
        migrations.AddField(
            model_name="customer",
            name="location_lng",
            field=models.DecimalField(
                blank=True, decimal_places=6, max_digits=9, null=True
            ),
        ),
        migrations.AddField(
            model_name="customer",
            name="building_name",
            field=models.CharField(blank=True, max_length=150),
        ),
        migrations.AddField(
            model_name="customer",
            name="house_number",
            field=models.CharField(blank=True, max_length=60),
        ),
    ]
