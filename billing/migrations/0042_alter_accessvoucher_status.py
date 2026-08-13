from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0041_accessvoucher_multi_device"),
    ]

    operations = [
        migrations.AlterField(
            model_name="accessvoucher",
            name="status",
            field=models.CharField(
                choices=[
                    ("valid", "Valid"),
                    ("expired", "Used"),
                    ("invalid", "Invalid"),
                ],
                db_index=True,
                default="valid",
                max_length=16,
            ),
        ),
    ]
