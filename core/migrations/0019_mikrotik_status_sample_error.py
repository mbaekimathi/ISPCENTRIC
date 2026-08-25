from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0018_mikrotik_default_cpe_credentials"),
    ]

    operations = [
        migrations.AddField(
            model_name="mikrotikstatussample",
            name="error",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]
