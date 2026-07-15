from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0010_organization_status"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="pppoe_compulsory",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "When enabled, only customers registered as PPPoE clients "
                    "are eligible to receive internet."
                ),
            ),
        ),
    ]
