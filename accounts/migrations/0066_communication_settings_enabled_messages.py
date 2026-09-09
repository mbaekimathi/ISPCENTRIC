from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0065_organization_daraja_company_shortcode"),
    ]

    operations = [
        migrations.AddField(
            model_name="communicationsettings",
            name="enabled_messages",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text=(
                    "Map of organization event keys to rule objects with message, recipients, "
                    'and channels (e.g. {"client_welcome": {"message": "...", '
                    '"recipients": ["client"], "channels": ["sms"]}}).'
                ),
                verbose_name="Enabled messages",
            ),
        ),
    ]
