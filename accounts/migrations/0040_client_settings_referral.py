from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0039_client_settings"),
    ]

    operations = [
        migrations.AddField(
            model_name="clientsettings",
            name="referral_enabled",
            field=models.BooleanField(
                default=False,
                help_text="When enabled, client referral features are available on the platform.",
                verbose_name="Enable referrals",
            ),
        ),
    ]
