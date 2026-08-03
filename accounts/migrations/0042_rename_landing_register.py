from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0041_organization_referral"),
    ]

    operations = [
        migrations.RenameField(
            model_name="clientsettings",
            old_name="landing_sign_uplink_enabled",
            new_name="landing_register_enabled",
        ),
        migrations.AlterField(
            model_name="clientsettings",
            name="landing_register_enabled",
            field=models.BooleanField(
                default=False,
                help_text="When enabled, the public landing page shows Register / Get started links.",
                verbose_name="Show Register on landing page",
            ),
        ),
    ]
