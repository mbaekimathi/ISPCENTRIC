# Generated manually for Google login settings on ClientSettings.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0066_communication_settings_enabled_messages"),
    ]

    operations = [
        migrations.AddField(
            model_name="clientsettings",
            name="google_login_enabled",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "When enabled, ISP clients can sign in with Google on the ISP client "
                    "login page (requires GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET)."
                ),
                verbose_name="Enable Google login",
            ),
        ),
        migrations.AddField(
            model_name="clientsettings",
            name="google_login_require_email_match",
            field=models.BooleanField(
                default=True,
                help_text=(
                    "When enabled, Google sign-in only works if the Google account email "
                    "matches an existing ISP client account email."
                ),
                verbose_name="Require matching email",
            ),
        ),
    ]
