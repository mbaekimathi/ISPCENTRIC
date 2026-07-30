from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0017_organization_daraja_api"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="hotspot_enabled",
            field=models.BooleanField(
                default=False,
                help_text="Allow Hotspot portals and voucher access for this organization.",
                verbose_name="Enable Hotspot",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_portal_title",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Title shown on the Hotspot login page.",
                max_length=120,
                verbose_name="Portal title",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_login_message",
            field=models.TextField(
                blank=True,
                default="",
                help_text="Welcome text shown on the Hotspot login page.",
                verbose_name="Login message",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_redirect_url",
            field=models.URLField(
                blank=True,
                default="",
                help_text="Optional URL clients open after a successful Hotspot login.",
                max_length=500,
                verbose_name="Redirect URL after login",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_voucher_validity_hours",
            field=models.PositiveIntegerField(
                default=24,
                help_text="Default lifetime for new Hotspot vouchers.",
                verbose_name="Default voucher validity (hours)",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_default_download_mbps",
            field=models.PositiveIntegerField(
                default=10,
                help_text="Default download speed for new Hotspot vouchers.",
                verbose_name="Default download (Mbps)",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_default_upload_mbps",
            field=models.PositiveIntegerField(
                default=5,
                help_text="Default upload speed for new Hotspot vouchers.",
                verbose_name="Default upload (Mbps)",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_idle_timeout_minutes",
            field=models.PositiveIntegerField(
                default=15,
                help_text=(
                    "Disconnect idle Hotspot sessions after this many minutes. "
                    "Use 0 for no idle timeout."
                ),
                verbose_name="Idle timeout (minutes)",
            ),
        ),
    ]
