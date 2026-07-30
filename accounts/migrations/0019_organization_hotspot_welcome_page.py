from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0018_organization_hotspot_settings"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="hotspot_use_welcome_page",
            field=models.BooleanField(
                default=True,
                help_text="After login, send clients to your customizable Hotspot welcome page.",
                verbose_name="Use ISPCENTRIC welcome page",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_welcome_title",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Headline on the post-login welcome page.",
                max_length=120,
                verbose_name="Welcome page title",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_welcome_message",
            field=models.TextField(
                blank=True,
                default="",
                help_text="Body text on the post-login welcome page.",
                verbose_name="Welcome page message",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_welcome_button_label",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Label for the main button on the welcome page.",
                max_length=80,
                verbose_name="Welcome button label",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_welcome_button_url",
            field=models.URLField(
                blank=True,
                default="",
                help_text="Optional link for the welcome page button (e.g. your website).",
                max_length=500,
                verbose_name="Welcome button link",
            ),
        ),
        migrations.AlterField(
            model_name="organization",
            name="hotspot_redirect_url",
            field=models.URLField(
                blank=True,
                default="",
                help_text="URL clients open after a successful Hotspot login.",
                max_length=500,
                verbose_name="Redirect URL after login",
            ),
        ),
    ]
