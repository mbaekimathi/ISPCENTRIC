# Generated manually for STK gateway modes

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0064_platform_enabled_messages"),
    ]

    operations = [
        migrations.AlterField(
            model_name="organization",
            name="daraja_environment",
            field=models.CharField(
                choices=[
                    ("sandbox", "Use Company"),
                    ("production", "Use My Gateway"),
                    ("company_shortcode", "Company keys + my shortcode"),
                ],
                default="sandbox",
                max_length=32,
                verbose_name="STK gateway",
            ),
        ),
    ]
