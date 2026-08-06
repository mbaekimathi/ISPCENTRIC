from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0034_stk_mikrotik_onboarding"),
    ]

    operations = [
        migrations.AddField(
            model_name="customer",
            name="package_paused_at",
            field=models.DateTimeField(
                blank=True,
                help_text=(
                    "When set, the package clock is frozen: surfing is blocked and the "
                    "remaining period is preserved until resume."
                ),
                null=True,
                verbose_name="Package paused at",
            ),
        ),
    ]
