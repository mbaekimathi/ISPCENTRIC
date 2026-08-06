from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0043_organization_referral_status_phone"),
    ]

    operations = [
        migrations.AddField(
            model_name="networkequipment",
            name="image",
            field=models.ImageField(
                blank=True,
                help_text="Optional photo of the equipment item.",
                null=True,
                upload_to="equipment/%Y/%m/",
                verbose_name="Equipment image",
            ),
        ),
    ]
