from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0057_organization_hotspot_welcome_quick_links"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="hotspot_welcome_link1_image",
            field=models.ImageField(
                blank=True,
                help_text="Optional advert image for quick link 1 on the welcome page.",
                null=True,
                upload_to="hotspot_ads/%Y/%m/",
                verbose_name="Quick link 1 image",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_welcome_link2_image",
            field=models.ImageField(
                blank=True,
                help_text="Optional advert image for quick link 2 on the welcome page.",
                null=True,
                upload_to="hotspot_ads/%Y/%m/",
                verbose_name="Quick link 2 image",
            ),
        ),
    ]
