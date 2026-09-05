from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0054_organization_adverts_subscriber_advertisement"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="adverts_redirect_url",
            field=models.URLField(
                blank=True,
                default="",
                help_text=(
                    "Where subscribers go when they tap Click to earn on the pay / pause popup. "
                    "Leave blank to use this ISP’s built-in adverts page."
                ),
                max_length=500,
                verbose_name="Click to earn redirect link",
            ),
        ),
    ]
