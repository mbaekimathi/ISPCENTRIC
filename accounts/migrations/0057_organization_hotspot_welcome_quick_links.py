from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0056_alter_adverts_enabled_help_text"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="hotspot_welcome_link1_label",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Label for the first website shortcut on the success page.",
                max_length=40,
                verbose_name="Quick link 1 label",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_welcome_link1_url",
            field=models.URLField(
                blank=True,
                default="",
                help_text="First website page shown under the success-page button.",
                max_length=500,
                verbose_name="Quick link 1 URL",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_welcome_link2_label",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Label for the second website shortcut on the success page.",
                max_length=40,
                verbose_name="Quick link 2 label",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="hotspot_welcome_link2_url",
            field=models.URLField(
                blank=True,
                default="",
                help_text="Second website page shown under the success-page button.",
                max_length=500,
                verbose_name="Quick link 2 URL",
            ),
        ),
    ]
