from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0033_alter_mikrotikonboardingsession_management_host_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="mikrotikrouter",
            name="uplink_account_no",
            field=models.CharField(
                blank=True,
                default="",
                help_text=(
                    "Provider / ISP account number used by this MikroTik — "
                    "stored for staff reference on the usage page."
                ),
                max_length=64,
                verbose_name="Uplink account no.",
            ),
        ),
    ]
