from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0055_customer_perf_indexes"),
    ]

    operations = [
        migrations.AddField(
            model_name="billingplan",
            name="download_guaranteed_mbps",
            field=models.PositiveIntegerField(
                default=0,
                help_text=(
                    "Optional CIR reserved on MikroTik when the shared uplink is busy "
                    "(0 = best-effort only). Cannot exceed download speed."
                ),
                verbose_name="Guaranteed download (Mbps)",
            ),
        ),
        migrations.AddField(
            model_name="billingplan",
            name="upload_guaranteed_mbps",
            field=models.PositiveIntegerField(
                default=0,
                help_text=(
                    "Optional CIR reserved on MikroTik when the shared uplink is busy "
                    "(0 = best-effort only). Cannot exceed upload speed."
                ),
                verbose_name="Guaranteed upload (Mbps)",
            ),
        ),
    ]
