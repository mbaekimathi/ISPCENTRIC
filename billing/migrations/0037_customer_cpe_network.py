from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0036_access_voucher"),
    ]

    operations = [
        migrations.AddField(
            model_name="customer",
            name="cpe_ip",
            field=models.CharField(
                blank=True,
                help_text="Fixed LAN IP for static clients (used for remote router access).",
                max_length=45,
                verbose_name="CPE IP address",
            ),
        ),
        migrations.AddField(
            model_name="customer",
            name="cpe_mac",
            field=models.CharField(
                blank=True,
                help_text="Router MAC for dynamic DHCP clients — IP is resolved from the NAS lease.",
                max_length=17,
                verbose_name="CPE MAC address",
            ),
        ),
    ]
