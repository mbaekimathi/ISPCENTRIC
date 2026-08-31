from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0020_security_hardening_encryption_audit"),
    ]

    operations = [
        migrations.AddField(
            model_name="wireguardreservation",
            name="lan_address",
            field=models.GenericIPAddressField(
                blank=True,
                help_text="Unique LAN gateway the Winbox script assigns on the MikroTik.",
                null=True,
                protocol="IPv4",
                verbose_name="Planned LAN IP",
            ),
        ),
    ]
