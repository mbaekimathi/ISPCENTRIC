"""Re-encrypt plaintext sensitive fields after enabling EncryptedCharField."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from ispcentric.encrypted_fields import encrypt_value, is_encrypted


class Command(BaseCommand):
    help = (
        "Walk sensitive credential fields and rewrite plaintext values as "
        "encrypted ciphertext (enc1:…). Safe to re-run."
    )

    def handle(self, *args, **options):
        total = 0
        total += self._encrypt_model(
            "core.MikroTikRouter",
            ["password", "wifi_password", "default_cpe_password", "vpn_private_key"],
        )
        total += self._encrypt_model(
            "core.WireGuardReservation",
            ["private_key"],
        )
        total += self._encrypt_model(
            "billing.Customer",
            ["pppoe_password", "cpe_password", "cpe_wifi_password"],
        )
        total += self._encrypt_model(
            "accounts.Organization",
            ["daraja_consumer_key", "daraja_consumer_secret", "daraja_passkey"],
        )
        total += self._encrypt_model(
            "accounts.PaymentGateway",
            ["consumer_key", "consumer_secret", "passkey"],
        )
        total += self._encrypt_model(
            "accounts.CommunicationSettings",
            [
                "sms_api_key",
                "email_host_password",
                "whatsapp_access_token",
                "whatsapp_api_key",
            ],
        )
        total += self._encrypt_model(
            "accounts.PlatformCommunicationSettings",
            [
                "sms_api_key",
                "email_host_password",
                "whatsapp_access_token",
                "whatsapp_api_key",
            ],
        )
        self.stdout.write(self.style.SUCCESS(f"Encrypted or verified {total} field values."))

    def _encrypt_model(self, label: str, fields: list[str]) -> int:
        from django.apps import apps

        app_label, model_name = label.split(".")
        model = apps.get_model(app_label, model_name)
        count = 0
        # Use .iterator and update via queryset.update to avoid double-encrypt
        # from model save (EncryptedCharField get_prep_value).
        for obj in model.objects.all().iterator(chunk_size=200):
            updates = {}
            for name in fields:
                # Read via ORM attribute (already decrypted by from_db_value).
                # Check raw DB value for already-encrypted prefix.
                raw = model.objects.filter(pk=obj.pk).values_list(name, flat=True).first()
                if raw is None or raw == "":
                    continue
                if is_encrypted(raw):
                    continue
                # Plaintext in DB — encrypt and write once.
                updates[name] = encrypt_value(raw)
            if updates:
                model.objects.filter(pk=obj.pk).update(**updates)
                count += len(updates)
        if count:
            self.stdout.write(f"  {label}: {count} values encrypted")
        else:
            self.stdout.write(f"  {label}: already encrypted / empty")
        return count
