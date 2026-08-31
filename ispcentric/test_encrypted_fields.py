"""Tests for at-rest encryption of sensitive CharFields."""

from django.test import SimpleTestCase, override_settings

from ispcentric.encrypted_fields import (
    PREFIX,
    decrypt_value,
    encrypt_value,
    is_encrypted,
)


@override_settings(
    SECRET_KEY="test-secret-key-for-field-encryption-unit-tests-only",
    FIELD_ENCRYPTION_KEY="unit-test-field-encryption-passphrase",
)
class EncryptedFieldsTests(SimpleTestCase):
    def test_round_trip(self):
        plain = "super-secret-router-password"
        cipher = encrypt_value(plain)
        self.assertTrue(cipher.startswith(PREFIX))
        self.assertNotEqual(cipher, plain)
        self.assertEqual(decrypt_value(cipher), plain)

    def test_plaintext_passthrough_on_decrypt(self):
        self.assertEqual(decrypt_value("already-plain"), "already-plain")

    def test_double_encrypt_is_idempotent(self):
        once = encrypt_value("abc")
        twice = encrypt_value(once)
        self.assertEqual(once, twice)
        self.assertTrue(is_encrypted(twice))

    def test_empty(self):
        self.assertEqual(encrypt_value(""), "")
        self.assertEqual(decrypt_value(""), "")
