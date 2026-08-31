"""
Transparent Fernet encryption for sensitive CharField values at rest.

Values are stored with an ``enc1:`` prefix. Legacy plaintext rows keep working
until the next save (or ``encrypt_sensitive_fields`` management command).

Key resolution (first match wins):
1. ``FIELD_ENCRYPTION_KEY`` — Fernet key or any passphrase
2. Derived from ``DJANGO_SECRET_KEY`` (stable hash) so hosted installs encrypt
   without an extra env var

Rotating ``SECRET_KEY`` without a dedicated ``FIELD_ENCRYPTION_KEY`` will make
existing ciphertext unreadable — set ``FIELD_ENCRYPTION_KEY`` in production.
"""

from __future__ import annotations

import base64
import hashlib
import logging

from django.conf import settings
from django.db import models

logger = logging.getLogger(__name__)

PREFIX = "enc1:"


def _fernet():
    from cryptography.fernet import Fernet

    raw = (getattr(settings, "FIELD_ENCRYPTION_KEY", "") or "").strip()
    if raw:
        if len(raw) == 44:
            try:
                return Fernet(raw.encode("utf-8"))
            except (ValueError, TypeError, Exception):
                pass
        digest = hashlib.sha256(
            b"ispcentric-field-enc-v1:" + raw.encode("utf-8")
        ).digest()
        return Fernet(base64.urlsafe_b64encode(digest))

    secret = (getattr(settings, "SECRET_KEY", "") or "").encode("utf-8")
    if not secret:
        return None
    # Prefer a dedicated key in production; derived key still beats plaintext.
    digest = hashlib.sha256(b"ispcentric-field-enc-v1:" + secret).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_value(value: str | None) -> str:
    if value is None or value == "":
        return ""
    text = str(value)
    if text.startswith(PREFIX):
        return text
    f = _fernet()
    if f is None:
        return text
    token = f.encrypt(text.encode("utf-8")).decode("ascii")
    return PREFIX + token


def decrypt_value(value: str | None) -> str:
    if value is None or value == "":
        return ""
    text = str(value)
    if not text.startswith(PREFIX):
        return text
    f = _fernet()
    if f is None:
        logger.error("Encrypted DB value found but no field encryption key is available")
        return ""
    from cryptography.fernet import InvalidToken

    try:
        return f.decrypt(text[len(PREFIX) :].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError):
        logger.error("Failed to decrypt a sensitive DB field (wrong key?)")
        return ""


def is_encrypted(value: str | None) -> bool:
    return bool(value) and str(value).startswith(PREFIX)


class EncryptedCharField(models.CharField):
    """CharField that encrypts on write and decrypts on read."""

    description = "Encrypted character field"

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return decrypt_value(value)

    def to_python(self, value):
        if value is None:
            return value
        if isinstance(value, str) and value.startswith(PREFIX):
            return decrypt_value(value)
        return value

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if value is None or value == "":
            return ""
        return encrypt_value(str(value))
