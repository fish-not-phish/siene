"""
Field-level encryption for sensitive registry credentials.

Uses Fernet (AES-128-CBC + HMAC-SHA256) with a key derived from
DJANGO_SECRET_KEY via HKDF-SHA256. This means no extra env var is needed —
the same key rotation story as Django's SECRET_KEY applies.

Usage:
    from registry.crypto import encrypt_field, decrypt_field

    stored = encrypt_field("my-secret-password")   # store this in DB
    plain  = decrypt_field(stored)                 # use this in code

encrypt_field("")  → ""   (empty string round-trips as empty)
decrypt_field("")  → ""
decrypt_field(plaintext_value_without_prefix) → plaintext_value_without_prefix
  (backwards-compat: values that are not Fernet tokens are returned as-is)
"""

from __future__ import annotations
import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


_FERNET_PREFIX = b"fernet1:"   # sentinel so we can detect encrypted values


def _get_fernet() -> Fernet:
    """Return a Fernet instance keyed from DJANGO_SECRET_KEY."""
    secret = os.environ.get("DJANGO_SECRET_KEY", os.environ.get("SECRET_KEY", ""))
    if not secret:
        # Fall back to a fixed dev key so tests don't explode — never used in prod
        secret = "django-insecure-dev-key-not-for-production"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"siene-field-encryption-v1",
        info=b"registry-credential",
    )
    raw_key = hkdf.derive(secret.encode())
    fernet_key = base64.urlsafe_b64encode(raw_key)
    return Fernet(fernet_key)


def encrypt_field(plaintext: str) -> str:
    """Encrypt a plaintext string. Returns a prefixed base64 token."""
    if not plaintext:
        return plaintext
    f = _get_fernet()
    token = f.encrypt(plaintext.encode())
    return (_FERNET_PREFIX + token).decode()


def decrypt_field(stored: str) -> str:
    """
    Decrypt a stored value. Handles three cases:
      - Empty string → empty string
      - Prefixed Fernet token → decrypt and return plaintext
      - Anything else → return as-is (backwards compat for plaintext rows)
    """
    if not stored:
        return stored
    b = stored.encode()
    if not b.startswith(_FERNET_PREFIX):
        # Plaintext legacy value — return unchanged
        return stored
    f = _get_fernet()
    try:
        return f.decrypt(b[len(_FERNET_PREFIX):]).decode()
    except InvalidToken:
        # Key mismatch or corrupt data — return as-is so the app doesn't crash
        return stored
