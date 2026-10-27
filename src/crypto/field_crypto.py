import os
import base64
import binascii
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.config import settings
from src.crypto.errors import CryptoUnavailableError

class FieldCrypto:
    """
    Implements field-level encryption (CTL-08) for PII columns:
    - Encrypts specific sensitive attributes (e.g. subject identities, SSNs, names)
      so database dumps protect PII while allowing surrounding metadata to remain indexed and queryable.
    """

    @staticmethod
    def _key() -> bytes:
        """Loads the AES-256 key from FIELD_ENCRYPTION_KEY (base64). Fails closed if missing or invalid."""
        raw = settings.FIELD_ENCRYPTION_KEY
        if not raw:
            raise CryptoUnavailableError("FIELD_ENCRYPTION_KEY is not set; refusing to encrypt or decrypt PII fields")
        try:
            key = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CryptoUnavailableError("FIELD_ENCRYPTION_KEY is not valid base64") from exc
        if len(key) != 32:
            raise CryptoUnavailableError("FIELD_ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256)")
        return key

    @classmethod
    def encrypt_field(cls, plaintext: Optional[str]) -> Optional[str]:
        if plaintext is None:
            return None
        aesgcm = AESGCM(cls._key())
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return "enc:v1:" + base64.b64encode(nonce + ciphertext).decode("utf-8")

    @classmethod
    def decrypt_field(cls, ciphertext: Optional[str]) -> Optional[str]:
        if ciphertext is None or not ciphertext.startswith("enc:v1:"):
            return ciphertext
        raw = base64.b64decode(ciphertext.replace("enc:v1:", "").encode("utf-8"))
        nonce, ct = raw[:12], raw[12:]
        aesgcm = AESGCM(cls._key())
        return aesgcm.decrypt(nonce, ct, None).decode("utf-8")
