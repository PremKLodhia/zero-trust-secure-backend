import os
import base64
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class FieldCrypto:
    """
    Implements field-level encryption (CTL-08) for PII columns:
    - Encrypts specific sensitive attributes (e.g. subject identities, SSNs, names)
      so database dumps protect PII while allowing surrounding metadata to remain indexed and queryable.
    """
    # Exactly 32 bytes (256-bit key) for AESGCM
    _FIELD_KEY = b"FIELD_LEVEL_PII_KEY_32_BYTES_KEY"

    @classmethod
    def encrypt_field(cls, plaintext: Optional[str]) -> Optional[str]:
        if plaintext is None:
            return None
        aesgcm = AESGCM(cls._FIELD_KEY)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return "enc:v1:" + base64.b64encode(nonce + ciphertext).decode("utf-8")

    @classmethod
    def decrypt_field(cls, ciphertext: Optional[str]) -> Optional[str]:
        if ciphertext is None or not ciphertext.startswith("enc:v1:"):
            return ciphertext
        raw = base64.b64decode(ciphertext.replace("enc:v1:", "").encode("utf-8"))
        nonce, ct = raw[:12], raw[12:]
        aesgcm = AESGCM(cls._FIELD_KEY)
        return aesgcm.decrypt(nonce, ct, None).decode("utf-8")
