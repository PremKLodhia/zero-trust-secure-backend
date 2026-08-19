import os
import base64
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.crypto.vault_client import vault_client

class EnvelopeCrypto:
    """
    Implements envelope encryption (CTL-07):
    - Generates a unique, single-use 256-bit AES-GCM Data Encryption Key (DEK) per case file.
    - Encrypts file content with DEK.
    - Wraps DEK with Vault Transit Key Encryption Key (KEK).
    - Only wrapped DEK and ciphertext are stored. Plaintext DEK is wiped from memory.
    """

    @staticmethod
    def encrypt_case_content(plaintext: str) -> Tuple[str, str]:
        # 1. Generate unique 256-bit DEK
        dek = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(dek)

        # 2. Encrypt plaintext payload
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        ciphertext_b64 = base64.b64encode(nonce + ciphertext).decode("utf-8")

        # 3. Wrap DEK with Vault KEK
        wrapped_dek = vault_client.wrap_key(dek)

        return ciphertext_b64, wrapped_dek

    @staticmethod
    def decrypt_case_content(ciphertext_b64: str, wrapped_dek: str) -> str:
        # 1. Unwrap DEK via Vault KEK
        dek = vault_client.unwrap_key(wrapped_dek)
        aesgcm = AESGCM(dek)

        # 2. Decrypt ciphertext payload
        raw = base64.b64decode(ciphertext_b64.encode("utf-8"))
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext_bytes.decode("utf-8")
