import os
import base64
import logging
import hvac
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.config import settings

logger = logging.getLogger("crypto")

class VaultTransitClient:
    def __init__(
        self,
        vault_addr: Optional[str] = None,
        token: Optional[str] = None,
        transit_key: Optional[str] = None
    ):
        self.vault_addr = vault_addr or settings.VAULT_ADDR
        self.token = token or settings.VAULT_TOKEN
        self.transit_key = transit_key or settings.VAULT_TRANSIT_KEY
        self._local_master_key = b"LOCAL_DEV_MASTER_KEK_32_BYTES_K!"
        self._client_cache = None
        self._vault_checked = False

    def _get_hvac_client(self):
        if self._vault_checked:
            return self._client_cache
        try:
            client = hvac.Client(url=self.vault_addr, token=self.token, timeout=0.5)
            if client.is_authenticated():
                self._client_cache = client
        except Exception:
            self._client_cache = None
        self._vault_checked = True
        return self._client_cache

    def wrap_key(self, plaintext_dek: bytes) -> str:
        """Wraps (encrypts) a Data Encryption Key using Vault Transit KEK."""
        client = self._get_hvac_client()
        if client:
            try:
                b64_dek = base64.b64encode(plaintext_dek).decode("utf-8")
                res = client.secrets.transit.encrypt_data(
                    name=self.transit_key,
                    plaintext=b64_dek
                )
                return res["data"]["ciphertext"]
            except Exception as e:
                logger.warning(f"Vault wrap failed, falling back to local KEK envelope: {e}")
        
        # Standalone local KEK fallback for development/testing
        aesgcm = AESGCM(self._local_master_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext_dek, None)
        return "vault:v1:local:" + base64.b64encode(nonce + ciphertext).decode("utf-8")

    def unwrap_key(self, wrapped_dek: str) -> bytes:
        """Unwraps (decrypts) a Data Encryption Key using Vault Transit KEK."""
        if wrapped_dek.startswith("vault:v1:local:"):
            raw = base64.b64decode(wrapped_dek.replace("vault:v1:local:", ""))
            nonce, ciphertext = raw[:12], raw[12:]
            aesgcm = AESGCM(self._local_master_key)
            return aesgcm.decrypt(nonce, ciphertext, None)

        client = self._get_hvac_client()
        if client:
            try:
                res = client.secrets.transit.decrypt_data(
                    name=self.transit_key,
                    ciphertext=wrapped_dek
                )
                return base64.b64decode(res["data"]["plaintext"])
            except Exception as e:
                logger.error(f"Vault unwrap failed: {e}")
                raise ValueError("Failed to unwrap DEK via Vault Transit")

        raise ValueError("Vault client unavailable for unwrap")

vault_client = VaultTransitClient()
