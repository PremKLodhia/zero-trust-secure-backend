import os
import base64
import logging
import hvac
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.config import settings
from src.crypto.errors import CryptoUnavailableError

logger = logging.getLogger("crypto")

LOCAL_PREFIX = "vault:v1:local:"


class VaultTransitClient:
    """Wraps data keys with Vault Transit.

    Fail closed: if Vault is unreachable or errors, wrapping and unwrapping raise
    CryptoUnavailableError. The local KEK fallback is used only when DEV_MODE=true,
    and locally wrapped keys are refused outside DEV_MODE.
    """

    def __init__(
        self,
        vault_addr: Optional[str] = None,
        token: Optional[str] = None,
        transit_key: Optional[str] = None,
        dev_mode: Optional[bool] = None
    ):
        self.vault_addr = vault_addr or settings.VAULT_ADDR
        self.token = token or settings.VAULT_TOKEN
        self.transit_key = transit_key or settings.VAULT_TRANSIT_KEY
        self._dev_mode = dev_mode
        # Development-only KEK; usable only when DEV_MODE is true.
        self._local_master_key = b"LOCAL_DEV_MASTER_KEK_32_BYTES_K!"
        self._client_cache = None

    @property
    def dev_mode(self) -> bool:
        return settings.DEV_MODE if self._dev_mode is None else self._dev_mode

    def _get_hvac_client(self):
        # Only a working client is cached, so Vault is retried after an outage.
        if self._client_cache is not None:
            return self._client_cache
        try:
            client = hvac.Client(url=self.vault_addr, token=self.token, timeout=0.5)
            if client.is_authenticated():
                self._client_cache = client
        except Exception as e:
            logger.warning(f"Vault unreachable at {self.vault_addr}: {e}")
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
                if not self.dev_mode:
                    logger.error(f"Vault wrap failed: {e}")
                    raise CryptoUnavailableError("Vault Transit wrap failed; refusing to encrypt") from e
                logger.warning(f"Vault wrap failed, DEV_MODE local KEK fallback: {e}")
        elif not self.dev_mode:
            raise CryptoUnavailableError("Vault is unavailable; refusing to encrypt (set DEV_MODE=true for local development)")

        # Local KEK fallback: DEV_MODE only
        aesgcm = AESGCM(self._local_master_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext_dek, None)
        return LOCAL_PREFIX + base64.b64encode(nonce + ciphertext).decode("utf-8")

    def unwrap_key(self, wrapped_dek: str) -> bytes:
        """Unwraps (decrypts) a Data Encryption Key using Vault Transit KEK."""
        if wrapped_dek.startswith(LOCAL_PREFIX):
            if not self.dev_mode:
                raise CryptoUnavailableError("Key was wrapped with the development KEK; refusing to decrypt outside DEV_MODE")
            raw = base64.b64decode(wrapped_dek[len(LOCAL_PREFIX):])
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
                raise CryptoUnavailableError("Failed to unwrap DEK via Vault Transit") from e

        raise CryptoUnavailableError("Vault is unavailable; refusing to decrypt")

vault_client = VaultTransitClient()
