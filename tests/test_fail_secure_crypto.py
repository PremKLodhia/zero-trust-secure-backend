import base64
import os
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.config import DEFAULT_JWT_SECRET_KEY, settings, validate_startup_settings
from src.crypto.errors import CryptoUnavailableError
from src.crypto.field_crypto import FieldCrypto
from src.crypto.vault_client import LOCAL_PREFIX, VaultTransitClient

UNREACHABLE_VAULT = "http://127.0.0.1:1"  # nothing listens on port 1
DEK = os.urandom(32)


# --- Vault KEK: fail closed unless DEV_MODE -----------------------------------

def test_production_mode_refuses_to_wrap_without_vault():
    client = VaultTransitClient(vault_addr=UNREACHABLE_VAULT, dev_mode=False)
    with pytest.raises(CryptoUnavailableError):
        client.wrap_key(DEK)


def test_production_mode_refuses_locally_wrapped_keys():
    dev = VaultTransitClient(vault_addr=UNREACHABLE_VAULT, dev_mode=True)
    wrapped = dev.wrap_key(DEK)
    prod = VaultTransitClient(vault_addr=UNREACHABLE_VAULT, dev_mode=False)
    with pytest.raises(CryptoUnavailableError):
        prod.unwrap_key(wrapped)


def test_production_mode_does_not_fall_back_when_vault_errors():
    client = VaultTransitClient(vault_addr=UNREACHABLE_VAULT, dev_mode=False)
    broken = MagicMock()
    broken.secrets.transit.encrypt_data.side_effect = RuntimeError("transit down")
    client._client_cache = broken
    with pytest.raises(CryptoUnavailableError):
        client.wrap_key(DEK)


def test_dev_mode_uses_local_fallback():
    client = VaultTransitClient(vault_addr=UNREACHABLE_VAULT, dev_mode=True)
    wrapped = client.wrap_key(DEK)
    assert wrapped.startswith(LOCAL_PREFIX)
    assert client.unwrap_key(wrapped) == DEK


def test_dev_mode_follows_settings(monkeypatch):
    client = VaultTransitClient(vault_addr=UNREACHABLE_VAULT)
    monkeypatch.setattr(settings, "DEV_MODE", False)
    with pytest.raises(CryptoUnavailableError):
        client.wrap_key(DEK)
    monkeypatch.setattr(settings, "DEV_MODE", True)
    assert client.wrap_key(DEK).startswith(LOCAL_PREFIX)


# --- Field key: loaded from settings, never from source ----------------------

def test_field_crypto_refuses_without_key(monkeypatch):
    ciphertext = FieldCrypto.encrypt_field("SYNTHETIC_PII")
    monkeypatch.setattr(settings, "FIELD_ENCRYPTION_KEY", "")
    with pytest.raises(CryptoUnavailableError):
        FieldCrypto.encrypt_field("SYNTHETIC_PII")
    with pytest.raises(CryptoUnavailableError):
        FieldCrypto.decrypt_field(ciphertext)


def test_field_crypto_rejects_wrong_length_key(monkeypatch):
    monkeypatch.setattr(settings, "FIELD_ENCRYPTION_KEY", base64.b64encode(os.urandom(16)).decode())
    with pytest.raises(CryptoUnavailableError):
        FieldCrypto.encrypt_field("SYNTHETIC_PII")


def test_field_crypto_uses_configured_key(monkeypatch):
    monkeypatch.setattr(settings, "FIELD_ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode())
    ciphertext = FieldCrypto.encrypt_field("SYNTHETIC_PII")
    assert FieldCrypto.decrypt_field(ciphertext) == "SYNTHETIC_PII"

    # A different key cannot read it, so the key really comes from settings.
    monkeypatch.setattr(settings, "FIELD_ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode())
    with pytest.raises(Exception):
        FieldCrypto.decrypt_field(ciphertext)


# --- Startup: default JWT secret ----------------------------------------------

def test_startup_refuses_default_jwt_secret_outside_dev_mode(monkeypatch):
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", DEFAULT_JWT_SECRET_KEY)
    monkeypatch.setattr(settings, "DEV_MODE", False)
    with pytest.raises(RuntimeError):
        validate_startup_settings()
    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass


def test_startup_refuses_env_example_placeholder(monkeypatch):
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", "change_this_in_production_super_secret_key_minimum_32_bytes_long")
    monkeypatch.setattr(settings, "DEV_MODE", False)
    with pytest.raises(RuntimeError):
        validate_startup_settings()


def test_startup_allows_default_secret_in_dev_mode(monkeypatch):
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", DEFAULT_JWT_SECRET_KEY)
    monkeypatch.setattr(settings, "DEV_MODE", True)
    validate_startup_settings()


def test_startup_allows_real_secret(monkeypatch):
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", "a-real-secret-" + os.urandom(16).hex())
    monkeypatch.setattr(settings, "DEV_MODE", False)
    validate_startup_settings()
