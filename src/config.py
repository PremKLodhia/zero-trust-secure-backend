from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

# Known insecure JWT secrets: the code default and the .env.example placeholder.
DEFAULT_JWT_SECRET_KEY = "insecure_dev_secret_key_needs_replacement_in_prod_12345"
INSECURE_JWT_SECRET_KEYS = {
    DEFAULT_JWT_SECRET_KEY,
    "change_this_in_production_super_secret_key_minimum_32_bytes_long",
}

class Settings(BaseSettings):
    APP_NAME: str = "Zero-Trust Secure Evidence Exchange"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    # Explicit opt-in for local development shortcuts (local KEK fallback, default JWT secret).
    DEV_MODE: bool = False
    DATABASE_URL: str = "sqlite:///./test.db"
    
    # Auth & Tokens
    JWT_SECRET_KEY: str = DEFAULT_JWT_SECRET_KEY
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # WebAuthn
    WEBAUTHN_RP_ID: str = "localhost"
    WEBAUTHN_RP_NAME: str = "ZeroTrustEvidenceExchange"
    WEBAUTHN_ORIGIN: str = "http://localhost:8000"
    
    # OPA
    OPA_URL: str = "http://localhost:8181/v1/data/case_access/allow"
    OPA_TIMEOUT_SECONDS: float = 2.0
    
    # Vault
    VAULT_ADDR: str = "http://localhost:8200"
    VAULT_TOKEN: str = "root"
    VAULT_TRANSIT_KEY: str = "case-dek-kek"

    # Field-level PII encryption: base64-encoded 32-byte AES-256 key. Required; never hard-coded.
    FIELD_ENCRYPTION_KEY: str = ""
    
    # Anomaly Detection
    ANOMALY_CONTAMINATION_RATE: float = 0.05

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()


def validate_startup_settings(current: Settings = None) -> None:
    """Refuse to start with a known insecure JWT secret unless DEV_MODE is explicitly enabled."""
    current = current or settings
    if current.JWT_SECRET_KEY in INSECURE_JWT_SECRET_KEYS and not current.DEV_MODE:
        raise RuntimeError(
            "Refusing to start: JWT_SECRET_KEY is a default/placeholder value. "
            "Set a strong secret, or set DEV_MODE=true for local development only."
        )
