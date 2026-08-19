from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    APP_NAME: str = "Zero-Trust Secure Evidence Exchange"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    DATABASE_URL: str = "sqlite:///./test.db"
    
    # Auth & Tokens
    JWT_SECRET_KEY: str = "insecure_dev_secret_key_needs_replacement_in_prod_12345"
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
    
    # Anomaly Detection
    ANOMALY_CONTAMINATION_RATE: float = 0.05

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
