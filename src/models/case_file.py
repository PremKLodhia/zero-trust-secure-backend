import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text
from src.database import Base

class CaseFile(Base):
    __tablename__ = "case_files"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    classification = Column(String(32), nullable=False, default="TLP:AMBER")  # TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:RED
    assigned_analyst_id = Column(String(36), nullable=False, index=True)
    encrypted_content = Column(Text, nullable=False)  # Base64 ciphertext or encrypted payload
    encrypted_pii_subject = Column(Text, nullable=True)  # Field-level encrypted PII identifier
    wrapped_dek = Column(Text, nullable=True)  # Envelope encryption: Vault-wrapped DEK
    metadata_json = Column(Text, nullable=True, default="{}")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
