import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime
from src.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    role = Column(String(32), nullable=False, default="analyst")  # admin, analyst, auditor
    is_active = Column(Boolean, default=True, nullable=False)
    webauthn_credential_id = Column(String(255), nullable=True)
    webauthn_public_key = Column(String(1024), nullable=True)
    webauthn_sign_count = Column(String(64), nullable=True, default="0")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
