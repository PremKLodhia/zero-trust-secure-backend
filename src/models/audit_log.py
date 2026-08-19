import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text
from src.database import Base

class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    actor_id = Column(String(64), nullable=False, index=True)
    actor_role = Column(String(32), nullable=False)
    action = Column(String(64), nullable=False, index=True)  # CREATE_CASE, READ_CASE, UPDATE_CASE, LOGIN, etc.
    resource_type = Column(String(64), nullable=False)       # case_file, user, auth
    resource_id = Column(String(64), nullable=True)
    client_ip = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default="SUCCESS")  # SUCCESS, DENIED, FAILED
    details = Column(Text, nullable=True)
