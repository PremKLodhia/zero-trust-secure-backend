from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class AuditLogResponse(BaseModel):
    id: str
    timestamp: datetime
    actor_id: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    client_ip: Optional[str] = None
    status: str
    details: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)
