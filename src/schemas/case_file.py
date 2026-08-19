from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class CaseFileCreate(BaseModel):
    title: str
    classification: str = "TLP:AMBER"
    assigned_analyst_id: str
    content: str
    pii_subject: Optional[str] = None
    metadata_json: Optional[str] = "{}"

class CaseFileUpdate(BaseModel):
    title: Optional[str] = None
    classification: Optional[str] = None
    assigned_analyst_id: Optional[str] = None
    content: Optional[str] = None
    pii_subject: Optional[str] = None
    metadata_json: Optional[str] = None

class CaseFileResponse(BaseModel):
    id: str
    title: str
    classification: str
    assigned_analyst_id: str
    encrypted_content: str
    encrypted_pii_subject: Optional[str] = None
    wrapped_dek: Optional[str] = None
    metadata_json: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)
