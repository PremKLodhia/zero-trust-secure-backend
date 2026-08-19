from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from src.database import get_db
from src.models.audit_log import AuditLog
from src.schemas.audit import AuditLogResponse

router = APIRouter(prefix="/audit-logs", tags=["Audit Log"])

@router.get("", response_model=List[AuditLogResponse])
def get_audit_logs(
    resource_type: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    query = db.query(AuditLog)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if action:
        query = query.filter(AuditLog.action == action)
    return query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
