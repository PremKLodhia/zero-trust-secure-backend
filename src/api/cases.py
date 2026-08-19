from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from src.database import get_db
from src.models.case_file import CaseFile
from src.models.audit_log import AuditLog
from src.schemas.case_file import CaseFileCreate, CaseFileUpdate, CaseFileResponse
from src.authz.dependencies import get_current_user
from src.authz.client import opa_client

router = APIRouter(prefix="/cases", tags=["Case Files"])

def log_audit_event(
    db: Session,
    actor_id: str,
    actor_role: str,
    action: str,
    resource_id: Optional[str],
    client_ip: str,
    status: str = "SUCCESS",
    details: str = ""
):
    log_entry = AuditLog(
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        resource_type="case_file",
        resource_id=resource_id,
        client_ip=client_ip,
        status=status,
        details=details
    )
    db.add(log_entry)
    db.commit()

@router.post("", response_model=CaseFileResponse, status_code=status.HTTP_201_CREATED)
def create_case(
    case_in: CaseFileCreate,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Evaluate OPA authorization policy
    allowed = opa_client.evaluate_access(
        user=current_user,
        action="CREATE_CASE",
        resource_type="case_file"
    )
    if not allowed:
        log_audit_event(
            db=db,
            actor_id=current_user["id"],
            actor_role=current_user["role"],
            action="CREATE_CASE",
            resource_id=None,
            client_ip=client_ip,
            status="DENIED",
            details="Access denied by OPA policy"
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied by policy engine")

    case = CaseFile(
        title=case_in.title,
        classification=case_in.classification,
        assigned_analyst_id=case_in.assigned_analyst_id,
        encrypted_content=case_in.content,
        encrypted_pii_subject=case_in.pii_subject,
        metadata_json=case_in.metadata_json or "{}"
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    log_audit_event(
        db=db,
        actor_id=current_user["id"],
        actor_role=current_user["role"],
        action="CREATE_CASE",
        resource_id=case.id,
        client_ip=client_ip,
        status="SUCCESS",
        details=f"Created case: {case.title} ({case.classification})"
    )

    return case

@router.get("", response_model=List[CaseFileResponse])
def list_cases(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "127.0.0.1"

    allowed = opa_client.evaluate_access(
        user=current_user,
        action="LIST_CASES",
        resource_type="case_file"
    )
    if not allowed:
        log_audit_event(
            db=db,
            actor_id=current_user["id"],
            actor_role=current_user["role"],
            action="LIST_CASES",
            resource_id=None,
            client_ip=client_ip,
            status="DENIED",
            details="Access denied by OPA policy"
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied by policy engine")

    cases = db.query(CaseFile).all()

    log_audit_event(
        db=db,
        actor_id=current_user["id"],
        actor_role=current_user["role"],
        action="LIST_CASES",
        resource_id=None,
        client_ip=client_ip,
        status="SUCCESS",
        details=f"Listed {len(cases)} cases"
    )

    return cases

@router.get("/{case_id}", response_model=CaseFileResponse)
def get_case(
    case_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "127.0.0.1"

    case = db.query(CaseFile).filter(CaseFile.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case file not found")

    case_attributes = {
        "id": case.id,
        "classification": case.classification,
        "assigned_analyst_id": case.assigned_analyst_id
    }

    allowed = opa_client.evaluate_access(
        user=current_user,
        action="READ_CASE",
        resource_type="case_file",
        case=case_attributes
    )
    if not allowed:
        log_audit_event(
            db=db,
            actor_id=current_user["id"],
            actor_role=current_user["role"],
            action="READ_CASE",
            resource_id=case_id,
            client_ip=client_ip,
            status="DENIED",
            details=f"Denied read access for classification {case.classification}"
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied by policy engine")

    log_audit_event(
        db=db,
        actor_id=current_user["id"],
        actor_role=current_user["role"],
        action="READ_CASE",
        resource_id=case.id,
        client_ip=client_ip,
        status="SUCCESS",
        details=f"Read case {case.title}"
    )

    return case

@router.put("/{case_id}", response_model=CaseFileResponse)
def update_case(
    case_id: str,
    case_update: CaseFileUpdate,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "127.0.0.1"

    case = db.query(CaseFile).filter(CaseFile.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case file not found")

    case_attributes = {
        "id": case.id,
        "classification": case.classification,
        "assigned_analyst_id": case.assigned_analyst_id
    }

    allowed = opa_client.evaluate_access(
        user=current_user,
        action="UPDATE_CASE",
        resource_type="case_file",
        case=case_attributes
    )
    if not allowed:
        log_audit_event(
            db=db,
            actor_id=current_user["id"],
            actor_role=current_user["role"],
            action="UPDATE_CASE",
            resource_id=case_id,
            client_ip=client_ip,
            status="DENIED",
            details=f"Denied update access: user {current_user['id']} is not assigned analyst {case.assigned_analyst_id}"
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied by policy engine")

    if case_update.title is not None:
        case.title = case_update.title
    if case_update.classification is not None:
        case.classification = case_update.classification
    if case_update.assigned_analyst_id is not None:
        case.assigned_analyst_id = case_update.assigned_analyst_id
    if case_update.content is not None:
        case.encrypted_content = case_update.content
    if case_update.pii_subject is not None:
        case.encrypted_pii_subject = case_update.pii_subject
    if case_update.metadata_json is not None:
        case.metadata_json = case_update.metadata_json

    db.commit()
    db.refresh(case)

    log_audit_event(
        db=db,
        actor_id=current_user["id"],
        actor_role=current_user["role"],
        action="UPDATE_CASE",
        resource_id=case.id,
        client_ip=client_ip,
        status="SUCCESS",
        details=f"Updated case {case.id}"
    )

    return case
