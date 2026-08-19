from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from typing import List, Optional
from src.database import get_db
from src.models.case_file import CaseFile
from src.models.audit_log import AuditLog
from src.schemas.case_file import CaseFileCreate, CaseFileUpdate, CaseFileResponse

router = APIRouter(prefix="/cases", tags=["Case Files"])

def log_audit_event(db: Session, actor_id: str, actor_role: str, action: str, resource_id: Optional[str], client_ip: str, status: str = "SUCCESS", details: str = ""):
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
def create_case(case_in: CaseFileCreate, request: Request, db: Session = Depends(get_db)):
    # Phase 1 note: Auth is not yet enforced. Actor is extracted from header or fallback.
    actor_id = request.headers.get("X-Actor-ID", "system_dev")
    actor_role = request.headers.get("X-Actor-Role", "analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    case = CaseFile(
        title=case_in.title,
        classification=case_in.classification,
        assigned_analyst_id=case_in.assigned_analyst_id,
        encrypted_content=case_in.content,  # Will be encrypted via Vault in Phase 5
        encrypted_pii_subject=case_in.pii_subject,
        metadata_json=case_in.metadata_json or "{}"
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    log_audit_event(
        db=db,
        actor_id=actor_id,
        actor_role=actor_role,
        action="CREATE_CASE",
        resource_id=case.id,
        client_ip=client_ip,
        status="SUCCESS",
        details=f"Created case: {case.title} with classification {case.classification}"
    )

    return case

@router.get("", response_model=List[CaseFileResponse])
def list_cases(request: Request, db: Session = Depends(get_db)):
    actor_id = request.headers.get("X-Actor-ID", "system_dev")
    actor_role = request.headers.get("X-Actor-Role", "analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    cases = db.query(CaseFile).all()

    log_audit_event(
        db=db,
        actor_id=actor_id,
        actor_role=actor_role,
        action="LIST_CASES",
        resource_id=None,
        client_ip=client_ip,
        status="SUCCESS",
        details=f"Listed {len(cases)} cases"
    )

    return cases

@router.get("/{case_id}", response_model=CaseFileResponse)
def get_case(case_id: str, request: Request, db: Session = Depends(get_db)):
    actor_id = request.headers.get("X-Actor-ID", "system_dev")
    actor_role = request.headers.get("X-Actor-Role", "analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    case = db.query(CaseFile).filter(CaseFile.id == case_id).first()
    if not case:
        log_audit_event(
            db=db,
            actor_id=actor_id,
            actor_role=actor_role,
            action="GET_CASE",
            resource_id=case_id,
            client_ip=client_ip,
            status="FAILED",
            details="Case not found"
        )
        raise HTTPException(status_code=404, detail="Case file not found")

    log_audit_event(
        db=db,
        actor_id=actor_id,
        actor_role=actor_role,
        action="GET_CASE",
        resource_id=case.id,
        client_ip=client_ip,
        status="SUCCESS",
        details=f"Retrieved case {case.title}"
    )

    return case

@router.put("/{case_id}", response_model=CaseFileResponse)
def update_case(case_id: str, case_update: CaseFileUpdate, request: Request, db: Session = Depends(get_db)):
    actor_id = request.headers.get("X-Actor-ID", "system_dev")
    actor_role = request.headers.get("X-Actor-Role", "analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    case = db.query(CaseFile).filter(CaseFile.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case file not found")

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
        actor_id=actor_id,
        actor_role=actor_role,
        action="UPDATE_CASE",
        resource_id=case.id,
        client_ip=client_ip,
        status="SUCCESS",
        details=f"Updated case {case.id}"
    )

    return case
