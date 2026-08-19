from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from typing import List
from src.database import get_db
from src.models.user import User
from src.models.audit_log import AuditLog
from src.schemas.user import UserCreate, UserResponse

router = APIRouter(prefix="/users", tags=["Users"])

@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user_in: UserCreate, request: Request, db: Session = Depends(get_db)):
    actor_id = request.headers.get("X-Actor-ID", "system_dev")
    actor_role = request.headers.get("X-Actor-Role", "admin")
    client_ip = request.client.host if request.client else "127.0.0.1"

    existing = db.query(User).filter((User.username == user_in.username) | (User.email == user_in.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already registered")

    user = User(
        username=user_in.username,
        email=user_in.email,
        role=user_in.role
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    audit = AuditLog(
        actor_id=actor_id,
        actor_role=actor_role,
        action="CREATE_USER",
        resource_type="user",
        resource_id=user.id,
        client_ip=client_ip,
        status="SUCCESS",
        details=f"Created user {user.username} with role {user.role}"
    )
    db.add(audit)
    db.commit()

    return user

@router.get("", response_model=List[UserResponse])
def list_users(db: Session = Depends(get_db)):
    return db.query(User).all()

@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
