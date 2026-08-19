from fastapi import APIRouter, Depends, HTTPException, Request, status, Body
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, Any, Optional
from src.database import get_db
from src.models.user import User
from src.models.audit_log import AuditLog
from src.auth.tokens.service import create_access_token, issue_refresh_token_family, rotate_refresh_token
from src.auth.webauthn.service import (
    get_registration_options,
    verify_registration,
    get_authentication_options,
    verify_authentication,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

class WebAuthnRegisterRequest(BaseModel):
    user_id: str

class WebAuthnVerifyRegisterRequest(BaseModel):
    user_id: str
    credential_json: str

class WebAuthnLoginRequest(BaseModel):
    username: str

class WebAuthnVerifyLoginRequest(BaseModel):
    username: str
    credential_json: str

class TokenRefreshRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

@router.post("/webauthn/register/options")
def register_options(payload: WebAuthnRegisterRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == payload.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    options_json = get_registration_options(user.id, user.username, user.username)
    return {"options": options_json}

@router.post("/webauthn/register/verify")
def register_verify(payload: WebAuthnVerifyRegisterRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == payload.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        cred_id, pub_key, sign_count = verify_registration(user.id, payload.credential_json)
        user.webauthn_credential_id = cred_id
        user.webauthn_public_key = pub_key
        user.webauthn_sign_count = str(sign_count)
        db.commit()
        return {"status": "registered", "credential_id": cred_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration verification failed: {str(e)}")

@router.post("/webauthn/login/options")
def login_options(payload: WebAuthnLoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not user.webauthn_credential_id:
        raise HTTPException(status_code=404, detail="User or WebAuthn credential not found")
    options_json = get_authentication_options(user.id, user.webauthn_credential_id)
    return {"options": options_json}

@router.post("/webauthn/login/verify", response_model=TokenResponse)
def login_verify(payload: WebAuthnVerifyLoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not user.webauthn_credential_id or not user.webauthn_public_key:
        raise HTTPException(status_code=404, detail="User credential record not found")

    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        stored_sign_count = int(user.webauthn_sign_count or 0)
        new_sign_count = verify_authentication(
            user.id,
            user.webauthn_credential_id,
            user.webauthn_public_key,
            stored_sign_count,
            payload.credential_json
        )
        user.webauthn_sign_count = str(new_sign_count)
        db.commit()

        # Generate tokens
        access_token = create_access_token(user.id, user.role)
        refresh_token = issue_refresh_token_family(db, user.id)

        # Audit log login
        audit = AuditLog(
            actor_id=user.id,
            actor_role=user.role,
            action="WEBAUTHN_LOGIN_SUCCESS",
            resource_type="auth",
            resource_id=user.id,
            client_ip=client_ip,
            status="SUCCESS",
            details="WebAuthn biometric/passkey verification successful"
        )
        db.add(audit)
        db.commit()

        return TokenResponse(access_token=access_token, refresh_token=refresh_token)
    except Exception as e:
        audit = AuditLog(
            actor_id=user.id if user else "unknown",
            actor_role="unknown",
            action="WEBAUTHN_LOGIN_FAILED",
            resource_type="auth",
            resource_id=None,
            client_ip=client_ip,
            status="FAILED",
            details=f"WebAuthn verification failure: {str(e)}"
        )
        db.add(audit)
        db.commit()
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")

@router.post("/tokens/refresh", response_model=TokenResponse)
def refresh_tokens(payload: TokenRefreshRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    new_access, new_refresh = rotate_refresh_token(db, payload.refresh_token, client_ip)
    return TokenResponse(access_token=new_access, refresh_token=new_refresh)

@router.post("/oauth/mock-login", response_model=TokenResponse)
def mock_oidc_login(payload: Dict[str, Any] = Body(...), request: Request = None, db: Session = Depends(get_db)):
    """Mock federated OIDC login endpoint for fallback auth."""
    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Missing email claim in OIDC payload")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(username=email.split("@")[0], email=email, role="analyst")
        db.add(user)
        db.commit()
        db.refresh(user)

    client_ip = request.client.host if request and request.client else "127.0.0.1"
    access_token = create_access_token(user.id, user.role)
    refresh_token = issue_refresh_token_family(db, user.id)

    audit = AuditLog(
        actor_id=user.id,
        actor_role=user.role,
        action="OIDC_LOGIN_SUCCESS",
        resource_type="auth",
        resource_id=user.id,
        client_ip=client_ip,
        status="SUCCESS",
        details=f"Federated OIDC login for {email}"
    )
    db.add(audit)
    db.commit()

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)
