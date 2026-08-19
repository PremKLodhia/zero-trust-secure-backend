import uuid
import jwt
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional, Dict, Any
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from src.config import settings
from src.models.token_store import RefreshTokenStore
from src.models.audit_log import AuditLog
from src.models.user import User

def create_access_token(user_id: str, role: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": user_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
        "type": "access"
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub", "role", "iat"]}
        )
        if payload.get("type") != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired")
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token validation error: {str(e)}")

def issue_refresh_token_family(db: Session, user_id: str) -> str:
    """Starts a new refresh token family lineage."""
    family_id = str(uuid.uuid4())
    jti = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    token_record = RefreshTokenStore(
        token_family_id=family_id,
        token_jti=jti,
        user_id=user_id,
        sequence_number=1,
        is_revoked=False,
        expires_at=expires_at
    )
    db.add(token_record)
    db.commit()

    payload = {
        "sub": user_id,
        "token_family_id": family_id,
        "jti": jti,
        "seq": 1,
        "type": "refresh",
        "exp": int(expires_at.timestamp())
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def rotate_refresh_token(db: Session, raw_token: str, client_ip: str = "127.0.0.1") -> Tuple[str, str]:
    """
    Rotates a refresh token.
    If an already-revoked or out-of-sequence token is presented, detects REUSE and
    revokes the entire token family immediately as a suspected credential theft event.
    """
    try:
        payload = jwt.decode(
            raw_token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub", "token_family_id", "jti", "seq"]}
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    family_id = payload["token_family_id"]
    jti = payload["jti"]
    user_id = payload["sub"]
    seq = payload["seq"]

    token_record = db.query(RefreshTokenStore).filter(RefreshTokenStore.token_jti == jti).first()

    # Reuse Detection condition:
    # 1. Token record does not exist OR
    # 2. Token record is already marked revoked OR
    # 3. Family has a higher sequence number than this token
    is_reused = False
    if not token_record or token_record.is_revoked:
        is_reused = True
    else:
        max_seq_in_family = db.query(RefreshTokenStore).filter(
            RefreshTokenStore.token_family_id == family_id
        ).order_by(RefreshTokenStore.sequence_number.desc()).first()
        if max_seq_in_family and max_seq_in_family.sequence_number > seq:
            is_reused = True

    if is_reused:
        # Critical Breach: Revoke all tokens in family
        db.query(RefreshTokenStore).filter(
            RefreshTokenStore.token_family_id == family_id
        ).update({"is_revoked": True})
        db.commit()

        # Log security audit event
        audit = AuditLog(
            actor_id=user_id,
            actor_role="unknown",
            action="REFRESH_TOKEN_FAMILY_REUSE_THEFT",
            resource_type="auth",
            resource_id=family_id,
            client_ip=client_ip,
            status="DENIED",
            details=f"Suspected token theft: Refresh token reuse detected for family {family_id} (seq {seq})"
        )
        db.add(audit)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Refresh token reuse detected. All sessions in this token family have been revoked."
        )

    # Valid rotation:
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account inactive or missing")

    # Mark current token as revoked (used)
    token_record.is_revoked = True

    # Issue next token in sequence
    new_jti = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    next_seq = seq + 1

    next_record = RefreshTokenStore(
        token_family_id=family_id,
        token_jti=new_jti,
        user_id=user_id,
        sequence_number=next_seq,
        is_revoked=False,
        expires_at=expires_at
    )
    db.add(next_record)
    db.commit()

    new_access_token = create_access_token(user_id=user.id, role=user.role)
    new_refresh_payload = {
        "sub": user_id,
        "token_family_id": family_id,
        "jti": new_jti,
        "seq": next_seq,
        "type": "refresh",
        "exp": int(expires_at.timestamp())
    }
    new_refresh_token = jwt.encode(new_refresh_payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    return new_access_token, new_refresh_token
