import pytest
import jwt
from datetime import timedelta
from src.config import settings
from src.models.user import User
from src.models.token_store import RefreshTokenStore
from src.models.audit_log import AuditLog
from src.auth.tokens.service import create_access_token, decode_access_token, issue_refresh_token_family, rotate_refresh_token

def test_access_token_creation_and_validation():
    user_id = "test-user-123"
    role = "analyst"
    token = create_access_token(user_id=user_id, role=role, expires_delta=timedelta(minutes=5))
    
    payload = decode_access_token(token)
    assert payload["sub"] == user_id
    assert payload["role"] == role
    assert payload["type"] == "access"
    assert "exp" in payload

def test_refresh_token_rotation_success(db_session):
    user = User(username="analyst_test", email="test@example.com", role="analyst")
    db_session.add(user)
    db_session.commit()

    # Step 1: Issue token 1 (seq 1)
    raw_token_1 = issue_refresh_token_family(db_session, user.id)
    payload_1 = jwt.decode(raw_token_1, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    assert payload_1["seq"] == 1
    family_id = payload_1["token_family_id"]

    # Step 2: Rotate token 1 -> token 2 (seq 2)
    acc_2, raw_token_2 = rotate_refresh_token(db_session, raw_token_1, client_ip="10.0.0.1")
    payload_2 = jwt.decode(raw_token_2, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    assert payload_2["seq"] == 2
    assert payload_2["token_family_id"] == family_id
    assert acc_2 is not None

    # Verify token 1 is marked revoked in DB
    rec_1 = db_session.query(RefreshTokenStore).filter(RefreshTokenStore.token_jti == payload_1["jti"]).first()
    assert rec_1.is_revoked is True

    # Step 3: Rotate token 2 -> token 3 (seq 3)
    acc_3, raw_token_3 = rotate_refresh_token(db_session, raw_token_2, client_ip="10.0.0.1")
    payload_3 = jwt.decode(raw_token_3, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    assert payload_3["seq"] == 3
    assert payload_3["token_family_id"] == family_id

def test_refresh_token_family_reuse_revocation_security(db_session):
    """
    CRITICAL SECURITY CONTROL (CTL-04):
    If an attacker replays a previously rotated refresh token (e.g. seq 1),
    the system must detect token reuse and immediately revoke ALL tokens in that family
    (including legitimate seq 2/3), invalidating all sessions for that lineage.
    """
    user = User(username="target_user", email="target@example.com", role="analyst")
    db_session.add(user)
    db_session.commit()

    # Legitimate user gets Token 1 and rotates to Token 2
    raw_token_1 = issue_refresh_token_family(db_session, user.id)
    _, raw_token_2 = rotate_refresh_token(db_session, raw_token_1, client_ip="192.168.1.50")
    
    # Legitimate user rotates Token 2 to Token 3
    _, raw_token_3 = rotate_refresh_token(db_session, raw_token_2, client_ip="192.168.1.50")

    # Attacker attempts to replay stolen Token 1 (which was already rotated)
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        rotate_refresh_token(db_session, raw_token_1, client_ip="198.51.100.99")

    assert exc_info.value.status_code == 403
    assert "reuse detected" in exc_info.value.detail.lower()

    # Assert that ALL tokens in this family are now revoked (including Token 3)
    family_tokens = db_session.query(RefreshTokenStore).all()
    assert len(family_tokens) == 3
    for t in family_tokens:
        assert t.is_revoked is True, f"Token seq {t.sequence_number} was not revoked!"

    # Assert security theft audit event was logged
    breach_logs = db_session.query(AuditLog).filter(AuditLog.action == "REFRESH_TOKEN_FAMILY_REUSE_THEFT").all()
    assert len(breach_logs) >= 1
    assert breach_logs[0].client_ip == "198.51.100.99"
    assert breach_logs[0].status == "DENIED"

    # Subsequent attempt by legitimate user with Token 3 also fails now
    with pytest.raises(HTTPException) as exc_info2:
        rotate_refresh_token(db_session, raw_token_3, client_ip="192.168.1.50")
    assert exc_info2.value.status_code == 403

def test_webauthn_registration_options_endpoint(client):
    user_resp = client.post("/users", json={"username": "webauthn_user", "email": "webauthn@example.com", "role": "analyst"})
    assert user_resp.status_code == 201
    user_id = user_resp.json()["id"]

    resp = client.post("/auth/webauthn/register/options", json={"user_id": user_id})
    assert resp.status_code == 200
    data = resp.json()
    assert "options" in data
    assert "challenge" in data["options"]
    assert "rp" in data["options"]

def test_mock_oidc_fallback_login(client):
    oidc_payload = {
        "sub": "oidc-google-sub-9988",
        "email": "federated_analyst@example.com",
        "name": "Federated Analyst"
    }
    resp = client.post("/auth/oauth/mock-login", json=oidc_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data

    # Verify access token works
    claims = decode_access_token(data["access_token"])
    assert claims["role"] == "analyst"
