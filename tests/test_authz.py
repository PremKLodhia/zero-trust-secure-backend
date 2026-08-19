import pytest
import httpx
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from src.auth.tokens.service import create_access_token
from src.authz.client import OPAClient, opa_client
from src.models.user import User
from src.models.case_file import CaseFile
from src.models.audit_log import AuditLog

def test_opa_client_fail_secure_on_connection_error():
    """
    CRITICAL FAIL-SECURE TEST (CTL-06):
    When OPA sidecar is completely down or unreachable, OPAClient MUST return False (DENY).
    Never silently allow through.
    """
    client = OPAClient(opa_url="http://non-existent-opa-host:8181/v1/data/case_access/allow")
    user = {"id": "user-1", "role": "admin"}
    allowed = client.evaluate_access(user=user, action="READ_CASE", case={"classification": "TLP:CLEAR"})
    assert allowed is False, "Fail-Secure violation: OPAClient returned True when OPA was unreachable!"

def test_opa_client_fail_secure_on_timeout():
    """
    CRITICAL FAIL-SECURE TEST (CTL-06):
    When OPA sidecar times out, authorization must default to DENY.
    """
    with patch("httpx.Client.post", side_effect=httpx.TimeoutException("Connection timed out")):
        client = OPAClient(opa_url="http://localhost:8181/v1/data/case_access/allow")
        user = {"id": "user-1", "role": "admin"}
        allowed = client.evaluate_access(user=user, action="READ_CASE")
        assert allowed is False, "Fail-Secure violation: OPAClient returned True on timeout!"

def test_opa_client_fail_secure_on_500_error():
    """
    CRITICAL FAIL-SECURE TEST (CTL-06):
    When OPA sidecar returns 500 Internal Server Error, authorization must default to DENY.
    """
    mock_response = MagicMock()
    mock_response.status_code = 500
    with patch("httpx.Client.post", return_value=mock_response):
        client = OPAClient(opa_url="http://localhost:8181/v1/data/case_access/allow")
        user = {"id": "user-1", "role": "admin"}
        allowed = client.evaluate_access(user=user, action="READ_CASE")
        assert allowed is False, "Fail-Secure violation: OPAClient returned True on HTTP 500!"

def test_api_fail_secure_integration(client, db_session):
    """
    Simulates OPA failure when a client makes a real API request to /cases.
    Must return HTTP 403 Forbidden and record a DENIED audit log.
    """
    # Create user and token
    user = User(username="analyst_failsec", email="failsec@example.com", role="analyst")
    db_session.add(user)
    db_session.commit()
    token = create_access_token(user_id=user.id, role=user.role)

    # Force OPA to fail
    with patch.object(opa_client, "evaluate_access", return_value=False):
        resp = client.post(
            "/cases",
            json={
                "title": "Incident 404",
                "classification": "TLP:AMBER",
                "assigned_analyst_id": user.id,
                "content": "Secret note"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403
        assert "access denied" in resp.json()["detail"].lower()

        # Verify audit log recorded DENIED status
        denied_logs = db_session.query(AuditLog).filter(AuditLog.status == "DENIED").all()
        assert len(denied_logs) >= 1
        assert denied_logs[-1].actor_id == user.id

def test_abac_and_rbac_authorization_matrix(client, db_session):
    # Create Alice (Analyst), Bob (Analyst), Eve (Auditor), Root (Admin)
    alice = User(username="alice_ana", email="alice_ana@example.com", role="analyst")
    bob = User(username="bob_ana", email="bob_ana@example.com", role="analyst")
    eve = User(username="eve_aud", email="eve_aud@example.com", role="auditor")
    root = User(username="root_adm", email="root_adm@example.com", role="admin")
    db_session.add_all([alice, bob, eve, root])
    db_session.commit()

    token_alice = create_access_token(user.id if (user := alice) else "", alice.role)
    token_bob = create_access_token(bob.id, bob.role)
    token_eve = create_access_token(eve.id, eve.role)
    token_root = create_access_token(root.id, root.role)

    # Policy simulator matching policies/case_access.rego logic
    def mock_eval(user, action, resource_type="case_file", case=None):
        role = user.get("role")
        user_id = user.get("id")
        if role == "admin":
            return True
        if role == "auditor":
            return action in ["READ_CASE", "LIST_CASES"]
        if role == "analyst":
            if action in ["CREATE_CASE", "LIST_CASES"]:
                return True
            if action == "READ_CASE" and case:
                if case.get("classification") in ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"]:
                    return True
                if case.get("classification") == "TLP:RED" and case.get("assigned_analyst_id") == user_id:
                    return True
                return False
            if action == "UPDATE_CASE" and case:
                return case.get("assigned_analyst_id") == user_id
        return False

    with patch.object(opa_client, "evaluate_access", side_effect=mock_eval):
        # 1. Alice creates a case assigned to herself
        res1 = client.post(
            "/cases",
            json={"title": "Alice Case", "classification": "TLP:AMBER", "assigned_analyst_id": alice.id, "content": "Evidence A"},
            headers={"Authorization": f"Bearer {token_alice}"}
        )
        assert res1.status_code == 201
        case_id = res1.json()["id"]

        # 2. Bob attempts ABAC violation: update Alice's case -> DENIED (403)
        res2 = client.put(
            f"/cases/{case_id}",
            json={"title": "Tampered Title by Bob"},
            headers={"Authorization": f"Bearer {token_bob}"}
        )
        assert res2.status_code == 403

        # 3. Alice updates her own case -> ALLOWED (200)
        res3 = client.put(
            f"/cases/{case_id}",
            json={"title": "Updated Title by Alice"},
            headers={"Authorization": f"Bearer {token_alice}"}
        )
        assert res3.status_code == 200
        assert res3.json()["title"] == "Updated Title by Alice"

        # 4. Auditor Eve attempts to create case -> DENIED (403)
        res4 = client.post(
            "/cases",
            json={"title": "Auditor Case", "classification": "TLP:CLEAR", "assigned_analyst_id": eve.id, "content": "Notes"},
            headers={"Authorization": f"Bearer {token_eve}"}
        )
        assert res4.status_code == 403

        # 5. Auditor Eve reads Alice's case -> ALLOWED (200)
        res5 = client.get(f"/cases/{case_id}", headers={"Authorization": f"Bearer {token_eve}"})
        assert res5.status_code == 200

        # 6. Alice creates TLP:RED case assigned to herself
        res6 = client.post(
            "/cases",
            json={"title": "Top Secret Red", "classification": "TLP:RED", "assigned_analyst_id": alice.id, "content": "Red Evidence"},
            headers={"Authorization": f"Bearer {token_alice}"}
        )
        red_case_id = res6.json()["id"]

        # 7. Bob attempts to read Alice's TLP:RED case -> DENIED (403)
        res7 = client.get(f"/cases/{red_case_id}", headers={"Authorization": f"Bearer {token_bob}"})
        assert res7.status_code == 403

        # 8. Admin Root reads Alice's TLP:RED case -> ALLOWED (200)
        res8 = client.get(f"/cases/{red_case_id}", headers={"Authorization": f"Bearer {token_root}"})
        assert res8.status_code == 200
