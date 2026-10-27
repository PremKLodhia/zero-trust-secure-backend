from unittest.mock import patch

from src.auth.tokens.service import create_access_token
from src.authz.client import opa_client
from src.models.case_file import CaseFile
from src.models.user import User


def policy(user, action, resource_type="case_file", case=None):
    """Mirror of policies/case_access.rego for analysts and admins."""
    case = case or {}
    if user["role"] == "admin":
        return True
    if user["role"] == "analyst":
        if action in ("CREATE_CASE", "LIST_CASES"):
            return True
        if action == "READ_CASE":
            if case.get("classification") in ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"):
                return True
            return case.get("classification") == "TLP:RED" and case.get("assigned_analyst_id") == user["id"]
    return False


def _user(db, name, role):
    u = User(username=name, email=f"{name}@example.com", role=role)
    db.add(u)
    db.commit()
    return u


def _case(db, title, classification, analyst_id):
    db.add(CaseFile(title=title, classification=classification, assigned_analyst_id=analyst_id,
                    encrypted_content="ciphertext", wrapped_dek="wrapped"))
    db.commit()


def _list_titles(client, user):
    token = create_access_token(user_id=user.id, role=user.role)
    with patch.object(opa_client, "evaluate_access", side_effect=policy):
        resp = client.get("/cases", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    return {c["title"] for c in resp.json()}


def test_unassigned_analyst_cannot_see_red_cases(client, db_session):
    owner = _user(db_session, "red_owner", "analyst")
    outsider = _user(db_session, "outsider", "analyst")
    _case(db_session, "Operation Nightjar (RED)", "TLP:RED", owner.id)
    _case(db_session, "Phishing triage (AMBER)", "TLP:AMBER", owner.id)

    titles = _list_titles(client, outsider)

    assert "Operation Nightjar (RED)" not in titles
    assert "Phishing triage (AMBER)" in titles


def test_assigned_analyst_and_admin_see_red_cases(client, db_session):
    owner = _user(db_session, "red_owner2", "analyst")
    admin = _user(db_session, "admin2", "admin")
    _case(db_session, "Operation Kestrel (RED)", "TLP:RED", owner.id)

    assert "Operation Kestrel (RED)" in _list_titles(client, owner)
    assert "Operation Kestrel (RED)" in _list_titles(client, admin)
