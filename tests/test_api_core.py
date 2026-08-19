import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.database import Base, get_db
from src.api.main import app
from src.models.audit_log import AuditLog

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_api.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def client():
    return TestClient(app)

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_create_and_get_user(client):
    user_payload = {
        "username": "analyst_alice",
        "email": "alice@example.com",
        "role": "analyst"
    }
    response = client.post("/users", json=user_payload, headers={"X-Actor-ID": "admin_root", "X-Actor-Role": "admin"})
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "analyst_alice"
    assert "id" in data

    # Verify audit log recorded creation
    audit_resp = client.get("/audit-logs?resource_type=user")
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert len(logs) >= 1
    assert logs[0]["action"] == "CREATE_USER"
    assert logs[0]["actor_id"] == "admin_root"

def test_case_file_crud_and_audit_trail(client):
    # 1. Create User
    user_resp = client.post("/users", json={"username": "analyst_bob", "email": "bob@example.com", "role": "analyst"})
    assert user_resp.status_code == 201
    analyst_id = user_resp.json()["id"]

    # 2. Create Case File
    case_payload = {
        "title": "Operation Red Sky - Evidence Bundle",
        "classification": "TLP:AMBER",
        "assigned_analyst_id": analyst_id,
        "content": "Encrypted memory dump artifact hash: sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "pii_subject": "SYNTHETIC_SUBJECT_PERSON_A_DOB_19850101",
        "metadata_json": "{\"evidence_type\": \"memory_dump\", \"priority\": \"high\"}"
    }
    create_resp = client.post("/cases", json=case_payload, headers={"X-Actor-ID": analyst_id, "X-Actor-Role": "analyst"})
    assert create_resp.status_code == 201
    case_data = create_resp.json()
    case_id = case_data["id"]
    assert case_data["title"] == case_payload["title"]

    # 3. Read Case File
    get_resp = client.get(f"/cases/{case_id}", headers={"X-Actor-ID": analyst_id, "X-Actor-Role": "analyst"})
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == case_id

    # 4. Update Case File
    update_payload = {"classification": "TLP:RED"}
    update_resp = client.put(f"/cases/{case_id}", json=update_payload, headers={"X-Actor-ID": analyst_id, "X-Actor-Role": "analyst"})
    assert update_resp.status_code == 200
    assert update_resp.json()["classification"] == "TLP:RED"

    # 5. Verify Audit Logs for Case
    audit_resp = client.get("/audit-logs?resource_type=case_file")
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    actions = [l["action"] for l in logs]
    assert "CREATE_CASE" in actions
    assert "GET_CASE" in actions
    assert "UPDATE_CASE" in actions
