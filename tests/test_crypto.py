import pytest
from unittest.mock import patch
from sqlalchemy import text
from src.crypto.envelope import EnvelopeCrypto
from src.crypto.field_crypto import FieldCrypto
from src.models.user import User
from src.auth.tokens.service import create_access_token
from src.authz.client import opa_client

def test_envelope_encryption_roundtrip():
    secret_evidence = "TOP_SECRET_MEMORY_DUMP_HASH_0xDEADBEEF_AUTHENTIC_SYNTHETIC"
    
    # Encrypt
    ciphertext_b64, wrapped_dek = EnvelopeCrypto.encrypt_case_content(secret_evidence)
    assert ciphertext_b64 != secret_evidence
    assert wrapped_dek is not None
    assert len(ciphertext_b64) > 16

    # Decrypt
    decrypted = EnvelopeCrypto.decrypt_case_content(ciphertext_b64, wrapped_dek)
    assert decrypted == secret_evidence

def test_field_level_pii_encryption_roundtrip():
    pii_payload = "SYNTHETIC_CITIZEN_SSN_000-12-3456_NAME_JANE_DOE"
    
    # Encrypt field
    encrypted_field = FieldCrypto.encrypt_field(pii_payload)
    assert encrypted_field.startswith("enc:v1:")
    assert pii_payload not in encrypted_field

    # Decrypt field
    decrypted_field = FieldCrypto.decrypt_field(encrypted_field)
    assert decrypted_field == pii_payload

def test_database_raw_ciphertext_storage_verification(client, db_session):
    """
    CRITICAL CRYPTOGRAPHIC DATA PROTECTION TEST (CTL-07 & CTL-08):
    Verifies that what is stored inside the database is strictly ciphertext and wrapped DEKs.
    Plaintext content and plaintext PII MUST NEVER exist in raw storage.
    """
    # 1. Create User and Token
    user = User(username="crypto_analyst", email="crypto_analyst@example.com", role="analyst")
    db_session.add(user)
    db_session.commit()
    token = create_access_token(user_id=user.id, role=user.role)
    headers = {"Authorization": f"Bearer {token}"}

    secret_raw_text = "RAW_PLAINTEXT_EVIDENCE_FOR_STORAGE_TEST_12345"
    secret_raw_pii = "RAW_PLAINTEXT_PII_SUBJECT_JOHN_SMITH_9999"

    with patch.object(opa_client, "evaluate_access", return_value=True):
        # 2. Create case via API
        create_resp = client.post(
            "/cases",
            json={
                "title": "Crypto Storage Verification Case",
                "classification": "TLP:AMBER",
                "assigned_analyst_id": user.id,
                "content": secret_raw_text,
                "pii_subject": secret_raw_pii
            },
            headers=headers
        )
        assert create_resp.status_code == 201
        case_id = create_resp.json()["id"]

        # 3. Direct raw SQL query on the database table
        raw_row = db_session.execute(
            text("SELECT encrypted_content, encrypted_pii_subject, wrapped_dek FROM case_files WHERE id = :id"),
            {"id": case_id}
        ).fetchone()

        db_encrypted_content = raw_row[0]
        db_encrypted_pii = raw_row[1]
        db_wrapped_dek = raw_row[2]

        # Verify raw storage properties
        assert secret_raw_text not in db_encrypted_content, "Plaintext evidence leaked to raw database storage!"
        assert secret_raw_pii not in db_encrypted_pii, "Plaintext PII leaked to raw database storage!"
        assert db_wrapped_dek is not None
        assert len(db_wrapped_dek) > 0

        # 4. Decrypt via authorized endpoint
        decrypt_resp = client.get(f"/cases/{case_id}/decrypt", headers=headers)
        assert decrypt_resp.status_code == 200
        dec_data = decrypt_resp.json()
        assert dec_data["content"] == secret_raw_text
        assert dec_data["pii_subject"] == secret_raw_pii
