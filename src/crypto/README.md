# Cryptographic Architecture: Envelope & Field-Level Encryption

This subsystem provides zero-trust data protection at rest and in transit.

## 1. Envelope Encryption (`src/crypto/envelope.py`)
- **Data Encryption Key (DEK)**: 256-bit AES-GCM key generated per case file.
- **Key Encryption Key (KEK)**: Vault Transit engine-managed master key (`case-dek-kek`).
- Plaintext DEKs are never persisted. Only the Vault-wrapped DEK is stored in the database.

## 2. Field-Level PII Encryption (`src/crypto/field_crypto.py`)
- Sensitive columns such as `encrypted_pii_subject` are encrypted individually before database insertion.
- General metadata (`title`, `classification`, `created_at`, `assigned_analyst_id`) remains unencrypted and indexed for query efficiency.

## 3. Synthetic Data Statement
All data, forensic notes, and PII attributes stored or processed within this project are **100% synthetic mock data** generated for testing and demonstration purposes. No real PII or live forensic keys are ever used.
