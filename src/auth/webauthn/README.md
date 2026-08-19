# WebAuthn & Passkeys Authentication

This subsystem implements standard FIDO2 / WebAuthn Level 3 ceremonies using the actively maintained `webauthn` (Duo Labs py_webauthn) library.

## Ceremonies Supported
1. **Registration Ceremony**:
   - `POST /auth/webauthn/register/options`: Issues cryptographic challenge, relying party ID (`localhost`), and authenticator criteria.
   - `POST /auth/webauthn/register/verify`: Validates client data JSON, attestation object, and stores `credential_id`, `public_key`, and initial sign count.
2. **Authentication Ceremony**:
   - `POST /auth/webauthn/login/options`: Generates authentication challenge for the registered credential ID.
   - `POST /auth/webauthn/login/verify`: Cryptographically verifies the authenticator signature, updates `sign_count`, and issues short-lived JWTs.

> **IMPORTANT**: Try the real WebAuthn registration/login ceremony yourself in the browser with Touch ID / Windows Hello / YubiKey once the service is running. While automated virtual authenticator emulation tests validate the cryptographic challenge-response pipelines in CI, they do not fully substitute for the real hardware-bound user experience.
