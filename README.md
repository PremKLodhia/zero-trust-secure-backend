# Zero-Trust Secure Backend & Identity Threat Detection

[![CI](https://github.com/org/zt-backend/actions/workflows/ci.yml/badge.svg)](https://github.com/org/zt-backend/actions)
[![Security: Fail-Secure](https://img.shields.io/badge/Security-Fail--Secure-green.svg)](#design-philosophy)
[![Authentication: WebAuthn](https://img.shields.io/badge/AuthN-WebAuthn%20%2F%20Passkeys-blue.svg)](#architecture)
[![Authorization: OPA](https://img.shields.io/badge/AuthZ-Open%20Policy%20Agent-purple.svg)](#architecture)

A defense-in-depth secure case-file exchange backend for security operations teams. The system implements end-to-end zero-trust controls, cryptographic data protection with HashiCorp Vault, fail-secure policy enforcement via Open Policy Agent (OPA), and behavioural identity threat detection via an IsolationForest ML pipeline.

---

## Key Highlights & Design Philosophy

1. **Fail-Secure Architecture**: Authorization decisions default to `DENY`. If OPA times out or is unreachable, the system rejects access unconditionally.
2. **Passwordless Primary Authentication**: WebAuthn/Passkeys as the primary authentication factor with OIDC federated fallback and rotating refresh token families with reuse revocation.
3. **Envelope & Field-Level Encryption**: HashiCorp Vault transit engine manages key encryption keys (KEK); local data encryption keys (DEK) protect sensitive evidence and PII at rest.
4. **Behavioral Identity Threat Detection**: Unsupervised machine learning (`IsolationForest`) on engineered per-session telemetry (impossible travel velocity, time-of-day deviations, device fingerprint changes) detecting credential stuffing, push-bombing, and anomalous access.
5. **Continuous Adversarial Validation**: Automated SAST (Semgrep) & DAST (OWASP ZAP) in CI, complemented by a documented deliberate vulnerability and remediation exercise.
6. **100% Synthetic Data & Honest Evaluation**: All data, PII, and telemetry are synthetically generated. Metrics are derived from reproducible runs without fabricated numbers.

---

## System Architecture

```
                                +-----------------------------+
                                |      Client / Browser       |
                                +--------------+--------------+
                                               |
                          WebAuthn / OIDC / Short-lived JWT
                                               v
+------------------------------------------------------------------------------+
| FastAPI Zero-Trust Backend Application                                       |
|                                                                              |
|  [Telemetry & Anomaly Middleware] ---> Logs Session Vector to Anomaly Model  |
|                                                                              |
|  [AuthN Layer]                    ---> WebAuthn / Token Family Rotation      |
|                                                                              |
|  [AuthZ Enforcement Engine]       ---> Queries OPA Sidecar (Fail-Secure)     |
|                                                                              |
|  [Crypto Engine]                  ---> Vault Transit Envelope Encryption     |
+----------------------+-----------------------+-------------------------------+
                       |                       |
                       v                       v
         +---------------------------+   +---------------------------+
         | Open Policy Agent (OPA)   |   |   HashiCorp Vault         |
         | Rego RBAC + ABAC Policies |   |   Transit Key Wrapping    |
         +---------------------------+   +---------------------------+
                       |
                       v
         +---------------------------+
         | PostgreSQL Database       |
         | Encrypted Case Records &  |
         | Append-Only Audit Logs    |
         +---------------------------+
```

---

## Project Status

- [x] **Phase 0**: Repo Scaffold & Baseline Tooling
- [ ] **Phase 1**: Core Service & Append-Only Audit Trail
- [ ] **Phase 2**: Threat Modeling (STRIDE) & Control Mapping (ASVS/ATT&CK)
- [ ] **Phase 3**: Authentication (WebAuthn, OIDC, Token Family Rotation)
- [ ] **Phase 4**: Authorization (OPA Sidecar & Fail-Secure Verification)
- [ ] **Phase 5**: Data Protection (Vault Envelope & Field-Level Encryption)
- [ ] **Phase 6**: Behavioural Identity Anomaly Detection Pipeline
- [ ] **Phase 7**: Continuous Adversarial Testing (Semgrep, ZAP, JWT Vuln & Fix)
- [ ] **Phase 8**: Rigorous Evaluation & Latency Benchmarks
- [ ] **Phase 9**: Portfolio Documentation & Release Packaging
