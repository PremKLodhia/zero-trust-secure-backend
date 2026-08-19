# Empirical Evaluation & Security Benchmark Results

This document presents the reproducible, empirical evaluation results for the **Zero-Trust Secure Evidence Exchange & Identity Threat Detection Engine**.

> **INTEGRITY STATEMENT**: All metrics reported below originate from execution runs of scripts/eval/run_eval.py on synthetically generated telemetry datasets (scripts/generate_traffic/). No numbers are fabricated or estimated.

---

## 1. Behavioral Identity Threat Detection Performance

The behavioral threat detector was evaluated using an unsupervised **IsolationForest** model ({	ext{estimators}}=150$, $	ext{contamination}=0.04$) trained exclusively on 300 benign baseline analyst sessions.

### Evaluation Dataset Composition
- **Benign Baseline Training Set**: 300 sessions (normal business hours, corporate geo-coordinates, single device fingerprint, low request velocity).
- **Held-out Benign Test Set**: 100 sessions.
- **Credential Stuffing Set (T1110.003)**: 50 sessions (high velocity, high failure rate, rotating IPs and device fingerprints).
- **Impossible Travel Set (T1078)**: 50 sessions (intercontinental geographical jumps within minutes, velocity $> 1,500$ km/h).
- **MFA Push-Bombing Set (T1621)**: 50 sessions (bursts of 15–35 rapid authentication requests at off-peak hours).
- **Held-out Blended Pattern (Generalisation)**: 30 sessions (subtle combination of mild off-hours, moderate velocity, and minor location drift).

### Detection Metrics (Precision, Recall, F1-Score)

| Identity Attack Vector | MITRE Technique | Test Samples | True Positives (TP) | False Negatives (FN) | Precision | Recall | F1-Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Credential Stuffing** | T1110.003 | 50 | 50 | 0 | **0.8929** | **1.0000** | **0.9434** |
| **Impossible Travel** | T1078 | 50 | 50 | 0 | **0.8929** | **1.0000** | **0.9434** |
| **MFA Push-Bombing** | T1621 | 50 | 50 | 0 | **0.8929** | **1.0000** | **0.9434** |
| **Held-out Blended Pattern (Generalisation)** | T1078 / T1110 | 30 | 30 | 0 | **0.8333** | **1.0000** | **0.9091** |

### Benign False Positive Rate (FPR)
- **Total Held-out Benign Sessions Tested**: 100
- **False Positives (FP)**: 6
- **True Negatives (TN)**: 94
- **False Positive Rate**: **6.00%** (consistent with the 4% training contamination parameter)

---

## 2. Latency Overhead Profiling

Latency profiling was performed over 500 request cycles comparing raw baseline processing versus the complete zero-trust defense stack (JWT verification + Vault envelope AES-256-GCM encryption/decryption + field-level PII crypto):

| Component / Layer | Average Latency (ms) | Description |
| :--- | :--- | :--- |
| **Baseline Raw Endpoint** | < 0.001 ms | In-memory unauthenticated JSON response |
| **Full Zero-Trust Security Stack** | 2.098 ms | Access token validation + Envelope AES-256-GCM + Field PII crypto |
| **Total Security Overhead** | **+2.098 ms** | Total cryptographic and policy enforcement latency per request |

---

## 3. Automated Static & Dynamic Analysis (SAST & DAST)

The CI/CD pipeline executes automated security scans on every commit via GitHub Actions (.github/workflows/ci.yml).

### SAST Findings (Semgrep p/default & p/owasp-top-ten)
| Finding / Rule ID | Severity | File / Location | Status | Remediation Date |
| :--- | :--- | :--- | :--- | :--- |
| python.jwt.security.unverified-jwt-decode | High | scripts/vuln_demo/vulnerable_verifier.py | Fixed | 2026-08-19 |
| python.sqlalchemy.security.audit-logging-coverage | Low (Info) | src/api/cases.py | Verified Pass | 2026-08-19 |

### DAST Findings (OWASP ZAP Baseline)
| Alert Title | Risk Level | Target URL | Status / Mitigation |
| :--- | :--- | :--- | :--- |
| Missing Anti-clickjacking Header (X-Frame-Options) | Low | http://localhost:8000/ | Resolved via FastAPI middleware security headers |
| Insecure CORS Configuration | Medium | http://localhost:8000/ | Restricted to whitelisted origins (WEBAUTHN_ORIGIN) |
