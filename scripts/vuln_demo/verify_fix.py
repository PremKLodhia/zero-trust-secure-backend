import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from scripts.vuln_demo.exploit import create_forged_alg_none_token
from scripts.vuln_demo.vulnerable_verifier import verify_token_vulnerable
from scripts.vuln_demo.remediated_verifier import verify_token_remediated

def verify_fix() -> bool:
    secret = "production_vault_backed_key_32_bytes_secret"
    forged_token = create_forged_alg_none_token(user_id="unauthorized_adversary", role="admin")

    # Step 1: Confirm vulnerable verifier is vulnerable (Exploit works)
    vuln_payload = verify_token_vulnerable(forged_token, secret)
    if vuln_payload.get("role") != "admin":
        print("[FAIL] Vulnerability harness did not trigger expected exploit on vulnerable target")
        return False

    # Step 2: Confirm remediated verifier blocks exploit
    try:
        verify_token_remediated(forged_token, secret)
        print("[FAIL] Remediated verifier allowed forged token!")
        return False
    except Exception as e:
        # Expected rejection
        pass

    print("[PASS] Deliberate Vulnerability Remediation Harness Verified:")
    print("       - Vulnerable state: Forged alg:none bypasses signature check.")
    print("       - Remediated state: Hardened parser strictly enforces HS256 whitelist and rejects forgery.")
    return True

if __name__ == "__main__":
    success = verify_fix()
    sys.exit(0 if success else 1)
