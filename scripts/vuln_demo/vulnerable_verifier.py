import jwt
from typing import Dict, Any

# Vulnerable implementation: Accepts unverified algorithms and fails to enforce algorithm whitelist
def verify_token_vulnerable(token: str, secret: str) -> Dict[str, Any]:
    """
    VULNERABLE IMPLEMENTATION (THR-ELEV-01 / CWE-327):
    Allows insecure 'none' algorithm header without validating cryptographic signature,
    allowing an unauthenticated attacker to forge any role payload (e.g. role='admin').
    """
    unverified_header = jwt.get_unverified_header(token)
    alg = unverified_header.get("alg")

    if alg == "none" or alg is None:
        # Insecurely decodes payload without signature verification
        return jwt.decode(token, options={"verify_signature": False})

    return jwt.decode(token, secret, algorithms=[alg])
