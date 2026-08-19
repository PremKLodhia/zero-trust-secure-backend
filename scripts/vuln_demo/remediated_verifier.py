import jwt
from typing import Dict, Any
from fastapi import HTTPException, status

ALLOWED_ALGORITHMS = ["HS256"]

# Hardened implementation: Strict algorithm pinning, required claims, signature enforcement
def verify_token_remediated(token: str, secret: str) -> Dict[str, Any]:
    """
    REMEDIATED IMPLEMENTATION (CTL-03 / ASVS V3.5.2):
    Strictly enforces HS256 algorithm pinning, rejects 'none' or mismatched headers,
    requires exp/sub/role claims, and cryptographically verifies the signature.
    """
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") not in ALLOWED_ALGORITHMS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Insecure algorithm {header.get('alg')} rejected. Only {ALLOWED_ALGORITHMS} allowed."
            )

        payload = jwt.decode(
            token,
            secret,
            algorithms=ALLOWED_ALGORITHMS,
            options={
                "verify_signature": True,
                "require": ["exp", "sub", "role", "iat"]
            }
        )
        return payload
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Cryptographic signature verification failed: {str(e)}"
        )
