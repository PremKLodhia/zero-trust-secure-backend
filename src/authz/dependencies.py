from fastapi import Depends, HTTPException, Header, status
from typing import Dict, Any, Optional
from src.auth.tokens.service import decode_access_token
from src.authz.client import opa_client

def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Bearer authorization token"
        )
    token = authorization.split(" ")[1]
    claims = decode_access_token(token)
    return {
        "id": claims["sub"],
        "role": claims["role"]
    }
