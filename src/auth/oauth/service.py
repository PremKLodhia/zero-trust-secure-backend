from typing import Dict, Any
from authlib.integrations.starlette_integration import OAuth
from src.config import settings

oauth = OAuth()

# Configure federated OIDC provider (e.g. Keycloak / Google / Mock OIDC)
oauth.register(
    name="federated_idp",
    client_id="zt-backend-client",
    client_secret="mock_oidc_secret",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

def verify_mock_oidc_id_token(id_token_claims: Dict[str, Any]) -> Dict[str, str]:
    """Helper to extract and validate standard OIDC claims for fallback federated auth."""
    if "email" not in id_token_claims or "sub" not in id_token_claims:
        raise ValueError("Invalid OIDC ID token claims: missing sub or email")
    return {
        "external_id": str(id_token_claims["sub"]),
        "email": str(id_token_claims["email"]),
        "name": str(id_token_claims.get("name", id_token_claims["email"]))
    }
