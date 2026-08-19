import logging
import httpx
from typing import Dict, Any, Optional
from src.config import settings

logger = logging.getLogger("authz")

class OPAClient:
    def __init__(self, opa_url: Optional[str] = None, timeout: float = 2.0):
        self.opa_url = opa_url or settings.OPA_URL
        self.timeout = timeout

    def evaluate_access(
        self,
        user: Dict[str, Any],
        action: str,
        resource_type: str = "case_file",
        case: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Queries the Open Policy Agent REST API to evaluate authorization.
        
        FAIL-SECURE PRINCIPLE (CTL-06):
        Under all failure conditions (network failure, timeout, OPA 5xx status,
        malformed JSON, or policy evaluation error), this function returns False (DENY).
        Never fail-open.
        """
        payload = {
            "input": {
                "user": user,
                "action": action,
                "resource_type": resource_type,
                "case": case or {}
            }
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(self.opa_url, json=payload)
                if response.status_code == 200:
                    result = response.json().get("result", False)
                    return bool(result)
                else:
                    logger.error(f"[FAIL-SECURE] OPA returned non-200 status code: {response.status_code}. Defaulting to DENY.")
                    return False
        except httpx.TimeoutException as exc:
            logger.error(f"[FAIL-SECURE] OPA request timed out: {exc}. Defaulting to DENY.")
            return False
        except httpx.RequestError as exc:
            logger.error(f"[FAIL-SECURE] OPA connection error: {exc}. Defaulting to DENY.")
            return False
        except Exception as exc:
            logger.error(f"[FAIL-SECURE] Unexpected error during OPA evaluation: {exc}. Defaulting to DENY.")
            return False

opa_client = OPAClient()
