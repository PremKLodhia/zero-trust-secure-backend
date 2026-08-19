import base64
import json
from typing import Dict, Any, Tuple
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.parse_registration_credential_json import parse_registration_credential_json
from webauthn.helpers.parse_authentication_credential_json import parse_authentication_credential_json
from webauthn.helpers.structs import (
    UserVerificationRequirement,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
)
from src.config import settings

# In-memory challenge store for active ceremonies
_active_challenges: Dict[str, bytes] = {}

def get_registration_options(user_id: str, username: str, user_display_name: str) -> str:
    user_handle = user_id.encode("utf-8")
    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=user_handle,
        user_name=username,
        user_display_name=user_display_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    _active_challenges[user_id] = options.challenge
    return options_to_json(options)

def verify_registration(user_id: str, credential_json: str) -> Tuple[str, str, int]:
    expected_challenge = _active_challenges.pop(user_id, None)
    if not expected_challenge:
        raise ValueError("No active registration challenge found for user")

    # In webauthn 3.0.0, use parse_registration_credential_json for Pydantic V2 compatibility
    credential = parse_registration_credential_json(credential_json)

    verification = verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_origin=settings.WEBAUTHN_ORIGIN,
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        require_user_verification=False,
    )

    credential_id_b64 = base64.urlsafe_b64encode(verification.credential_id).decode("utf-8")
    public_key_b64 = base64.urlsafe_b64encode(verification.credential_public_key).decode("utf-8")
    sign_count = verification.sign_count

    return credential_id_b64, public_key_b64, sign_count

def get_authentication_options(user_id: str, credential_id_b64: str) -> str:
    raw_cred_id = base64.urlsafe_b64decode(credential_id_b64.encode("utf-8"))
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    _active_challenges[user_id] = options.challenge
    return options_to_json(options)

def verify_authentication(
    user_id: str,
    credential_id_b64: str,
    public_key_b64: str,
    stored_sign_count: int,
    credential_json: str
) -> int:
    expected_challenge = _active_challenges.pop(user_id, None)
    if not expected_challenge:
        raise ValueError("No active authentication challenge found for user")

    raw_public_key = base64.urlsafe_b64decode(public_key_b64.encode("utf-8"))

    # In webauthn 3.0.0, use parse_authentication_credential_json for Pydantic V2 compatibility
    credential = parse_authentication_credential_json(credential_json)

    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_origin=settings.WEBAUTHN_ORIGIN,
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        credential_public_key=raw_public_key,
        credential_current_sign_count=stored_sign_count,
        require_user_verification=False,
    )

    return verification.new_sign_count
