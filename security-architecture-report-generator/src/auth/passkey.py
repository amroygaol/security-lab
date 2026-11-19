from __future__ import annotations

import base64
import json
from typing import Any

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .store import find_user, load_auth_config, load_users, save_users
from ..core.config import CONFIG


def _bytes_to_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _get_passkey_settings() -> dict[str, str]:
    auth_config = load_auth_config()
    passkey_cfg = auth_config.get("passkey", {}) if isinstance(auth_config, dict) else {}
    rp_name = str(passkey_cfg.get("display_name") or CONFIG.auth_passkey_rp_name).strip() or CONFIG.auth_passkey_rp_name
    rp_id = str(passkey_cfg.get("rp_id") or CONFIG.auth_passkey_rp_id).strip() or CONFIG.auth_passkey_rp_id
    origin = str(passkey_cfg.get("origin") or CONFIG.auth_passkey_origin).strip() or CONFIG.auth_passkey_origin
    return {
        "rp_name": rp_name,
        "rp_id": rp_id,
        "origin": origin.rstrip("/"),
    }


def _credential_descriptors(user: dict[str, Any]) -> list[PublicKeyCredentialDescriptor]:
    descriptors: list[PublicKeyCredentialDescriptor] = []
    for credential in user.get("webauthn_credentials", []):
        credential_id = str(credential.get("credential_id", "")).strip()
        if not credential_id:
            continue
        descriptors.append(PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential_id)))
    return descriptors


def passkey_summary(user: dict[str, Any] | None) -> dict[str, Any]:
    if not user:
        return {"count": 0, "labels": []}
    credentials = user.get("webauthn_credentials", [])
    if not isinstance(credentials, list):
        return {"count": 0, "labels": []}
    labels = []
    for idx, credential in enumerate(credentials, start=1):
        device_type = str(credential.get("credential_device_type", "authenticator")).replace("_", " ").title()
        backed_up = bool(credential.get("credential_backed_up", False))
        suffix = "backed up" if backed_up else "single device"
        labels.append(f"Credential {idx}: {device_type}, {suffix}")
    return {"count": len(credentials), "labels": labels}


def begin_passkey_registration(user: dict[str, Any]) -> dict[str, str]:
    settings = _get_passkey_settings()
    username = str(user.get("username", "")).strip()
    full_name = str(user.get("full_name", "")).strip() or username
    webauthn_user_id = str(user.get("webauthn_user_id", "")).strip() or username
    options = generate_registration_options(
        rp_id=settings["rp_id"],
        rp_name=settings["rp_name"],
        user_id=webauthn_user_id.encode("utf-8"),
        user_name=username,
        user_display_name=full_name,
        exclude_credentials=_credential_descriptors(user),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
        ),
    )
    options_json = options_to_json(options)
    payload = json.loads(options_json)
    return {
        "options_json": options_json,
        "challenge": str(payload.get("challenge", "")),
        "rp_id": settings["rp_id"],
        "origin": settings["origin"],
    }


def finish_passkey_registration(user: dict[str, Any], credential: dict[str, Any], expected_challenge: str) -> dict[str, Any] | None:
    settings = _get_passkey_settings()
    verification = verify_registration_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(expected_challenge),
        expected_rp_id=settings["rp_id"],
        expected_origin=settings["origin"],
        require_user_verification=True,
    )

    username = str(user.get("username", "")).strip().lower()
    users = load_users()
    for idx, row in enumerate(users):
        if str(row.get("username", "")).strip().lower() != username:
            continue

        stored_credentials = row.get("webauthn_credentials", [])
        if not isinstance(stored_credentials, list):
            stored_credentials = []

        credential_id = _bytes_to_base64url(verification.credential_id)
        credential_record = {
            "credential_id": credential_id,
            "public_key": _bytes_to_base64url(verification.credential_public_key),
            "sign_count": int(verification.sign_count),
            "credential_device_type": str(verification.credential_device_type),
            "credential_backed_up": bool(verification.credential_backed_up),
            "transports": credential.get("response", {}).get("transports", []),
        }

        existing_idx = next(
            (
                cred_idx
                for cred_idx, existing in enumerate(stored_credentials)
                if str(existing.get("credential_id", "")).strip() == credential_id
            ),
            -1,
        )
        if existing_idx >= 0:
            stored_credentials[existing_idx] = credential_record
        else:
            stored_credentials.append(credential_record)

        row["webauthn_credentials"] = stored_credentials
        row["passkey_code_hash"] = ""
        users[idx] = row
        save_users(users)
        return row

    return None


def begin_passkey_authentication(username: str = "") -> dict[str, str] | None:
    settings = _get_passkey_settings()
    normalized_username = str(username or "").strip().lower()
    allow_credentials: list[PublicKeyCredentialDescriptor] = []

    if normalized_username:
        user = find_user(normalized_username)
        if not user or not bool(user.get("enabled", True)):
            return None
        allow_credentials = _credential_descriptors(user)
        if not allow_credentials:
            return None

    options = generate_authentication_options(
        rp_id=settings["rp_id"],
        allow_credentials=allow_credentials or None,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    options_json = options_to_json(options)
    payload = json.loads(options_json)
    return {
        "options_json": options_json,
        "challenge": str(payload.get("challenge", "")),
        "rp_id": settings["rp_id"],
        "origin": settings["origin"],
    }


def finish_passkey_authentication(credential: dict[str, Any], expected_challenge: str, username: str = "") -> dict[str, Any] | None:
    settings = _get_passkey_settings()
    credential_id = str(credential.get("id", "")).strip()
    if not credential_id:
        return None

    normalized_username = str(username or "").strip().lower()
    matched_user: dict[str, Any] | None = None
    matched_credential: dict[str, Any] | None = None

    for user in load_users():
        if normalized_username and str(user.get("username", "")).strip().lower() != normalized_username:
            continue
        if not bool(user.get("enabled", True)):
            continue

        for stored_credential in user.get("webauthn_credentials", []):
            if str(stored_credential.get("credential_id", "")).strip() != credential_id:
                continue
            matched_user = user
            matched_credential = stored_credential
            break
        if matched_user:
            break

    if not matched_user or not matched_credential:
        return None

    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(expected_challenge),
        expected_rp_id=settings["rp_id"],
        expected_origin=settings["origin"],
        credential_public_key=base64url_to_bytes(str(matched_credential.get("public_key", ""))),
        credential_current_sign_count=int(matched_credential.get("sign_count", 0)),
        require_user_verification=True,
    )

    users = load_users()
    for user_idx, user in enumerate(users):
        if str(user.get("username", "")).strip().lower() != str(matched_user.get("username", "")).strip().lower():
            continue
        credentials = user.get("webauthn_credentials", [])
        if not isinstance(credentials, list):
            credentials = []

        for cred_idx, stored_credential in enumerate(credentials):
            if str(stored_credential.get("credential_id", "")).strip() != credential_id:
                continue
            stored_credential["sign_count"] = int(verification.new_sign_count)
            stored_credential["credential_device_type"] = str(verification.credential_device_type)
            stored_credential["credential_backed_up"] = bool(verification.credential_backed_up)
            credentials[cred_idx] = stored_credential
            break

        user["webauthn_credentials"] = credentials
        users[user_idx] = user
        save_users(users)
        return user

    return None
