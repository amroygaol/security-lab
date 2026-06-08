from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..core.config import CONFIG


def _portal_dir() -> Path:
    path = Path(CONFIG.portal_data_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _dataset_path(name: str) -> Path:
    return _portal_dir() / name


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _read_or_seed(path: Path, seed_data: Any) -> Any:
    if not path.exists():
        path.write_text(json.dumps(seed_data, indent=2), encoding="utf-8")
        return seed_data

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        data = seed_data
        path.write_text(json.dumps(seed_data, indent=2), encoding="utf-8")
    return data


def _normalize_username(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "", (value or "").strip().lower())


def hash_secret(secret: str) -> str:
    salt = secrets.token_hex(16)
    iterations = 200_000
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${digest.hex()}"


def verify_secret(secret: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_str, salt, expected = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_str)
    except ValueError:
        return False

    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt.encode("utf-8"), iterations)
    return hmac.compare_digest(digest.hex(), expected)


def _seed_users() -> list[dict[str, Any]]:
    admin_user = _normalize_username(CONFIG.auth_bootstrap_admin_user)
    return [
        {
            "username": admin_user,
            "full_name": "Portal Administrator",
            "email": "admin@local",
            "role": "admin",
            "enabled": True,
            "password_hash": hash_secret(CONFIG.auth_bootstrap_admin_password),
            "saml_subject": "",
            "webauthn_user_id": secrets.token_urlsafe(24),
            "webauthn_credentials": [],
            "passkey_code_hash": "",
            "created_at_utc": _utc_now(),
            "updated_at_utc": _utc_now(),
        }
    ]


def _seed_auth_config() -> dict[str, Any]:
    return {
        "auth_enabled": True,
        "providers": {
            "local": True,
            "saml": True,
            "passkey": True,
        },
        "saml": {
            "enabled": False,
            "auto_provision": True,
            "allowed_domains": [],
            "entity_id": "security-architecture-portal",
            "idp_sso_url": "",
            "idp_metadata_url": "",
        },
        "passkey": {
            "enabled": False,
            "auto_provision": False,
            "display_name": CONFIG.auth_passkey_rp_name,
            "rp_id": CONFIG.auth_passkey_rp_id,
            "origin": CONFIG.auth_passkey_origin,
            "note": "Use a browser or device authenticator backed by WebAuthn passkeys.",
        },
    }


def _ensure_user_shape(user: dict[str, Any]) -> dict[str, Any]:
    normalized_username = _normalize_username(str(user.get("username", "")))
    shaped_user = dict(user)
    shaped_user["username"] = normalized_username
    shaped_user["webauthn_user_id"] = str(shaped_user.get("webauthn_user_id", "")).strip() or secrets.token_urlsafe(24)
    credentials = shaped_user.get("webauthn_credentials", [])
    shaped_user["webauthn_credentials"] = credentials if isinstance(credentials, list) else []
    shaped_user["passkey_code_hash"] = str(shaped_user.get("passkey_code_hash", ""))
    return shaped_user


def load_users() -> list[dict[str, Any]]:
    users = _read_or_seed(_dataset_path("auth_users.json"), _seed_users())
    if not isinstance(users, list):
        users = _seed_users()
    normalized_users = [_ensure_user_shape(user) for user in users if isinstance(user, dict)]
    if normalized_users != users:
        save_users(normalized_users)
    return normalized_users


def save_users(rows: list[dict[str, Any]]) -> None:
    _dataset_path("auth_users.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")


def load_auth_config() -> dict[str, Any]:
    config = _read_or_seed(_dataset_path("auth_config.json"), _seed_auth_config())
    if not isinstance(config, dict):
        config = _seed_auth_config()
    return config


def save_auth_config(config: dict[str, Any]) -> None:
    _dataset_path("auth_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")


def find_user(username: str) -> dict[str, Any] | None:
    key = _normalize_username(username)
    for user in load_users():
        if _normalize_username(str(user.get("username", ""))) == key:
            return user
    return None


def upsert_user(user_input: dict[str, Any], password: str = "", passkey_code: str = "") -> dict[str, Any]:
    users = load_users()
    username = _normalize_username(str(user_input.get("username", "")))
    if not username:
        raise ValueError("Username is required.")

    now = _utc_now()
    existing_idx = next(
        (
            idx
            for idx, user in enumerate(users)
            if _normalize_username(str(user.get("username", ""))) == username
        ),
        -1,
    )

    existing = users[existing_idx] if existing_idx >= 0 else {}
    updated = {
        "username": username,
        "full_name": str(user_input.get("full_name", existing.get("full_name", ""))).strip(),
        "email": str(user_input.get("email", existing.get("email", ""))).strip().lower(),
        "role": str(user_input.get("role", existing.get("role", "viewer"))).strip().lower() or "viewer",
        "enabled": bool(user_input.get("enabled", existing.get("enabled", True))),
        "password_hash": str(existing.get("password_hash", "")),
        "saml_subject": str(user_input.get("saml_subject", existing.get("saml_subject", ""))).strip(),
        "webauthn_user_id": str(existing.get("webauthn_user_id", "")).strip() or secrets.token_urlsafe(24),
        "webauthn_credentials": existing.get("webauthn_credentials", []),
        "passkey_code_hash": str(existing.get("passkey_code_hash", "")),
        "created_at_utc": str(existing.get("created_at_utc", now)),
        "updated_at_utc": now,
    }

    if password.strip():
        updated["password_hash"] = hash_secret(password.strip())
    if passkey_code.strip():
        updated["passkey_code_hash"] = hash_secret(passkey_code.strip())

    if existing_idx >= 0:
        users[existing_idx] = updated
    else:
        users.append(updated)

    save_users(users)
    return updated


def delete_user(username: str) -> bool:
    key = _normalize_username(username)
    if key == _normalize_username(CONFIG.auth_bootstrap_admin_user):
        return False

    users = load_users()
    kept = [row for row in users if _normalize_username(str(row.get("username", ""))) != key]
    if len(kept) == len(users):
        return False
    save_users(kept)
    return True


def authenticate_local(username: str, password: str) -> dict[str, Any] | None:
    user = find_user(username)
    if not user or not user.get("enabled", True):
        return None

    password_hash = str(user.get("password_hash", ""))
    if not password_hash:
        return None

    if not verify_secret(password, password_hash):
        return None

    return user


def authenticate_passkey(username: str, passkey_code: str) -> dict[str, Any] | None:
    user = find_user(username)
    if not user or not user.get("enabled", True):
        return None

    passkey_hash = str(user.get("passkey_code_hash", ""))
    if not passkey_hash:
        return None

    if not verify_secret(passkey_code, passkey_hash):
        return None

    return user


def register_passkey(username: str, passkey_code: str) -> dict[str, Any] | None:
    key = _normalize_username(username)
    if not key or not passkey_code.strip():
        return None

    users = load_users()
    for idx, user in enumerate(users):
        if _normalize_username(str(user.get("username", ""))) != key:
            continue
        if not bool(user.get("enabled", True)):
            return None

        user["passkey_code_hash"] = hash_secret(passkey_code.strip())
        user["updated_at_utc"] = _utc_now()
        users[idx] = user
        save_users(users)
        return user

    return None


def register_local_user(
    username: str,
    password: str,
    full_name: str = "",
    email: str = "",
) -> dict[str, Any]:
    normalized_username = _normalize_username(username)
    if not normalized_username:
        raise ValueError("Username is required.")
    if len(password.strip()) < 8:
        raise ValueError("Password must be at least 8 characters.")

    existing = find_user(normalized_username)
    if existing is not None:
        raise ValueError("Username is already registered.")

    created = upsert_user(
        {
            "username": normalized_username,
            "full_name": full_name.strip() or normalized_username,
            "email": email.strip().lower(),
            "role": "viewer",
            "enabled": True,
            "saml_subject": "",
        },
        password=password.strip(),
    )
    return created


def update_user_profile(
    username: str,
    *,
    full_name: str,
    email: str,
    role: str,
    enabled: bool,
    saml_subject: str,
) -> dict[str, Any] | None:
    key = _normalize_username(username)
    if not key:
        return None

    bootstrap_admin = _normalize_username(CONFIG.auth_bootstrap_admin_user)
    if key == bootstrap_admin and not enabled:
        raise ValueError("Bootstrap admin cannot be disabled.")

    users = load_users()
    for idx, user in enumerate(users):
        if _normalize_username(str(user.get("username", ""))) != key:
            continue

        user["full_name"] = full_name.strip() or key
        user["email"] = email.strip().lower()
        user["role"] = role.strip().lower() or "viewer"
        user["enabled"] = bool(enabled)
        user["saml_subject"] = saml_subject.strip()
        user["updated_at_utc"] = _utc_now()
        users[idx] = user
        save_users(users)
        return user

    return None


def reset_local_password(username: str, new_password: str) -> dict[str, Any] | None:
    if len(new_password.strip()) < 8:
        raise ValueError("New password must be at least 8 characters.")

    key = _normalize_username(username)
    if not key:
        return None

    users = load_users()
    for idx, user in enumerate(users):
        if _normalize_username(str(user.get("username", ""))) != key:
            continue
        if not bool(user.get("enabled", True)):
            return None

        user["password_hash"] = hash_secret(new_password.strip())
        user["updated_at_utc"] = _utc_now()
        users[idx] = user
        save_users(users)
        return user

    return None


def reset_user_passkey(username: str, new_passkey_code: str) -> dict[str, Any] | None:
    if len(new_passkey_code.strip()) < 6:
        raise ValueError("Passkey code must be at least 6 characters.")
    return register_passkey(username, new_passkey_code)


def clear_user_passkeys(username: str) -> dict[str, Any] | None:
    key = _normalize_username(username)
    if not key:
        return None

    users = load_users()
    for idx, user in enumerate(users):
        if _normalize_username(str(user.get("username", ""))) != key:
            continue

        user["webauthn_credentials"] = []
        user["passkey_code_hash"] = ""
        user["updated_at_utc"] = _utc_now()
        users[idx] = user
        save_users(users)
        return user

    return None


def change_local_password(username: str, current_password: str, new_password: str) -> dict[str, Any] | None:
    if len(new_password.strip()) < 8:
        raise ValueError("New password must be at least 8 characters.")

    verified_user = authenticate_local(username, current_password)
    if not verified_user:
        return None

    key = _normalize_username(username)
    users = load_users()
    for idx, user in enumerate(users):
        if _normalize_username(str(user.get("username", ""))) != key:
            continue
        if not bool(user.get("enabled", True)):
            return None

        user["password_hash"] = hash_secret(new_password.strip())
        user["updated_at_utc"] = _utc_now()
        users[idx] = user
        save_users(users)
        return user

    return None


def reset_password_with_passkey(username: str, passkey_code: str, new_password: str) -> dict[str, Any] | None:
    if len(new_password.strip()) < 8:
        raise ValueError("New password must be at least 8 characters.")

    verified_user = authenticate_passkey(username, passkey_code)
    if not verified_user:
        return None

    key = _normalize_username(username)
    users = load_users()
    for idx, user in enumerate(users):
        if _normalize_username(str(user.get("username", ""))) != key:
            continue
        if not bool(user.get("enabled", True)):
            return None

        user["password_hash"] = hash_secret(new_password.strip())
        user["updated_at_utc"] = _utc_now()
        users[idx] = user
        save_users(users)
        return user

    return None


def authenticate_saml_identity(subject: str, email: str, full_name: str) -> dict[str, Any] | None:
    config = load_auth_config()
    saml_cfg = config.get("saml", {}) if isinstance(config, dict) else {}
    if not bool(saml_cfg.get("enabled", False)):
        return None

    normalized_subject = str(subject or "").strip()
    normalized_email = str(email or "").strip().lower()
    allowed_domains = [str(domain).strip().lower() for domain in saml_cfg.get("allowed_domains", []) if str(domain).strip()]

    if allowed_domains and normalized_email:
        email_domain = normalized_email.split("@")[-1].lower()
        if email_domain not in allowed_domains:
            return None

    users = load_users()
    candidate = None

    if normalized_subject:
        candidate = next((u for u in users if str(u.get("saml_subject", "")).strip() == normalized_subject), None)

    if candidate is None and normalized_email:
        candidate = next((u for u in users if str(u.get("email", "")).strip().lower() == normalized_email), None)

    if candidate and not candidate.get("enabled", True):
        return None

    if candidate:
        return candidate

    if not bool(saml_cfg.get("auto_provision", False)):
        return None

    base_username = _normalize_username(normalized_email.split("@")[0] if "@" in normalized_email else normalized_subject)
    if not base_username:
        base_username = f"saml_user_{secrets.randbelow(1_000_000):06d}"

    username = base_username
    suffix = 1
    existing_usernames = {_normalize_username(str(u.get("username", ""))) for u in users}
    while username in existing_usernames:
        suffix += 1
        username = f"{base_username}{suffix}"

    created = upsert_user(
        {
            "username": username,
            "full_name": full_name.strip() or normalized_email or username,
            "email": normalized_email,
            "role": "viewer",
            "enabled": True,
            "saml_subject": normalized_subject,
        },
        password="",
    )
    return created

