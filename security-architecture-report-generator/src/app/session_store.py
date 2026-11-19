from __future__ import annotations

import json
import secrets
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..core.config import CONFIG

_LOCK = threading.Lock()


def _store_path() -> Path:
    return Path(CONFIG.portal_data_dir) / "sessions.json"


def _load() -> dict[str, Any]:
    p = _store_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(data: dict[str, Any]) -> None:
    p = _store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, default=str), encoding="utf-8")


def _cleanup(data: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    return {k: v for k, v in data.items() if str(v.get("expires_at_utc", "")) > now}


def create_session(user: dict[str, Any], method: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(UTC) + timedelta(minutes=CONFIG.auth_session_timeout_minutes)).isoformat()
    with _LOCK:
        data = _cleanup(_load())
        data[token] = {
            "username": str(user.get("username", "")).strip().lower(),
            "method": method,
            "expires_at_utc": expires,
        }
        _save(data)
    return token


def get_session(token: str) -> dict[str, Any] | None:
    if not token or not token.strip():
        return None
    with _LOCK:
        data = _load()
    record = data.get(token.strip())
    if not record:
        return None
    try:
        expires = datetime.fromisoformat(str(record["expires_at_utc"]))
    except (KeyError, ValueError):
        return None
    if datetime.now(UTC) >= expires:
        return None
    return record


def delete_session(token: str) -> None:
    if not token or not token.strip():
        return
    with _LOCK:
        data = _load()
        data.pop(token.strip(), None)
        _save(data)


def renew_session(token: str) -> None:
    """Extend the expiry of an existing valid session."""
    if not token or not token.strip():
        return
    with _LOCK:
        data = _load()
        record = data.get(token.strip())
        if not record:
            return
        record["expires_at_utc"] = (
            datetime.now(UTC) + timedelta(minutes=CONFIG.auth_session_timeout_minutes)
        ).isoformat()
        data[token.strip()] = record
        _save(data)
