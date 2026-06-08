from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..core.config import CONFIG

_ANALYTICS_DIR = Path(CONFIG.portal_data_dir).parent / "soc_analytics"
_LATEST_FILE = _ANALYTICS_DIR / "latest.json"


def analytics_path() -> Path:
    return _LATEST_FILE


def load_analytics() -> dict[str, Any] | None:
    """Return the latest analytics JSON, or None if it hasn't been generated yet."""
    try:
        if _LATEST_FILE.exists():
            return json.loads(_LATEST_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    return None


def save_analytics(payload: dict[str, Any]) -> None:
    """Persist analytics payload atomically."""
    _ANALYTICS_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _LATEST_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(_LATEST_FILE)


def analytics_age_seconds() -> float | None:
    """Return how old the cached analytics file is, or None if absent."""
    try:
        if _LATEST_FILE.exists():
            mtime = _LATEST_FILE.stat().st_mtime
            import time
            return time.time() - mtime
    except OSError:
        pass
    return None
