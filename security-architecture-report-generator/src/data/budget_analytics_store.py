from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..core.config import CONFIG

_ANALYTICS_DIR = Path(CONFIG.portal_data_dir).parent / "budget_analytics"
_LATEST_FILE = _ANALYTICS_DIR / "latest.json"


def load_budget_analytics() -> dict[str, Any] | None:
    try:
        if _LATEST_FILE.exists():
            return json.loads(_LATEST_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    return None


def save_budget_analytics(payload: dict[str, Any]) -> None:
    _ANALYTICS_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _LATEST_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(_LATEST_FILE)


def budget_analytics_age_seconds() -> float | None:
    try:
        if _LATEST_FILE.exists():
            return time.time() - _LATEST_FILE.stat().st_mtime
    except OSError:
        pass
    return None
