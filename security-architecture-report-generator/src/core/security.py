from __future__ import annotations

import re
from typing import Iterable


_ALLOWED_EXTENSIONS = {".xlsx"}
_MAX_TEXT_LEN = 12000


def validate_file_name(file_name: str) -> bool:
    lowered = file_name.lower().strip()
    return any(lowered.endswith(ext) for ext in _ALLOWED_EXTENSIONS)


def validate_file_size(file_size_bytes: int, max_upload_mb: int) -> bool:
    max_bytes = max_upload_mb * 1024 * 1024
    return 0 < file_size_bytes <= max_bytes


def sanitize_for_llm(text: str) -> str:
    """Strip control chars and constrain prompt size to reduce prompt injection surface."""
    without_ctrl = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)
    without_fences = without_ctrl.replace("```", "'''")
    compact = re.sub(r"\s+", " ", without_fences).strip()
    return compact[:_MAX_TEXT_LEN]


def sanitize_many(items: Iterable[str]) -> list[str]:
    return [sanitize_for_llm(str(item)) for item in items if str(item).strip()]

