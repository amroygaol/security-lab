from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ..core.config import CONFIG


def _history_dir() -> Path:
    path = Path(CONFIG.report_history_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_report(report_markdown: str, source_name: str) -> dict[str, str]:
    now = datetime.now(UTC)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    safe_source = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in source_name)[:80]
    base_name = f"{stamp}_{safe_source or 'report'}"

    history = _history_dir()
    md_path = history / f"{base_name}.md"
    meta_path = history / f"{base_name}.json"

    md_path.write_text(report_markdown, encoding="utf-8")
    meta = {
        "id": base_name,
        "created_at_utc": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source_name,
        "markdown_file": md_path.name,
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def list_reports(limit: int = 200) -> list[dict[str, str]]:
    history = _history_dir()
    rows: list[dict[str, str]] = []
    for meta_file in sorted(history.glob("*.json"), reverse=True):
        try:
            data = json.loads(meta_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        md_path = history / data.get("markdown_file", "")
        if not md_path.exists():
            continue
        rows.append(
            {
                "id": data.get("id", meta_file.stem),
                "created_at_utc": data.get("created_at_utc", "unknown"),
                "source": data.get("source", "unknown"),
                "markdown_path": str(md_path),
            }
        )
        if len(rows) >= limit:
            break
    return rows


def load_report(markdown_path: str) -> str:
    return Path(markdown_path).read_text(encoding="utf-8")

