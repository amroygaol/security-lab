from __future__ import annotations

import json
from typing import Any
from urllib import error, request

from ..core.config import CONFIG


def _candidate_endpoints() -> list[str]:
    base_url = CONFIG.elasticsearch_url.rstrip("/")
    endpoints = [f"{base_url}/security-jira-soc-tickets/_search"]

    replacements = {
        "http://localhost:9200": "http://elasticsearch:9200",
        "http://127.0.0.1:9200": "http://elasticsearch:9200",
        "http://localhost": "http://elasticsearch",
        "http://127.0.0.1": "http://elasticsearch",
    }
    fallback_base = replacements.get(base_url)
    if fallback_base:
        fallback_endpoint = f"{fallback_base}/security-jira-soc-tickets/_search"
        if fallback_endpoint not in endpoints:
            endpoints.append(fallback_endpoint)

    return endpoints


def load_soc_tickets() -> list[dict[str, Any]]:
    query = {
        "size": 1000,
        "track_total_hits": True,
        "_source": [
            "key",
            "summary",
            "description",
            "status",
            "created",
            "updated",
            "reporter",
            "assignee",
            "priority",
            "issue_type",
            "labels",
            "detection_id",
            "start_time",
            "alert_name",
            "risk_score",
            "severity",
            "taktik",
            "teknik",
            "@timestamp",
        ],
        "sort": [{"created": {"order": "desc"}}],
    }

    payload: dict[str, Any] | None = None
    for endpoint in _candidate_endpoints():
        req = request.Request(
            endpoint,
            data=json.dumps(query).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8"))
                break
        except (error.URLError, error.HTTPError, TimeoutError, json.JSONDecodeError):
            continue

    if payload is None:
        return []

    rows: list[dict[str, Any]] = []
    for hit in payload.get("hits", {}).get("hits", []):
        source = hit.get("_source", {})
        rows.append(
            {
                "key": source.get("key", ""),
                "summary": source.get("summary", ""),
                "description": source.get("description", ""),
                "status": source.get("status", ""),
                "created": source.get("created", ""),
                "updated": source.get("updated", ""),
                "reporter": source.get("reporter", ""),
                "assignee": source.get("assignee", ""),
                "priority": source.get("priority", ""),
                "issue_type": source.get("issue_type", ""),
                "labels": source.get("labels", []),
                "detection_id": source.get("detection_id", ""),
                "start_time": source.get("start_time", ""),
                "alert_name": source.get("alert_name", ""),
                "risk_score": source.get("risk_score", ""),
                "severity": source.get("severity", ""),
                "taktik": source.get("taktik", ""),
                "teknik": source.get("teknik", ""),
                "timestamp": source.get("@timestamp", ""),
            }
        )
    return rows
