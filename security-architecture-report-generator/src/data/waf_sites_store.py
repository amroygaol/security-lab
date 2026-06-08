from __future__ import annotations

import json
from typing import Any
from urllib import error, request

from ..core.config import CONFIG

_WAF_SITES_INDEX = "security-imperva-sites"


def _candidate_endpoints() -> list[str]:
    base_url = CONFIG.elasticsearch_url.rstrip("/")
    endpoints = [f"{base_url}/{_WAF_SITES_INDEX}/_search"]

    replacements = {
        "http://localhost:9200": "http://elasticsearch:9200",
        "http://127.0.0.1:9200": "http://elasticsearch:9200",
        "http://localhost": "http://elasticsearch",
        "http://127.0.0.1": "http://elasticsearch",
    }
    fallback_base = replacements.get(base_url)
    if fallback_base:
        fallback_endpoint = f"{fallback_base}/{_WAF_SITES_INDEX}/_search"
        if fallback_endpoint not in endpoints:
            endpoints.append(fallback_endpoint)

    return endpoints


def load_waf_sites() -> list[dict[str, Any]]:
    query = {
        "size": CONFIG.security_assets_fetch_size,
        "track_total_hits": True,
        "_source": [
            "domain",
            "ips",
            "status",
            "ddos_protection",
            "waf_mode",
            "@timestamp",
        ],
        "query": {"match_all": {}},
        "sort": [
            {"domain.keyword": {"order": "asc", "unmapped_type": "keyword"}},
        ],
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

        ips = source.get("ips") or []
        if not isinstance(ips, list):
            ips = [str(ips)] if ips else []

        rows.append(
            {
                "domain": source.get("domain", ""),
                "ips": ips,
                "status": source.get("status", ""),
                "ddos_protection": source.get("ddos_protection", False),
                "waf_mode": source.get("waf_mode", ""),
                "timestamp": source.get("@timestamp", ""),
            }
        )
    return rows
