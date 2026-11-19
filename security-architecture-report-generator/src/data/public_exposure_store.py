from __future__ import annotations

import json
from typing import Any
from urllib import error, request

from ..core.config import CONFIG


def _candidate_endpoints() -> list[str]:
    base_url = CONFIG.elasticsearch_url.rstrip("/")
    endpoints = [f"{base_url}/{CONFIG.security_assets_index}/_search"]

    replacements = {
        "http://localhost:9200": "http://elasticsearch:9200",
        "http://127.0.0.1:9200": "http://elasticsearch:9200",
        "http://localhost": "http://elasticsearch",
        "http://127.0.0.1": "http://elasticsearch",
    }
    fallback_base = replacements.get(base_url)
    if fallback_base:
        fallback_endpoint = f"{fallback_base}/{CONFIG.security_assets_index}/_search"
        if fallback_endpoint not in endpoints:
            endpoints.append(fallback_endpoint)

    return endpoints


def load_public_exposures() -> list[dict[str, Any]]:
    query = {
        "size": CONFIG.security_assets_fetch_size,
        "track_total_hits": True,
        "_source": [
            "subdomain",
            "cname",
            "ip_addresses",
            "provider",
            "ssl_issuer_org",
            "ssl_not_after",
            "has_public_ip",
            "@timestamp",
        ],
        "query": {
            "bool": {
                "should": [
                    {"term": {"has_public_ip": True}},
                    {"exists": {"field": "ip_addresses"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "sort": [
            {"subdomain.keyword": {"order": "asc", "unmapped_type": "keyword"}},
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
        ip_addresses = source.get("ip_addresses") or []
        if not isinstance(ip_addresses, list):
            ip_addresses = [str(ip_addresses)]

        if not ip_addresses and not source.get("has_public_ip"):
            continue

        rows.append(
            {
                "subdomain": source.get("subdomain", ""),
                "cname": source.get("cname", ""),
                "ip_addresses": ip_addresses,
                "provider": source.get("provider", ""),
                "ssl_issuer_org": source.get("ssl_issuer_org", ""),
                "ssl_not_after": source.get("ssl_not_after", ""),
                "timestamp": source.get("@timestamp", ""),
            }
        )
    return rows
