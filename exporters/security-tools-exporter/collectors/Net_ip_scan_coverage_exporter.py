"""
IP Scan Coverage Collector  (Direct-API mode)
=============================================
Cross-references exposed public IPs against Rapid7 InsightVM by querying
both sources directly — no Elasticsearch intermediate dependency.

Pipeline:
  1. Read exposed IPs from the local snapshot file written by
     Net_ip_exposure_exporter (/data/ip-exposure/<domain>_latest.json).
     This file is always fresh because the exposure collector runs in Phase 2
     before this collector runs in Phase 3.

  2. Pull ALL Rapid7 assets from the InsightVM Cloud API with pagination
     and build an in-memory IP → asset detail map.
     A configurable in-memory cache avoids re-pulling every cycle; the default
     pull interval matches the main Rapid7 collector (6 hours).

  3. Cross-reference: classify each exposed IP as scanned / unscanned.

  4. Emit Prometheus gauges.

  5. Store per-IP coverage docs to security-ip-scan-coverage (Elasticsearch).

Environment variables:
  RAPID7_API_KEY                  – required; same key as GRC_rapid7_exporter
  IP_EXPOSURE_OUTPUT_DIR          – directory with ip-exposure snapshot files
                                    (default /data/ip-exposure)
  SUBDOMAIN_TARGET_DOMAIN         – target domain (default bri.co.id)
  IP_SCAN_COVERAGE_R7_TIMEOUT     – per-request timeout in seconds (default 60)
  IP_SCAN_COVERAGE_R7_PAGE_SIZE   – assets per Rapid7 page (default 100)
  IP_SCAN_COVERAGE_PULL_HOURS     – how often to re-pull Rapid7 (default 6)
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from glob import glob

import requests
from prometheus_client import Gauge

from es_store import store_ip_scan_coverage

# ── Prometheus metrics ─────────────────────────────────────────────────────────

ip_scan_coverage_exposed_total = Gauge(
    "ip_scan_coverage_exposed_total",
    "Total unique public IPs discovered from exposed subdomains",
)

ip_scan_coverage_scanned_total = Gauge(
    "ip_scan_coverage_scanned_total",
    "Exposed public IPs that are already known to Rapid7 (covered)",
)

ip_scan_coverage_unscanned_total = Gauge(
    "ip_scan_coverage_unscanned_total",
    "Exposed public IPs NOT found in Rapid7 – coverage gap",
)

ip_scan_coverage_ratio = Gauge(
    "ip_scan_coverage_ratio",
    "Fraction of exposed IPs covered by Rapid7 scans (0.0 – 1.0)",
)

ip_scan_coverage_critical_gap_total = Gauge(
    "ip_scan_coverage_critical_gap_total",
    "Unscanned exposed IPs that have open ports detected (high-risk gap)",
)

# ── In-memory Rapid7 cache ────────────────────────────────────────────────────
# Stores { ip -> {last_scan_end, risk_score, total_vulnerabilities,
#                 critical_vulnerabilities, is_stale, assessed} }

_r7_cache: dict = {}
_r7_cache_ts: datetime | None = None
_R7_BASE_URL = "https://ap.api.insight.rapid7.com/vm/v4/integration/assets"


def _cache_is_stale():
    global _r7_cache_ts
    if _r7_cache_ts is None:
        return True
    pull_hours = int(os.getenv("IP_SCAN_COVERAGE_PULL_HOURS", "6"))
    elapsed = (datetime.now(timezone.utc) - _r7_cache_ts).total_seconds()
    return elapsed >= pull_hours * 3600


def _is_stale_asset(last_scan_end, threshold_days=30):
    if not last_scan_end:
        return True
    try:
        dt = datetime.fromisoformat(last_scan_end.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days > threshold_days
    except (ValueError, TypeError):
        return True


def _pull_rapid7_assets_from_es():
    """Read Rapid7 asset IPs from the already-populated security-rapid7-assets
    Elasticsearch index.  This avoids re-paginating the full Rapid7 API (65+
    pages) every cycle and makes Phase 3 nearly instantaneous.

    Returns the same dict shape as _pull_rapid7_assets():
        { ip -> {last_scan_end, risk_score, total_vulnerabilities,
                 critical_vulnerabilities, is_stale, assessed} }
    Returns {} on any error so the API fallback can take over.
    """
    es_host = os.getenv("ES_HOST", "").strip()
    if not es_host:
        return {}
    try:
        r = requests.post(
            f"{es_host}/security-rapid7-assets/_search",
            json={
                "size": 10000,
                "_source": [
                    "ip", "risk_score", "critical_vulnerabilities",
                    "total_vulnerabilities", "is_stale",
                    "last_scan_end", "assessed_for_vulnerabilities",
                ],
            },
            timeout=30,
            headers={"Content-Type": "application/json"},
        )
        if r.status_code != 200:
            logging.warning(
                "ip_scan_coverage: ES rapid7-assets query failed (%s)", r.status_code
            )
            return {}
        hits = r.json().get("hits", {}).get("hits", [])
        ip_map = {}
        for hit in hits:
            src = hit.get("_source", {})
            ip = src.get("ip", "")
            if not ip:
                continue
            ip_map[ip] = {
                "last_scan_end": src.get("last_scan_end", ""),
                "risk_score": src.get("risk_score", 0.0),
                "total_vulnerabilities": src.get("total_vulnerabilities", 0),
                "critical_vulnerabilities": src.get("critical_vulnerabilities", 0),
                "is_stale": src.get("is_stale", True),
                "assessed_for_vulnerabilities": src.get("assessed_for_vulnerabilities", False),
            }
        logging.info(
            "ip_scan_coverage: loaded %s Rapid7 assets from Elasticsearch", len(ip_map)
        )
        return ip_map
    except Exception as exc:
        logging.warning("ip_scan_coverage: ES rapid7-assets read failed: %s", exc)
        return {}


def _pull_rapid7_assets(api_key):
    """Pull all Rapid7 assets from the InsightVM API and return an IP map.

    Returns dict { ip: {last_scan_end, risk_score, total_vulnerabilities,
                         critical_vulnerabilities, is_stale, assessed} }
    """
    headers = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json",
    }
    timeout = int(os.getenv("IP_SCAN_COVERAGE_R7_TIMEOUT", "60"))
    page_size = int(os.getenv("IP_SCAN_COVERAGE_R7_PAGE_SIZE", "100"))

    ip_map = {}
    cursor = None
    page = 0

    while True:
        body = {"size": page_size}
        if cursor:
            body["cursor"] = cursor

        try:
            r = requests.post(_R7_BASE_URL, headers=headers, json=body, timeout=timeout)
            r.raise_for_status()
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "?"
            logging.error("ip_scan_coverage: Rapid7 API error (status=%s): %s", status, exc)
            break
        except Exception as exc:
            logging.error("ip_scan_coverage: Rapid7 API request failed: %s", exc)
            break

        data = r.json()
        assets = data.get("data", [])
        if not assets:
            break

        for asset in assets:
            ip = asset.get("ip", "")
            if not ip:
                continue
            last_scan = asset.get("last_scan_end") or asset.get("last_scan_start") or ""
            ip_map[ip] = {
                "last_scan_end": last_scan,
                "risk_score": asset.get("risk_score", 0.0),
                "total_vulnerabilities": asset.get("total_vulnerabilities", 0),
                "critical_vulnerabilities": asset.get("critical_vulnerabilities", 0),
                "is_stale": _is_stale_asset(last_scan),
                "assessed_for_vulnerabilities": asset.get("assessed_for_vulnerabilities", False),
            }

        page += 1
        if page % 20 == 0:
            logging.info("ip_scan_coverage: pulled %s Rapid7 assets so far...", len(ip_map))

        cursor = data.get("metadata", {}).get("cursor")
        if not cursor:
            break

        time.sleep(0.05)

    logging.info("ip_scan_coverage: pulled total %s Rapid7 assets from API", len(ip_map))
    return ip_map


def _get_rapid7_ip_map(api_key):
    """Return the cached Rapid7 IP map, refreshing if stale.

    Refresh strategy (fastest first):
    1. Read from security-rapid7-assets Elasticsearch index (populated by
       GRC_rapid7_exporter which runs in Phase 2 every cycle).
    2. Fall back to direct Rapid7 API pagination if ES has no data.
    """
    global _r7_cache, _r7_cache_ts
    if _cache_is_stale():
        logging.info("ip_scan_coverage: refreshing Rapid7 asset cache from Elasticsearch...")
        fresh = _pull_rapid7_assets_from_es()
        if not fresh:
            logging.info(
                "ip_scan_coverage: ES empty/unavailable, falling back to Rapid7 API..."
            )
            fresh = _pull_rapid7_assets(api_key)
        if fresh:
            _r7_cache = fresh
            _r7_cache_ts = datetime.now(timezone.utc)
        else:
            logging.warning("ip_scan_coverage: Rapid7 pull returned 0 assets; using previous cache")
    return _r7_cache


# ── Local snapshot reader ──────────────────────────────────────────────────────

def _sanitize_name(value):
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    cleaned = "".join(ch if ch in allowed else "_" for ch in value.lower())
    return cleaned or "domain"


def _read_exposed_ips(output_dir, domain_key):
    """Read the latest ip-exposure JSON snapshot and return:
        { ip -> {subdomain, target_domain, provider, has_open_ports, open_ports} }
    """
    latest = os.path.join(output_dir, f"{domain_key}_latest.json")

    # Fallback to newest timestamped snapshot if _latest isn't there yet
    if not os.path.exists(latest) or os.path.getsize(latest) == 0:
        pattern = os.path.join(output_dir, f"{domain_key}_2*.json")
        candidates = sorted(glob(pattern), key=os.path.getmtime, reverse=True)
        for c in candidates:
            if os.path.getsize(c) > 0:
                latest = c
                logging.warning("ip_scan_coverage: using fallback snapshot %s", latest)
                break

    if not os.path.exists(latest):
        logging.warning("ip_scan_coverage: no ip-exposure snapshot found in %s", output_dir)
        return {}

    try:
        with open(latest, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception as exc:
        logging.error("ip_scan_coverage: failed reading snapshot %s: %s", latest, exc)
        return {}

    target_domain = payload.get("target_domain", "")
    ip_details = payload.get("ip_details", {})
    shodan_data = payload.get("shodan", {})

    ip_meta = {}
    for ip in payload.get("public_ips", []):
        detail = ip_details.get(ip, {})
        shodan = shodan_data.get(ip, {})
        open_ports = shodan.get("ports", []) if shodan else []
        subdomains = detail.get("subdomains", [])
        ip_meta[ip] = {
            "subdomain": subdomains[0] if subdomains else "",
            "subdomains": subdomains,
            "target_domain": target_domain,
            "provider": detail.get("provider", "Unknown"),
            "has_open_ports": bool(open_ports),
            "open_ports": open_ports,
        }

    logging.info(
        "ip_scan_coverage: read %s exposed IPs from snapshot %s",
        len(ip_meta), latest,
    )
    return ip_meta


# ── Document builder ───────────────────────────────────────────────────────────

def _build_coverage_docs(exposed_ip_meta, rapid7_ip_map, timestamp):
    """Return one ES document per exposed IP with scan status and risk enrichment."""
    docs = []
    for ip in sorted(exposed_ip_meta.keys()):
        meta = exposed_ip_meta[ip]
        r7 = rapid7_ip_map.get(ip)
        is_scanned = r7 is not None

        doc = {
            "@timestamp": timestamp,
            "ip": ip,
            "subdomain": meta["subdomain"],
            "subdomains": meta["subdomains"],
            "target_domain": meta["target_domain"],
            "provider": meta["provider"],
            "has_open_ports": meta["has_open_ports"],
            "open_ports": meta["open_ports"],
            "is_scanned_by_rapid7": is_scanned,
            "scan_status": "scanned" if is_scanned else "unscanned",
            "coverage_gap": not is_scanned,
            # Rapid7 enrichment – empty/zero when not scanned
            "rapid7_last_scan_end": r7["last_scan_end"] if r7 else "",
            "rapid7_risk_score": r7["risk_score"] if r7 else 0.0,
            "rapid7_total_vulnerabilities": r7["total_vulnerabilities"] if r7 else 0,
            "rapid7_critical_vulnerabilities": r7["critical_vulnerabilities"] if r7 else 0,
            "rapid7_is_stale": r7["is_stale"] if r7 else False,
            "rapid7_assessed": r7["assessed_for_vulnerabilities"] if r7 else False,
        }
        docs.append(doc)
    return docs


# ── Public entry point ─────────────────────────────────────────────────────────

def collect_ip_scan_coverage():
    api_key = os.getenv("RAPID7_API_KEY", "").strip()
    if not api_key:
        logging.warning("ip_scan_coverage: RAPID7_API_KEY not set; skipping")
        return

    target_domain = os.getenv("SUBDOMAIN_TARGET_DOMAIN", "bri.co.id").strip().lower()
    domain_key = _sanitize_name(target_domain)
    output_dir = os.getenv("IP_EXPOSURE_OUTPUT_DIR", "/data/ip-exposure").strip()

    # 1. Read local snapshot for exposed IPs
    exposed_ip_meta = _read_exposed_ips(output_dir, domain_key)
    if not exposed_ip_meta:
        logging.warning("ip_scan_coverage: no exposed IPs found; nothing to cross-reference")
        ip_scan_coverage_exposed_total.set(0)
        ip_scan_coverage_scanned_total.set(0)
        ip_scan_coverage_unscanned_total.set(0)
        ip_scan_coverage_ratio.set(0)
        ip_scan_coverage_critical_gap_total.set(0)
        return

    # 2. Pull Rapid7 assets directly from API (cached per pull interval)
    rapid7_ip_map = _get_rapid7_ip_map(api_key)

    # 3. Cross-reference
    exposed_ips = set(exposed_ip_meta.keys())
    scanned = {ip for ip in exposed_ips if ip in rapid7_ip_map}
    unscanned = exposed_ips - scanned

    total_exposed = len(exposed_ips)
    total_scanned = len(scanned)
    total_unscanned = len(unscanned)
    ratio = total_scanned / total_exposed if total_exposed > 0 else 0.0
    critical_gap = sum(
        1 for ip in unscanned if exposed_ip_meta[ip]["has_open_ports"]
    )

    # 4. Emit Prometheus gauges
    ip_scan_coverage_exposed_total.set(total_exposed)
    ip_scan_coverage_scanned_total.set(total_scanned)
    ip_scan_coverage_unscanned_total.set(total_unscanned)
    ip_scan_coverage_ratio.set(ratio)
    ip_scan_coverage_critical_gap_total.set(critical_gap)

    logging.info(
        "ip_scan_coverage: exposed=%s scanned=%s unscanned=%s ratio=%.2f critical_gap=%s",
        total_exposed, total_scanned, total_unscanned, ratio, critical_gap,
    )

    # 5. Store per-IP records to Elasticsearch
    timestamp = datetime.now(timezone.utc).isoformat()
    docs = _build_coverage_docs(exposed_ip_meta, rapid7_ip_map, timestamp)
    if docs:
        store_ip_scan_coverage(docs)
