import requests
import os
import time
import logging
import ipaddress
from datetime import datetime, timezone

from prometheus_client import Gauge

from es_store import store_rapid7, store_rapid7_assets


rapid7_assets_total = Gauge(
    "rapid7_assets_total",
    "Total assets discovered by Rapid7"
)

rapid7_assets_public = Gauge(
    "rapid7_assets_public",
    "Public internet-facing assets in Rapid7"
)

rapid7_assets_internal = Gauge(
    "rapid7_assets_internal",
    "Internal/private assets in Rapid7"
)

rapid7_vuln_total = Gauge(
    "rapid7_vulnerabilities_total",
    "Total vulnerabilities in Rapid7"
)

rapid7_vuln_critical = Gauge(
    "rapid7_vulnerabilities_critical",
    "Critical vulnerabilities"
)

rapid7_vuln_high = Gauge(
    "rapid7_vulnerabilities_high",
    "High vulnerabilities"
)

# Track last full asset pull time to avoid re-pulling every 15 minutes
_last_full_pull_utc = None
# Full pull interval: 6 hours (assets don't change that fast)
_FULL_PULL_INTERVAL_HOURS = int(os.getenv("RAPID7_FULL_PULL_HOURS", "6"))


def _is_public_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return False


def _paginate_assets(headers, timeout=30):
    """Paginate through ALL Rapid7 assets. Yields individual asset dicts."""
    url = "https://ap.api.insight.rapid7.com/vm/v4/integration/assets"
    cursor = None
    page = 0

    while True:
        body = {"size": 10}
        if cursor:
            body["cursor"] = cursor

        r = requests.post(url, headers=headers, json=body, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        assets = data.get("data", [])

        if not assets:
            break

        for asset in assets:
            yield asset

        page += 1
        if page % 100 == 0:
            logging.info("Rapid7: paginated %s assets so far...", page * 10)

        cursor = data.get("metadata", {}).get("cursor")
        if not cursor:
            break

        time.sleep(0.1)


def _build_asset_doc(asset):
    """Transform a raw Rapid7 asset into an ES-friendly document."""
    ip = asset.get("ip", "")
    is_public = _is_public_ip(ip)

    tags = asset.get("tags", [])
    tag_names = [t.get("name", "") for t in tags if isinstance(t, dict)]
    site_tags = [t.get("name", "") for t in tags
                 if isinstance(t, dict) and t.get("type") == "SITE"]

    return {
        "asset_id": asset.get("id", ""),
        "ip": ip,
        "is_public": is_public,
        "network_zone": "public" if is_public else "internal",
        "os_description": asset.get("os_description", ""),
        "os_family": asset.get("os_family", ""),
        "os_name": asset.get("os_name", ""),
        "os_vendor": asset.get("os_vendor", ""),
        "os_version": asset.get("os_version", ""),
        "os_architecture": asset.get("os_architecture", ""),
        "risk_score": asset.get("risk_score", 0.0),
        "critical_vulnerabilities": asset.get("critical_vulnerabilities", 0),
        "severe_vulnerabilities": asset.get("severe_vulnerabilities", 0),
        "moderate_vulnerabilities": asset.get("moderate_vulnerabilities", 0),
        "total_vulnerabilities": asset.get("total_vulnerabilities", 0),
        "exploits": asset.get("exploits", 0),
        "malware_kits": asset.get("malware_kits", 0),
        "assessed_for_vulnerabilities": asset.get("assessed_for_vulnerabilities", False),
        "last_scan_start": asset.get("last_scan_start", ""),
        "last_scan_end": asset.get("last_scan_end", ""),
        "last_assessed_for_vulnerabilities": asset.get("last_assessed_for_vulnerabilities", ""),
        "tags": tag_names,
        "site_tags": site_tags,
        "has_critical": asset.get("critical_vulnerabilities", 0) > 0,
        "has_vulnerabilities": asset.get("total_vulnerabilities", 0) > 0,
    }


def _should_full_pull():
    """Check if enough time has passed to do a full asset pull."""
    global _last_full_pull_utc
    if _last_full_pull_utc is None:
        return True
    elapsed = (datetime.now(timezone.utc) - _last_full_pull_utc).total_seconds()
    return elapsed >= _FULL_PULL_INTERVAL_HOURS * 3600


def collect_rapid7():
    api_key = os.getenv("RAPID7_API_KEY")
    if not api_key:
        logging.warning("Rapid7: RAPID7_API_KEY not set, skipping")
        return

    headers = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json"
    }

    try:
        # --- Quick metrics (every cycle, ~2 API calls) ---
        asset_url = "https://ap.api.insight.rapid7.com/vm/v4/integration/assets"
        r = requests.post(asset_url, headers=headers, json={"size": 1}, timeout=30)
        r.raise_for_status()
        total_assets = r.json().get("metadata", {}).get("totalResources", 0)
        rapid7_assets_total.set(total_assets)

        vuln_url = "https://ap.api.insight.rapid7.com/vm/v4/integration/vulnerabilities"
        r = requests.post(vuln_url, headers=headers, json={"size": 1}, timeout=30)
        r.raise_for_status()
        total_vulns = r.json().get("metadata", {}).get("totalResources", 0)
        rapid7_vuln_total.set(total_vulns)

        logging.info("Rapid7: quick metrics - assets=%s vulns=%s", total_assets, total_vulns)

    except Exception as exc:
        logging.exception("Rapid7: quick metrics failed: %s", exc)
        return

    # --- Full asset pull (every N hours) ---
    if not _should_full_pull():
        logging.info("Rapid7: skipping full pull (last pull was recent)")
        # Still store summary metrics
        store_rapid7(total_assets, total_vulns, 0, 0)
        return

    global _last_full_pull_utc
    logging.info("Rapid7: starting full asset pull (%s assets)...", total_assets)

    asset_docs = []
    total_public = 0
    total_internal = 0
    total_critical = 0
    total_severe = 0

    try:
        for raw_asset in _paginate_assets(headers):
            doc = _build_asset_doc(raw_asset)
            asset_docs.append(doc)

            if doc["is_public"]:
                total_public += 1
            else:
                total_internal += 1
            if doc["has_critical"]:
                total_critical += 1
            if doc["severe_vulnerabilities"] > 0:
                total_severe += 1

    except Exception as exc:
        logging.exception("Rapid7: full pull interrupted after %s assets: %s",
                          len(asset_docs), exc)

    if asset_docs:
        rapid7_assets_public.set(total_public)
        rapid7_assets_internal.set(total_internal)
        rapid7_vuln_critical.set(total_critical)
        rapid7_vuln_high.set(total_severe)

        store_rapid7(total_assets, total_vulns, total_critical, total_severe)
        store_rapid7_assets(asset_docs)

        _last_full_pull_utc = datetime.now(timezone.utc)

        logging.info(
            "Rapid7: full pull complete - total=%s public=%s internal=%s "
            "with_critical=%s with_severe=%s",
            len(asset_docs), total_public, total_internal,
            total_critical, total_severe,
        )