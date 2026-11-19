import requests
import os
import time
import logging
import ipaddress
from datetime import datetime, timezone

from prometheus_client import Gauge

from es_store import store_rapid7, store_rapid7_assets, store_rapid7_vulnerabilities

# ── Asset Metrics ──────────────────────────────────────────────
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
rapid7_assets_assessed = Gauge(
    "rapid7_assets_assessed",
    "Assets that have been assessed for vulnerabilities"
)
rapid7_assets_unassessed = Gauge(
    "rapid7_assets_unassessed",
    "Assets never assessed for vulnerabilities"
)
rapid7_assets_stale = Gauge(
    "rapid7_assets_stale",
    "Assets not scanned in the last 30 days"
)

# ── Vulnerability Metrics ──────────────────────────────────────
rapid7_vuln_total = Gauge(
    "rapid7_vulnerabilities_total",
    "Total vulnerabilities across all assets"
)
rapid7_vuln_critical = Gauge(
    "rapid7_vulnerabilities_critical",
    "Total critical vulnerabilities across all assets"
)
rapid7_vuln_high = Gauge(
    "rapid7_vulnerabilities_high",
    "Total high/severe vulnerabilities across all assets"
)
rapid7_vuln_moderate = Gauge(
    "rapid7_vulnerabilities_moderate",
    "Total moderate vulnerabilities across all assets"
)

# ── Risk & Exploitability Metrics ──────────────────────────────
rapid7_risk_score_avg = Gauge(
    "rapid7_risk_score_avg",
    "Average risk score across all assets"
)
rapid7_risk_score_max = Gauge(
    "rapid7_risk_score_max",
    "Highest risk score among all assets"
)
rapid7_assets_with_exploits = Gauge(
    "rapid7_assets_with_exploits",
    "Assets with known public exploits"
)
rapid7_assets_with_malware_kits = Gauge(
    "rapid7_assets_with_malware_kits",
    "Assets associated with malware kits"
)
rapid7_total_exploits = Gauge(
    "rapid7_total_exploits",
    "Total exploit count across all assets"
)

# Track last full asset pull time to avoid re-pulling every 15 minutes
_last_full_pull_utc = None
# Full pull interval: 6 hours (assets don't change that fast)
_FULL_PULL_INTERVAL_HOURS = int(os.getenv("RAPID7_FULL_PULL_HOURS", "6"))
# Assets not scanned within this many days are considered stale
_STALE_THRESHOLD_DAYS = int(os.getenv("RAPID7_STALE_DAYS", "30"))


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


def _is_stale(asset, threshold_days):
    """Check if an asset hasn't been scanned within threshold_days."""
    last_scan = asset.get("last_scan_end") or asset.get("last_scan_start") or ""
    if not last_scan:
        return True
    try:
        scan_dt = datetime.fromisoformat(last_scan.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - scan_dt).days
        return age > threshold_days
    except (ValueError, TypeError):
        return True


def _build_asset_doc(asset):
    """Transform a raw Rapid7 asset into an ES-friendly document."""
    ip = asset.get("ip", "")
    is_public = _is_public_ip(ip)

    tags = asset.get("tags", [])
    tag_names = [t.get("name", "") for t in tags if isinstance(t, dict)]
    site_tags = [t.get("name", "") for t in tags
                 if isinstance(t, dict) and t.get("type") == "SITE"]

    critical = asset.get("critical_vulnerabilities", 0)
    severe = asset.get("severe_vulnerabilities", 0)
    moderate = asset.get("moderate_vulnerabilities", 0)
    total_vulns = asset.get("total_vulnerabilities", 0)
    exploits = asset.get("exploits", 0)
    malware_kits = asset.get("malware_kits", 0)
    assessed = asset.get("assessed_for_vulnerabilities", False)
    stale = _is_stale(asset, _STALE_THRESHOLD_DAYS)

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
        "critical_vulnerabilities": critical,
        "severe_vulnerabilities": severe,
        "moderate_vulnerabilities": moderate,
        "total_vulnerabilities": total_vulns,
        "exploits": exploits,
        "malware_kits": malware_kits,
        "assessed_for_vulnerabilities": assessed,
        "is_stale": stale,
        "last_scan_start": asset.get("last_scan_start", ""),
        "last_scan_end": asset.get("last_scan_end", ""),
        "last_assessed_for_vulnerabilities": asset.get("last_assessed_for_vulnerabilities", ""),
        "tags": tag_names,
        "site_tags": site_tags,
        "has_critical": critical > 0,
        "has_exploits": exploits > 0,
        "has_malware_kits": malware_kits > 0,
        "has_vulnerabilities": total_vulns > 0,
    }


def _should_full_pull():
    """Check if enough time has passed to do a full asset pull."""
    global _last_full_pull_utc
    if _last_full_pull_utc is None:
        return True
    elapsed = (datetime.now(timezone.utc) - _last_full_pull_utc).total_seconds()
    return elapsed >= _FULL_PULL_INTERVAL_HOURS * 3600


def _paginate_vulnerabilities(headers, timeout=30):
    """Paginate through Rapid7 vulnerabilities. Yields individual vuln dicts."""
    url = "https://ap.api.insight.rapid7.com/vm/v4/integration/vulnerabilities"
    cursor = None
    page = 0

    while True:
        body = {"size": 500}
        if cursor:
            body["cursor"] = cursor

        r = requests.post(url, headers=headers, json=body, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("data", [])

        if not vulns:
            break

        for vuln in vulns:
            yield vuln

        page += 1
        if page % 20 == 0:
            logging.info("Rapid7: paginated %s vulns so far...", page * 500)

        cursor = data.get("metadata", {}).get("cursor")
        if not cursor:
            break

        time.sleep(0.1)


def _build_vuln_doc(vuln):
    """Transform a raw Rapid7 vulnerability into an ES-friendly document."""
    severity = vuln.get("severity", "").lower()
    # exploits/malware_kits may be returned as a list (references) or int (count)
    raw_exploits = vuln.get("exploits", 0)
    exploits_count = len(raw_exploits) if isinstance(raw_exploits, list) else int(raw_exploits or 0)
    raw_malware = vuln.get("malware_kits", 0)
    malware_count = len(raw_malware) if isinstance(raw_malware, list) else int(raw_malware or 0)
    return {
        "vuln_id": vuln.get("id", ""),
        "title": vuln.get("title", ""),
        "description": (vuln.get("description", "") or "")[:500],
        "severity": severity,
        "severity_score": vuln.get("severity_score", 0),
        "risk_score": vuln.get("risk_score", 0),
        "cvss_v2_score": vuln.get("cvss", {}).get("v2", {}).get("score", 0),
        "cvss_v3_score": vuln.get("cvss", {}).get("v3", {}).get("score", 0),
        "exploits": exploits_count,
        "malware_kits": malware_count,
        "has_exploits": exploits_count > 0,
        "published": vuln.get("published", ""),
        "modified": vuln.get("modified", ""),
        "categories": vuln.get("categories", []),
    }


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

    # --- Full pull (every N hours) ---
    if not _should_full_pull():
        logging.info("Rapid7: skipping full pull (last pull was recent)")
        return

    global _last_full_pull_utc
    logging.info("Rapid7: starting full pull (%s assets, %s vulns)...", total_assets, total_vulns)

    # ── Asset collection ───────────────────────────────────────
    asset_docs = []
    stats = {
        "public": 0, "internal": 0,
        "assessed": 0, "unassessed": 0, "stale": 0,
        "sum_critical": 0, "sum_severe": 0, "sum_moderate": 0,
        "sum_risk_score": 0.0, "max_risk_score": 0.0,
        "with_exploits": 0, "with_malware_kits": 0,
        "total_exploits": 0,
    }

    try:
        for raw_asset in _paginate_assets(headers):
            doc = _build_asset_doc(raw_asset)
            asset_docs.append(doc)

            # Network zone
            if doc["is_public"]:
                stats["public"] += 1
            else:
                stats["internal"] += 1

            # Scan coverage
            if doc["assessed_for_vulnerabilities"]:
                stats["assessed"] += 1
            else:
                stats["unassessed"] += 1
            if doc["is_stale"]:
                stats["stale"] += 1

            # Vulnerability counts (actual totals, not just "has")
            stats["sum_critical"] += doc["critical_vulnerabilities"]
            stats["sum_severe"] += doc["severe_vulnerabilities"]
            stats["sum_moderate"] += doc["moderate_vulnerabilities"]

            # Risk & exploitability
            stats["sum_risk_score"] += doc["risk_score"]
            if doc["risk_score"] > stats["max_risk_score"]:
                stats["max_risk_score"] = doc["risk_score"]
            if doc["has_exploits"]:
                stats["with_exploits"] += 1
            if doc["has_malware_kits"]:
                stats["with_malware_kits"] += 1
            stats["total_exploits"] += doc["exploits"]

    except Exception as exc:
        logging.exception("Rapid7: asset pull interrupted after %s assets: %s",
                          len(asset_docs), exc)

    # ── Vulnerability collection ───────────────────────────────
    vuln_docs = []
    vuln_severity_counts = {"critical": 0, "high": 0, "moderate": 0, "low": 0}

    try:
        for raw_vuln in _paginate_vulnerabilities(headers):
            doc = _build_vuln_doc(raw_vuln)
            vuln_docs.append(doc)
            sev = doc["severity"]
            if sev in vuln_severity_counts:
                vuln_severity_counts[sev] += 1
    except Exception as exc:
        logging.exception("Rapid7: vuln pull interrupted after %s vulns: %s",
                          len(vuln_docs), exc)

    # ── Update Prometheus metrics ──────────────────────────────
    if asset_docs:
        rapid7_assets_public.set(stats["public"])
        rapid7_assets_internal.set(stats["internal"])
        rapid7_assets_assessed.set(stats["assessed"])
        rapid7_assets_unassessed.set(stats["unassessed"])
        rapid7_assets_stale.set(stats["stale"])

        rapid7_vuln_critical.set(stats["sum_critical"])
        rapid7_vuln_high.set(stats["sum_severe"])
        rapid7_vuln_moderate.set(stats["sum_moderate"])

        avg_risk = stats["sum_risk_score"] / len(asset_docs) if asset_docs else 0
        rapid7_risk_score_avg.set(round(avg_risk, 2))
        rapid7_risk_score_max.set(stats["max_risk_score"])
        rapid7_assets_with_exploits.set(stats["with_exploits"])
        rapid7_assets_with_malware_kits.set(stats["with_malware_kits"])
        rapid7_total_exploits.set(stats["total_exploits"])

    # ── Store to Elasticsearch ─────────────────────────────────
    summary = {
        "total_assets": total_assets,
        "total_vulnerabilities": total_vulns,
        "assets_public": stats["public"],
        "assets_internal": stats["internal"],
        "assets_assessed": stats["assessed"],
        "assets_unassessed": stats["unassessed"],
        "assets_stale": stats["stale"],
        "vulns_critical": stats["sum_critical"],
        "vulns_severe": stats["sum_severe"],
        "vulns_moderate": stats["sum_moderate"],
        "risk_score_avg": round(avg_risk, 2) if asset_docs else 0,
        "risk_score_max": stats["max_risk_score"],
        "assets_with_exploits": stats["with_exploits"],
        "assets_with_malware_kits": stats["with_malware_kits"],
        "total_exploits": stats["total_exploits"],
        "vuln_catalog_critical": vuln_severity_counts["critical"],
        "vuln_catalog_high": vuln_severity_counts["high"],
        "vuln_catalog_moderate": vuln_severity_counts["moderate"],
        "vuln_catalog_low": vuln_severity_counts["low"],
    }
    store_rapid7(summary)

    if asset_docs:
        store_rapid7_assets(asset_docs)
    if vuln_docs:
        store_rapid7_vulnerabilities(vuln_docs)

    _last_full_pull_utc = datetime.now(timezone.utc)

    logging.info(
        "Rapid7: full pull complete - assets=%s (public=%s internal=%s "
        "assessed=%s stale=%s) vulns=%s (crit=%s high=%s mod=%s) "
        "exploitable=%s risk_avg=%.1f risk_max=%.1f vuln_catalog=%s",
        len(asset_docs), stats["public"], stats["internal"],
        stats["assessed"], stats["stale"],
        total_vulns, stats["sum_critical"], stats["sum_severe"],
        stats["sum_moderate"], stats["with_exploits"],
        avg_risk if asset_docs else 0, stats["max_risk_score"],
        len(vuln_docs),
    )