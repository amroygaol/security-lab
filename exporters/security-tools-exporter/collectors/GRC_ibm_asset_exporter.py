import os
import logging
from datetime import datetime, timezone
from collections import Counter

import requests
from prometheus_client import Gauge

from es_store import store_ibm_maximo

# ── Metrics Infrastructure ──────────────────────────────────────────
maximo_assets_total = Gauge(
    "maximo_assets_total", 
    "Total managed assets registered in IBM Maximo"
)
maximo_assets_by_status = Gauge(
    "maximo_assets_by_status", 
    "Managed assets categorized by operational status", 
    ["status"]
)
maximo_assets_by_type = Gauge(
    "maximo_assets_by_type", 
    "Managed assets categorized by asset type hardware/software mapping", 
    ["type"]
)

maximo_collection_success = Gauge(
    "maximo_collection_success", 
    "1 if IBM Maximo OSLC REST API collection succeeded, 0 otherwise"
)
maximo_collection_duration_seconds = Gauge(
    "maximo_collection_duration_seconds", 
    "Duration of Maximo collection in absolute seconds"
)


class IbmMaximoAPI:
    """Standard OSLC REST API Wrapper for IBM Maximo Asset Management."""

    def __init__(self, host, user, password, timeout=60, verify_ssl=False):
        self.base_url = host.rstrip('/')
        self.user = user
        self.password = password
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def get_assets(self, select_fields="assetnum,status,assettype,description,siteid,location"):
        """Fetches bulk IT assets via OSLC Pagination Protocol."""
        url = f"{self.base_url}/maxrest/oslc/os/mxasset"
        params = {"oslc.select": select_fields, "oslc.pageSize": 500}
        
        all_assets = []
        next_url = url
        
        while next_url:
            r = requests.get(
                next_url, 
                auth=(self.user, self.password), 
                params=params if next_url == url else None,
                headers={"Accept": "application/json"}, 
                timeout=self.timeout, 
                verify=self.verify_ssl
            )
            r.raise_for_status()
            data = r.json()
            
            member = data.get("rdfs:member", data.get("member", []))
            all_assets.extend(member)
            
            # IBM Maximo OSLC pagination handling
            next_url = None
            response_info = data.get("oslc:responseInfo", {})
            next_link = response_info.get("oslc:nextPage", {}).get("rdf:resource")
            if next_link:
                next_url = next_link
                
        return all_assets


def collect_ibm_maximo():
    host = os.getenv("IBM_MAXIMO_HOST", "").strip()
    user = os.getenv("IBM_MAXIMO_USER", "").strip()
    password = os.getenv("IBM_MAXIMO_PASSWORD", "").strip()

    if not all([host, user, password]):
        logging.warning("IBM MAXIMO: Missing IBM_MAXIMO_HOST, USER, or PASSWORD — skipping logic.")
        return

    timeout = int(os.getenv("IBM_MAXIMO_TIMEOUT_SECONDS", "60"))
    verify_ssl = os.getenv("IBM_MAXIMO_VERIFY_SSL", "false").lower() == "true"
    start_time = datetime.now(timezone.utc)

    try:
        api = IbmMaximoAPI(host, user, password, timeout=timeout, verify_ssl=verify_ssl)
        logging.info("IBM MAXIMO: Establishing REST API connection to fetch assets...")
        assets = api.get_assets()
    except Exception as exc:
        logging.exception("IBM MAXIMO: Connection or parsing failed: %s", exc)
        maximo_collection_success.set(0)
        return

    metrics = {
        "assets_total": len(assets),
        "assets_by_status": {},
        "assets_by_type": {}
    }

    try:
        status_counter = Counter()
        type_counter = Counter()

        for asset in assets:
            # OSLC occasionally injects nesting depending on Maximo server configs
            status = asset.get("status", "UNKNOWN")
            assettype = asset.get("assettype", "UNKNOWN")
            
            if isinstance(status, dict):
                status = status.get("title", status.get("value", "UNKNOWN"))
            if isinstance(assettype, dict):
                assettype = assettype.get("title", assettype.get("value", "UNKNOWN"))

            status_counter[str(status).upper()] += 1
            if assettype and assettype != "UNKNOWN":
                type_counter[str(assettype).upper()] += 1

        # Populate Prometheus Gauges
        maximo_assets_total.set(len(assets))
        
        for stat, count in status_counter.items():
            maximo_assets_by_status.labels(status=stat).set(count)
            metrics["assets_by_status"][stat] = count
            
        for atype, count in type_counter.items():
            maximo_assets_by_type.labels(type=atype).set(count)
            metrics["assets_by_type"][atype] = count

    except Exception as exc:
        logging.exception("IBM MAXIMO: error mathematically mapping asset metrics %s", exc)

    # Dislodge the payload into the central Elasticsearch lake
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    maximo_collection_success.set(1)
    maximo_collection_duration_seconds.set(elapsed)
    logging.info("IBM MAXIMO: Exporter module completed in %.1fs (Total Assets Captured: %s)", elapsed, len(assets))

    store_ibm_maximo(metrics)
