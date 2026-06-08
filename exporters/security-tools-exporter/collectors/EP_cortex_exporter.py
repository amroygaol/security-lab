import requests
import os
import logging

from prometheus_client import Gauge

from es_store import store_cortex


cortex_xdr_endpoints_total = Gauge(
    "cortex_xdr_endpoints_total",
    "Total endpoints in Cortex XDR"
)

cortex_xdr_endpoints_online = Gauge(
    "cortex_xdr_endpoints_online",
    "Active/online endpoints in Cortex XDR"
)

cortex_xdr_malware_alerts_total = Gauge(
    "cortex_xdr_malware_alerts_total",
    "Total malware alerts in Cortex XDR"
)

cortex_xdr_incidents_open = Gauge(
    "cortex_xdr_incidents_open",
    "Open incidents in Cortex XDR"
)

cortex_xdr_incidents_high = Gauge(
    "cortex_xdr_incidents_high",
    "Open incidents with high severity in Cortex XDR"
)

cortex_xdr_incidents_medium = Gauge(
    "cortex_xdr_incidents_medium",
    "Open incidents with medium severity in Cortex XDR"
)

cortex_xdr_incidents_low = Gauge(
    "cortex_xdr_incidents_low",
    "Open incidents with low severity in Cortex XDR"
)

cortex_xdr_alerts_total = Gauge(
    "cortex_xdr_alerts_total",
    "Total alerts in Cortex XDR"
)

cortex_xdr_agents_outdated = Gauge(
    "cortex_xdr_agents_outdated",
    "Outdated agents in Cortex XDR"
)


def collect_cortex():
    api_key_id = os.getenv("CORTEX_API_KEY_ID")
    api_key = os.getenv("CORTEX_API_KEY")
    region = os.getenv("CORTEX_REGION", "ultima2")
    domain = os.getenv("CORTEX_DOMAIN", "id")

    if not api_key_id or not api_key:
        print("Cortex collector error: CORTEX_API_KEY_ID and CORTEX_API_KEY must be set")
        return

    headers = {
        "x-xdr-auth-id": api_key_id,
        "Authorization": api_key,
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip"
    }

    base_url = f"https://api-{region}.xdr.{domain}.paloaltonetworks.com/public_api/v1"
    timeout_seconds = int(os.getenv("CORTEX_TIMEOUT_SECONDS", "180"))
    page_size = int(os.getenv("CORTEX_PAGE_SIZE", "100"))
    # Keep default cycle time reasonable; increase via env for deeper scans.
    max_incident_pages = int(os.getenv("CORTEX_MAX_INCIDENT_PAGES", "20"))
    max_malware_pages = int(os.getenv("CORTEX_MAX_MALWARE_PAGES", "20"))

    def normalize_severity(value):
        if value is None:
            return ""

        text = str(value).strip().lower()
        mapping = {
            "3": "high",
            "2": "medium",
            "1": "low",
            "critical": "high",
            "severe": "high",
        }
        return mapping.get(text, text)

    def count_severity(items):
        high = 0
        medium = 0
        low = 0
        for item in items:
            if not isinstance(item, dict):
                continue

            sev = normalize_severity(
                item.get("severity")
                or item.get("severity_name")
                or item.get("alert_severity")
                or item.get("incident_severity")
            )

            if sev == "high":
                high += 1
            elif sev == "medium":
                medium += 1
            elif sev == "low":
                low += 1

        return high, medium, low


    def extract_items(reply_obj, key):
        if isinstance(reply_obj, list):
            return reply_obj
        if isinstance(reply_obj, dict):
            return reply_obj.get(key, [])
        return []

    def extract_total_count(reply_obj, fallback_count):
        if isinstance(reply_obj, dict):
            total = reply_obj.get("total_count")
            if isinstance(total, int):
                return total
        return fallback_count

    def extract_result_count(reply_obj, fallback_count):
        if isinstance(reply_obj, dict):
            result = reply_obj.get("result_count")
            if isinstance(result, int):
                return result
        return fallback_count

    def post_reply(url, body):
        r = requests.post(url, headers=headers, json=body, timeout=timeout_seconds)
        r.raise_for_status()
        data = r.json()
        reply = data.get("reply", {})
        return reply, r.status_code

    def post_items(url, body, key):
        reply, status_code = post_reply(url, body)
        return extract_items(reply, key), status_code

    # Reset gauges each cycle to avoid stale values if calls fail.
    cortex_xdr_endpoints_total.set(0)
    cortex_xdr_endpoints_online.set(0)
    cortex_xdr_agents_outdated.set(0)
    cortex_xdr_malware_alerts_total.set(0)
    cortex_xdr_incidents_open.set(0)
    cortex_xdr_incidents_high.set(0)
    cortex_xdr_incidents_medium.set(0)
    cortex_xdr_incidents_low.set(0)
    cortex_xdr_alerts_total.set(0)

    # Local accumulators for ES store
    _total_endpoints = 0
    _online_count = 0
    _outdated_count = 0
    _open_incidents = 0
    _incidents_high = 0
    _incidents_medium = 0
    _incidents_low = 0
    _total_alerts = 0
    _malware_alerts = 0

    try:
        # Total endpoints
        endpoint_url = f"{base_url}/endpoints/get_endpoints"
        logging.info("Cortex: Fetching endpoints")
        endpoints, endpoint_status = post_items(endpoint_url, {"request_data": {"limit": 200}}, "endpoints")
        total_endpoints = len(endpoints)
        logging.info(f"Cortex: Endpoints response status {endpoint_status}, items {total_endpoints}")
        cortex_xdr_endpoints_total.set(total_endpoints)
        _total_endpoints = total_endpoints

        # Online endpoints
        online_count = sum(1 for ep in endpoints if isinstance(ep, dict) and ep.get("agent_status") == "CONNECTED")
        cortex_xdr_endpoints_online.set(online_count)
        _online_count = online_count

        # Some tenants do not expose version fields in this endpoint. As practical fallback,
        # treat disconnected agents as attention-needed for this metric.
        outdated_count = sum(1 for ep in endpoints if isinstance(ep, dict) and ep.get("agent_status") != "CONNECTED")
        cortex_xdr_agents_outdated.set(outdated_count)
        _outdated_count = outdated_count
    except Exception as e:
        logging.exception("Cortex: Endpoints collection failed: %s", e)

    # Early alerts snapshot so total/malware don't remain 0 while deeper
    # incident pagination is still in progress.
    try:
        alert_url = f"{base_url}/alerts/get_alerts"
        snapshot_body = {"request_data": {"limit": page_size, "offset": 0}}
        snapshot_reply, _ = post_reply(alert_url, snapshot_body)
        snapshot_alerts = extract_items(snapshot_reply, "alerts")
        snapshot_total = extract_total_count(snapshot_reply, len(snapshot_alerts))
        cortex_xdr_alerts_total.set(snapshot_total)
        snapshot_malware = sum(
            1 for a in snapshot_alerts
            if isinstance(a, dict) and str(a.get("category", "")).strip().lower() == "malware"
        )
        cortex_xdr_malware_alerts_total.set(snapshot_malware)
    except Exception as e:
        logging.exception("Cortex: Early alerts snapshot failed: %s", e)

    try:
        # Open incidents: use total_count for full value; paginate incidents for severity split.
        incident_url = f"{base_url}/incidents/get_incidents"
        # Use broader open-like statuses; 'open' may not exist on all tenants.
        body = {"request_data": {"filters": [{"field": "status", "operator": "in", "value": ["new", "under_investigation", "open"]}], "limit": page_size, "offset": 0}}
        logging.info("Cortex: Fetching open incidents")
        reply, incident_status = post_reply(incident_url, body)
        incidents = extract_items(reply, "incidents")
        open_incidents = extract_total_count(reply, len(incidents))
        logging.info(f"Cortex: Open incidents response status {incident_status}, result={len(incidents)}, total={open_incidents}")
        cortex_xdr_incidents_open.set(open_incidents)
        _open_incidents = open_incidents

        # Severity split requires scanning pages because incidents API doesn't allow severity filter.
        all_incidents = list(incidents)
        search_from = extract_result_count(reply, len(incidents))
        page = 1
        while len(all_incidents) < open_incidents and page < max_incident_pages:
            page += 1
            page_body = {
                "request_data": {
                    "filters": [{"field": "status", "operator": "in", "value": ["new", "under_investigation", "open"]}],
                    "limit": page_size,
                    "offset": search_from,
                }
            }
            page_reply, _ = post_reply(incident_url, page_body)
            page_incidents = extract_items(page_reply, "incidents")
            if not page_incidents:
                break
            all_incidents.extend(page_incidents)
            page_result = extract_result_count(page_reply, len(page_incidents))
            if page_result <= 0:
                break
            search_from += page_result

        incidents_high, incidents_medium, incidents_low = count_severity(all_incidents)
        cortex_xdr_incidents_high.set(incidents_high)
        cortex_xdr_incidents_medium.set(incidents_medium)
        cortex_xdr_incidents_low.set(incidents_low)
        _incidents_high = incidents_high
        _incidents_medium = incidents_medium
        _incidents_low = incidents_low
    except Exception as e:
        logging.exception("Cortex: Incidents collection failed: %s", e)

    try:
        # All alerts + severity breakdown.
        # Use total_count directly to avoid page-size cap of 100.
        alert_total_body = {"request_data": {"limit": page_size, "offset": 0}}
        logging.info("Cortex: Fetching all alerts")
        alert_url = f"{base_url}/alerts/get_alerts"
        reply, all_alerts_status = post_reply(alert_url, alert_total_body)
        all_alerts = extract_items(reply, "alerts")
        total_alerts = extract_total_count(reply, len(all_alerts))
        logging.info(f"Cortex: All alerts response status {all_alerts_status}, result={len(all_alerts)}, total={total_alerts}")
        cortex_xdr_alerts_total.set(total_alerts)
        _total_alerts = total_alerts

        # Derive malware count from sampled all-alerts pages.
        malware_alerts = 0
        scanned_alerts = 0
        page = 0
        offset = 0
        while page < max_malware_pages:
            sample_body = {"request_data": {"limit": page_size, "offset": offset}}
            sample_reply, _ = post_reply(alert_url, sample_body)
            sample_alerts = extract_items(sample_reply, "alerts")
            if not sample_alerts:
                break
            page += 1
            scanned_alerts += len(sample_alerts)
            malware_alerts += sum(
                1 for a in sample_alerts
                if isinstance(a, dict) and str(a.get("category", "")).strip().lower() == "malware"
            )
            page_result = extract_result_count(sample_reply, len(sample_alerts))
            if page_result <= 0:
                break
            offset += page_result
            if offset >= total_alerts:
                break
        cortex_xdr_malware_alerts_total.set(malware_alerts)
        _malware_alerts = malware_alerts
        logging.info(
            "Cortex: Malware alerts derived from alerts pages, scanned=%s pages=%s malware=%s",
            scanned_alerts,
            page,
            malware_alerts,
        )

        store_cortex(
            _total_endpoints, _online_count, _malware_alerts,
            _open_incidents, _incidents_high, _incidents_medium,
            _incidents_low, _total_alerts, _outdated_count,
        )

    except Exception as e:
        logging.exception("Cortex: Alerts collection failed: %s", e)