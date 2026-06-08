"""
Elasticsearch storage for security collector data.

Each collector produces a document that gets indexed into a dedicated
index with a timestamped @timestamp field for Grafana time-series queries.

Indices created:
  - security-digicert
  - security-subdomains
  - security-ip-exposure
  - security-rapid7
  - security-cortex
  - security-entraid
  - security-intune
  - security-panorama
  - security-bmc-cmdb
  - security-imperva
  - security-defectdojo
  - security-apigee
  - security-webmethods
  - security-ip-scan-coverage
"""

import json
import logging
import os
from datetime import datetime, timezone

import requests

_ES_HOST = None


def _get_es_host():
    global _ES_HOST
    if _ES_HOST is None:
        _ES_HOST = os.getenv("ES_HOST", "").strip()
    return _ES_HOST


def _es_available():
    host = _get_es_host()
    if not host:
        return False
    try:
        r = requests.get(host, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def _delete_by_domain(index_name, target_domain):
    """Delete all documents in an index matching a target_domain."""
    host = _get_es_host()
    if not host:
        return
    try:
        r = requests.post(
            f"{host}/{index_name}/_delete_by_query",
            json={"query": {"term": {"target_domain.keyword": target_domain}}},
            timeout=30,
            headers={"Content-Type": "application/json"},
        )
        if r.status_code in (200, 201):
            deleted = r.json().get("deleted", 0)
            logging.info("es_store: cleared %s old docs from %s for %s",
                         deleted, index_name, target_domain)
        else:
            logging.warning("es_store: delete_by_query %s failed (%s)",
                            index_name, r.status_code)
    except Exception as exc:
        logging.warning("es_store: delete_by_query %s error: %s", index_name, exc)


def index_document(index_name, doc):
    """Index a single document into Elasticsearch."""
    host = _get_es_host()
    if not host:
        return

    doc.setdefault("@timestamp", datetime.now(timezone.utc).isoformat())

    url = f"{host}/{index_name}/_doc"
    try:
        r = requests.post(url, json=doc, timeout=10,
                          headers={"Content-Type": "application/json"})
        if r.status_code not in (200, 201):
            logging.warning("es_store: index %s failed (%s): %s",
                            index_name, r.status_code, r.text[:200])
    except Exception as exc:
        logging.warning("es_store: index %s error: %s", index_name, exc)


def _bulk_index(index_name, docs):
    """Index multiple documents using the ES _bulk API."""
    host = _get_es_host()
    if not host or not docs:
        return

    now = datetime.now(timezone.utc).isoformat()
    lines = []
    for doc in docs:
        doc.setdefault("@timestamp", now)
        lines.append(json.dumps({"index": {"_index": index_name}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"

    try:
        r = requests.post(
            f"{host}/_bulk",
            data=body,
            timeout=30,
            headers={"Content-Type": "application/x-ndjson"},
        )
        if r.status_code not in (200, 201):
            logging.warning("es_store: bulk index %s failed (%s): %s",
                            index_name, r.status_code, r.text[:300])
        else:
            result = r.json()
            if result.get("errors"):
                failed = sum(1 for item in result.get("items", [])
                             if item.get("index", {}).get("status", 200) >= 400)
                logging.warning("es_store: bulk index %s had %s errors", index_name, failed)
            else:
                logging.info("es_store: bulk indexed %s docs into %s", len(docs), index_name)
    except Exception as exc:
        logging.warning("es_store: bulk index %s error: %s", index_name, exc)


def store_digicert(total, active, expired, revoked, exp30, exp14, exp7):
    if not _es_available():
        return
    doc = {
        "total": total,
        "active": active,
        "expired": expired,
        "revoked": revoked,
        "expiring_30_days": exp30,
        "expiring_14_days": exp14,
        "expiring_7_days": exp7,
    }
    index_document("security-digicert", doc)


def store_subdomains(target_domain, total, source_counts, subdomain_map):
    if not _es_available():
        return
        
    formatted_subdomains = []
    if isinstance(subdomain_map, dict):
        for sub, issuers in sorted(subdomain_map.items()):
            formatted_subdomains.append({
                "subdomain": sub,
                "issuers": sorted(list(issuers))
            })
        raw_keys = sorted(list(subdomain_map.keys()))
    else:
        # Fallback if someone passed a legacy flat list
        formatted_subdomains = [{"subdomain": s, "issuers": ["Unknown"]} for s in sorted(subdomain_map)]
        raw_keys = sorted(list(subdomain_map))
        
    doc = {
        "target_domain": target_domain,
        "total": total,
        "source_counts": source_counts,
        "subdomains": raw_keys,
        "subdomain_details": formatted_subdomains,
    }
    index_document("security-subdomains", doc)


def store_ip_exposure(payload):
    """Disabled: no longer storing ip-exposure into Elasticsearch."""
    return


def store_rapid7(summary):
    """Store Rapid7 summary metrics as a single timestamped document."""
    if not _es_available():
        return
    index_document("security-rapid7", summary)


def _delete_by_query(index_name, query=None):
    """Delete documents from an index. query=None deletes all."""
    host = _get_es_host()
    if not host:
        return
    body = {"query": query or {"match_all": {}}}
    try:
        r = requests.post(
            f"{host}/{index_name}/_delete_by_query?conflicts=proceed&refresh=true",
            json=body, timeout=30,
            headers={"Content-Type": "application/json"},
        )
        if r.status_code in (200, 201):
            deleted = r.json().get("deleted", 0)
            logging.info("es_store: deleted %s docs from %s", deleted, index_name)
    except Exception as exc:
        logging.warning("es_store: delete_by_query %s error: %s", index_name, exc)


def store_rapid7_assets(assets):
    """Store individual Rapid7 assets into 'security-rapid7-assets'.

    Replaces all previous asset docs each cycle so the index reflects current state.
    """
    if not _es_available() or not assets:
        return
    _delete_by_query("security-rapid7-assets")
    # Bulk in batches of 500 to avoid oversized requests
    batch_size = 500
    for i in range(0, len(assets), batch_size):
        _bulk_index("security-rapid7-assets", assets[i:i + batch_size])
    logging.info("es_store: stored %s rapid7 assets", len(assets))


def store_rapid7_vulnerabilities(vulns):
    """Store individual Rapid7 vulnerabilities into 'security-rapid7-vulns'.

    Replaces all previous vuln docs each cycle.
    """
    if not _es_available() or not vulns:
        return
    _delete_by_query("security-rapid7-vulns")
    batch_size = 500
    for i in range(0, len(vulns), batch_size):
        _bulk_index("security-rapid7-vulns", vulns[i:i + batch_size])
    logging.info("es_store: stored %s rapid7 vulnerabilities", len(vulns))


def store_cortex(endpoints_total, endpoints_online, malware_alerts,
                 incidents_open, incidents_high, incidents_medium,
                 incidents_low, alerts_total, agents_outdated):
    if not _es_available():
        return
    doc = {
        "endpoints_total": endpoints_total,
        "endpoints_online": endpoints_online,
        "malware_alerts": malware_alerts,
        "incidents_open": incidents_open,
        "incidents_high": incidents_high,
        "incidents_medium": incidents_medium,
        "incidents_low": incidents_low,
        "alerts_total": alerts_total,
        "agents_outdated": agents_outdated,
    }
    index_document("security-cortex", doc)


def store_ip_records(target_domain, ip_to_subdomains, ip_providers,
                    cname_map, shodan_records=None, all_ips_map=None,
                    ssl_map=None, all_subdomains=None):
    """Store one document per subdomain into 'security-assets' index.

    Each document represents a subdomain with its resolved IPs, CNAME,
    SSL/TLS info, provider, and Shodan enrichment — individually searchable in Kibana.
    """
    if not _es_available():
        return

    import ipaddress

    shodan_records = shodan_records or {}
    all_ips_map = all_ips_map or {}
    ssl_map = ssl_map or {}
    all_subdomains = all_subdomains or []

    # Build reverse map from public IPs: subdomain -> list of public IPs
    subdomain_to_public_ips = {}
    for ip, subs in ip_to_subdomains.items():
        for sub in subs:
            subdomain_to_public_ips.setdefault(sub, []).append(ip)

    # Use all_subdomains to cover every discovered subdomain
    all_subs_set = set(all_subdomains)
    # Also include any that appeared in ip resolution
    for sub in subdomain_to_public_ips:
        all_subs_set.add(sub)
    for sub in all_ips_map:
        all_subs_set.add(sub)

    docs = []
    for subdomain in sorted(all_subs_set):
        all_ips = sorted(all_ips_map.get(subdomain, set()))
        public_ips = sorted(subdomain_to_public_ips.get(subdomain, []))
        private_ips = sorted(
            ip for ip in all_ips
            if not ipaddress.ip_address(ip).is_global
        ) if all_ips else []

        # Provider detection for public IPs
        providers = list({ip_providers.get(ip, "Unknown") for ip in public_ips}) if public_ips else []
        
        cname = cname_map.get(subdomain, "")
        is_external_cname = bool(
            cname and not cname.endswith("." + target_domain) and cname != target_domain
        )

        doc = {
            "target_domain": target_domain,
            "subdomain": subdomain,
            "ip_addresses": all_ips,
            "public_ips": public_ips,
            "private_ips": private_ips,
            "ip_count": len(all_ips),
            "has_public_ip": bool(public_ips),
            "has_private_ip": bool(private_ips),
            "provider": providers[0] if len(providers) == 1 else ", ".join(sorted(providers)) if providers else "",
            "providers": sorted(providers),
            "cname": cname,
            "has_cname": bool(cname),
            "is_external_cname": is_external_cname,
            "dns_resolves": bool(all_ips),
        }

        # SSL/TLS info
        ssl_info = ssl_map.get(subdomain)
        if ssl_info:
            doc["ssl_enabled"] = True
            doc["ssl_issuer"] = ssl_info.get("issuer", "Unknown")
            doc["ssl_issuer_org"] = ssl_info.get("issuer_org", "Unknown")
            doc["ssl_subject"] = ssl_info.get("subject", "")
            doc["ssl_not_before"] = ssl_info.get("not_before", "")
            doc["ssl_not_after"] = ssl_info.get("not_after", "")
        else:
            doc["ssl_enabled"] = False

        # Enrich with Shodan data if available for any of the public IPs
        for ip in public_ips:
            shodan_info = shodan_records.get(ip)
            if shodan_info:
                doc["shodan"] = {
                    "ip": ip,
                    "org": shodan_info.get("org", ""),
                    "isp": shodan_info.get("isp", ""),
                    "asn": shodan_info.get("asn", ""),
                    "ports": shodan_info.get("ports", []),
                    "hostnames": shodan_info.get("hostnames", []),
                    "last_update": shodan_info.get("last_update", ""),
                }
                break

        docs.append(doc)

    if docs:
        # Clear previous asset records for this domain before inserting fresh ones
        _delete_by_domain("security-assets", target_domain)
        _bulk_index("security-assets", docs)
        logging.info("es_store: stored %s asset records for %s", len(docs), target_domain)


def store_entraid(metrics):
    """Store EntraID posture metrics into 'security-entraid' index."""
    if not _es_available() or not metrics:
        return
    index_document("security-entraid", dict(metrics))


def store_intune(metrics):
    """Store Intune posture metrics into 'security-intune' index."""
    if not _es_available() or not metrics:
        return
    index_document("security-intune", dict(metrics))


def store_panorama(metrics):
    """Store Panorama firewall metrics into 'security-panorama' index."""
    if not _es_available() or not metrics:
        return
    index_document("security-panorama", dict(metrics))


def store_bmc_cmdb(metrics):
    """Store BMC CMDB posture metrics into 'security-bmc-cmdb' index."""
    if not _es_available() or not metrics:
        return
    index_document("security-bmc-cmdb", dict(metrics))


def store_imperva(metrics):
    """Store Imperva Cloud WAF metrics into 'security-imperva' index."""
    if not _es_available() or not metrics:
        return
    index_document("security-imperva", dict(metrics))


def store_imperva_sites(sites):
    """Store per-site Imperva WAF asset details into 'security-imperva-sites'.

    Replaces all previous docs each cycle so the index reflects current state.
    """
    if not _es_available() or not sites:
        return
    _delete_by_query("security-imperva-sites")
    batch_size = 500
    for i in range(0, len(sites), batch_size):
        _bulk_index("security-imperva-sites", sites[i:i + batch_size])
    logging.info("es_store: stored %s imperva site assets", len(sites))


def store_ip_scan_coverage(docs):
    """Store per-IP scan coverage cross-reference into 'security-ip-scan-coverage'.

    Replaces all previous docs each cycle so the table always reflects the
    current exposure vs Rapid7 scan state.
    """
    if not _es_available() or not docs:
        return
    _delete_by_query("security-ip-scan-coverage")
    batch_size = 500
    for i in range(0, len(docs), batch_size):
        _bulk_index("security-ip-scan-coverage", docs[i:i + batch_size])
    logging.info("es_store: stored %s IP scan coverage records", len(docs))


def store_defectdojo(metrics):
    """Store DefectDojo AppSec metrics into 'security-defectdojo' index."""
    if not _es_available() or not metrics:
        return
    index_document("security-defectdojo", dict(metrics))


def store_apigee(metrics):
    """Store Apigee API Gateway metrics into 'security-apigee' index."""
    if not _es_available() or not metrics:
        return
    index_document("security-apigee", dict(metrics))


def store_webmethods(metrics):
    """Store webMethods API Gateway metrics into 'security-webmethods' index."""
    if not _es_available() or not metrics:
        return
    index_document("security-webmethods", dict(metrics))

def store_ibm_maximo(metrics):
    """Store IBM Maximo Asset metrics into 'security-ibm-maximo' precision root index."""
    if not _es_available() or not metrics:
        return
    index_document("security-ibm-maximo", dict(metrics))


def store_jira_tickets(tickets):
    """Store Jira pentest tickets into 'security-jira-tickets' index.

    Replaces all previous ticket docs each cycle so the index reflects current state.
    """
    if not _es_available() or not tickets:
        return
    _delete_by_query("security-jira-tickets")
    batch_size = 500
    for i in range(0, len(tickets), batch_size):
        _bulk_index("security-jira-tickets", tickets[i:i + batch_size])
    logging.info("es_store: stored %s jira tickets", len(tickets))


def store_soc_jira_tickets(tickets):
    """Store SOC Jira tickets into 'security-jira-soc-tickets' index.

    Replaces all previous ticket docs each cycle so the index reflects current state.
    """
    if not _es_available() or not tickets:
        return
    _delete_by_query("security-jira-soc-tickets")
    batch_size = 500
    for i in range(0, len(tickets), batch_size):
        _bulk_index("security-jira-soc-tickets", tickets[i:i + batch_size])
    logging.info("es_store: stored %s SOC jira tickets", len(tickets))
