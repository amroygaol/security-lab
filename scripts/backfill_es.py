"""
Backfill Elasticsearch with existing data files from /data/ directory.

Run once after ES is healthy to index historical snapshots.

Usage:
  python scripts/backfill_es.py [--es-host http://localhost:9200]

Indices populated:
  - security-ip-exposure   (from data/ip-exposure/*.json)
  - security-subdomains    (from data/subdomains/*.txt)
"""

import argparse
import json
import os
import re
import sys

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "..", "data")


def wait_for_es(es_host, retries=30, delay=2):
    import time
    for i in range(retries):
        try:
            r = requests.get(es_host, timeout=5)
            if r.status_code == 200:
                print(f"Elasticsearch ready at {es_host}")
                return True
        except Exception:
            pass
        print(f"Waiting for Elasticsearch... ({i+1}/{retries})")
        time.sleep(delay)
    print("Elasticsearch not available, aborting.")
    return False


def index_doc(es_host, index_name, doc):
    doc.setdefault("@timestamp", doc.get("generated_at_utc", ""))
    url = f"{es_host}/{index_name}/_doc"
    r = requests.post(url, json=doc, timeout=10,
                      headers={"Content-Type": "application/json"})
    return r.status_code in (200, 201)


def bulk_index(es_host, index_name, docs):
    """Index multiple documents using ES _bulk API."""
    if not docs:
        return 0
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": index_name}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"
    r = requests.post(f"{es_host}/_bulk", data=body, timeout=30,
                      headers={"Content-Type": "application/x-ndjson"})
    if r.status_code not in (200, 201):
        return 0
    result = r.json()
    ok_count = sum(1 for item in result.get("items", [])
                   if item.get("index", {}).get("status", 400) < 400)
    return ok_count


def parse_timestamp_from_filename(filename):
    """Extract ISO timestamp from filename like bri.co.id_20260317T063839Z.json"""
    m = re.search(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z", filename)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}T{m.group(4)}:{m.group(5)}:{m.group(6)}Z"
    return None


def _flatten_ip_exposure_doc(doc):
    """Convert dict-keyed structures to arrays for ES-friendly indexing."""
    ip_details = doc.pop("ip_details", doc.pop("ip_to_subdomains", {}))
    if isinstance(ip_details, dict):
        # Handle both formats: {ip: {provider, subdomains}} and {ip: [subdomains]}
        result = []
        for ip, info in ip_details.items():
            if isinstance(info, dict):
                result.append({"ip": ip, "provider": info.get("provider", "Unknown"),
                               "subdomains": info.get("subdomains", [])})
            elif isinstance(info, list):
                result.append({"ip": ip, "provider": "Unknown", "subdomains": info})
        doc["ip_details"] = result

    cname_map = doc.pop("domains_with_external_cname", {})
    if isinstance(cname_map, dict):
        doc["domains_with_external_cname"] = [
            {"domain": d, "cname": c} for d, c in cname_map.items()
        ]

    port_counts = doc.pop("port_counts", {})
    if isinstance(port_counts, dict):
        doc["port_counts"] = [
            {"port": p, "count": c} for p, c in port_counts.items()
        ]

    provider_counts = doc.pop("provider_counts", {})
    if isinstance(provider_counts, dict):
        doc["provider_counts"] = [
            {"provider": p, "count": c} for p, c in provider_counts.items()
        ]

    # ip_providers flat map -> drop (already in ip_details)
    doc.pop("ip_providers", None)

    shodan = doc.pop("shodan", {})
    if isinstance(shodan, dict):
        doc["shodan"] = [dict(record, ip=ip) for ip, record in shodan.items()]

    return doc


def backfill_ip_exposure(es_host):
    ip_dir = os.path.join(DATA_DIR, "ip-exposure")
    if not os.path.isdir(ip_dir):
        print("No ip-exposure directory found, skipping.")
        return

    files = sorted(f for f in os.listdir(ip_dir) if f.endswith(".json") and "_latest" not in f)
    print(f"\n--- Backfilling security-ip-exposure: {len(files)} snapshot(s) ---")

    for fname in files:
        path = os.path.join(ip_dir, fname)
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)

        ts = doc.get("generated_at_utc") or parse_timestamp_from_filename(fname)
        if ts:
            doc["@timestamp"] = ts

        doc = _flatten_ip_exposure_doc(doc)
        ok = index_doc(es_host, "security-ip-exposure", doc)
        status = "OK" if ok else "FAIL"
        print(f"  [{status}] {fname}")


def backfill_subdomains(es_host):
    sub_dir = os.path.join(DATA_DIR, "subdomains")
    if not os.path.isdir(sub_dir):
        print("No subdomains directory found, skipping.")
        return

    files = sorted(f for f in os.listdir(sub_dir) if f.endswith(".txt") and "_latest" not in f)
    print(f"\n--- Backfilling security-subdomains: {len(files)} snapshot(s) ---")

    for fname in files:
        path = os.path.join(sub_dir, fname)
        with open(path, "r", encoding="utf-8") as fh:
            lines = [line.strip() for line in fh if line.strip()]

        ts = parse_timestamp_from_filename(fname)
        domain = fname.split("_")[0] if "_" in fname else "unknown"

        doc = {
            "target_domain": domain,
            "total": len(lines),
            "subdomains": sorted(lines),
            "source_counts": {"backfill": len(lines)},
        }
        if ts:
            doc["@timestamp"] = ts

        ok = index_doc(es_host, "security-subdomains", doc)
        status = "OK" if ok else "FAIL"
        print(f"  [{status}] {fname} ({len(lines)} subdomains)")


def backfill_assets(es_host):
    """Create per-subdomain asset records from ip-exposure JSON snapshots."""
    ip_dir = os.path.join(DATA_DIR, "ip-exposure")
    if not os.path.isdir(ip_dir):
        print("No ip-exposure directory found, skipping assets.")
        return

    # Use the latest JSON for backfill
    latest = os.path.join(ip_dir, "bri.co.id_latest.json")
    if not os.path.isfile(latest):
        files = sorted(f for f in os.listdir(ip_dir) if f.endswith(".json"))
        if not files:
            print("No ip-exposure JSON files found, skipping assets.")
            return
        latest = os.path.join(ip_dir, files[-1])

    with open(latest, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    target_domain = data.get("target_domain", "unknown")
    ip_details = data.get("ip_details", {})
    cname_map = data.get("domains_with_external_cname", {})
    if isinstance(cname_map, list):
        cname_map = {e["domain"]: e["cname"] for e in cname_map if isinstance(e, dict)}
    shodan = data.get("shodan", {})
    if isinstance(shodan, list):
        shodan = {e["ip"]: e for e in shodan if isinstance(e, dict) and "ip" in e}
    ts = data.get("generated_at_utc", "")

    # Build subdomain -> IPs reverse map from ip_details
    subdomain_to_ips = {}
    ip_providers = {}
    if isinstance(ip_details, dict):
        for ip, info in ip_details.items():
            provider = info.get("provider", "Unknown") if isinstance(info, dict) else "Unknown"
            subs = info.get("subdomains", []) if isinstance(info, dict) else info
            ip_providers[ip] = provider
            for sub in subs:
                subdomain_to_ips.setdefault(sub, []).append(ip)
    elif isinstance(ip_details, list):
        for entry in ip_details:
            ip = entry.get("ip", "")
            provider = entry.get("provider", "Unknown")
            ip_providers[ip] = provider
            for sub in entry.get("subdomains", []):
                subdomain_to_ips.setdefault(sub, []).append(ip)

    docs = []
    for subdomain, ips in sorted(subdomain_to_ips.items()):
        ips_sorted = sorted(ips)
        providers = list({ip_providers.get(ip, "Unknown") for ip in ips_sorted})
        cname = cname_map.get(subdomain, "")

        doc = {
            "@timestamp": ts,
            "target_domain": target_domain,
            "subdomain": subdomain,
            "ip_addresses": ips_sorted,
            "ip_count": len(ips_sorted),
            "provider": providers[0] if len(providers) == 1 else ", ".join(sorted(providers)),
            "providers": sorted(providers),
            "cname": cname,
            "has_cname": bool(cname),
            "has_public_ip": True,
        }

        shodan_info = None
        for ip in ips_sorted:
            if ip in shodan:
                shodan_info = shodan[ip]
                break
        if shodan_info:
            doc["shodan"] = {
                "ip": shodan_info.get("ip", ip),
                "org": shodan_info.get("org", ""),
                "isp": shodan_info.get("isp", ""),
                "asn": shodan_info.get("asn", ""),
                "ports": shodan_info.get("ports", []),
                "hostnames": shodan_info.get("hostnames", []),
            }

        docs.append(doc)

    print(f"\n--- Backfilling security-assets: {len(docs)} records ---")
    ok = bulk_index(es_host, "security-assets", docs)
    print(f"  [OK] {ok}/{len(docs)} asset records indexed from {os.path.basename(latest)}")


def main():
    parser = argparse.ArgumentParser(description="Backfill Elasticsearch with existing data files")
    parser.add_argument("--es-host", default="http://localhost:9200", help="Elasticsearch URL")
    args = parser.parse_args()

    if not wait_for_es(args.es_host):
        sys.exit(1)

    backfill_ip_exposure(args.es_host)
    backfill_subdomains(args.es_host)
    backfill_assets(args.es_host)

    print("\nBackfill complete.")


if __name__ == "__main__":
    main()
