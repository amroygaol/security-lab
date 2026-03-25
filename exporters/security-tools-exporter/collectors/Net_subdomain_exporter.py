import logging
import os
import re
import time
from glob import glob
from datetime import datetime
from urllib.parse import urljoin

import requests
from prometheus_client import Gauge

from es_store import store_subdomains

public_subdomains_total = Gauge(
    "public_subdomains_total",
    "Total unique public subdomains discovered from free sources"
)

public_subdomains_source_total = Gauge(
    "public_subdomains_source_total",
    "Unique public subdomains discovered per source",
    ["source"],
)

public_subdomains_last_collection_success = Gauge(
    "public_subdomains_last_collection_success",
    "1 when latest collection succeeded, otherwise 0",
)


def _sanitize_domain_for_filename(value):
    return re.sub(r"[^a-z0-9.-]", "_", value.lower())


def _prune_snapshots(output_dir, domain_key, max_keep=5):
    pattern = os.path.join(output_dir, f"{domain_key}_20*.txt")
    snapshots = sorted(glob(pattern))
    for old_file in snapshots[:-max_keep]:
        try:
            os.remove(old_file)
        except OSError:
            pass


def _read_existing_subdomains(latest_path):
    """Read previously discovered subdomains from the latest file."""
    if not os.path.isfile(latest_path):
        return set()
    try:
        with open(latest_path, "r", encoding="utf-8") as fh:
            return {line.strip() for line in fh if line.strip()}
    except Exception:
        return set()


def _write_subdomain_files(target_domain, subdomains, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    domain_key = _sanitize_domain_for_filename(target_domain)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    latest_path = os.path.join(output_dir, f"{domain_key}_latest.txt")
    snapshot_path = os.path.join(output_dir, f"{domain_key}_{timestamp}.txt")

    # Merge with existing data so partial source failures don't shrink the list
    existing = _read_existing_subdomains(latest_path)
    merged = existing | subdomains

    content = "\n".join(sorted(merged))
    if content:
        content += "\n"

    with open(latest_path, "w", encoding="utf-8") as latest_file:
        latest_file.write(content)

    with open(snapshot_path, "w", encoding="utf-8") as snapshot_file:
        snapshot_file.write(content)

    _prune_snapshots(output_dir, domain_key)

    return latest_path, snapshot_path, len(merged)


def _normalize_hostname(value):
    if not value:
        return None

    host = str(value).strip().lower()
    host = host.replace("\x00", "")

    if "@" in host:
        return None

    if host.startswith("*."):
        host = host[2:]

    host = host.rstrip(".")

    # Skip obvious non-hostname values.
    if "/" in host or " " in host:
        return None

    return host or None


def _get_org(issuer_raw):
    """Extract Organization (O) or Common Name (CN) from raw issuer string."""
    if not issuer_raw:
        return "Unknown"
    for part in str(issuer_raw).split(','):
        if part.strip().startswith('O='):
            return part.strip()[2:].strip('"')
    for part in str(issuer_raw).split(','):
        if part.strip().startswith('CN='):
            return part.strip()[3:].strip('"')
    return str(issuer_raw).strip()

def _extract_from_crtsh(target_domain):
    rows = None
    for query in (f"%25.{target_domain}", target_domain):
        url = f"https://crt.sh/?q={query}&output=json"
        
        # Implement a robust retry mechanism because crt.sh takes extremely long to render massive wildcards
        for attempt in range(3):
            try:
                response = requests.get(url, timeout=120)

                # crt.sh frequently crashes with 500/502/503 on high-volume domains.
                if response.status_code >= 500 or response.status_code == 404:
                    logging.warning("subdomain_exporter: crt.sh returned HTTP %s for %s. Skipping to fallback...", response.status_code, query)
                    break # Break retry loop immediately, proceed to the narrower fallback query

                response.raise_for_status()
                rows = response.json()
                break # Extracted cleanly! Escape the retry circuit
                
            except requests.exceptions.Timeout:
                logging.warning("subdomain_exporter: crt.sh timed out on attempt %s for %s. Retrying...", attempt+1, query)
                time.sleep(10)
            except Exception as exc: # Catches all RequestExceptions and JSONDecodeErrors
                logging.warning("subdomain_exporter: crt.sh crashed on attempt %s for %s: %s", attempt+1, query, exc)
                time.sleep(10)
                
        # If rows populated successfully, don't execute the fall-back query
        if rows is not None:
             break

    if rows is None:
        return {}
    
    found = {}

    for row in rows:
        name_value = row.get("name_value")
        if not name_value:
            continue
            
        issuer_raw = row.get("issuer_name", "Unknown")
        issuer = str(issuer_raw).strip()

        for candidate in str(name_value).splitlines():
            host = _normalize_hostname(candidate)
            if not host:
                continue
            if host == target_domain:
                continue
            if host.endswith("." + target_domain):
                if host not in found:
                    found[host] = set()
                found[host].add(issuer)

    return found


def _parse_next_link(link_header):
    if not link_header:
        return None

    # Example: <https://...&cursor=abc>; rel="next"
    match = re.search(r"<([^>]+)>\s*;\s*rel=\"next\"", link_header)
    if not match:
        return None

    return match.group(1)


def _extract_from_certspotter(target_domain, max_pages):
    base_url = "https://api.certspotter.com"
    url = (
        f"{base_url}/v1/issuances"
        f"?domain={target_domain}&include_subdomains=true&expand=dns_names&expand=issuer"
    )

    headers = {}
    api_token = os.getenv("CERTSPOTTER_API_KEY", "").strip()
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"

    found = {}
    pages = 0

    while url and pages < max_pages:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        rows = response.json()

        for row in rows:
            issuer_raw = row.get("issuer", {}).get("name", "Unknown")
            issuer = _get_org(issuer_raw)
            
            for dns_name in row.get("dns_names", []):
                host = _normalize_hostname(dns_name)
                if not host:
                    continue
                if host == target_domain:
                    continue
                if host.endswith("." + target_domain):
                    if host not in found:
                        found[host] = set()
                    found[host].add(issuer)

        pages += 1
        next_link = _parse_next_link(response.headers.get("Link"))
        url = urljoin(base_url, next_link) if next_link else None

    return found


def collect_public_subdomains():
    target_domain = os.getenv("SUBDOMAIN_TARGET_DOMAIN", "bri.co.id").strip().lower()
    certspotter_max_pages = int(os.getenv("SUBDOMAIN_CERTSPOTTER_MAX_PAGES", "5"))
    output_dir = os.getenv("SUBDOMAIN_OUTPUT_DIR", "/data/subdomains").strip()

    crtsh_set = {}
    certspotter_set = {}

    try:
        crtsh_set = _extract_from_crtsh(target_domain)
    except Exception as exc:
        logging.warning("subdomain_exporter: crt.sh collection failed: %s", exc)

    try:
        certspotter_set = _extract_from_certspotter(target_domain, certspotter_max_pages)
    except Exception as exc:
        logging.warning("subdomain_exporter: certspotter collection failed: %s", exc)

    merged = {}
    for k, v in crtsh_set.items():
        if k not in merged: merged[k] = set()
        merged[k].update(v)
    for k, v in certspotter_set.items():
        if k not in merged: merged[k] = set()
        merged[k].update(v)

    public_subdomains_source_total.labels(source="crtsh").set(len(crtsh_set))
    public_subdomains_source_total.labels(source="certspotter").set(len(certspotter_set))
    public_subdomains_total.set(len(merged))

    # Mark failure only when both free sources fail to return any data.
    public_subdomains_last_collection_success.set(1 if merged else 0)

    if merged:
        try:
            latest_path, snapshot_path, merged_total = _write_subdomain_files(target_domain, set(merged.keys()), output_dir)
            # Update metric to reflect the full merged set (existing + new)
            public_subdomains_total.set(merged_total)
            logging.info(
                "Subdomain files updated: latest=%s snapshot=%s (new=%s merged=%s)",
                latest_path,
                snapshot_path,
                len(merged),
                merged_total,
            )
        except Exception as exc:
            logging.warning("subdomain_exporter: failed writing output files: %s", exc)
    else:
        logging.warning(
            "subdomain_exporter: no subdomains discovered for %s; keeping previous output files",
            target_domain,
        )

    logging.info(
        "Subdomain collection for %s: total=%s crtsh=%s certspotter=%s",
        target_domain,
        len(merged),
        len(crtsh_set),
        len(certspotter_set),
    )

    store_subdomains(
        target_domain,
        len(merged),
        {"crtsh": len(crtsh_set), "certspotter": len(certspotter_set)},
        merged,
    )
