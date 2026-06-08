import ipaddress
import json
import logging
import os
import socket
import ssl
import struct
from glob import glob
from datetime import datetime

import requests
from prometheus_client import Gauge

import dns.resolver

from es_store import store_ip_exposure, store_ip_records

public_exposed_ips_total = Gauge(
    "public_exposed_ips_total",
    "Total unique public IPs resolved from public subdomains",
)

public_exposed_ips_with_open_ports_total = Gauge(
    "public_exposed_ips_with_open_ports_total",
    "Unique public IPs with at least one open port from passive Shodan data",
)

public_exposed_ports_total = Gauge(
    "public_exposed_ports_total",
    "Count of public IP exposures by open port from passive Shodan data",
    ["port"],
)

public_exposed_subdomains_processed_total = Gauge(
    "public_exposed_subdomains_processed_total",
    "Total subdomains processed for DNS resolution",
)

public_exposed_shodan_enriched_total = Gauge(
    "public_exposed_shodan_enriched_total",
    "Public IPs successfully enriched using Shodan API",
)

public_exposed_last_collection_success = Gauge(
    "public_exposed_last_collection_success",
    "1 when latest passive IP exposure collection succeeded, otherwise 0",
)

public_subdomains_with_public_ip = Gauge(
    "public_subdomains_with_public_ip",
    "Subdomains that resolve to at least one public IP address",
)

public_subdomains_with_cname_external = Gauge(
    "public_subdomains_with_cname_external",
    "Subdomains with CNAME records pointing outside the target domain",
)

public_exposed_by_provider = Gauge(
    "public_exposed_by_provider",
    "Public IPs grouped by cloud or hosting provider",
    ["provider"],
)

public_exposed_asn_prefixes_total = Gauge(
    "public_exposed_asn_prefixes_total",
    "Total IPv4 CIDR prefixes announced by the target ASN",
)

public_exposed_asn_ips_total = Gauge(
    "public_exposed_asn_ips_total",
    "Total IP addresses covered by announced ASN prefixes",
)


def _sanitize_name(value):
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    cleaned = "".join(ch if ch in allowed else "_" for ch in value.lower())
    return cleaned or "domain"


def _read_subdomains(path):
    if not os.path.exists(path):
        return []

    items = []
    with open(path, "r", encoding="utf-8") as file_obj:
        for line in file_obj:
            value = line.strip().lower()
            if value:
                items.append(value)

    return sorted(set(items))


def _find_latest_snapshot_file(default_latest_file, domain_key):
    directory = os.path.dirname(default_latest_file)
    pattern = os.path.join(directory, f"{domain_key}_*.txt")
    candidates = [item for item in glob(pattern) if not item.endswith("_latest.txt")]
    if not candidates:
        return None

    candidates.sort(key=os.path.getmtime, reverse=True)
    for candidate in candidates:
        if os.path.getsize(candidate) > 0:
            return candidate

    return None


def _is_public_ip(value):
    try:
        ip_obj = ipaddress.ip_address(value)
        return ip_obj.is_global
    except ValueError:
        return False


def _resolve_public_ips(hostname):
    found = set()
    try:
        results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        for result in results:
            ip_value = result[4][0]
            if _is_public_ip(ip_value):
                found.add(ip_value)
    except socket.gaierror:
        return set()

    return found


def _resolve_all_ips(hostname):
    """Resolve all IPs (public + private) for a hostname."""
    found = set()
    try:
        results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        for result in results:
            ip_value = result[4][0]
            found.add(ip_value)
    except socket.gaierror:
        pass
    return found


def _probe_ssl(hostname, timeout=3):
    """Probe port 443 for TLS certificate and return issuer info.

    Returns dict with ssl_enabled, issuer, issuer_org, subject, not_before, not_after
    or None if SSL is not available.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # accept self-signed/expired certs
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return {"ssl_enabled": True, "issuer": "Unknown", "issuer_org": "Unknown"}
                return _parse_der_cert_issuer(der)
    except (socket.timeout, socket.gaierror, ConnectionRefusedError,
            ConnectionResetError, OSError):
        return None
    except Exception:
        return None


def _parse_der_cert_issuer(der_bytes):
    """Extract issuer from DER-encoded certificate using ssl module."""
    import tempfile, subprocess, shutil

    # Try using the cryptography library if available
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der_bytes)
        issuer_str = cert.issuer.rfc4514_string()
        # Extract O= from issuer
        issuer_org = "Unknown"
        for attr in cert.issuer:
            if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                issuer_org = attr.value
                break
        not_before = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else str(cert.not_valid_before)
        not_after = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else str(cert.not_valid_after)
        subject_str = cert.subject.rfc4514_string()
        return {
            "ssl_enabled": True,
            "issuer": issuer_str,
            "issuer_org": issuer_org,
            "subject": subject_str,
            "not_before": not_before,
            "not_after": not_after,
        }
    except ImportError:
        pass

    # Minimal fallback: just report SSL is enabled
    return {"ssl_enabled": True, "issuer": "Unknown", "issuer_org": "Unknown"}


def _resolve_cname(hostname):
    """Resolve CNAME for hostname using dnspython.

    Returns the CNAME target as a string, or None if no CNAME exists.
    Follows the first CNAME hop only.
    """
    try:
        answers = dns.resolver.resolve(hostname, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".").lower()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.Timeout,
            dns.name.EmptyLabel, Exception):
        pass
    return None


_PROVIDER_CIDRS = None


def _build_provider_cidrs():
    """Build a list of (network, provider_name) tuples from well-known CIDR ranges."""
    raw = [
        # Google Cloud
        ("34.64.0.0/10", "Google Cloud"),
        ("34.128.0.0/10", "Google Cloud"),
        ("35.184.0.0/13", "Google Cloud"),
        ("35.192.0.0/12", "Google Cloud"),
        ("35.208.0.0/12", "Google Cloud"),
        ("35.224.0.0/12", "Google Cloud"),
        ("35.240.0.0/13", "Google Cloud"),
        ("104.196.0.0/14", "Google Cloud"),
        ("104.154.0.0/15", "Google Cloud"),
        # AWS
        ("3.0.0.0/9", "AWS"),
        ("3.128.0.0/9", "AWS"),
        ("13.32.0.0/11", "AWS"),
        ("13.64.0.0/11", "AWS"),
        ("13.208.0.0/12", "AWS"),
        ("13.224.0.0/12", "AWS"),
        ("13.248.0.0/13", "AWS"),
        ("15.0.0.0/9", "AWS"),
        ("15.128.0.0/10", "AWS"),
        ("15.192.0.0/11", "AWS"),
        ("16.0.0.0/8", "AWS"),
        ("18.0.0.0/8", "AWS"),
        ("43.192.0.0/11", "AWS"),
        ("43.224.0.0/12", "AWS"),
        ("44.192.0.0/10", "AWS"),
        ("52.0.0.0/10", "AWS"),
        ("52.64.0.0/11", "AWS"),
        ("52.192.0.0/10", "AWS"),
        ("54.0.0.0/8", "AWS"),
        ("99.77.0.0/16", "AWS"),
        ("99.150.0.0/15", "AWS"),
        # Azure
        ("13.64.0.0/11", "Azure"),
        ("13.96.0.0/13", "Azure"),
        ("13.104.0.0/14", "Azure"),
        ("20.0.0.0/8", "Azure"),
        ("40.64.0.0/10", "Azure"),
        ("51.104.0.0/14", "Azure"),
        ("52.96.0.0/12", "Azure"),
        ("52.112.0.0/13", "Azure"),
        ("52.120.0.0/14", "Azure"),
        ("52.224.0.0/11", "Azure"),
        ("104.40.0.0/13", "Azure"),
        ("104.208.0.0/13", "Azure"),
        ("168.61.0.0/16", "Azure"),
        ("168.62.0.0/15", "Azure"),
        ("191.232.0.0/13", "Azure"),
        # Cloudflare
        ("103.21.244.0/22", "Cloudflare"),
        ("103.22.200.0/22", "Cloudflare"),
        ("103.31.4.0/22", "Cloudflare"),
        ("104.16.0.0/13", "Cloudflare"),
        ("104.24.0.0/14", "Cloudflare"),
        ("108.162.192.0/18", "Cloudflare"),
        ("131.0.72.0/22", "Cloudflare"),
        ("141.101.64.0/18", "Cloudflare"),
        ("162.158.0.0/15", "Cloudflare"),
        ("172.64.0.0/13", "Cloudflare"),
        ("173.245.48.0/20", "Cloudflare"),
        ("188.114.96.0/20", "Cloudflare"),
        ("190.93.240.0/20", "Cloudflare"),
        ("197.234.240.0/22", "Cloudflare"),
        ("198.41.128.0/17", "Cloudflare"),
        # Akamai
        ("23.0.0.0/12", "Akamai"),
        ("23.32.0.0/11", "Akamai"),
        ("23.64.0.0/14", "Akamai"),
        ("23.192.0.0/11", "Akamai"),
        ("104.64.0.0/10", "Akamai"),
        ("184.24.0.0/13", "Akamai"),
        ("184.50.0.0/15", "Akamai"),
        ("184.84.0.0/14", "Akamai"),
        # DigitalOcean
        ("104.131.0.0/16", "DigitalOcean"),
        ("128.199.0.0/16", "DigitalOcean"),
        ("138.68.0.0/15", "DigitalOcean"),
        ("139.59.0.0/16", "DigitalOcean"),
        ("142.93.0.0/16", "DigitalOcean"),
        ("143.198.0.0/16", "DigitalOcean"),
        ("157.245.0.0/16", "DigitalOcean"),
        ("159.65.0.0/16", "DigitalOcean"),
        ("159.89.0.0/16", "DigitalOcean"),
        ("161.35.0.0/16", "DigitalOcean"),
        ("164.90.0.0/16", "DigitalOcean"),
        ("165.22.0.0/16", "DigitalOcean"),
        ("167.172.0.0/16", "DigitalOcean"),
        ("167.71.0.0/16", "DigitalOcean"),
        ("174.138.0.0/16", "DigitalOcean"),
        ("178.128.0.0/16", "DigitalOcean"),
        # Alibaba Cloud
        ("47.74.0.0/15", "Alibaba Cloud"),
        ("47.88.0.0/14", "Alibaba Cloud"),
        ("47.236.0.0/14", "Alibaba Cloud"),
        ("47.240.0.0/13", "Alibaba Cloud"),
        ("47.248.0.0/14", "Alibaba Cloud"),
        ("47.252.0.0/14", "Alibaba Cloud"),
        ("8.208.0.0/12", "Alibaba Cloud"),
        ("149.129.0.0/16", "Alibaba Cloud"),
        ("161.117.0.0/16", "Alibaba Cloud"),
        # Linode / Akamai Connected Cloud
        ("45.33.0.0/16", "Linode"),
        ("45.56.0.0/16", "Linode"),
        ("45.79.0.0/16", "Linode"),
        ("66.175.208.0/20", "Linode"),
        ("69.164.192.0/18", "Linode"),
        ("96.126.96.0/19", "Linode"),
        ("170.187.128.0/17", "Linode"),
        ("172.104.0.0/15", "Linode"),
        ("172.232.0.0/14", "Linode"),
        ("173.255.192.0/18", "Linode"),
        ("178.79.128.0/17", "Linode"),
        ("192.155.80.0/20", "Linode"),
        ("194.195.192.0/18", "Linode"),
        ("198.58.96.0/19", "Linode"),
        # Fastly
        ("23.235.32.0/20", "Fastly"),
        ("43.249.72.0/22", "Fastly"),
        ("103.244.50.0/24", "Fastly"),
        ("104.156.80.0/20", "Fastly"),
        ("140.248.64.0/18", "Fastly"),
        ("151.101.0.0/16", "Fastly"),
        ("157.52.64.0/18", "Fastly"),
        ("167.82.0.0/17", "Fastly"),
        ("185.31.16.0/22", "Fastly"),
        ("199.27.72.0/21", "Fastly"),
        # Incapsula / Imperva
        ("45.60.0.0/16", "Imperva"),
        ("107.154.0.0/16", "Imperva"),
        ("199.83.128.0/21", "Imperva"),
        # Sectigo / Comodo
        ("185.3.92.0/22", "Sectigo"),
        # === Indonesian Local Providers ===
        # BRI own allocation (PT Bank Rakyat Indonesia via Telkom)
        ("103.63.96.0/22", "BRI (Own)"),
        # Telkom Indonesia (PT Telekomunikasi Indonesia)
        ("36.64.0.0/11", "Telkom Indonesia"),
        ("36.68.0.0/14", "Telkom Indonesia"),
        ("36.72.0.0/13", "Telkom Indonesia"),
        ("36.80.0.0/12", "Telkom Indonesia"),
        ("103.3.56.0/22", "Telkom Indonesia"),
        ("103.10.66.0/23", "Telkom Indonesia"),
        ("110.136.0.0/13", "Telkom Indonesia"),
        ("114.120.0.0/13", "Telkom Indonesia"),
        ("114.124.0.0/14", "Telkom Indonesia"),
        ("125.160.0.0/13", "Telkom Indonesia"),
        ("140.213.0.0/16", "Telkom Indonesia"),
        ("180.240.0.0/12", "Telkom Indonesia"),
        ("180.252.0.0/14", "Telkom Indonesia"),
        ("202.134.0.0/15", "Telkom Indonesia"),
        ("202.152.0.0/14", "Telkom Indonesia"),
        ("202.158.0.0/15", "Telkom Indonesia"),
        ("203.130.192.0/18", "Telkom Indonesia"),
        # Telkomsel (mobile arm of Telkom)
        ("103.28.112.0/22", "Telkomsel"),
        ("114.0.0.0/13", "Telkomsel"),
        ("114.8.0.0/14", "Telkomsel"),
        ("182.0.0.0/12", "Telkomsel"),
        # XL Axiata
        ("103.11.216.0/22", "XL Axiata"),
        ("103.47.132.0/22", "XL Axiata"),
        ("112.215.0.0/16", "XL Axiata"),
        ("118.96.0.0/11", "XL Axiata"),
        # Indosat Ooredoo
        ("103.28.12.0/22", "Indosat Ooredoo"),
        ("114.31.0.0/16", "Indosat Ooredoo"),
        ("114.141.0.0/16", "Indosat Ooredoo"),
        ("116.58.0.0/15", "Indosat Ooredoo"),
        ("124.81.0.0/16", "Indosat Ooredoo"),
        ("124.153.0.0/16", "Indosat Ooredoo"),
        ("180.214.224.0/19", "Indosat Ooredoo"),
        # Biznet
        ("112.78.128.0/17", "Biznet"),
        ("117.102.64.0/18", "Biznet"),
        ("202.169.32.0/19", "Biznet"),
        ("203.142.64.0/18", "Biznet"),
        # Lintasarta (enterprise/banking ISP)
        ("202.162.192.0/18", "Lintasarta"),
        ("202.152.0.0/17", "Lintasarta"),
        ("103.226.138.0/23", "Lintasarta"),
        # CBN (Cyberindo Aditama)
        ("202.158.52.0/22", "CBN"),
        ("210.210.128.0/18", "CBN"),
        # MNC (Media Nusantara Citra)
        ("103.87.108.0/22", "MNC"),
        ("118.136.0.0/13", "MNC"),
        # MyRepublic Indonesia
        ("103.82.204.0/22", "MyRepublic"),
        ("36.86.63.0/24", "MyRepublic"),
        # First Media
        ("103.19.56.0/22", "First Media"),
        ("110.93.32.0/19", "First Media"),
        ("175.103.32.0/19", "First Media"),
    ]
    return [(ipaddress.ip_network(cidr, strict=False), name) for cidr, name in raw]


def _detect_provider(ip_value):
    """Detect hosting/cloud provider by matching against known CIDR ranges."""
    global _PROVIDER_CIDRS
    if _PROVIDER_CIDRS is None:
        _PROVIDER_CIDRS = _build_provider_cidrs()

    try:
        addr = ipaddress.ip_address(ip_value)
    except ValueError:
        return "Unknown"

    for network, provider_name in _PROVIDER_CIDRS:
        if addr in network:
            return provider_name

    return "Other"


def _fetch_asn_prefixes(asn, timeout=30):
    """Fetch announced IPv4 prefixes for an ASN via RIPE Stat (primary) or BGPView (fallback)."""
    # Primary: RIPE Stat
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        prefixes = []
        for entry in data.get("data", {}).get("prefixes", []):
            prefix = entry.get("prefix")
            if prefix:
                prefixes.append(prefix)
        if prefixes:
            logging.info("ip_exposure_exporter: fetched %s prefixes from RIPE Stat for AS%s", len(prefixes), asn)
            return prefixes
    except Exception as exc:
        logging.warning("ip_exposure_exporter: RIPE Stat ASN lookup failed: %s", exc)

    # Fallback: BGPView
    try:
        url = f"https://api.bgpview.io/asn/{asn}/prefixes"
        resp = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
        resp.raise_for_status()
        data = resp.json()
        prefixes = []
        for entry in data.get("data", {}).get("ipv4_prefixes", []):
            prefix = entry.get("prefix")
            if prefix:
                prefixes.append(prefix)
        if prefixes:
            logging.info("ip_exposure_exporter: fetched %s prefixes from BGPView for AS%s", len(prefixes), asn)
            return prefixes
    except Exception as exc:
        logging.warning("ip_exposure_exporter: BGPView ASN lookup failed: %s", exc)

    return []


def _query_shodan(ip_value, api_key, timeout_seconds):
    url = f"https://api.shodan.io/shodan/host/{ip_value}"
    response = requests.get(url, params={"key": api_key}, timeout=timeout_seconds)

    if response.status_code == 404:
        return None

    response.raise_for_status()
    return response.json()


def _prune_snapshots(output_dir, domain_key, max_keep=5):
    pattern = os.path.join(output_dir, f"{domain_key}_20*.json")
    snapshots = sorted(glob(pattern))
    for old_file in snapshots[:-max_keep]:
        try:
            os.remove(old_file)
        except OSError:
            pass


def _write_outputs(output_dir, domain_key, payload):
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    latest_json = os.path.join(output_dir, f"{domain_key}_latest.json")
    snapshot_json = os.path.join(output_dir, f"{domain_key}_{timestamp}.json")
    latest_ip_txt = os.path.join(output_dir, f"{domain_key}_latest_ips.txt")

    text_lines = []
    for ip_value in payload.get("public_ips", []):
        text_lines.append(ip_value)
    text_content = "\n".join(text_lines)
    if text_content:
        text_content += "\n"

    json_content = json.dumps(payload, indent=2, sort_keys=True)

    for path in (latest_json, snapshot_json):
        with open(path, "w", encoding="utf-8") as file_obj:
            file_obj.write(json_content)
            file_obj.write("\n")

    with open(latest_ip_txt, "w", encoding="utf-8") as file_obj:
        file_obj.write(text_content)

    _prune_snapshots(output_dir, domain_key)


def collect_public_ip_exposure():
    target_domain = os.getenv("SUBDOMAIN_TARGET_DOMAIN", "bri.co.id").strip().lower()
    domain_key = _sanitize_name(target_domain)

    subdomain_file = os.getenv(
        "SUBDOMAIN_LATEST_FILE",
        f"/data/subdomains/{domain_key}_latest.txt",
    ).strip()
    output_dir = os.getenv("IP_EXPOSURE_OUTPUT_DIR", "/data/ip-exposure").strip()
    shodan_api_key = os.getenv("SHODAN_API_KEY", "").strip()
    shodan_timeout = int(os.getenv("IP_EXPOSURE_SHODAN_TIMEOUT", "20"))
    max_ips = int(os.getenv("IP_EXPOSURE_MAX_IPS", "300"))
    target_asn = os.getenv("TARGET_ASN", "").strip()

    subdomains = _read_subdomains(subdomain_file)
    effective_subdomain_file = subdomain_file

    if not subdomains:
        snapshot_file = _find_latest_snapshot_file(subdomain_file, domain_key)
        if snapshot_file:
            fallback_subdomains = _read_subdomains(snapshot_file)
            if fallback_subdomains:
                subdomains = fallback_subdomains
                effective_subdomain_file = snapshot_file
                logging.warning(
                    "ip_exposure_exporter: using fallback snapshot file %s",
                    snapshot_file,
                )
    public_exposed_subdomains_processed_total.set(len(subdomains))

    ip_to_subdomains = {}
    domains_with_public_ip = set()
    domains_with_external_cname = set()
    cname_map = {}           # ALL CNAMEs (internal + external)
    all_ips_map = {}         # subdomain -> set of all IPs (public + private)
    ssl_map = {}             # subdomain -> ssl probe result

    total_subs = len(subdomains)
    for idx, subdomain in enumerate(subdomains, 1):
        if idx % 50 == 0 or idx == total_subs:
            logging.warning("ip_exposure_exporter: processing %s/%s subdomains...", idx, total_subs)
        # Resolve all IPs (public + private)
        all_ips = _resolve_all_ips(subdomain)
        if all_ips:
            all_ips_map[subdomain] = all_ips

        # Track public IPs separately for existing metrics
        public_ips_for_sub = {ip for ip in all_ips if _is_public_ip(ip)}
        if public_ips_for_sub:
            domains_with_public_ip.add(subdomain)
        for ip_value in public_ips_for_sub:
            if ip_value not in ip_to_subdomains:
                ip_to_subdomains[ip_value] = set()
            ip_to_subdomains[ip_value].add(subdomain)

        # Resolve CNAME (all, not just external)
        cname_target = _resolve_cname(subdomain)
        if cname_target:
            cname_map[subdomain] = cname_target
            if not cname_target.endswith("." + target_domain) and cname_target != target_domain:
                domains_with_external_cname.add(subdomain)

        # Probe SSL/TLS
        ssl_info = _probe_ssl(subdomain)
        if ssl_info:
            ssl_map[subdomain] = ssl_info

    # --- ASN-based IP prefix discovery ---
    asn_prefixes = []
    asn_total_ips = 0
    if target_asn:
        asn_prefixes = _fetch_asn_prefixes(target_asn)
        for prefix_str in asn_prefixes:
            try:
                net = ipaddress.ip_network(prefix_str, strict=False)
                asn_total_ips += net.num_addresses
                # Add network + broadcast address as representative IPs
                for ip_obj in [net.network_address, net.broadcast_address]:
                    ip_value = str(ip_obj)
                    if _is_public_ip(ip_value) and ip_value not in ip_to_subdomains:
                        ip_to_subdomains[ip_value] = set()
            except ValueError:
                pass
        logging.info(
            "ip_exposure_exporter: ASN %s announced %s prefixes covering %s IPs",
            target_asn, len(asn_prefixes), asn_total_ips,
        )

    public_exposed_asn_prefixes_total.set(len(asn_prefixes))
    public_exposed_asn_ips_total.set(asn_total_ips)

    public_ips = sorted(ip_to_subdomains.keys())
    selected_ips = public_ips[:max_ips]

    provider_counts = {}
    ip_providers = {}
    for ip_value in public_ips:
        provider = _detect_provider(ip_value)
        ip_providers[ip_value] = provider
        provider_counts[provider] = provider_counts.get(provider, 0) + 1

    port_counts = {}
    ips_with_ports = set()
    shodan_enriched = 0
    shodan_records = {}

    # --- Shodan enrichment temporarily disabled (free plan has 0 query credits) ---
    # To re-enable: remove the 'if False and' prefix below
    if False and shodan_api_key:
        for ip_value in selected_ips:
            try:
                record = _query_shodan(ip_value, shodan_api_key, shodan_timeout)
                if not record:
                    continue

                shodan_enriched += 1
                ports = sorted(set(record.get("ports", [])))
                if ports:
                    ips_with_ports.add(ip_value)
                for port in ports:
                    key = str(port)
                    port_counts[key] = port_counts.get(key, 0) + 1

                shodan_records[ip_value] = {
                    "org": record.get("org"),
                    "isp": record.get("isp"),
                    "asn": record.get("asn"),
                    "ports": ports,
                    "last_update": record.get("last_update"),
                    "hostnames": record.get("hostnames", []),
                }
            except requests.HTTPError as exc:
                status_code = exc.response.status_code if exc.response is not None else "unknown"
                if status_code in (401, 403):
                    logging.warning(
                        "ip_exposure_exporter: shodan access denied (status=%s), stopping enrichment",
                        status_code,
                    )
                    break
                if status_code == 429:
                    logging.warning("ip_exposure_exporter: shodan rate limit hit, stopping enrichment")
                    break
                logging.warning(
                    "ip_exposure_exporter: shodan HTTP error for %s (status=%s)",
                    ip_value,
                    status_code,
                )
            except Exception as exc:
                logging.warning("ip_exposure_exporter: shodan lookup failed for %s", ip_value)

    public_exposed_ips_total.set(len(public_ips))
    public_exposed_ips_with_open_ports_total.set(len(ips_with_ports))
    public_exposed_shodan_enriched_total.set(shodan_enriched)
    public_subdomains_with_public_ip.set(len(domains_with_public_ip))
    public_subdomains_with_cname_external.set(len(domains_with_external_cname))

    for provider, count in provider_counts.items():
        public_exposed_by_provider.labels(provider=provider).set(count)

    # Update only seen ports. Existing labels are left as-is by Prometheus client.
    for port, count in port_counts.items():
        public_exposed_ports_total.labels(port=port).set(count)

    success = 1 if (public_ips or asn_prefixes) else 0
    public_exposed_last_collection_success.set(success)

    payload = {
        "target_domain": target_domain,
        "generated_at_utc": datetime.utcnow().isoformat() + "Z",
        "subdomain_file": effective_subdomain_file,
        "subdomains_processed": len(subdomains),
        "public_ips_total": len(public_ips),
        "public_ips_selected_for_shodan": len(selected_ips),
        "shodan_enriched_total": shodan_enriched,
        "ips_with_open_ports_total": len(ips_with_ports),
        "public_ips": public_ips,
        "ip_details": {
            ip: {
                "provider": ip_providers.get(ip, "Unknown"),
                "subdomains": sorted(ip_to_subdomains.get(ip, set())),
            }
            for ip in public_ips
        },
        "asn": target_asn if target_asn else None,
        "asn_prefixes": asn_prefixes,
        "asn_prefixes_total": len(asn_prefixes),
        "asn_ips_total": asn_total_ips,
        "domains_with_public_ip": sorted(domains_with_public_ip),
        "domains_with_public_ip_total": len(domains_with_public_ip),
        "domains_with_external_cname": {k: v for k, v in sorted(cname_map.items())},
        "domains_with_external_cname_total": len(domains_with_external_cname),
        "provider_counts": provider_counts,
        "port_counts": port_counts,
        "shodan": shodan_records,
    }

    try:
        _write_outputs(output_dir, domain_key, payload)
    except Exception as exc:
        logging.warning("ip_exposure_exporter: failed writing output files: %s", exc)

    store_ip_exposure(payload)
    store_ip_records(target_domain, ip_to_subdomains, ip_providers,
                     cname_map, shodan_records, all_ips_map, ssl_map,
                     subdomains)

    logging.info(
        "Passive IP exposure for %s: subdomains=%s public_ips=%s asn_prefixes=%s asn_ips=%s domains_with_ip=%s external_cname=%s total_cname=%s ssl_enabled=%s shodan_enriched=%s ips_with_ports=%s",
        target_domain,
        len(subdomains),
        len(public_ips),
        len(asn_prefixes),
        asn_total_ips,
        len(domains_with_public_ip),
        len(domains_with_external_cname),
        len(cname_map),
        len(ssl_map),
        shodan_enriched,
        len(ips_with_ports),
    )
