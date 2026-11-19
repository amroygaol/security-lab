#!/usr/bin/env python3
"""
Test script for security tools exporters.
This script calls the collect functions and prints the metric values to the console.
It does not start the Prometheus HTTP server.
"""

import os
import sys

# Load environment variables from .env file if it exists
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()

# Add the current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

# Import the collector modules
from collectors.Net_digicert_exporter import (
    collect_digicert,
    digicert_cert_total,
    digicert_cert_active,
    digicert_cert_expired,
    digicert_cert_revoked,
    digicert_cert_expiring_30,
    digicert_cert_expiring_14,
    digicert_cert_expiring_7,
)
from collectors.GRC_rapid7_exporter import collect_rapid7, rapid7_assets_total, rapid7_vuln_total, rapid7_vuln_critical, rapid7_vuln_high
from collectors.EP_cortex_exporter import (
    collect_cortex,
    cortex_xdr_endpoints_total,
    cortex_xdr_endpoints_online,
    cortex_xdr_malware_alerts_total,
    cortex_xdr_incidents_open,
    cortex_xdr_incidents_high,
    cortex_xdr_incidents_medium,
    cortex_xdr_incidents_low,
    cortex_xdr_alerts_total,
    cortex_xdr_alerts,
    cortex_xdr_agents_outdated,
)
from collectors.Net_subdomain_exporter import (
    collect_public_subdomains,
    public_subdomains_total,
    public_subdomains_source_total,
    public_subdomains_last_collection_success,
)
from collectors.Net_ip_exposure_exporter import (
    collect_public_ip_exposure,
    public_exposed_ips_total,
    public_exposed_ips_with_open_ports_total,
    public_exposed_subdomains_processed_total,
    public_exposed_shodan_enriched_total,
    public_exposed_last_collection_success,
    public_subdomains_with_public_ip,
    public_subdomains_with_cname_external,
    public_exposed_by_provider,
    public_exposed_asn_prefixes_total,
    public_exposed_asn_ips_total,
)

def test_collectors():
    print("Testing Security Tools Exporters...")
    print("=" * 50)

    # Test DigiCert
    print("\n1. Testing DigiCert Exporter:")
    try:
        # collect_digicert()
        print(f"   Total certificates: {digicert_cert_total._value.get()}")
        print(f"   Active certificates: {digicert_cert_active._value.get()}")
        print(f"   Expired certificates: {digicert_cert_expired._value.get()}")
        print(f"   Revoked certificates: {digicert_cert_revoked._value.get()}")
        print(f"   Expiring in 30 days: {digicert_cert_expiring_30._value.get()}")
        print(f"   Expiring in 14 days: {digicert_cert_expiring_14._value.get()}")
        print(f"   Expiring in 7 days: {digicert_cert_expiring_7._value.get()}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test Rapid7
    print("\n2. Testing Rapid7 Exporter:")
    try:
        collect_rapid7()
        print(f"   Total assets: {rapid7_assets_total._value.get()}")
        print(f"   Total vulnerabilities: {rapid7_vuln_total._value.get()}")
        print(f"   Critical vulnerabilities: {rapid7_vuln_critical._value.get()}")
        print(f"   High vulnerabilities: {rapid7_vuln_high._value.get()}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test Cortex
    print("\n3. Testing Cortex XDR Exporter:")
    try:
        collect_cortex()
        print(f"   Total endpoints: {cortex_xdr_endpoints_total._value.get()}")
        print(f"   Online endpoints: {cortex_xdr_endpoints_online._value.get()}")
        print(f"   Malware alerts: {cortex_xdr_malware_alerts_total._value.get()}")
        print(f"   Open incidents: {cortex_xdr_incidents_open._value.get()}")
        print(f"   Open incidents (high): {cortex_xdr_incidents_high._value.get()}")
        print(f"   Open incidents (medium): {cortex_xdr_incidents_medium._value.get()}")
        print(f"   Open incidents (low): {cortex_xdr_incidents_low._value.get()}")
        print(f"   Alerts total: {cortex_xdr_alerts_total._value.get()}")
        print(f"   Alerts (high): {cortex_xdr_alerts.labels(severity='high')._value.get()}")
        print(f"   Alerts (medium): {cortex_xdr_alerts.labels(severity='medium')._value.get()}")
        print(f"   Alerts (low): {cortex_xdr_alerts.labels(severity='low')._value.get()}")
        print(f"   Outdated agents: {cortex_xdr_agents_outdated._value.get()}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test Public Subdomain Collector
    print("\n4. Testing Public Subdomain Exporter (Free Sources):")
    try:
        collect_public_subdomains()
        print(f"   Total public subdomains: {public_subdomains_total._value.get()}")
        print(f"   crt.sh unique subdomains: {public_subdomains_source_total.labels(source='crtsh')._value.get()}")
        print(f"   Cert Spotter unique subdomains: {public_subdomains_source_total.labels(source='certspotter')._value.get()}")
        print(f"   Collection success: {public_subdomains_last_collection_success._value.get()}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test Passive IP Exposure Collector
    print("\n5. Testing Passive IP Exposure Exporter (DNS + Shodan):")
    try:
        collect_public_ip_exposure()
        print(f"   Public IPs total: {public_exposed_ips_total._value.get()}")
        print(f"   Subdomains processed: {public_exposed_subdomains_processed_total._value.get()}")
        print(f"   Shodan enriched IPs: {public_exposed_shodan_enriched_total._value.get()}")
        print(f"   IPs with open ports: {public_exposed_ips_with_open_ports_total._value.get()}")
        print(f"   Domains with public IP: {public_subdomains_with_public_ip._value.get()}")
        print(f"   Domains with external CNAME: {public_subdomains_with_cname_external._value.get()}")
        # Print per-provider breakdown
        for sample in public_exposed_by_provider._metrics.items():
            labels, metric = sample
            print(f"   Provider {labels}: {metric._value.get()}")
        print(f"   Collection success: {public_exposed_last_collection_success._value.get()}")
    except Exception as e:
        print(f"   Error: {e}")

    print("\n" + "=" * 50)
    print("Test completed. Check the output above for collected data.")

if __name__ == "__main__":
    test_collectors()