import sys
import os
import importlib.util
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ensure the current directory is in the Python path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from prometheus_client import start_http_server
import time

# --- Active collectors ---
from collectors.Net_subdomain_exporter import collect_public_subdomains
from collectors.Net_ip_exposure_exporter import collect_public_ip_exposure

# --- Re-enabled ---
from collectors.Net_digicert_exporter import collect_digicert
from collectors.GRC_rapid7_exporter import collect_rapid7
from collectors.EP_cortex_exporter import collect_cortex
# --- Re-enabled ---
from collectors.App_defectdojo_exporter import collect_defectdojo
# --- Disabled: credentials not configured (CHANGE_ME) ---
# from collectors.IAM_entraid_exporter import collect_entraid
# from collectors.EP_intune_exporter import collect_intune
# from collectors.Net_panorama_exporter import collect_panorama
# from collectors.GRC_bmc_cmdb_exporter import collect_bmc_cmdb
# from collectors.Net_imperva_exporter import collect_imperva
# from collectors.App_apigee_exporter import collect_apigee
# from collectors.App_webmethods_exporter import collect_webmethods
# from collectors.GRC_ibm_asset_exporter import collect_ibm_maximo


# Collectors that must run sequentially first (ip_exposure depends on subdomain output)
_SEQUENTIAL_FIRST = [
    ("public_subdomains", collect_public_subdomains),
]

# Collectors that can safely run in parallel after sequential ones finish
_PARALLEL_COLLECTORS = [
    ("public_ip_exposure", collect_public_ip_exposure),
    ("digicert", collect_digicert),
    ("rapid7", collect_rapid7),
    ("cortex", collect_cortex),
    ("defectdojo", collect_defectdojo),
    # --- Disabled: credentials not configured (CHANGE_ME) ---
    # ("entraid", collect_entraid),
    # ("intune", collect_intune),
    # ("panorama", collect_panorama),
    # ("bmc_cmdb", collect_bmc_cmdb),
    # ("imperva", collect_imperva),
    # ("apigee", collect_apigee),
    # ("webmethods", collect_webmethods),
    # ("ibm_maximo", collect_ibm_maximo),
]


def run_collectors():
    # Phase 1: run subdomain collector first (ip_exposure reads its output file)
    for name, collector in _SEQUENTIAL_FIRST:
        try:
            collector()
        except Exception as exc:
            logging.exception("Collector %s failed: %s", name, exc)

    # Phase 2: run remaining collectors in parallel
    with ThreadPoolExecutor(max_workers=len(_PARALLEL_COLLECTORS)) as pool:
        futures = {
            pool.submit(collector): name
            for name, collector in _PARALLEL_COLLECTORS
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                future.result()
            except Exception as exc:
                logging.exception("Collector %s failed: %s", name, exc)


if __name__ == "__main__":

    print("Starting Security Exporter")

    start_http_server(9105)

    while True:

        run_collectors()

        time.sleep(900)