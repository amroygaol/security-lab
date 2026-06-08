import sys
import os
import importlib.util
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

# Ensure the current directory is in the Python path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from prometheus_client import Counter, Gauge, start_http_server
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
from collectors.Pentest_jira_exporter import collect_jira_tickets
from collectors.SOC_jira_exporter import collect_soc_jira_tickets
# --- Disabled: credentials not configured (CHANGE_ME) ---
# from collectors.IAM_entraid_exporter import collect_entraid
# from collectors.EP_intune_exporter import collect_intune
# from collectors.Net_panorama_exporter import collect_panorama
# from collectors.GRC_bmc_cmdb_exporter import collect_bmc_cmdb
from collectors.Net_imperva_exporter import collect_imperva
from collectors.Net_ip_scan_coverage_exporter import collect_ip_scan_coverage
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
    ("jira_tickets", collect_jira_tickets),
    ("soc_jira_tickets", collect_soc_jira_tickets),
    # --- Disabled: credentials not configured (CHANGE_ME) ---
    # ("entraid", collect_entraid),
    # ("intune", collect_intune),
    # ("panorama", collect_panorama),
    # ("bmc_cmdb", collect_bmc_cmdb),
    ("imperva", collect_imperva),
    # ("apigee", collect_apigee),
    # ("webmethods", collect_webmethods),
    # ("ibm_maximo", collect_ibm_maximo),
]

# Collectors that cross-reference data written by Phases 1+2; run last.
_SEQUENTIAL_LAST = [
    ("ip_scan_coverage", collect_ip_scan_coverage),
]

# ── Hourly scheduling for Imperva (expensive operation) ───────────
_LAST_IMPERVA_RUN = None
_IMPERVA_INTERVAL_SECONDS = 3600  # 1 hour


_COLLECTOR_STATUS_VALUES = ("idle", "running", "success", "error", "skipped")

collector_running = Gauge(
    "security_exporter_collector_running",
    "1 while a collector is currently pulling data, 0 otherwise",
    ["collector"],
)
collector_last_duration_seconds = Gauge(
    "security_exporter_collector_last_duration_seconds",
    "Duration of the last collector run in seconds",
    ["collector"],
)
collector_last_run_timestamp = Gauge(
    "security_exporter_collector_last_run_timestamp",
    "Unix timestamp of the latest collector execution attempt",
    ["collector"],
)
collector_last_error_timestamp = Gauge(
    "security_exporter_collector_last_error_timestamp",
    "Unix timestamp of the latest failed collector execution",
    ["collector"],
)
collector_last_status = Gauge(
    "security_exporter_collector_last_status",
    "One-hot status for each collector (idle/running/success/error/skipped)",
    ["collector", "status"],
)
collector_runs_total = Counter(
    "security_exporter_collector_runs_total",
    "Total collector executions grouped by result",
    ["collector", "result"],
)


def _set_collector_status(name, status):
    for value in _COLLECTOR_STATUS_VALUES:
        collector_last_status.labels(collector=name, status=value).set(1 if value == status else 0)


def _mark_collector_skipped(name):
    now = datetime.now()
    collector_running.labels(collector=name).set(0)
    collector_last_run_timestamp.labels(collector=name).set(now.timestamp())
    collector_last_duration_seconds.labels(collector=name).set(0)
    _set_collector_status(name, "skipped")
    collector_runs_total.labels(collector=name, result="skipped").inc()


def _run_collector(name, collector):
    started = datetime.now()
    collector_running.labels(collector=name).set(1)
    collector_last_run_timestamp.labels(collector=name).set(started.timestamp())
    _set_collector_status(name, "running")

    try:
        collector()
        elapsed = (datetime.now() - started).total_seconds()
        collector_last_duration_seconds.labels(collector=name).set(elapsed)
        collector_runs_total.labels(collector=name, result="success").inc()
        _set_collector_status(name, "success")
        return True
    except Exception as exc:
        elapsed = (datetime.now() - started).total_seconds()
        collector_last_duration_seconds.labels(collector=name).set(elapsed)
        collector_last_error_timestamp.labels(collector=name).set(datetime.now().timestamp())
        collector_runs_total.labels(collector=name, result="error").inc()
        _set_collector_status(name, "error")
        logging.exception("Collector %s failed: %s", name, exc)
        return False
    finally:
        collector_running.labels(collector=name).set(0)


def run_collectors():
    global _LAST_IMPERVA_RUN
    
    current_time = datetime.now()
    
    # Phase 1: run subdomain collector first (ip_exposure reads its output file)
    for name, collector in _SEQUENTIAL_FIRST:
        _run_collector(name, collector)

    # Phase 2: run remaining collectors in parallel
    # ── Separate Imperva from other collectors for hourly scheduling ──
    parallel_to_run = _PARALLEL_COLLECTORS.copy()
    
    # Check if Imperva should run (hourly schedule)
    should_run_imperva = False
    if _LAST_IMPERVA_RUN is None:
        # First run - execute immediately
        should_run_imperva = True
        logging.info("Imperva: running for first time (initial collection)")
    else:
        time_since_last_run = current_time - _LAST_IMPERVA_RUN
        if time_since_last_run.total_seconds() >= _IMPERVA_INTERVAL_SECONDS:
            should_run_imperva = True
            logging.info(
                "Imperva: running on hourly schedule (last run %.1f min ago)",
                time_since_last_run.total_seconds() / 60,
            )
        else:
            time_until_next = _IMPERVA_INTERVAL_SECONDS - time_since_last_run.total_seconds()
            logging.debug(
                "Imperva: skipping (next run in %.1f min)",
                time_until_next / 60,
            )
    
    if not should_run_imperva:
        # Remove Imperva from parallel collectors if not scheduled
        parallel_to_run = [
            (name, collector) for name, collector in parallel_to_run
            if name != "imperva"
        ]
        _mark_collector_skipped("imperva")
    
    with ThreadPoolExecutor(max_workers=len(parallel_to_run)) as pool:
        futures = {
            pool.submit(_run_collector, name, collector): name
            for name, collector in parallel_to_run
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                if name == "imperva" and should_run_imperva:
                    _LAST_IMPERVA_RUN = current_time
            except Exception as exc:
                logging.exception("Collector %s failed: %s", name, exc)

    # Phase 3: cross-reference collectors (must run after Phase 1+2 have finished
    # writing to Elasticsearch so the coverage query sees fresh data)
    for name, collector in _SEQUENTIAL_LAST:
        _run_collector(name, collector)


if __name__ == "__main__":

    print("Starting Security Exporter")
    
    # ── Configure Imperva collection frequency ───────────────────────
    imperva_hours = int(os.getenv("IMPERVA_COLLECTION_HOURS", "1").strip())
    _IMPERVA_INTERVAL_SECONDS = imperva_hours * 3600
    logging.info(
        "Imperva collection scheduled for every %d hour(s) (%d seconds)",
        imperva_hours,
        _IMPERVA_INTERVAL_SECONDS,
    )

    start_http_server(9105)

    while True:

        run_collectors()

        time.sleep(900)