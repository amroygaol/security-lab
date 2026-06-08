import os
import logging
from datetime import datetime, timezone
from collections import Counter

import requests
from prometheus_client import Gauge

from es_store import store_bmc_cmdb

# ── CI inventory ────────────────────────────────────────────────────
cmdb_ci_total = Gauge(
    "cmdb_ci_total",
    "Total Configuration Items in BMC CMDB",
)
cmdb_ci_by_class = Gauge(
    "cmdb_ci_by_class",
    "Configuration Items by CI class",
    ["ci_class"],
)
cmdb_ci_by_status = Gauge(
    "cmdb_ci_by_status",
    "Configuration Items by operational status",
    ["status"],
)

# ── Asset lifecycle ─────────────────────────────────────────────────
cmdb_ci_in_service = Gauge(
    "cmdb_ci_in_service",
    "CIs currently in Deployed/In Production status",
)
cmdb_ci_decommissioned = Gauge(
    "cmdb_ci_decommissioned",
    "CIs in End Of Life / Decommissioned status",
)
cmdb_ci_in_maintenance = Gauge(
    "cmdb_ci_in_maintenance",
    "CIs currently in maintenance / repair status",
)
cmdb_ci_ordered = Gauge(
    "cmdb_ci_ordered",
    "CIs in Ordered / On Order status (incoming assets)",
)

# ── Servers ─────────────────────────────────────────────────────────
cmdb_servers_total = Gauge(
    "cmdb_servers_total",
    "Total server CIs (physical + virtual)",
)
cmdb_servers_physical = Gauge(
    "cmdb_servers_physical",
    "Physical server CIs",
)
cmdb_servers_virtual = Gauge(
    "cmdb_servers_virtual",
    "Virtual server CIs",
)
cmdb_servers_by_os = Gauge(
    "cmdb_servers_by_os",
    "Server CIs by operating system category",
    ["os"],
)
cmdb_servers_missing_owner = Gauge(
    "cmdb_servers_missing_owner",
    "Server CIs without an assigned owner (data quality gap)",
)
cmdb_servers_missing_location = Gauge(
    "cmdb_servers_missing_location",
    "Server CIs without a location set",
)

# ── Network devices ─────────────────────────────────────────────────
cmdb_network_devices_total = Gauge(
    "cmdb_network_devices_total",
    "Total network device CIs (switches, routers, firewalls, load balancers)",
)

# ── Applications ────────────────────────────────────────────────────
cmdb_applications_total = Gauge(
    "cmdb_applications_total",
    "Total application CIs registered in CMDB",
)
cmdb_applications_without_owner = Gauge(
    "cmdb_applications_without_owner",
    "Application CIs without a defined owner/support group",
)

# ── Database instances ──────────────────────────────────────────────
cmdb_databases_total = Gauge(
    "cmdb_databases_total",
    "Total database instance CIs",
)

# ── Stale / data quality ────────────────────────────────────────────
cmdb_ci_stale_90d = Gauge(
    "cmdb_ci_stale_90d",
    "CIs not updated/reconciled in the last 90 days",
)
cmdb_ci_stale_180d = Gauge(
    "cmdb_ci_stale_180d",
    "CIs not updated/reconciled in the last 180 days",
)
cmdb_ci_missing_category = Gauge(
    "cmdb_ci_missing_category",
    "CIs without a Tier 1 category assignment (data quality)",
)

# ── Relationships ───────────────────────────────────────────────────
cmdb_relationships_total = Gauge(
    "cmdb_relationships_total",
    "Total CI relationships (impact/dependency mapping)",
)
cmdb_ci_without_relationships = Gauge(
    "cmdb_ci_without_relationships",
    "In-service CIs with zero relationships (isolated — likely incomplete)",
)

# ── Discovery / reconciliation ──────────────────────────────────────
cmdb_ci_discovered = Gauge(
    "cmdb_ci_discovered",
    "CIs that were populated via automated discovery",
)
cmdb_ci_manual = Gauge(
    "cmdb_ci_manual",
    "CIs that were manually entered (no discovery source)",
)
cmdb_discovery_coverage_percent = Gauge(
    "cmdb_discovery_coverage_percent",
    "Percentage of in-service CIs covered by discovery",
)

# ── Incidents / change correlation ──────────────────────────────────
cmdb_ci_with_open_incidents = Gauge(
    "cmdb_ci_with_open_incidents",
    "CIs that have at least one open incident associated",
)
cmdb_ci_with_open_changes = Gauge(
    "cmdb_ci_with_open_changes",
    "CIs that have at least one open change request associated",
)

# ── Collection health ───────────────────────────────────────────────
cmdb_collection_success = Gauge(
    "cmdb_collection_success",
    "1 when the latest BMC CMDB collection succeeded, 0 otherwise",
)
cmdb_collection_duration_seconds = Gauge(
    "cmdb_collection_duration_seconds",
    "Duration of the last BMC CMDB collection run in seconds",
)


# ─── BMC CMDB REST API helper ───────────────────────────────────────
class BmcCmdbAPI:
    """Thin wrapper around BMC Helix / Remedy AR REST API for CMDB queries."""

    def __init__(self, host, user, password, timeout=60, verify_ssl=False):
        self.base_url = f"https://{host}"
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.token = None
        self._login(user, password)

    def _login(self, user, password):
        url = f"{self.base_url}/api/jwt/login"
        r = requests.post(
            url,
            data={"username": user, "password": password},
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        self.token = r.text.strip()

    def _headers(self):
        return {"Authorization": f"AR-JWT {self.token}"}

    def query_form(self, form_name, qualification="", fields=None,
                   offset=0, limit=1000):
        """Query a BMC AR form (CMDB class) with optional qualification."""
        url = f"{self.base_url}/api/arsys/v1/entry/{form_name}"
        params = {"offset": offset, "limit": limit}

        if qualification:
            params["q"] = qualification
        if fields:
            params["fields"] = ",".join(f"values({f})" for f in fields)

        r = requests.get(
            url, headers=self._headers(), params=params,
            timeout=self.timeout, verify=self.verify_ssl,
        )
        r.raise_for_status()
        data = r.json()
        return data.get("entries", [])

    def query_all(self, form_name, qualification="", fields=None,
                  page_size=1000, max_pages=100):
        """Paginate through all entries matching the qualification."""
        all_entries = []
        for page in range(max_pages):
            entries = self.query_form(
                form_name, qualification, fields,
                offset=page * page_size, limit=page_size,
            )
            all_entries.extend(entries)
            if len(entries) < page_size:
                break
        return all_entries

    def count_form(self, form_name, qualification=""):
        """Get count of entries matching qualification without fetching all data."""
        # Fetch just 1 entry with stats to discover total via offset trick
        url = f"{self.base_url}/api/arsys/v1/entry/{form_name}"
        params = {"offset": 0, "limit": 1}
        if qualification:
            params["q"] = qualification
        r = requests.get(
            url, headers=self._headers(), params=params,
            timeout=self.timeout, verify=self.verify_ssl,
        )
        r.raise_for_status()
        # BMC returns total in X-AR-Total-Count header if available
        total = r.headers.get("X-AR-Total-Count")
        if total is not None:
            return int(total)
        # Fallback: paginate and count
        return len(self.query_all(form_name, qualification, fields=["Request ID"]))

    def logout(self):
        try:
            requests.post(
                f"{self.base_url}/api/jwt/logout",
                headers=self._headers(),
                timeout=10,
                verify=self.verify_ssl,
            )
        except Exception:
            pass


# ─── Helpers ─────────────────────────────────────────────────────────
def _val(entry, field, default=""):
    """Extract a field value from a BMC REST entry."""
    values = entry.get("values", {})
    v = values.get(field)
    if v is None:
        return default
    if isinstance(v, str):
        return v.strip()
    return v


_STATUS_MAP = {
    "deployed": "in_service",
    "in production": "in_service",
    "assigned": "in_service",
    "end of life": "decommissioned",
    "decommissioned": "decommissioned",
    "disposed": "decommissioned",
    "retired": "decommissioned",
    "on order": "ordered",
    "ordered": "ordered",
    "received": "ordered",
    "in repair": "maintenance",
    "maintenance": "maintenance",
    "down": "maintenance",
}


def _normalize_status(raw):
    return _STATUS_MAP.get(raw.lower(), raw.lower()) if raw else "unknown"


# ═════════════════════════════════════════════════════════════════════
#  Main collector
# ═════════════════════════════════════════════════════════════════════
def collect_bmc_cmdb():
    host = os.getenv("BMC_CMDB_HOST", "").strip()
    user = os.getenv("BMC_CMDB_USER", "").strip()
    password = os.getenv("BMC_CMDB_PASSWORD", "").strip()

    if not all([host, user, password]):
        logging.warning(
            "BMC CMDB: BMC_CMDB_HOST, BMC_CMDB_USER, and "
            "BMC_CMDB_PASSWORD must all be set — skipping"
        )
        return

    timeout = int(os.getenv("BMC_CMDB_TIMEOUT_SECONDS", "60"))
    verify_ssl = os.getenv("BMC_CMDB_VERIFY_SSL", "false").lower() == "true"
    start_time = datetime.now(timezone.utc)

    try:
        api = BmcCmdbAPI(host, user, password, timeout=timeout, verify_ssl=verify_ssl)
    except Exception as exc:
        logging.exception("BMC CMDB: login failed: %s", exc)
        cmdb_collection_success.set(0)
        return

    now = datetime.now(timezone.utc)
    metrics = {}

    # Standard BMC CMDB forms used
    # BMC.CORE:BMC_BaseElement — root CI class
    # BMC.CORE:BMC_ComputerSystem — servers
    # BMC.CORE:BMC_ApplicationSystem — applications
    # BMC.CORE:BMC_Database — databases
    # BMC.CORE:BMC_NetworkDevice — network devices
    # BMC.CORE:BMC_BaseRelationship — relationships

    ci_form = os.getenv("BMC_CI_FORM", "AST:ComputerSystem")
    rel_form = os.getenv("BMC_REL_FORM", "BMC.CORE:BMC_BaseRelationship")

    # ── 1. Total CIs and breakdown by class/status ──────────────────
    try:
        logging.info("BMC CMDB: fetching CI inventory")
        # Query primary CI forms and aggregate
        ci_forms = {
            "Server": os.getenv("BMC_FORM_SERVER", "BMC.CORE:BMC_ComputerSystem"),
            "Application": os.getenv("BMC_FORM_APP", "BMC.CORE:BMC_ApplicationSystem"),
            "Database": os.getenv("BMC_FORM_DB", "BMC.CORE:BMC_Database"),
            "NetworkDevice": os.getenv("BMC_FORM_NETWORK", "BMC.CORE:BMC_NetworkDevice"),
        }

        class_counts = Counter()
        status_counter = Counter()
        all_ci_entries = {}  # class -> entries
        total_ci = 0

        for ci_class, form_name in ci_forms.items():
            try:
                entries = api.query_all(
                    form_name,
                    fields=[
                        "ReconciliationIdentity", "Name", "OperationalStatus",
                        "Item", "Category", "Type", "OwnerName",
                        "Site", "DatasetId", "AttributeDataSourceList",
                        "Last Modified Date",
                    ],
                )
                class_counts[ci_class] = len(entries)
                all_ci_entries[ci_class] = entries
                total_ci += len(entries)

                for entry in entries:
                    raw_status = _val(entry, "OperationalStatus")
                    norm = _normalize_status(raw_status)
                    status_counter[norm] += 1

            except Exception as exc:
                logging.warning("BMC CMDB: failed querying %s (%s): %s",
                                ci_class, form_name, exc)

        cmdb_ci_total.set(total_ci)
        for ci_class, count in class_counts.items():
            cmdb_ci_by_class.labels(ci_class=ci_class).set(count)
        for status, count in status_counter.items():
            cmdb_ci_by_status.labels(status=status).set(count)

        # Lifecycle buckets
        cmdb_ci_in_service.set(status_counter.get("in_service", 0))
        cmdb_ci_decommissioned.set(status_counter.get("decommissioned", 0))
        cmdb_ci_in_maintenance.set(status_counter.get("maintenance", 0))
        cmdb_ci_ordered.set(status_counter.get("ordered", 0))

        metrics.update(
            ci_total=total_ci,
            ci_by_class=dict(class_counts),
            ci_by_status=dict(status_counter),
            ci_in_service=status_counter.get("in_service", 0),
            ci_decommissioned=status_counter.get("decommissioned", 0),
            ci_in_maintenance=status_counter.get("maintenance", 0),
            ci_ordered=status_counter.get("ordered", 0),
        )

        logging.info(
            "BMC CMDB: CI inventory total=%s classes=%s",
            total_ci, dict(class_counts),
        )
    except Exception as exc:
        logging.exception("BMC CMDB: CI inventory collection failed: %s", exc)

    # ── 2. Server deep-dive ─────────────────────────────────────────
    try:
        servers = all_ci_entries.get("Server", [])
        servers_total = len(servers)

        physical = 0
        virtual = 0
        os_counter = Counter()
        missing_owner = 0
        missing_location = 0

        for s in servers:
            # Virtual detection — check Item field or category
            item_val = _val(s, "Item", "").lower()
            cat_val = _val(s, "Category", "").lower()
            if any(k in item_val or k in cat_val
                   for k in ("virtual", "vm", "vmware", "hyper-v", "kvm", "xen")):
                virtual += 1
            else:
                physical += 1

            # OS category
            os_type = _val(s, "Type", "Unknown")
            if not os_type:
                os_type = "Unknown"
            os_counter[os_type] += 1

            # Data quality: owner
            owner = _val(s, "OwnerName")
            if not owner:
                missing_owner += 1

            # Data quality: location
            location = _val(s, "Site")
            if not location:
                missing_location += 1

        cmdb_servers_total.set(servers_total)
        cmdb_servers_physical.set(physical)
        cmdb_servers_virtual.set(virtual)
        cmdb_servers_missing_owner.set(missing_owner)
        cmdb_servers_missing_location.set(missing_location)

        for os_name, count in os_counter.items():
            cmdb_servers_by_os.labels(os=os_name).set(count)

        metrics.update(
            servers_total=servers_total,
            servers_physical=physical,
            servers_virtual=virtual,
            servers_missing_owner=missing_owner,
            servers_missing_location=missing_location,
            servers_by_os=dict(os_counter),
        )

        logging.info(
            "BMC CMDB: servers total=%s physical=%s virtual=%s "
            "missing_owner=%s missing_location=%s",
            servers_total, physical, virtual, missing_owner, missing_location,
        )
    except Exception as exc:
        logging.exception("BMC CMDB: server analysis failed: %s", exc)

    # ── 3. Network devices ──────────────────────────────────────────
    try:
        net_total = class_counts.get("NetworkDevice", 0)
        cmdb_network_devices_total.set(net_total)
        metrics["network_devices_total"] = net_total
    except Exception as exc:
        logging.exception("BMC CMDB: network devices failed: %s", exc)

    # ── 4. Applications ─────────────────────────────────────────────
    try:
        apps = all_ci_entries.get("Application", [])
        apps_total = len(apps)
        apps_no_owner = sum(1 for a in apps if not _val(a, "OwnerName"))

        cmdb_applications_total.set(apps_total)
        cmdb_applications_without_owner.set(apps_no_owner)
        metrics.update(
            applications_total=apps_total,
            applications_without_owner=apps_no_owner,
        )
    except Exception as exc:
        logging.exception("BMC CMDB: applications failed: %s", exc)

    # ── 5. Databases ────────────────────────────────────────────────
    try:
        db_total = class_counts.get("Database", 0)
        cmdb_databases_total.set(db_total)
        metrics["databases_total"] = db_total
    except Exception as exc:
        logging.exception("BMC CMDB: databases failed: %s", exc)

    # ── 6. Stale CIs (not updated in 90/180 days) ───────────────────
    try:
        logging.info("BMC CMDB: computing stale CI counts")
        stale_90 = 0
        stale_180 = 0
        missing_category = 0
        threshold_90 = (now - __import__("datetime").timedelta(days=90)).isoformat()
        threshold_180 = (now - __import__("datetime").timedelta(days=180)).isoformat()

        for ci_class, entries in all_ci_entries.items():
            for entry in entries:
                # Only count in-service CIs for staleness
                raw_status = _val(entry, "OperationalStatus")
                if _normalize_status(raw_status) != "in_service":
                    continue

                last_mod = _val(entry, "Last Modified Date")
                if last_mod:
                    try:
                        mod_dt = datetime.fromisoformat(
                            str(last_mod).replace("Z", "+00:00")
                        )
                        days_since = (now - mod_dt).days
                        if days_since >= 90:
                            stale_90 += 1
                        if days_since >= 180:
                            stale_180 += 1
                    except (ValueError, TypeError):
                        stale_90 += 1
                        stale_180 += 1
                else:
                    # No modification date = stale
                    stale_90 += 1
                    stale_180 += 1

                category = _val(entry, "Category")
                if not category:
                    missing_category += 1

        cmdb_ci_stale_90d.set(stale_90)
        cmdb_ci_stale_180d.set(stale_180)
        cmdb_ci_missing_category.set(missing_category)

        metrics.update(
            ci_stale_90d=stale_90,
            ci_stale_180d=stale_180,
            ci_missing_category=missing_category,
        )

        logging.info(
            "BMC CMDB: stale CIs 90d=%s 180d=%s missing_category=%s",
            stale_90, stale_180, missing_category,
        )
    except Exception as exc:
        logging.exception("BMC CMDB: staleness analysis failed: %s", exc)

    # ── 7. Relationships ────────────────────────────────────────────
    try:
        logging.info("BMC CMDB: fetching relationships")
        rel_total = api.count_form(rel_form)
        cmdb_relationships_total.set(rel_total)
        metrics["relationships_total"] = rel_total
        logging.info("BMC CMDB: relationships total=%s", rel_total)
    except Exception as exc:
        logging.exception("BMC CMDB: relationships count failed: %s", exc)

    # ── 8. Discovery coverage ───────────────────────────────────────
    try:
        logging.info("BMC CMDB: computing discovery coverage")
        discovered = 0
        manual = 0
        in_service_total = 0

        for ci_class, entries in all_ci_entries.items():
            for entry in entries:
                raw_status = _val(entry, "OperationalStatus")
                if _normalize_status(raw_status) != "in_service":
                    continue

                in_service_total += 1
                ds_list = _val(entry, "AttributeDataSourceList") or _val(entry, "DatasetId")
                if ds_list:
                    discovered += 1
                else:
                    manual += 1

        cmdb_ci_discovered.set(discovered)
        cmdb_ci_manual.set(manual)

        coverage = (discovered / in_service_total * 100) if in_service_total > 0 else 0
        cmdb_discovery_coverage_percent.set(round(coverage, 1))

        metrics.update(
            ci_discovered=discovered,
            ci_manual=manual,
            discovery_coverage_percent=round(coverage, 1),
        )

        logging.info(
            "BMC CMDB: discovery coverage=%.1f%% discovered=%s manual=%s",
            coverage, discovered, manual,
        )
    except Exception as exc:
        logging.exception("BMC CMDB: discovery coverage failed: %s", exc)

    # ── 9. CIs with open incidents / changes ────────────────────────
    try:
        logging.info("BMC CMDB: checking CIs with open incidents")
        incident_form = os.getenv("BMC_FORM_INCIDENT", "HPD:Help Desk")

        ci_with_incidents = api.count_form(
            incident_form,
            qualification="'Status' < \"Resolved\"",
        )
        cmdb_ci_with_open_incidents.set(ci_with_incidents)
        metrics["ci_with_open_incidents"] = ci_with_incidents
    except Exception as exc:
        logging.debug("BMC CMDB: open incidents query failed: %s", exc)

    try:
        change_form = os.getenv("BMC_FORM_CHANGE", "CHG:Infrastructure Change")
        ci_with_changes = api.count_form(
            change_form,
            qualification="'Change Request Status' < \"Completed\"",
        )
        cmdb_ci_with_open_changes.set(ci_with_changes)
        metrics["ci_with_open_changes"] = ci_with_changes
    except Exception as exc:
        logging.debug("BMC CMDB: open changes query failed: %s", exc)

    # ── Finalize ────────────────────────────────────────────────────
    try:
        api.logout()
    except Exception:
        pass

    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    cmdb_collection_success.set(1)
    cmdb_collection_duration_seconds.set(elapsed)
    logging.info("BMC CMDB: collection completed in %.1fs", elapsed)

    store_bmc_cmdb(metrics)
