import os
import logging
from datetime import datetime, timezone, timedelta
from collections import Counter

import requests
from requests import RequestException
from prometheus_client import Gauge

from es_store import store_defectdojo

# ── Findings (vulnerabilities) ──────────────────────────────────────
dojo_findings_total = Gauge(
    "defectdojo_findings_total",
    "Total findings across all products",
)
dojo_findings_active = Gauge(
    "defectdojo_findings_active",
    "Currently active (open) findings",
)
dojo_findings_verified = Gauge(
    "defectdojo_findings_verified",
    "Findings that have been verified/triaged",
)
dojo_findings_mitigated = Gauge(
    "defectdojo_findings_mitigated",
    "Findings that have been mitigated/resolved",
)
dojo_findings_false_positive = Gauge(
    "defectdojo_findings_false_positive",
    "Findings marked as false positive",
)
dojo_findings_risk_accepted = Gauge(
    "defectdojo_findings_risk_accepted",
    "Findings with accepted risk",
)
dojo_findings_duplicate = Gauge(
    "defectdojo_findings_duplicate",
    "Findings marked as duplicates",
)

# ── Severity breakdown ──────────────────────────────────────────────
dojo_findings_critical = Gauge(
    "defectdojo_findings_critical",
    "Active findings with Critical severity",
)
dojo_findings_high = Gauge(
    "defectdojo_findings_high",
    "Active findings with High severity",
)
dojo_findings_medium = Gauge(
    "defectdojo_findings_medium",
    "Active findings with Medium severity",
)
dojo_findings_low = Gauge(
    "defectdojo_findings_low",
    "Active findings with Low severity",
)
dojo_findings_info = Gauge(
    "defectdojo_findings_info",
    "Active findings with Info severity",
)

# ── SLA breach ──────────────────────────────────────────────────────
dojo_findings_sla_breached = Gauge(
    "defectdojo_findings_sla_breached",
    "Active findings that have breached their SLA remediation deadline",
)

# ── Age / staleness ─────────────────────────────────────────────────
dojo_findings_older_30d = Gauge(
    "defectdojo_findings_older_30d",
    "Active findings open longer than 30 days",
)
dojo_findings_older_90d = Gauge(
    "defectdojo_findings_older_90d",
    "Active findings open longer than 90 days",
)
dojo_findings_older_180d = Gauge(
    "defectdojo_findings_older_180d",
    "Active findings open longer than 180 days (chronic debt)",
)

# ── Products ────────────────────────────────────────────────────────
dojo_products_total = Gauge(
    "defectdojo_products_total",
    "Total products (applications) registered in DefectDojo",
)
dojo_products_with_critical = Gauge(
    "defectdojo_products_with_critical_findings",
    "Products that have at least one active critical finding",
)
dojo_products_with_high = Gauge(
    "defectdojo_products_with_high_findings",
    "Products that have at least one active high finding",
)

# ── Engagements ─────────────────────────────────────────────────────
dojo_engagements_total = Gauge(
    "defectdojo_engagements_total",
    "Total engagements (security assessments)",
)
dojo_engagements_active = Gauge(
    "defectdojo_engagements_active",
    "Currently active/in-progress engagements",
)

# ── Tests (scan imports) ────────────────────────────────────────────
dojo_tests_total = Gauge(
    "defectdojo_tests_total",
    "Total tests (scan imports) in DefectDojo",
)
dojo_tests_by_type = Gauge(
    "defectdojo_tests_by_scan_type",
    "Tests grouped by scan tool type",
    ["scan_type"],
)

# ── Endpoints ───────────────────────────────────────────────────────
dojo_endpoints_total = Gauge(
    "defectdojo_endpoints_total",
    "Total endpoints tracked across all products",
)

# ── SAST / DAST / SCA breakdown ─────────────────────────────────────
dojo_findings_static = Gauge(
    "defectdojo_findings_sast",
    "Active findings from static analysis (SAST) tools",
)
dojo_findings_dynamic = Gauge(
    "defectdojo_findings_dast",
    "Active findings from dynamic analysis (DAST) tools",
)
dojo_findings_sca = Gauge(
    "defectdojo_findings_sca",
    "Active findings from software composition analysis (SCA) tools",
)

# ── Mean time metrics ───────────────────────────────────────────────
dojo_mttr_days = Gauge(
    "defectdojo_mean_time_to_remediate_days",
    "Mean time to remediate findings (in days), computed from mitigated findings in last 90 days",
)

# ── Collection health ───────────────────────────────────────────────
dojo_collection_success = Gauge(
    "defectdojo_collection_success",
    "1 when the latest DefectDojo collection succeeded, 0 otherwise",
)
dojo_collection_duration_seconds = Gauge(
    "defectdojo_collection_duration_seconds",
    "Duration of the last DefectDojo collection run in seconds",
)


# ─── Tool type classification ───────────────────────────────────────
_SAST_TOOLS = frozenset({
    "sonarqube", "sonar", "semgrep", "bandit", "checkmarx",
    "fortify", "veracode sast", "codeql", "brakeman", "spotbugs",
    "findbugs", "pmd", "eslint", "gosec", "snyk code",
})
_DAST_TOOLS = frozenset({
    "zap", "owasp zap", "burp", "burp suite", "nikto",
    "arachni", "acunetix", "netsparker", "qualys was",
    "veracode dast", "nuclei",
})
_SCA_TOOLS = frozenset({
    "dependency check", "owasp dependency check", "snyk",
    "npm audit", "yarn audit", "safety", "trivy",
    "grype", "anchore", "whitesource", "mend", "black duck",
    "retire.js", "pip audit", "bundler audit",
})


def _classify_scan_type(scan_type_name):
    """Classify a scan type into sast/dast/sca/other."""
    lower = (scan_type_name or "").strip().lower()
    if any(t in lower for t in _SAST_TOOLS):
        return "sast"
    if any(t in lower for t in _DAST_TOOLS):
        return "dast"
    if any(t in lower for t in _SCA_TOOLS):
        return "sca"
    # Heuristic keywords
    if "static" in lower or "sast" in lower or "source" in lower:
        return "sast"
    if "dynamic" in lower or "dast" in lower or "pen" in lower:
        return "dast"
    if "composition" in lower or "sca" in lower or "dependency" in lower:
        return "sca"
    return "other"


# ─── DefectDojo API helper ──────────────────────────────────────────
class DefectDojoAPI:
    """Thin wrapper around DefectDojo REST API v2."""

    def __init__(self, host, api_token, timeout=30, verify_ssl=True):
        self.base_url = f"{host}/api/v2"
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.headers = {
            "Authorization": f"Token {api_token}",
            "Accept": "application/json",
        }

    def _get(self, endpoint, params=None):
        r = requests.get(
            f"{self.base_url}{endpoint}",
            headers=self.headers,
            params=params,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        return r.json()

    def get_count(self, endpoint, params=None):
        """Get just the count from a paginated endpoint."""
        p = dict(params or {})
        p["limit"] = 1
        p["offset"] = 0
        data = self._get(endpoint, p)
        return data.get("count", 0)

    def get_all(self, endpoint, params=None, page_size=200, max_pages=100):
        """Paginate through all results."""
        items = []
        p = dict(params or {})
        p["limit"] = page_size

        for page in range(max_pages):
            p["offset"] = page * page_size
            data = self._get(endpoint, p)
            results = data.get("results", [])
            items.extend(results)
            if len(results) < page_size or len(items) >= data.get("count", 0):
                break

        return items

    def check_connectivity(self):
        """Raise on auth/connectivity issues using a cheap endpoint call."""
        self.get_count("/products/")


# ═════════════════════════════════════════════════════════════════════
#  Main collector
# ═════════════════════════════════════════════════════════════════════
def collect_defectdojo():
    host = os.getenv("DEFECTDOJO_URL", "").strip().rstrip("/")
    api_token = os.getenv("DEFECTDOJO_API_TOKEN", "").strip()

    if not host or not api_token:
        logging.warning(
            "DefectDojo: DEFECTDOJO_URL and DEFECTDOJO_API_TOKEN must be set — skipping"
        )
        return

    timeout = int(os.getenv("DEFECTDOJO_TIMEOUT_SECONDS", "30"))
    verify_ssl = os.getenv("DEFECTDOJO_VERIFY_SSL", "true").lower() == "true"
    start_time = datetime.now(timezone.utc)

    api = DefectDojoAPI(host, api_token, timeout=timeout, verify_ssl=verify_ssl)
    now = datetime.now(timezone.utc)
    metrics = {}

    # Fail fast when host/token/network is not reachable to avoid per-step timeout spam.
    try:
        api.check_connectivity()
    except RequestException as exc:
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        dojo_collection_success.set(0)
        dojo_collection_duration_seconds.set(elapsed)
        logging.error("DefectDojo: connectivity/auth check failed: %s", exc)
        return
    except Exception as exc:
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        dojo_collection_success.set(0)
        dojo_collection_duration_seconds.set(elapsed)
        logging.error("DefectDojo: preflight failed: %s", exc)
        return

    # ── 1. Findings overview ────────────────────────────────────────
    try:
        logging.info("DefectDojo: fetching findings overview")

        total = api.get_count("/findings/")
        active = api.get_count("/findings/", {"active": "true"})
        verified = api.get_count("/findings/", {"verified": "true"})
        mitigated = api.get_count("/findings/", {"is_mitigated": "true"})
        false_pos = api.get_count("/findings/", {"false_p": "true"})
        risk_acc = api.get_count("/findings/", {"risk_accepted": "true"})
        duplicate = api.get_count("/findings/", {"duplicate": "true"})

        dojo_findings_total.set(total)
        dojo_findings_active.set(active)
        dojo_findings_verified.set(verified)
        dojo_findings_mitigated.set(mitigated)
        dojo_findings_false_positive.set(false_pos)
        dojo_findings_risk_accepted.set(risk_acc)
        dojo_findings_duplicate.set(duplicate)

        metrics.update(
            findings_total=total,
            findings_active=active,
            findings_verified=verified,
            findings_mitigated=mitigated,
            findings_false_positive=false_pos,
            findings_risk_accepted=risk_acc,
            findings_duplicate=duplicate,
        )

        logging.info(
            "DefectDojo: findings total=%s active=%s verified=%s mitigated=%s",
            total, active, verified, mitigated,
        )
    except Exception as exc:
        logging.exception("DefectDojo: findings overview failed: %s", exc)

    # ── 2. Active findings by severity ──────────────────────────────
    try:
        logging.info("DefectDojo: fetching severity breakdown")

        critical = api.get_count("/findings/", {"active": "true", "severity": "Critical"})
        high = api.get_count("/findings/", {"active": "true", "severity": "High"})
        medium = api.get_count("/findings/", {"active": "true", "severity": "Medium"})
        low = api.get_count("/findings/", {"active": "true", "severity": "Low"})
        info = api.get_count("/findings/", {"active": "true", "severity": "Info"})

        dojo_findings_critical.set(critical)
        dojo_findings_high.set(high)
        dojo_findings_medium.set(medium)
        dojo_findings_low.set(low)
        dojo_findings_info.set(info)

        metrics.update(
            findings_critical=critical,
            findings_high=high,
            findings_medium=medium,
            findings_low=low,
            findings_info=info,
        )

        logging.info(
            "DefectDojo: active severities C=%s H=%s M=%s L=%s I=%s",
            critical, high, medium, low, info,
        )
    except Exception as exc:
        logging.exception("DefectDojo: severity breakdown failed: %s", exc)

    # ── 3. SLA breached findings ────────────────────────────────────
    try:
        sla_breached = api.get_count("/findings/", {
            "active": "true",
            "sla_expiration_date__lt": now.strftime("%Y-%m-%d"),
        })
        dojo_findings_sla_breached.set(sla_breached)
        metrics["findings_sla_breached"] = sla_breached
        logging.info("DefectDojo: SLA breached=%s", sla_breached)
    except Exception as exc:
        logging.debug("DefectDojo: SLA query failed (may not be configured): %s", exc)

    # ── 4. Finding age analysis ─────────────────────────────────────
    try:
        logging.info("DefectDojo: computing finding age buckets")

        d30 = (now - timedelta(days=30)).strftime("%Y-%m-%d")
        d90 = (now - timedelta(days=90)).strftime("%Y-%m-%d")
        d180 = (now - timedelta(days=180)).strftime("%Y-%m-%d")

        older_30 = api.get_count("/findings/", {"active": "true", "date__lt": d30})
        older_90 = api.get_count("/findings/", {"active": "true", "date__lt": d90})
        older_180 = api.get_count("/findings/", {"active": "true", "date__lt": d180})

        dojo_findings_older_30d.set(older_30)
        dojo_findings_older_90d.set(older_90)
        dojo_findings_older_180d.set(older_180)

        metrics.update(
            findings_older_30d=older_30,
            findings_older_90d=older_90,
            findings_older_180d=older_180,
        )

        logging.info(
            "DefectDojo: age >30d=%s >90d=%s >180d=%s",
            older_30, older_90, older_180,
        )
    except Exception as exc:
        logging.exception("DefectDojo: age analysis failed: %s", exc)

    # ── 5. Products with critical/high findings ─────────────────────
    try:
        logging.info("DefectDojo: fetching products")
        products = api.get_all("/products/", params={"limit": 500})
        products_total = len(products)
        dojo_products_total.set(products_total)

        products_with_crit = 0
        products_with_high = 0

        for product in products:
            pid = product.get("id")
            if not pid:
                continue
            findings_count = product.get("findings_count", 0)
            if findings_count == 0:
                continue

            crit_count = api.get_count("/findings/", {
                "test__engagement__product": pid,
                "active": "true",
                "severity": "Critical",
            })
            if crit_count > 0:
                products_with_crit += 1

            high_count = api.get_count("/findings/", {
                "test__engagement__product": pid,
                "active": "true",
                "severity": "High",
            })
            if high_count > 0:
                products_with_high += 1

        dojo_products_with_critical.set(products_with_crit)
        dojo_products_with_high.set(products_with_high)

        metrics.update(
            products_total=products_total,
            products_with_critical=products_with_crit,
            products_with_high=products_with_high,
        )

        logging.info(
            "DefectDojo: products total=%s with_critical=%s with_high=%s",
            products_total, products_with_crit, products_with_high,
        )
    except Exception as exc:
        logging.exception("DefectDojo: products analysis failed: %s", exc)

    # ── 6. Engagements ──────────────────────────────────────────────
    try:
        logging.info("DefectDojo: fetching engagements")
        eng_total = api.get_count("/engagements/")
        eng_active = api.get_count("/engagements/", {"status": "In Progress"})

        dojo_engagements_total.set(eng_total)
        dojo_engagements_active.set(eng_active)

        metrics.update(
            engagements_total=eng_total,
            engagements_active=eng_active,
        )
    except Exception as exc:
        logging.exception("DefectDojo: engagements failed: %s", exc)

    # ── 7. Tests by scan type ───────────────────────────────────────
    try:
        logging.info("DefectDojo: fetching tests")
        tests = api.get_all("/tests/", params={
            "limit": 500,
        }, max_pages=20)

        tests_total = len(tests)
        dojo_tests_total.set(tests_total)

        scan_type_counter = Counter()
        sast_findings = 0
        dast_findings = 0
        sca_findings = 0

        # Collect scan type names from test_type
        test_type_cache = {}

        for test in tests:
            tt_id = test.get("test_type")
            tt_name = test.get("test_type_name", "")

            if not tt_name and tt_id:
                if tt_id not in test_type_cache:
                    try:
                        tt_data = api._get(f"/test_types/{tt_id}/")
                        test_type_cache[tt_id] = tt_data.get("name", f"type_{tt_id}")
                    except Exception:
                        test_type_cache[tt_id] = f"type_{tt_id}"
                tt_name = test_type_cache[tt_id]

            scan_type_counter[tt_name] += 1

        for scan_type, count in scan_type_counter.items():
            dojo_tests_by_type.labels(scan_type=scan_type).set(count)

        metrics.update(
            tests_total=tests_total,
            tests_by_scan_type=dict(scan_type_counter),
        )

        logging.info("DefectDojo: tests total=%s types=%s",
                      tests_total, dict(scan_type_counter))
    except Exception as exc:
        logging.exception("DefectDojo: tests collection failed: %s", exc)

    # ── 8. SAST / DAST / SCA finding classification ─────────────────
    try:
        logging.info("DefectDojo: classifying findings by tool category")

        # Get active findings with test info to classify
        active_findings = api.get_all("/findings/", params={
            "active": "true",
            "limit": 500,
        }, max_pages=50)

        # Build test_id -> scan_type mapping
        test_ids = {f.get("test") for f in active_findings if f.get("test")}
        test_scan_types = {}

        for test in tests:
            tid = test.get("id")
            tt_name = test.get("test_type_name", "")
            if not tt_name:
                tt_id = test.get("test_type")
                tt_name = test_type_cache.get(tt_id, "")
            if tid:
                test_scan_types[tid] = _classify_scan_type(tt_name)

        sast_count = 0
        dast_count = 0
        sca_count = 0

        for finding in active_findings:
            tid = finding.get("test")
            category = test_scan_types.get(tid, "other")
            if category == "sast":
                sast_count += 1
            elif category == "dast":
                dast_count += 1
            elif category == "sca":
                sca_count += 1

        dojo_findings_static.set(sast_count)
        dojo_findings_dynamic.set(dast_count)
        dojo_findings_sca.set(sca_count)

        metrics.update(
            findings_sast=sast_count,
            findings_dast=dast_count,
            findings_sca=sca_count,
        )

        logging.info(
            "DefectDojo: SAST=%s DAST=%s SCA=%s",
            sast_count, dast_count, sca_count,
        )
    except Exception as exc:
        logging.exception("DefectDojo: SAST/DAST/SCA classification failed: %s", exc)

    # ── 9. Endpoints ────────────────────────────────────────────────
    try:
        endpoints_total = api.get_count("/endpoints/")
        dojo_endpoints_total.set(endpoints_total)
        metrics["endpoints_total"] = endpoints_total
    except Exception as exc:
        logging.debug("DefectDojo: endpoints count failed: %s", exc)

    # ── 10. Mean Time to Remediate (MTTR) ───────────────────────────
    try:
        logging.info("DefectDojo: computing MTTR")
        d90_ago = (now - timedelta(days=90)).strftime("%Y-%m-%d")

        mitigated_findings = api.get_all("/findings/", params={
            "is_mitigated": "true",
            "mitigated__gte": d90_ago,
            "limit": 500,
        }, max_pages=20)

        remediation_days = []
        for f in mitigated_findings:
            created = f.get("date")
            mitigated_dt = f.get("mitigated")
            if not created or not mitigated_dt:
                continue
            try:
                c_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                m_dt = datetime.fromisoformat(mitigated_dt.replace("Z", "+00:00"))
                delta = (m_dt - c_dt).days
                if delta >= 0:
                    remediation_days.append(delta)
            except (ValueError, TypeError):
                pass

        if remediation_days:
            mttr = round(sum(remediation_days) / len(remediation_days), 1)
        else:
            mttr = 0.0

        dojo_mttr_days.set(mttr)
        metrics["mttr_days"] = mttr

        logging.info(
            "DefectDojo: MTTR=%.1f days (from %s mitigated findings in 90d)",
            mttr, len(remediation_days),
        )
    except Exception as exc:
        logging.exception("DefectDojo: MTTR computation failed: %s", exc)

    # ── Finalize ────────────────────────────────────────────────────
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    dojo_collection_success.set(1)
    dojo_collection_duration_seconds.set(elapsed)
    logging.info("DefectDojo: collection completed in %.1fs", elapsed)

    store_defectdojo(metrics)
