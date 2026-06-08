import os
import logging
from datetime import datetime, timezone, timedelta
from collections import Counter

import requests
from prometheus_client import Gauge

from es_store import store_webmethods

# ── APIs ────────────────────────────────────────────────────────────
wm_apis_total = Gauge(
    "webmethods_apis_total",
    "Total APIs registered in webMethods API Gateway",
)
wm_apis_active = Gauge(
    "webmethods_apis_active",
    "APIs in active/published state",
)
wm_apis_inactive = Gauge(
    "webmethods_apis_inactive",
    "APIs in inactive/suspended state",
)
wm_apis_by_type = Gauge(
    "webmethods_apis_by_type",
    "APIs by type (REST, SOAP, OData, etc.)",
    ["api_type"],
)

# ── Applications (consumers) ───────────────────────────────────────
wm_applications_total = Gauge(
    "webmethods_applications_total",
    "Total applications (API consumers) registered",
)
wm_applications_active = Gauge(
    "webmethods_applications_active",
    "Applications in active state",
)
wm_applications_suspended = Gauge(
    "webmethods_applications_suspended",
    "Applications in suspended state",
)

# ── Security aliases ───────────────────────────────────────────────
wm_aliases_total = Gauge(
    "webmethods_aliases_total",
    "Total aliases configured (keystores, truststores, endpoints)",
)

# ── Policies ────────────────────────────────────────────────────────
wm_policies_total = Gauge(
    "webmethods_policies_total",
    "Total policies defined in the gateway",
)
wm_global_policies_total = Gauge(
    "webmethods_global_policies_total",
    "Global policies applied to all APIs",
)

# ── Security posture ───────────────────────────────────────────────
wm_apis_with_auth = Gauge(
    "webmethods_apis_with_auth_policy",
    "APIs that have an authentication/authorization policy enforced",
)
wm_apis_no_auth = Gauge(
    "webmethods_apis_without_auth_policy",
    "APIs with NO authentication policy (security risk)",
)
wm_apis_with_rate_limit = Gauge(
    "webmethods_apis_with_rate_limiting",
    "APIs with throttling/rate-limiting policy",
)
wm_apis_with_logging = Gauge(
    "webmethods_apis_with_log_invocation",
    "APIs with request/response logging enabled",
)

# ── Threat protection ──────────────────────────────────────────────
wm_apis_with_threat_protection = Gauge(
    "webmethods_apis_with_threat_protection",
    "APIs with threat protection policy (SQL injection, XSS, etc.)",
)

# ── Runtime traffic (last 1 hour) ──────────────────────────────────
wm_traffic_total = Gauge(
    "webmethods_traffic_total_1h",
    "Total API invocations in the last 1 hour",
)
wm_traffic_success = Gauge(
    "webmethods_traffic_success_1h",
    "Successful API responses (2xx) in the last 1 hour",
)
wm_traffic_errors = Gauge(
    "webmethods_traffic_errors_1h",
    "Error responses (4xx+5xx) in the last 1 hour",
)
wm_traffic_error_rate = Gauge(
    "webmethods_traffic_error_rate_percent_1h",
    "API error rate percentage in the last 1 hour",
)
wm_traffic_policy_violations = Gauge(
    "webmethods_traffic_policy_violations_1h",
    "Requests rejected by policy enforcement in the last 1 hour",
)
wm_avg_response_time_ms = Gauge(
    "webmethods_avg_response_time_ms_1h",
    "Average API response time in ms over the last 1 hour",
)

# ── API scopes / access profiles ───────────────────────────────────
wm_access_profiles_total = Gauge(
    "webmethods_access_profiles_total",
    "Total access profiles / API scopes defined",
)

# ── Packages / Plans ───────────────────────────────────────────────
wm_packages_total = Gauge(
    "webmethods_packages_total",
    "Total packages (API bundles) defined",
)
wm_plans_total = Gauge(
    "webmethods_plans_total",
    "Total subscription plans defined",
)

# ── Port / Listener configuration ──────────────────────────────────
wm_listeners_total = Gauge(
    "webmethods_listeners_total",
    "Total HTTP/HTTPS listeners (ports) configured",
)
wm_listeners_https = Gauge(
    "webmethods_listeners_https",
    "HTTPS listeners (secure)",
)
wm_listeners_http = Gauge(
    "webmethods_listeners_http",
    "HTTP-only listeners (plaintext — security risk in production)",
)

# ── Collection health ───────────────────────────────────────────────
wm_collection_success = Gauge(
    "webmethods_collection_success",
    "1 when the latest webMethods collection succeeded, 0 otherwise",
)
wm_collection_duration_seconds = Gauge(
    "webmethods_collection_duration_seconds",
    "Duration of the last webMethods collection run in seconds",
)


# ─── webMethods API Gateway REST API helper ──────────────────────────
class WebMethodsAPI:
    """Wrapper around webMethods API Gateway Administration REST API."""

    def __init__(self, host, user, password, timeout=30, verify_ssl=False):
        self.base_url = f"https://{host}/rest/apigateway"
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.auth = (user, password)

    def _get(self, path, params=None):
        r = requests.get(
            f"{self.base_url}{path}",
            auth=self.auth,
            params=params,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        return r.json()

    def list_apis(self):
        data = self._get("/apis")
        return data.get("apiResponse", data.get("apis", []))

    def get_api(self, api_id):
        data = self._get(f"/apis/{api_id}")
        return data.get("apiResponse", data)

    def list_applications(self):
        data = self._get("/applications")
        return data.get("applications", [])

    def list_policies(self):
        data = self._get("/policies")
        return data.get("policies", [])

    def list_global_policies(self):
        data = self._get("/policies?policyType=Global")
        return data.get("policies", [])

    def list_aliases(self):
        data = self._get("/alias")
        return data.get("alias", data.get("aliases", []))

    def list_access_profiles(self):
        try:
            data = self._get("/accessProfiles")
            return data.get("accessProfiles", [])
        except Exception:
            return []

    def list_packages(self):
        try:
            data = self._get("/packages")
            return data.get("packages", [])
        except Exception:
            return []

    def list_plans(self):
        try:
            data = self._get("/plans")
            return data.get("plans", [])
        except Exception:
            return []

    def list_listeners(self):
        try:
            data = self._get("/ports")
            return data.get("listenersList", data.get("ports", []))
        except Exception:
            return []

    def get_transaction_stats(self, from_ts, to_ts):
        """Get aggregated runtime transaction data."""
        try:
            data = self._get("/transactionalEvents", params={
                "from": from_ts,
                "to": to_ts,
            })
            return data.get("transactionalEvents", data.get("events", []))
        except Exception:
            return []

    def get_analytics(self, from_ts, to_ts):
        """Get analytics summary."""
        try:
            data = self._get("/analytics/transactionalEvents", params={
                "from": from_ts,
                "to": to_ts,
                "eventType": "transactionalEvents",
            })
            return data
        except Exception:
            return {}


_AUTH_POLICY_TYPES = frozenset({
    "Identify & Authorize Application",
    "Identify & Authorize",
    "Require HTTP / HTTPS",
    "Inbound Authentication - Message",
    "Inbound Authentication - Transport",
    "Authorize User",
    "OAuth2",
    "OpenID Connect",
    "JWT",
    "API Key",
    "NTLM Authentication",
    "Kerberos",
})

_RATE_LIMIT_TYPES = frozenset({
    "Throttling",
    "Traffic Optimization",
    "Rate Limiting",
    "Surge Protection",
})

_THREAT_POLICY_TYPES = frozenset({
    "Threat Protection",
    "Data Masking",
    "Request Validation",
    "Schema Validation",
})


# ═════════════════════════════════════════════════════════════════════
#  Main collector
# ═════════════════════════════════════════════════════════════════════
def collect_webmethods():
    host = os.getenv("WEBMETHODS_HOST", "").strip()
    user = os.getenv("WEBMETHODS_USER", "").strip()
    password = os.getenv("WEBMETHODS_PASSWORD", "").strip()

    if not all([host, user, password]):
        logging.warning(
            "webMethods: WEBMETHODS_HOST, WEBMETHODS_USER, and "
            "WEBMETHODS_PASSWORD must be set — skipping"
        )
        return

    timeout = int(os.getenv("WEBMETHODS_TIMEOUT_SECONDS", "30"))
    verify_ssl = os.getenv("WEBMETHODS_VERIFY_SSL", "false").lower() == "true"
    start_time = datetime.now(timezone.utc)

    api = WebMethodsAPI(host, user, password, timeout=timeout, verify_ssl=verify_ssl)
    now = datetime.now(timezone.utc)
    metrics = {}

    # ── 1. APIs inventory + security posture ────────────────────────
    try:
        logging.info("webMethods: fetching APIs")
        apis_raw = api.list_apis()

        # Normalize — response varies by version
        apis = []
        if isinstance(apis_raw, list):
            for item in apis_raw:
                if isinstance(item, dict):
                    inner = item.get("responseStatus") or item.get("api") or item
                    if inner.get("apiId") or inner.get("id"):
                        apis.append(inner)
                    else:
                        apis.append(item)

        total_apis = len(apis)
        active_count = 0
        inactive_count = 0
        type_counter = Counter()
        with_auth = 0
        no_auth = 0
        with_rate_limit = 0
        with_logging = 0
        with_threat = 0

        for api_obj in apis:
            is_active = str(api_obj.get("isActive", api_obj.get("status", "true"))).lower()
            if is_active in ("true", "active", "published"):
                active_count += 1
            else:
                inactive_count += 1

            api_type = api_obj.get("type", api_obj.get("apiType", "REST"))
            type_counter[api_type] += 1

            # Check enforced policies on this API
            policies_applied = api_obj.get("policies", api_obj.get("policyIds", []))
            policy_names = set()

            if isinstance(policies_applied, list):
                for p in policies_applied:
                    if isinstance(p, str):
                        policy_names.add(p)
                    elif isinstance(p, dict):
                        policy_names.add(p.get("policyName", p.get("name", "")))

            # Also check via detailed API if policies list is embedded
            enforced_actions = api_obj.get("policyActions", [])
            if isinstance(enforced_actions, list):
                for action in enforced_actions:
                    if isinstance(action, dict):
                        template_key = action.get("templateKey", "")
                        policy_names.add(template_key)

            has_auth = any(
                any(auth_t.lower() in pn.lower() for auth_t in _AUTH_POLICY_TYPES)
                for pn in policy_names
            ) if policy_names else False

            has_rate = any(
                any(rt.lower() in pn.lower() for rt in _RATE_LIMIT_TYPES)
                for pn in policy_names
            ) if policy_names else False

            has_log = any("log" in pn.lower() for pn in policy_names) if policy_names else False

            has_threat = any(
                any(tt.lower() in pn.lower() for tt in _THREAT_POLICY_TYPES)
                for pn in policy_names
            ) if policy_names else False

            if has_auth:
                with_auth += 1
            else:
                no_auth += 1
            if has_rate:
                with_rate_limit += 1
            if has_log:
                with_logging += 1
            if has_threat:
                with_threat += 1

        wm_apis_total.set(total_apis)
        wm_apis_active.set(active_count)
        wm_apis_inactive.set(inactive_count)
        wm_apis_with_auth.set(with_auth)
        wm_apis_no_auth.set(no_auth)
        wm_apis_with_rate_limit.set(with_rate_limit)
        wm_apis_with_logging.set(with_logging)
        wm_apis_with_threat_protection.set(with_threat)

        for api_type, count in type_counter.items():
            wm_apis_by_type.labels(api_type=api_type).set(count)

        metrics.update(
            apis_total=total_apis,
            apis_active=active_count,
            apis_inactive=inactive_count,
            apis_with_auth=with_auth,
            apis_no_auth=no_auth,
            apis_with_rate_limit=with_rate_limit,
            apis_with_logging=with_logging,
            apis_with_threat_protection=with_threat,
            apis_by_type=dict(type_counter),
        )

        logging.info(
            "webMethods: APIs total=%s active=%s no_auth=%s rate_limit=%s threat=%s",
            total_apis, active_count, no_auth, with_rate_limit, with_threat,
        )
    except Exception as exc:
        logging.exception("webMethods: APIs collection failed: %s", exc)

    # ── 2. Applications ─────────────────────────────────────────────
    try:
        logging.info("webMethods: fetching applications")
        apps = api.list_applications()
        apps_total = len(apps)
        apps_active = 0
        apps_suspended = 0

        for app in apps:
            status = str(app.get("status", app.get("isActive", ""))).lower()
            if status in ("active", "true"):
                apps_active += 1
            elif status in ("suspended", "false", "inactive"):
                apps_suspended += 1

        wm_applications_total.set(apps_total)
        wm_applications_active.set(apps_active)
        wm_applications_suspended.set(apps_suspended)
        metrics.update(
            applications_total=apps_total,
            applications_active=apps_active,
            applications_suspended=apps_suspended,
        )
    except Exception as exc:
        logging.exception("webMethods: applications failed: %s", exc)

    # ── 3. Policies ─────────────────────────────────────────────────
    try:
        pol_all = api.list_policies()
        pol_global = api.list_global_policies()
        wm_policies_total.set(len(pol_all))
        wm_global_policies_total.set(len(pol_global))
        metrics.update(policies_total=len(pol_all), global_policies_total=len(pol_global))
    except Exception as exc:
        logging.debug("webMethods: policies failed: %s", exc)

    # ── 4. Aliases ──────────────────────────────────────────────────
    try:
        aliases = api.list_aliases()
        wm_aliases_total.set(len(aliases))
        metrics["aliases_total"] = len(aliases)
    except Exception as exc:
        logging.debug("webMethods: aliases failed: %s", exc)

    # ── 5. Access profiles, packages, plans ─────────────────────────
    try:
        ap = api.list_access_profiles()
        wm_access_profiles_total.set(len(ap))
        metrics["access_profiles_total"] = len(ap)
    except Exception:
        pass

    try:
        pkgs = api.list_packages()
        wm_packages_total.set(len(pkgs))
        metrics["packages_total"] = len(pkgs)
    except Exception:
        pass

    try:
        plans = api.list_plans()
        wm_plans_total.set(len(plans))
        metrics["plans_total"] = len(plans)
    except Exception:
        pass

    # ── 6. Listeners (ports) ────────────────────────────────────────
    try:
        listeners = api.list_listeners()
        listeners_total = len(listeners)
        https_count = 0
        http_count = 0

        for lis in listeners:
            protocol = str(lis.get("protocol", lis.get("listenerType", ""))).lower()
            if "https" in protocol or lis.get("ssl") or lis.get("sslEnabled"):
                https_count += 1
            elif "http" in protocol:
                http_count += 1

        wm_listeners_total.set(listeners_total)
        wm_listeners_https.set(https_count)
        wm_listeners_http.set(http_count)
        metrics.update(
            listeners_total=listeners_total,
            listeners_https=https_count,
            listeners_http=http_count,
        )
    except Exception as exc:
        logging.debug("webMethods: listeners failed: %s", exc)

    # ── 7. Runtime traffic (last 1 hour) ────────────────────────────
    try:
        logging.info("webMethods: fetching traffic stats")
        one_hour_ago = now - timedelta(hours=1)
        from_ts = one_hour_ago.strftime("%Y-%m-%dT%H:%M:%S")
        to_ts = now.strftime("%Y-%m-%dT%H:%M:%S")

        analytics = api.get_analytics(from_ts, to_ts)

        total_inv = 0
        success = 0
        errors = 0
        policy_violations = 0
        response_times = []

        events = analytics.get("transactionalEvents", [])
        if isinstance(events, list):
            total_inv = len(events)
            for ev in events:
                status_code = ev.get("responseCode", ev.get("httpResponseCode", 200))
                try:
                    sc = int(status_code)
                except (ValueError, TypeError):
                    sc = 0
                if 200 <= sc < 400:
                    success += 1
                elif sc >= 400:
                    errors += 1

                if ev.get("policyViolation") or ev.get("threatProtectionViolation"):
                    policy_violations += 1

                resp_time = ev.get("totalResponseTime", ev.get("responseTime"))
                if resp_time is not None:
                    try:
                        response_times.append(float(resp_time))
                    except (ValueError, TypeError):
                        pass
        else:
            # Analytics summary format
            total_inv = analytics.get("totalInvocations", analytics.get("total", 0))
            success = analytics.get("successCount", 0)
            errors = analytics.get("failureCount", analytics.get("errorCount", 0))
            policy_violations = analytics.get("policyViolationCount", 0)
            avg_rt = analytics.get("avgResponseTime", 0)
            if avg_rt:
                response_times.append(float(avg_rt))

        wm_traffic_total.set(total_inv)
        wm_traffic_success.set(success)
        wm_traffic_errors.set(errors)
        wm_traffic_policy_violations.set(policy_violations)

        error_rate = round((errors / total_inv * 100), 2) if total_inv > 0 else 0
        wm_traffic_error_rate.set(error_rate)

        avg_resp = round(sum(response_times) / len(response_times), 1) if response_times else 0
        wm_avg_response_time_ms.set(avg_resp)

        metrics.update(
            traffic_total_1h=total_inv,
            traffic_success_1h=success,
            traffic_errors_1h=errors,
            traffic_error_rate_1h=error_rate,
            traffic_policy_violations_1h=policy_violations,
            avg_response_time_ms=avg_resp,
        )

        logging.info(
            "webMethods: traffic(1h) total=%s success=%s errors=%s rate=%.1f%%",
            total_inv, success, errors, error_rate,
        )
    except Exception as exc:
        logging.exception("webMethods: traffic stats failed: %s", exc)

    # ── Finalize ────────────────────────────────────────────────────
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    wm_collection_success.set(1)
    wm_collection_duration_seconds.set(elapsed)
    logging.info("webMethods: collection completed in %.1fs", elapsed)

    store_webmethods(metrics)
