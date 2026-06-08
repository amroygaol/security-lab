import os
import logging
from datetime import datetime, timezone, timedelta
from collections import Counter

import requests
from prometheus_client import Gauge

from es_store import store_apigee

# ── API Proxies ─────────────────────────────────────────────────────
apigee_proxies_total = Gauge(
    "apigee_api_proxies_total",
    "Total API proxies deployed in Apigee",
)
apigee_proxies_deployed = Gauge(
    "apigee_api_proxies_deployed",
    "API proxies currently deployed to at least one environment",
)
apigee_proxies_undeployed = Gauge(
    "apigee_api_proxies_undeployed",
    "API proxies with no active deployment",
)
apigee_proxies_by_env = Gauge(
    "apigee_api_proxies_by_environment",
    "API proxy deployments per environment",
    ["environment"],
)

# ── Shared Flows ────────────────────────────────────────────────────
apigee_shared_flows_total = Gauge(
    "apigee_shared_flows_total",
    "Total shared flows in Apigee",
)

# ── API Products ────────────────────────────────────────────────────
apigee_products_total = Gauge(
    "apigee_api_products_total",
    "Total API products defined",
)

# ── Developers & Apps ───────────────────────────────────────────────
apigee_developers_total = Gauge(
    "apigee_developers_total",
    "Total registered developers",
)
apigee_apps_total = Gauge(
    "apigee_developer_apps_total",
    "Total developer apps (API consumers)",
)
apigee_apps_approved = Gauge(
    "apigee_developer_apps_approved",
    "Developer apps with approved status",
)
apigee_apps_revoked = Gauge(
    "apigee_developer_apps_revoked",
    "Developer apps with revoked credentials",
)

# ── Environments ────────────────────────────────────────────────────
apigee_environments_total = Gauge(
    "apigee_environments_total",
    "Total environments configured",
)

# ── Traffic (last 1 hour) ──────────────────────────────────────────
apigee_traffic_total = Gauge(
    "apigee_traffic_total_1h",
    "Total API traffic in the last 1 hour",
)
apigee_traffic_errors = Gauge(
    "apigee_traffic_errors_1h",
    "Total API error responses (4xx+5xx) in the last 1 hour",
)
apigee_traffic_error_rate = Gauge(
    "apigee_traffic_error_rate_percent_1h",
    "API error rate percentage in the last 1 hour",
)
apigee_traffic_policy_errors = Gauge(
    "apigee_traffic_policy_errors_1h",
    "Errors caused by policy violations (security policies) in the last 1 hour",
)

# ── Latency ─────────────────────────────────────────────────────────
apigee_avg_latency_ms = Gauge(
    "apigee_avg_total_latency_ms_1h",
    "Average total response latency in ms over the last 1 hour",
)
apigee_avg_target_latency_ms = Gauge(
    "apigee_avg_target_latency_ms_1h",
    "Average target (backend) latency in ms over the last 1 hour",
)

# ── Security policies ──────────────────────────────────────────────
apigee_proxies_with_oauth = Gauge(
    "apigee_proxies_with_oauth",
    "Proxies that have OAuthV2 or VerifyAPIKey policy attached",
)
apigee_proxies_with_spike_arrest = Gauge(
    "apigee_proxies_with_spike_arrest",
    "Proxies with SpikeArrest rate-limiting policy",
)
apigee_proxies_with_quota = Gauge(
    "apigee_proxies_with_quota",
    "Proxies with Quota enforcement policy",
)
apigee_proxies_no_auth = Gauge(
    "apigee_proxies_without_auth_policy",
    "Proxies with NO authentication policy (security risk)",
)

# ── Target servers ──────────────────────────────────────────────────
apigee_target_servers_total = Gauge(
    "apigee_target_servers_total",
    "Total target servers configured across all environments",
)
apigee_target_servers_ssl_enabled = Gauge(
    "apigee_target_servers_ssl_enabled",
    "Target servers with SSL/TLS enabled",
)

# ── KVMs ────────────────────────────────────────────────────────────
apigee_kvms_total = Gauge(
    "apigee_kvms_total",
    "Total Key Value Maps across org and environments",
)
apigee_kvms_encrypted = Gauge(
    "apigee_kvms_encrypted",
    "Encrypted Key Value Maps",
)

# ── Collection health ───────────────────────────────────────────────
apigee_collection_success = Gauge(
    "apigee_collection_success",
    "1 when the latest Apigee collection succeeded, 0 otherwise",
)
apigee_collection_duration_seconds = Gauge(
    "apigee_collection_duration_seconds",
    "Duration of the last Apigee collection run in seconds",
)


# ─── Apigee API helper ──────────────────────────────────────────────
class ApigeeAPI:
    """Wrapper for Google Apigee (X / hybrid) Management API."""

    def __init__(self, org, auth_token, timeout=30, is_edge=False):
        if is_edge:
            self.base_url = f"https://api.enterprise.apigee.com/v1/organizations/{org}"
        else:
            self.base_url = f"https://apigee.googleapis.com/v1/organizations/{org}"
        self.timeout = timeout
        self.headers = {
            "Authorization": f"Bearer {auth_token}",
            "Accept": "application/json",
        }
        self.org = org

    def _get(self, path, params=None):
        r = requests.get(
            f"{self.base_url}{path}",
            headers=self.headers,
            params=params,
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def list_proxies(self):
        data = self._get("/apis")
        # Apigee X returns {"proxies": [...]}, Edge returns list of names
        if isinstance(data, dict):
            return data.get("proxies", data.get("apiProxies", []))
        return data if isinstance(data, list) else []

    def get_proxy(self, name):
        return self._get(f"/apis/{name}")

    def get_proxy_deployments(self, name):
        return self._get(f"/apis/{name}/deployments")

    def list_environments(self):
        data = self._get("/environments")
        if isinstance(data, list):
            return data
        return data.get("environments", [])

    def list_shared_flows(self):
        data = self._get("/sharedflows")
        if isinstance(data, dict):
            return data.get("sharedFlows", [])
        return data if isinstance(data, list) else []

    def list_products(self):
        data = self._get("/apiproducts")
        if isinstance(data, dict):
            return data.get("apiProduct", [])
        return data if isinstance(data, list) else []

    def list_developers(self):
        data = self._get("/developers")
        if isinstance(data, list):
            return data
        return data.get("developer", [])

    def list_apps(self):
        data = self._get("/apps", params={"expand": "true"})
        if isinstance(data, dict):
            return data.get("app", [])
        return data if isinstance(data, list) else []

    def list_target_servers(self, env):
        data = self._get(f"/environments/{env}/targetservers")
        if isinstance(data, list):
            return data
        return data.get("targetServers", [])

    def get_target_server(self, env, name):
        return self._get(f"/environments/{env}/targetservers/{name}")

    def list_kvms_org(self):
        data = self._get("/keyvaluemaps")
        if isinstance(data, list):
            return data
        return data.get("keyValueMaps", [])

    def list_kvms_env(self, env):
        data = self._get(f"/environments/{env}/keyvaluemaps")
        if isinstance(data, list):
            return data
        return data.get("keyValueMaps", [])

    def get_analytics(self, env, select, time_range, time_unit="hour"):
        """Query Apigee Analytics API."""
        return self._get(f"/environments/{env}/stats/", params={
            "select": select,
            "timeRange": time_range,
            "timeUnit": time_unit,
        })

    def get_proxy_revision_policies(self, proxy_name, revision):
        """List policies in a proxy revision."""
        data = self._get(f"/apis/{proxy_name}/revisions/{revision}/policies")
        if isinstance(data, list):
            return data
        return data.get("policies", [])

    def get_policy(self, proxy_name, revision, policy_name):
        return self._get(f"/apis/{proxy_name}/revisions/{revision}/policies/{policy_name}")


# ═════════════════════════════════════════════════════════════════════
#  Main collector
# ═════════════════════════════════════════════════════════════════════
def collect_apigee():
    org = os.getenv("APIGEE_ORG", "").strip()
    auth_token = os.getenv("APIGEE_AUTH_TOKEN", "").strip()
    is_edge = os.getenv("APIGEE_IS_EDGE", "false").lower() == "true"

    if not org or not auth_token:
        logging.warning("Apigee: APIGEE_ORG and APIGEE_AUTH_TOKEN must be set — skipping")
        return

    timeout = int(os.getenv("APIGEE_TIMEOUT_SECONDS", "30"))
    start_time = datetime.now(timezone.utc)

    api = ApigeeAPI(org, auth_token, timeout=timeout, is_edge=is_edge)
    now = datetime.now(timezone.utc)
    metrics = {}

    # ── 1. Environments ─────────────────────────────────────────────
    environments = []
    try:
        logging.info("Apigee: fetching environments")
        environments = api.list_environments()
        apigee_environments_total.set(len(environments))
        metrics["environments_total"] = len(environments)
    except Exception as exc:
        logging.exception("Apigee: environments failed: %s", exc)

    # ── 2. API Proxies + deployment + security policy analysis ──────
    try:
        logging.info("Apigee: fetching API proxies")
        proxy_names = api.list_proxies()
        # Handle both name strings and proxy objects
        if proxy_names and isinstance(proxy_names[0], dict):
            proxy_names = [p.get("name", p.get("apiProxy", "")) for p in proxy_names]

        total_proxies = len(proxy_names)
        deployed = 0
        undeployed = 0
        env_counter = Counter()
        with_oauth = 0
        with_spike = 0
        with_quota = 0
        no_auth = 0

        for proxy_name in proxy_names:
            if not proxy_name:
                continue

            # Deployment status
            try:
                dep_data = api.get_proxy_deployments(proxy_name)
                deployments = dep_data.get("deployments", dep_data.get("environment", []))
                if deployments:
                    deployed += 1
                    for dep in deployments:
                        env_name = dep.get("environment") or dep.get("name", "unknown")
                        env_counter[env_name] += 1
                else:
                    undeployed += 1
            except Exception:
                undeployed += 1

            # Security policy scan on latest revision
            try:
                proxy_info = api.get_proxy(proxy_name)
                revisions = proxy_info.get("revision", proxy_info.get("revisions", []))
                if revisions:
                    latest_rev = max(revisions, key=lambda x: int(x) if str(x).isdigit() else 0)
                    policies = api.get_proxy_revision_policies(proxy_name, latest_rev)
                    policy_types = set()
                    for pol_name in policies:
                        if isinstance(pol_name, str):
                            lower = pol_name.lower()
                            if "oauth" in lower or "verifyapikey" in lower or "verify-api-key" in lower:
                                policy_types.add("auth")
                            if "spikearrest" in lower or "spike" in lower:
                                policy_types.add("spike")
                            if "quota" in lower:
                                policy_types.add("quota")
                    if "auth" in policy_types:
                        with_oauth += 1
                    else:
                        no_auth += 1
                    if "spike" in policy_types:
                        with_spike += 1
                    if "quota" in policy_types:
                        with_quota += 1
            except Exception:
                pass

        apigee_proxies_total.set(total_proxies)
        apigee_proxies_deployed.set(deployed)
        apigee_proxies_undeployed.set(undeployed)
        apigee_proxies_with_oauth.set(with_oauth)
        apigee_proxies_with_spike_arrest.set(with_spike)
        apigee_proxies_with_quota.set(with_quota)
        apigee_proxies_no_auth.set(no_auth)

        for env_name, count in env_counter.items():
            apigee_proxies_by_env.labels(environment=env_name).set(count)

        metrics.update(
            proxies_total=total_proxies,
            proxies_deployed=deployed,
            proxies_undeployed=undeployed,
            proxies_with_oauth=with_oauth,
            proxies_with_spike_arrest=with_spike,
            proxies_with_quota=with_quota,
            proxies_no_auth=no_auth,
            proxies_by_env=dict(env_counter),
        )

        logging.info(
            "Apigee: proxies total=%s deployed=%s no_auth=%s oauth=%s spike=%s",
            total_proxies, deployed, no_auth, with_oauth, with_spike,
        )
    except Exception as exc:
        logging.exception("Apigee: proxies collection failed: %s", exc)

    # ── 3. Shared flows, products ───────────────────────────────────
    try:
        flows = api.list_shared_flows()
        apigee_shared_flows_total.set(len(flows) if isinstance(flows, list) else 0)
        metrics["shared_flows_total"] = len(flows) if isinstance(flows, list) else 0
    except Exception as exc:
        logging.debug("Apigee: shared flows failed: %s", exc)

    try:
        products = api.list_products()
        apigee_products_total.set(len(products) if isinstance(products, list) else 0)
        metrics["products_total"] = len(products) if isinstance(products, list) else 0
    except Exception as exc:
        logging.debug("Apigee: products failed: %s", exc)

    # ── 4. Developers & Apps ────────────────────────────────────────
    try:
        logging.info("Apigee: fetching developers and apps")
        devs = api.list_developers()
        apigee_developers_total.set(len(devs))
        metrics["developers_total"] = len(devs)

        apps = api.list_apps()
        apps_total = len(apps)
        approved = 0
        revoked = 0
        for app in apps:
            creds = app.get("credentials", [])
            if any(c.get("status") == "revoked" for c in creds):
                revoked += 1
            elif any(c.get("status") == "approved" for c in creds):
                approved += 1

        apigee_apps_total.set(apps_total)
        apigee_apps_approved.set(approved)
        apigee_apps_revoked.set(revoked)
        metrics.update(apps_total=apps_total, apps_approved=approved, apps_revoked=revoked)
    except Exception as exc:
        logging.exception("Apigee: developers/apps failed: %s", exc)

    # ── 5. Target servers ───────────────────────────────────────────
    try:
        logging.info("Apigee: fetching target servers")
        ts_total = 0
        ts_ssl = 0
        for env in environments:
            env_name = env if isinstance(env, str) else env.get("name", "")
            if not env_name:
                continue
            try:
                ts_names = api.list_target_servers(env_name)
                for name in ts_names:
                    ts_name = name if isinstance(name, str) else name.get("name", "")
                    if not ts_name:
                        continue
                    ts_total += 1
                    try:
                        ts_detail = api.get_target_server(env_name, ts_name)
                        ssl_info = ts_detail.get("sSLInfo", ts_detail.get("sslInfo", {}))
                        if ssl_info and ssl_info.get("enabled"):
                            ts_ssl += 1
                    except Exception:
                        pass
            except Exception:
                pass

        apigee_target_servers_total.set(ts_total)
        apigee_target_servers_ssl_enabled.set(ts_ssl)
        metrics.update(target_servers_total=ts_total, target_servers_ssl=ts_ssl)
    except Exception as exc:
        logging.exception("Apigee: target servers failed: %s", exc)

    # ── 6. KVMs ─────────────────────────────────────────────────────
    try:
        kvm_total = 0
        kvm_encrypted = 0

        org_kvms = api.list_kvms_org()
        for kvm in (org_kvms if isinstance(org_kvms, list) else []):
            kvm_total += 1
            name = kvm if isinstance(kvm, str) else kvm.get("name", "")
            if isinstance(kvm, dict) and kvm.get("encrypted"):
                kvm_encrypted += 1

        for env in environments:
            env_name = env if isinstance(env, str) else env.get("name", "")
            if not env_name:
                continue
            try:
                env_kvms = api.list_kvms_env(env_name)
                for kvm in (env_kvms if isinstance(env_kvms, list) else []):
                    kvm_total += 1
                    if isinstance(kvm, dict) and kvm.get("encrypted"):
                        kvm_encrypted += 1
            except Exception:
                pass

        apigee_kvms_total.set(kvm_total)
        apigee_kvms_encrypted.set(kvm_encrypted)
        metrics.update(kvms_total=kvm_total, kvms_encrypted=kvm_encrypted)
    except Exception as exc:
        logging.debug("Apigee: KVMs failed: %s", exc)

    # ── 7. Traffic analytics (last 1 hour) ──────────────────────────
    try:
        logging.info("Apigee: fetching traffic analytics")
        one_hour_ago = now - timedelta(hours=1)
        time_range = (
            f"{one_hour_ago.strftime('%m/%d/%Y %H:%M')}~"
            f"{now.strftime('%m/%d/%Y %H:%M')}"
        )

        total_traffic = 0
        total_errors = 0
        total_policy_errors = 0
        total_latency_sum = 0
        total_target_latency_sum = 0
        latency_count = 0

        for env in environments:
            env_name = env if isinstance(env, str) else env.get("name", "")
            if not env_name:
                continue
            try:
                stats = api.get_analytics(
                    env_name,
                    "sum(message_count),sum(is_error),sum(policy_error),"
                    "avg(total_response_time),avg(target_response_time)",
                    time_range,
                )
                # Parse analytics response
                for dim in stats.get("Response", {}).get("stats", {}).get("data", []):
                    for metric_item in dim.get("metric", []):
                        name = metric_item.get("name", "")
                        values = metric_item.get("values", [])
                        val = float(values[0]) if values else 0

                        if "message_count" in name:
                            total_traffic += int(val)
                        elif name == "sum(is_error)":
                            total_errors += int(val)
                        elif "policy_error" in name:
                            total_policy_errors += int(val)
                        elif "total_response_time" in name:
                            total_latency_sum += val
                            latency_count += 1
                        elif "target_response_time" in name:
                            total_target_latency_sum += val
            except Exception:
                pass

        apigee_traffic_total.set(total_traffic)
        apigee_traffic_errors.set(total_errors)
        apigee_traffic_policy_errors.set(total_policy_errors)

        error_rate = round((total_errors / total_traffic * 100), 2) if total_traffic > 0 else 0
        apigee_traffic_error_rate.set(error_rate)

        avg_latency = round(total_latency_sum / latency_count, 1) if latency_count > 0 else 0
        avg_target = round(total_target_latency_sum / latency_count, 1) if latency_count > 0 else 0
        apigee_avg_latency_ms.set(avg_latency)
        apigee_avg_target_latency_ms.set(avg_target)

        metrics.update(
            traffic_total_1h=total_traffic,
            traffic_errors_1h=total_errors,
            traffic_error_rate_1h=error_rate,
            traffic_policy_errors_1h=total_policy_errors,
            avg_latency_ms=avg_latency,
            avg_target_latency_ms=avg_target,
        )

        logging.info(
            "Apigee: traffic(1h) total=%s errors=%s rate=%.1f%% latency=%.0fms",
            total_traffic, total_errors, error_rate, avg_latency,
        )
    except Exception as exc:
        logging.exception("Apigee: analytics failed: %s", exc)

    # ── Finalize ────────────────────────────────────────────────────
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    apigee_collection_success.set(1)
    apigee_collection_duration_seconds.set(elapsed)
    logging.info("Apigee: collection completed in %.1fs", elapsed)

    store_apigee(metrics)
