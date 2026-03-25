import os
import logging
from datetime import datetime, timezone, timedelta
from collections import Counter

import requests
from prometheus_client import Gauge

from es_store import store_imperva

# ── Sites / Protected assets ────────────────────────────────────────
imperva_sites_total = Gauge(
    "imperva_waf_sites_total",
    "Total sites (web applications) protected by Imperva Cloud WAF",
)
imperva_sites_active = Gauge(
    "imperva_waf_sites_active",
    "Sites with active WAF protection",
)
imperva_sites_bypassed = Gauge(
    "imperva_waf_sites_bypassed",
    "Sites in bypass / pass-through mode (NOT protected)",
)

# ── SSL / TLS posture ───────────────────────────────────────────────
imperva_sites_ssl_enabled = Gauge(
    "imperva_waf_sites_ssl_enabled",
    "Sites with SSL/TLS enabled",
)
imperva_sites_ssl_disabled = Gauge(
    "imperva_waf_sites_ssl_disabled",
    "Sites without SSL/TLS (HTTP only — security risk)",
)
imperva_sites_custom_cert = Gauge(
    "imperva_waf_sites_custom_certificate",
    "Sites using a custom (uploaded) SSL certificate",
)

# ── WAF security settings ──────────────────────────────────────────
imperva_sites_waf_rules_block = Gauge(
    "imperva_waf_sites_blocking_mode",
    "Sites with WAF rules set to block (actively protecting)",
)
imperva_sites_waf_rules_alert = Gauge(
    "imperva_waf_sites_alert_only_mode",
    "Sites with WAF rules in alert-only mode (monitoring, not blocking)",
)

# ── DDoS protection ────────────────────────────────────────────────
imperva_sites_ddos_enabled = Gauge(
    "imperva_waf_sites_ddos_protection_enabled",
    "Sites with DDoS protection active",
)

# ── Bot mitigation ──────────────────────────────────────────────────
imperva_sites_bot_mitigation = Gauge(
    "imperva_waf_sites_bot_mitigation_enabled",
    "Sites with bot mitigation / advanced bot protection enabled",
)

# ── Threat stats (last 30 days) ─────────────────────────────────────
imperva_threats_total = Gauge(
    "imperva_waf_threats_total_30d",
    "Total threats/attacks blocked in the last 30 days",
)
imperva_threats_by_type = Gauge(
    "imperva_waf_threats_by_type_30d",
    "Threats blocked by attack type in the last 30 days",
    ["attack_type"],
)
imperva_threats_sql_injection = Gauge(
    "imperva_waf_threats_sql_injection_30d",
    "SQL injection attacks blocked in the last 30 days",
)
imperva_threats_xss = Gauge(
    "imperva_waf_threats_xss_30d",
    "Cross-site scripting attacks blocked in the last 30 days",
)
imperva_threats_rfi = Gauge(
    "imperva_waf_threats_remote_file_inclusion_30d",
    "Remote file inclusion attacks blocked in the last 30 days",
)
imperva_threats_illegal_resource = Gauge(
    "imperva_waf_threats_illegal_resource_30d",
    "Illegal resource access attempts blocked in the last 30 days",
)
imperva_threats_bot = Gauge(
    "imperva_waf_threats_bot_30d",
    "Bot attacks blocked in the last 30 days",
)
imperva_threats_backdoor = Gauge(
    "imperva_waf_threats_backdoor_30d",
    "Backdoor/shell access attempts blocked in the last 30 days",
)

# ── Traffic stats (last 30 days) ────────────────────────────────────
imperva_requests_total = Gauge(
    "imperva_waf_requests_total_30d",
    "Total HTTP requests processed in the last 30 days",
)
imperva_requests_blocked = Gauge(
    "imperva_waf_requests_blocked_30d",
    "HTTP requests blocked by WAF in the last 30 days",
)
imperva_bandwidth_total_gb = Gauge(
    "imperva_waf_bandwidth_total_gb_30d",
    "Total bandwidth served in GB over the last 30 days",
)
imperva_bandwidth_cached_gb = Gauge(
    "imperva_waf_bandwidth_cached_gb_30d",
    "Bandwidth served from CDN cache in GB over the last 30 days",
)

# ── Incidents ───────────────────────────────────────────────────────
imperva_incidents_open = Gauge(
    "imperva_waf_incidents_open",
    "Currently open WAF incidents/events",
)

# ── Top attacking countries ─────────────────────────────────────────
imperva_attacks_by_country = Gauge(
    "imperva_waf_attacks_by_country_30d",
    "Attacks blocked per source country (top countries)",
    ["country"],
)

# ── IP ACL rules ────────────────────────────────────────────────────
imperva_acl_rules_total = Gauge(
    "imperva_waf_acl_rules_total",
    "Total IP-based ACL rules across all sites",
)

# ── Cache hit ratio ─────────────────────────────────────────────────
imperva_cache_hit_ratio = Gauge(
    "imperva_waf_cache_hit_ratio_percent",
    "CDN cache hit ratio percentage (performance indicator)",
)

# ── Data centers ────────────────────────────────────────────────────
imperva_data_centers_total = Gauge(
    "imperva_waf_data_centers_total",
    "Total origin data centers configured across all sites",
)
imperva_data_centers_enabled = Gauge(
    "imperva_waf_data_centers_enabled",
    "Origin data centers currently enabled",
)

# ── Collection health ───────────────────────────────────────────────
imperva_collection_success = Gauge(
    "imperva_waf_collection_success",
    "1 when the latest Imperva collection succeeded, 0 otherwise",
)
imperva_collection_duration_seconds = Gauge(
    "imperva_waf_collection_duration_seconds",
    "Duration of the last Imperva collection run in seconds",
)


# ─── Imperva Cloud WAF API helper ───────────────────────────────────
class ImpervaAPI:
    """Wrapper around Imperva Cloud WAF (formerly Incapsula) REST API."""

    def __init__(self, api_id, api_key, account_id="", timeout=30):
        self.base_url = "https://my.imperva.com/api/prov/v1"
        self.api_id = api_id
        self.api_key = api_key
        self.account_id = account_id
        self.timeout = timeout

    def _post(self, endpoint, data=None):
        payload = dict(data or {})
        payload["api_id"] = self.api_id
        payload["api_key"] = self.api_key
        if self.account_id:
            payload["account_id"] = self.account_id

        r = requests.post(
            f"{self.base_url}{endpoint}",
            data=payload,
            timeout=self.timeout,
        )
        r.raise_for_status()
        result = r.json()

        res_code = result.get("res", result.get("res_code", -1))
        if int(res_code) != 0:
            msg = result.get("res_message", "unknown error")
            raise RuntimeError(f"Imperva API error {res_code}: {msg}")

        return result

    def list_sites(self, page_size=100, max_pages=50):
        """Paginate through all sites."""
        all_sites = []
        for page in range(max_pages):
            result = self._post("/sites/list", {
                "page_size": page_size,
                "page_num": page,
            })
            sites = result.get("sites", [])
            all_sites.extend(sites)
            if len(sites) < page_size:
                break
        return all_sites

    def get_site_status(self, site_id):
        """Get detailed site configuration/status."""
        return self._post("/sites/status", {"site_id": site_id})

    def get_site_security(self, site_id):
        """Get WAF security configuration for a site."""
        try:
            return self._post("/sites/configure/security", {"site_id": site_id})
        except Exception:
            return {}

    def get_stats(self, site_id, stats, time_range="last_30_days"):
        """Get visit/threat statistics for a site."""
        return self._post("/stats/stats", {
            "site_id": site_id,
            "stats": stats,
            "time_range": time_range,
        })

    def get_data_centers(self, site_id):
        """Get origin data centers for a site."""
        return self._post("/sites/dataCenters/list", {"site_id": site_id})


# ═════════════════════════════════════════════════════════════════════
#  Main collector
# ═════════════════════════════════════════════════════════════════════
def collect_imperva():
    api_id = os.getenv("IMPERVA_API_ID", "").strip()
    api_key = os.getenv("IMPERVA_API_KEY", "").strip()
    account_id = os.getenv("IMPERVA_ACCOUNT_ID", "").strip()

    if not api_id or not api_key:
        logging.warning(
            "Imperva: IMPERVA_API_ID and IMPERVA_API_KEY must be set — skipping"
        )
        return

    timeout = int(os.getenv("IMPERVA_TIMEOUT_SECONDS", "30"))
    start_time = datetime.now(timezone.utc)

    api = ImpervaAPI(api_id, api_key, account_id=account_id, timeout=timeout)
    metrics = {}

    # ── 1. Sites inventory ──────────────────────────────────────────
    try:
        logging.info("Imperva: fetching sites")
        sites = api.list_sites()

        total_sites = len(sites)
        active = 0
        bypassed = 0
        ssl_enabled = 0
        ssl_disabled = 0
        custom_cert = 0
        waf_block = 0
        waf_alert = 0
        ddos_enabled = 0
        bot_enabled = 0
        acl_rules_total = 0
        dc_total = 0
        dc_enabled = 0

        for site in sites:
            site_id = site.get("site_id")
            status = (site.get("status") or "").lower()

            if status == "active":
                active += 1
            elif status in ("bypass", "passthrough"):
                bypassed += 1

            # SSL
            ssl_info = site.get("ssl", {})
            if isinstance(ssl_info, dict):
                origin_ssl = ssl_info.get("origin_server", {})
                if ssl_info.get("custom_certificate") or origin_ssl:
                    ssl_enabled += 1
                    if ssl_info.get("custom_certificate"):
                        custom_cert += 1
                else:
                    ssl_disabled += 1
            else:
                ssl_disabled += 1

            # Security settings from site object
            security = site.get("security", {})
            if isinstance(security, dict):
                waf = security.get("waf", {})
                if isinstance(waf, dict):
                    rules = waf.get("rules", [])
                    has_block = False
                    for rule in (rules if isinstance(rules, list) else []):
                        action = (rule.get("action") or "").lower()
                        if action in ("block_request", "block"):
                            has_block = True
                    if has_block:
                        waf_block += 1
                    elif rules:
                        waf_alert += 1

            # DDoS
            ddos = site.get("ddos_protection")
            if ddos or (isinstance(security, dict)
                        and security.get("ddos", {}).get("activation_mode")):
                ddos_enabled += 1

            # Bot mitigation
            advanced_bot = site.get("extended_ddos")
            if advanced_bot or (isinstance(security, dict)
                                and security.get("bot_access_control")):
                bot_enabled += 1

            # ACL rules
            acl = site.get("acl", site.get("acls", {}))
            if isinstance(acl, dict):
                rules_list = acl.get("rules", [])
                acl_rules_total += len(rules_list) if isinstance(rules_list, list) else 0

            # Data centers
            try:
                dc_result = api.get_data_centers(site_id)
                dcs = dc_result.get("DCs", dc_result.get("data_centers", []))
                if isinstance(dcs, list):
                    dc_total += len(dcs)
                    dc_enabled += sum(
                        1 for dc in dcs
                        if (dc.get("enabled") or str(dc.get("is_enabled", "")).lower()) in
                           (True, "true", "yes")
                    )
            except Exception:
                pass

        imperva_sites_total.set(total_sites)
        imperva_sites_active.set(active)
        imperva_sites_bypassed.set(bypassed)
        imperva_sites_ssl_enabled.set(ssl_enabled)
        imperva_sites_ssl_disabled.set(ssl_disabled)
        imperva_sites_custom_cert.set(custom_cert)
        imperva_sites_waf_rules_block.set(waf_block)
        imperva_sites_waf_rules_alert.set(waf_alert)
        imperva_sites_ddos_enabled.set(ddos_enabled)
        imperva_sites_bot_mitigation.set(bot_enabled)
        imperva_acl_rules_total.set(acl_rules_total)
        imperva_data_centers_total.set(dc_total)
        imperva_data_centers_enabled.set(dc_enabled)

        metrics.update(
            sites_total=total_sites,
            sites_active=active,
            sites_bypassed=bypassed,
            sites_ssl_enabled=ssl_enabled,
            sites_ssl_disabled=ssl_disabled,
            sites_custom_cert=custom_cert,
            sites_waf_blocking=waf_block,
            sites_waf_alert_only=waf_alert,
            sites_ddos_enabled=ddos_enabled,
            sites_bot_mitigation=bot_enabled,
            acl_rules_total=acl_rules_total,
            data_centers_total=dc_total,
            data_centers_enabled=dc_enabled,
        )

        logging.info(
            "Imperva: sites total=%s active=%s bypassed=%s "
            "ssl_on=%s waf_block=%s ddos=%s",
            total_sites, active, bypassed,
            ssl_enabled, waf_block, ddos_enabled,
        )
    except Exception as exc:
        logging.exception("Imperva: sites collection failed: %s", exc)
        imperva_collection_success.set(0)
        return

    # ── 2. Threat & traffic stats (aggregated across sites) ─────────
    try:
        logging.info("Imperva: fetching threat/traffic stats")

        total_threats = 0
        total_requests = 0
        total_blocked = 0
        total_bw = 0.0
        total_cached_bw = 0.0
        attack_type_counter = Counter()
        country_counter = Counter()

        for site in sites:
            site_id = site.get("site_id")
            if not site_id:
                continue

            try:
                # Threat stats
                threat_result = api.get_stats(
                    site_id,
                    "visits_timeseries,threats",
                    time_range="last_30_days",
                )

                # Aggregate threats by type
                threats = threat_result.get("threats", [])
                if isinstance(threats, list):
                    for t in threats:
                        t_name = t.get("name", "other")
                        t_count = t.get("incidents", t.get("count", 0))
                        if isinstance(t_count, (int, float)):
                            attack_type_counter[t_name] += int(t_count)
                            total_threats += int(t_count)

                # Visit / request stats
                visits_ts = threat_result.get("visits_timeseries", [])
                if isinstance(visits_ts, list):
                    for ts_entry in visits_ts:
                        if isinstance(ts_entry, dict):
                            total_requests += ts_entry.get("total", 0)
                            total_blocked += ts_entry.get("blocked", 0)

                # Country stats
                geo = threat_result.get("attacks_origin", threat_result.get("geo", []))
                if isinstance(geo, list):
                    for g in geo:
                        c_name = g.get("country", g.get("name", "Unknown"))
                        c_count = g.get("incidents", g.get("count", 0))
                        if isinstance(c_count, (int, float)):
                            country_counter[c_name] += int(c_count)

            except Exception as exc:
                logging.debug("Imperva: stats for site %s failed: %s", site_id, exc)

            try:
                # Bandwidth stats
                bw_result = api.get_stats(
                    site_id,
                    "bandwidth_timeseries",
                    time_range="last_30_days",
                )
                bw_ts = bw_result.get("bandwidth_timeseries", [])
                if isinstance(bw_ts, list):
                    for ts_entry in bw_ts:
                        if isinstance(ts_entry, dict):
                            total_bw += ts_entry.get("total", 0)
                            total_cached_bw += ts_entry.get("cached", 0)
            except Exception:
                pass

        imperva_threats_total.set(total_threats)
        imperva_requests_total.set(total_requests)
        imperva_requests_blocked.set(total_blocked)

        # Convert bandwidth from bytes to GB
        bw_gb = round(total_bw / (1024 ** 3), 2)
        cached_gb = round(total_cached_bw / (1024 ** 3), 2)
        imperva_bandwidth_total_gb.set(bw_gb)
        imperva_bandwidth_cached_gb.set(cached_gb)

        # Cache hit ratio
        if total_bw > 0:
            cache_ratio = round((total_cached_bw / total_bw) * 100, 1)
        else:
            cache_ratio = 0.0
        imperva_cache_hit_ratio.set(cache_ratio)

        # Attack-type breakdown
        type_mapping = {
            "sql_injection": imperva_threats_sql_injection,
            "cross_site_scripting": imperva_threats_xss,
            "remote_file_inclusion": imperva_threats_rfi,
            "illegal_resource_access": imperva_threats_illegal_resource,
            "bot_access_control": imperva_threats_bot,
            "backdoor": imperva_threats_backdoor,
        }
        for key, gauge in type_mapping.items():
            gauge.set(0)  # Reset first

        for attack_name, count in attack_type_counter.items():
            norm = attack_name.lower().replace(" ", "_").replace("-", "_")
            imperva_threats_by_type.labels(attack_type=attack_name).set(count)
            if norm in type_mapping:
                type_mapping[norm].set(count)

        # Top 10 attacking countries
        for country, count in country_counter.most_common(10):
            imperva_attacks_by_country.labels(country=country).set(count)

        metrics.update(
            threats_total_30d=total_threats,
            requests_total_30d=total_requests,
            requests_blocked_30d=total_blocked,
            bandwidth_total_gb=bw_gb,
            bandwidth_cached_gb=cached_gb,
            cache_hit_ratio_percent=cache_ratio,
            attack_types=dict(attack_type_counter),
            top_attacking_countries=dict(country_counter.most_common(10)),
        )

        logging.info(
            "Imperva: threats=%s requests=%s blocked=%s "
            "bw=%.1fGB cached=%.1fGB cache_ratio=%.1f%%",
            total_threats, total_requests, total_blocked,
            bw_gb, cached_gb, cache_ratio,
        )
    except Exception as exc:
        logging.exception("Imperva: threat/traffic stats failed: %s", exc)

    # ── Finalize ────────────────────────────────────────────────────
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    imperva_collection_success.set(1)
    imperva_collection_duration_seconds.set(elapsed)
    logging.info("Imperva: collection completed in %.1fs", elapsed)

    store_imperva(metrics)
