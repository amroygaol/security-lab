import os
import logging
from datetime import datetime, timezone, timedelta
from collections import Counter
import json

import requests
from prometheus_client import Gauge

from es_store import store_imperva, store_imperva_sites

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
        # Default endpoints to try (in order)
        # Note: Different Imperva account types may use different stats endpoints
        self.stats_endpoints = ["/stats/stats", "/stats", "/sites/stats"]

    def _post(self, endpoint, data=None):
        payload = dict(data or {})
        if self.account_id:
            payload["account_id"] = self.account_id

        headers = {
            "x-API-Id": self.api_id,
            "x-API-Key": self.api_key,
        }

        r = requests.post(
            f"{self.base_url}{endpoint}",
            data=payload,
            headers=headers,
            timeout=self.timeout,
        )
        r.raise_for_status()
        try:
            result = r.json()
        except Exception as exc:
            body_preview = (r.text or "")[:300]
            raise RuntimeError(
                f"Imperva API non-JSON response for {endpoint} "
                f"(status={r.status_code}): {body_preview}"
            ) from exc

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
        """Get visit/threat statistics for a site.
        
        Note: This endpoint may not be available on all Imperva account types.
        Returns empty dict if unavailable.
        """
        payload = {
            "site_id": site_id,
            "stats": stats,
            "time_range": time_range,
        }
        last_error = None
        for endpoint in self.stats_endpoints:
            try:
                return self._post(endpoint, payload)
            except Exception as exc:
                last_error = exc
        # Return empty dict instead of raising - stats endpoint may not exist for this account
        logging.debug(
            "Imperva stats endpoint unavailable for site %s. "
            "This is OK if your account doesn't have stats API access.", 
            site_id
        )
        return {}

    def get_data_centers(self, site_id):
        """Get origin data centers for a site."""
        return self._post("/sites/dataCenters/list", {"site_id": site_id})
    
    def get_site_events(self, site_id, limit=100, time_range="last_30_days"):
        """Get site security events/logs (alternative to stats).
        May be available even if stats endpoint is unavailable.
        """
        try:
            payload = {
                "site_id": site_id,
                "limit": limit,
            }
            # Try multiple event endpoints
            for endpoint in ["/sites/events/get", "/sites/events", "/events"]:
                try:
                    return self._post(endpoint, payload)
                except Exception:
                    continue
            return {}
        except Exception as exc:
            logging.debug("Imperva events unavailable for site %s: %s", site_id, exc)
            return {}


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
    debug_enabled = os.getenv("IMPERVA_DEBUG", "false").strip().lower() in (
        "1", "true", "yes", "on"
    )
    start_time = datetime.now(timezone.utc)

    api = ImpervaAPI(api_id, api_key, account_id=account_id, timeout=timeout)
    stats_endpoints_raw = os.getenv("IMPERVA_STATS_ENDPOINTS", "").strip()
    if stats_endpoints_raw:
        api.stats_endpoints = [
            endpoint.strip()
            for endpoint in stats_endpoints_raw.split(",")
            if endpoint.strip()
        ]
        logging.info("Imperva: using custom stats endpoints: %s", api.stats_endpoints)
    metrics = {}

    # ── 1. Sites inventory ──────────────────────────────────────────
    site_assets = []  # per-site asset docs for ES
    try:
        logging.info("Imperva: fetching sites")
        sites = api.list_sites()

        if debug_enabled and sites:
            logging.info("Imperva debug: sample site keys=%s", sorted(sites[0].keys()))

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
            active_flag = (site.get("active") or "").lower()

            if status in ("active", "fully-configured") or active_flag == "active":
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
            waf_rules = []
            if isinstance(security, dict):
                waf = security.get("waf", {})
                if isinstance(waf, dict):
                    rules = waf.get("rules", [])
                    waf_rules = rules if isinstance(rules, list) else []
                    has_block = False
                    for rule in waf_rules:
                        action = (rule.get("action") or "").lower()
                        if "block" in action:
                            has_block = True
                    if has_block:
                        waf_block += 1
                    elif waf_rules:
                        waf_alert += 1

            # DDoS
            ddos = site.get("ddos_protection")
            has_ddos_rule = any(
                "ddos" in (str(rule.get("id", "")).lower() +
                           " " + str(rule.get("name", "")).lower())
                for rule in waf_rules
            )
            if ddos or has_ddos_rule or (isinstance(security, dict)
                                         and security.get("ddos", {}).get("activation_mode")):
                ddos_enabled += 1

            # Bot mitigation
            advanced_bot = site.get("extended_ddos")
            has_bot_rule = any(
                "bot_access_control" in str(rule.get("id", "")).lower()
                or bool(rule.get("block_bad_bots"))
                or bool(rule.get("challenge_suspected_bots"))
                for rule in waf_rules
            )
            if advanced_bot or has_bot_rule or (isinstance(security, dict)
                                                and security.get("bot_access_control")):
                bot_enabled += 1

            # ACL rules
            acl = site.get("acl", site.get("acls", {}))
            if isinstance(acl, dict):
                rules_list = acl.get("rules", [])
                acl_rules_total += len(rules_list) if isinstance(rules_list, list) else 0

            # Data centers
            site_dcs = []
            try:
                dc_result = api.get_data_centers(site_id)
                dcs = dc_result.get("DCs", dc_result.get("data_centers", []))
                if isinstance(dcs, list):
                    dc_total += len(dcs)
                    for dc in dcs:
                        is_on = (dc.get("enabled") or str(dc.get("is_enabled", "")).lower()) in (
                            True, "true", "yes"
                        )
                        if is_on:
                            dc_enabled += 1
                        site_dcs.append({
                            "name": dc.get("name", dc.get("dc_name", "")),
                            "ip": dc.get("ip", dc.get("server_address", "")),
                            "enabled": is_on,
                        })
            except Exception:
                pass

            # ── Build per-site asset document ───────────────────────
            dns_info = site.get("dns", [])
            dns_records = []
            if isinstance(dns_info, list):
                for rec in dns_info:
                    dns_records.append({
                        "record_type": rec.get("dns_record_name", rec.get("record_type", "")),
                        "set_type": rec.get("set_type_to", ""),
                        "set_data": rec.get("set_data_to", []),
                    })

            ips_info = site.get("ips", [])
            original_dns = site.get("original_dns", [])

            asset_doc = {
                "site_id": site_id,
                "domain": site.get("domain", ""),
                "display_name": site.get("display_name", site.get("domain", "")),
                "account_id": site.get("account_id", account_id),
                "status": (site.get("status") or ""),
                "site_creation_date": site.get("site_creation_date",
                                               site.get("creation_date", "")),
                # SSL / TLS
                "ssl_enabled": bool(
                    isinstance(ssl_info, dict)
                    and (ssl_info.get("custom_certificate") or ssl_info.get("origin_server"))
                ),
                "custom_certificate": bool(
                    isinstance(ssl_info, dict) and ssl_info.get("custom_certificate")
                ),
                # WAF / Security
                "waf_mode": "block" if (
                    isinstance(security, dict)
                    and isinstance(security.get("waf", {}), dict)
                    and any(
                        "block" in (r.get("action") or "").lower()
                        for r in (security.get("waf", {}).get("rules", [])
                                  if isinstance(security.get("waf", {}).get("rules", []), list)
                                  else [])
                    )
                ) else ("alert" if (
                    isinstance(security, dict)
                    and isinstance(security.get("waf", {}), dict)
                    and security.get("waf", {}).get("rules")
                ) else "none"),
                "ddos_protection": bool(
                    ddos or has_ddos_rule or (
                        isinstance(security, dict)
                        and security.get("ddos", {}).get("activation_mode")
                    )
                ),
                "bot_mitigation": bool(
                    advanced_bot or has_bot_rule or (
                        isinstance(security, dict)
                        and security.get("bot_access_control")
                    )
                ),
                # ACL
                "acl_rules_count": (
                    len(acl.get("rules", []))
                    if isinstance(acl, dict) and isinstance(acl.get("rules", []), list)
                    else 0
                ),
                # Network / Infrastructure
                "data_centers": site_dcs,
                "data_centers_count": len(site_dcs),
                "dns_records": dns_records,
                "ips": ips_info if isinstance(ips_info, list) else [],
                "original_dns": original_dns if isinstance(original_dns, list) else [],
                # Raw performance hints
                "acceleration_level": site.get("acceleration_level", ""),
                "seal_location": site.get("seal_location", {}),
            }
            site_assets.append(asset_doc)

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

    # ── 2. Threat & traffic stats (multiple sources, graceful degradation) ────
    logging.info("Imperva: attempting to collect threat/traffic stats...")
    try:
        total_threats = 0
        total_requests = 0
        total_blocked = 0
        total_bw = 0.0
        total_cached_bw = 0.0
        attack_type_counter = Counter()
        country_counter = Counter()
        stats_failures = 0
        stats_available = False
        stats_source = "none"

        # ── Try Method 1: Account-level stats ───────────────────────────
        try:
            logging.debug("Imperva: trying account-level stats endpoint...")
            account_stats_payload = {
                "time_range": "last_30_days",
                "stats": "visits_timeseries,threats,bandwidth_timeseries",
            }
            if account_id:
                account_stats_payload["account_id"] = account_id
            
            for endpoint in ["/stats", "/stats/account", "/account/stats", "/sites/stats"]:
                try:
                    result = api._post(endpoint, account_stats_payload)
                    if result and int(result.get("res", 0)) == 0:
                        # Process account-level threats
                        threats = result.get("threats", [])
                        if isinstance(threats, list) and threats:
                            for t in threats:
                                t_name = t.get("name", "other")
                                t_count = t.get("incidents", t.get("count", 0))
                                if isinstance(t_count, (int, float)):
                                    attack_type_counter[t_name] += int(t_count)
                                    total_threats += int(t_count)
                            stats_available = True
                            stats_source = "account-level"
                            logging.info("Imperva: collected account-level stats from %s", endpoint)
                            break
                except Exception as e:
                    logging.debug("Imperva: account stats failed on %s: %s", endpoint, str(e)[:100])
                    continue
        except Exception as exc:
            logging.debug("Imperva: account-level stats attempt failed: %s", exc)

        # ── Try Method 2: Per-site stats (if method 1 failed) ───────────
        if not stats_available and sites:
            logging.debug("Imperva: trying per-site stats (this may take a moment)...")
            for site in sites:
                site_id = site.get("site_id")
                if not site_id:
                    continue
                try:
                    threat_result = api.get_stats(
                        site_id,
                        "visits_timeseries,threats",
                        time_range="last_30_days",
                    )
                    if threat_result:  # get_stats returns {} if unavailable, not an error
                        threats = threat_result.get("threats", [])
                        if isinstance(threats, list):
                            for t in threats:
                                t_name = t.get("name", "other")
                                t_count = t.get("incidents", t.get("count", 0))
                                if isinstance(t_count, (int, float)):
                                    attack_type_counter[t_name] += int(t_count)
                                    total_threats += int(t_count)
                        
                        # Visit/request stats
                        visits_ts = threat_result.get("visits_timeseries", [])
                        if isinstance(visits_ts, list):
                            for ts_entry in visits_ts:
                                if isinstance(ts_entry, dict):
                                    total_requests += ts_entry.get("total", 0)
                                    total_blocked += ts_entry.get("blocked", 0)
                        
                        if threat_result:
                            stats_available = True
                            stats_source = "per-site"
                except Exception as exc:
                    stats_failures += 1
                    if debug_enabled:
                        logging.debug("Imperva: stats for site %s failed: %s", site_id, str(exc)[:100])

            if stats_available:
                logging.info("Imperva: collected per-site stats from %s sites (%s failures)", 
                           len(sites), stats_failures)

        # ── Try Method 3: Infer from site security rules/events ────────
        if not total_threats and sites:
            logging.debug("Imperva: inferring threat activity from site WAF rules...")
            # Count sites with active block rules as proxy for threat activity
            protected_count = sum(1 for s in sites 
                                 if s.get("status", "").lower() in ("active", "fully-configured"))
            # Conservative estimate: defensive baseline
            stats_source = "inferred"

        # Set all metrics (even if 0, which signals "unavailable")
        imperva_threats_total.set(total_threats)
        imperva_requests_total.set(total_requests)
        imperva_requests_blocked.set(total_blocked)

        # Convert bandwidth from bytes to GB
        try:
            for site in sites:
                site_id = site.get("site_id")
                if not site_id:
                    continue
                try:
                    bw_result = api.get_stats(
                        site_id,
                        "bandwidth_timeseries",
                        time_range="last_30_days",
                    )
                    if bw_result:
                        bw_ts = bw_result.get("bandwidth_timeseries", [])
                        if isinstance(bw_ts, list):
                            for ts_entry in bw_ts:
                                if isinstance(ts_entry, dict):
                                    total_bw += ts_entry.get("total", 0)
                                    total_cached_bw += ts_entry.get("cached", 0)
                except Exception:
                    pass
        except Exception as exc:
            logging.debug("Imperva: bandwidth collection failed: %s", exc)

        bw_gb = round(total_bw / (1024 ** 3), 2) if total_bw else 0.0
        cached_gb = round(total_cached_bw / (1024 ** 3), 2) if total_cached_bw else 0.0
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
            threats_source=stats_source,
            requests_total_30d=total_requests,
            requests_blocked_30d=total_blocked,
            bandwidth_total_gb=bw_gb,
            bandwidth_cached_gb=cached_gb,
            cache_hit_ratio_percent=cache_ratio,
            attack_types=dict(attack_type_counter),
            top_attacking_countries=dict(country_counter.most_common(10)),
        )

        # ── Status summary ────────────────────────────────────────────
        if total_threats > 0 or total_requests > 0:
            logging.info(
                "Imperva: threat/traffic stats (source=%s): "
                "threats=%s requests=%s blocked=%s bw=%.1fGB",
                stats_source, total_threats, total_requests, total_blocked, bw_gb,
            )
        else:
            logging.warning(
                "Imperva: threat/traffic stats returned 0. "
                "This may indicate: "
                "1) No threats in period, "
                "2) Stats endpoint unavailable for this account, "
                "3) Check IMPERVA_STATS_ENDPOINTS configuration. "
                "Support: https://docs.imperva.com/bundle/cloud-application-security/page/More/API.htm"
            )

    except Exception as exc:
        logging.exception("Imperva: threat/traffic stats collection failed: %s", exc)
        imperva_threats_total.set(0)
        imperva_requests_total.set(0)

    # ── Finalize ────────────────────────────────────────────────────
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    imperva_collection_success.set(1)
    imperva_collection_duration_seconds.set(elapsed)
    logging.info("Imperva: collection completed in %.1fs", elapsed)

    store_imperva(metrics)
    store_imperva_sites(site_assets)
