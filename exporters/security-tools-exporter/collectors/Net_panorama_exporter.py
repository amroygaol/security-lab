import os
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from collections import Counter
from urllib.parse import quote

import requests
from prometheus_client import Gauge

from es_store import store_panorama

# Suppress SSL warnings for on-prem Panorama with self-signed certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Managed firewalls ───────────────────────────────────────────────
panorama_firewalls_total = Gauge(
    "panorama_managed_firewalls_total",
    "Total firewalls managed by Panorama",
)
panorama_firewalls_connected = Gauge(
    "panorama_firewalls_connected",
    "Firewalls currently connected to Panorama",
)
panorama_firewalls_disconnected = Gauge(
    "panorama_firewalls_disconnected",
    "Firewalls currently disconnected from Panorama",
)

# ── Firewall HA status ──────────────────────────────────────────────
panorama_firewalls_ha_active = Gauge(
    "panorama_firewalls_ha_active",
    "Firewalls in HA active state",
)
panorama_firewalls_ha_passive = Gauge(
    "panorama_firewalls_ha_passive",
    "Firewalls in HA passive state",
)
panorama_firewalls_ha_none = Gauge(
    "panorama_firewalls_ha_none",
    "Firewalls not in HA pair (standalone)",
)

# ── Software version currency ───────────────────────────────────────
panorama_firewalls_by_version = Gauge(
    "panorama_firewalls_by_panos_version",
    "Managed firewalls by PAN-OS version",
    ["version"],
)
panorama_firewalls_outdated = Gauge(
    "panorama_firewalls_panos_outdated",
    "Firewalls not running the latest PAN-OS version seen in the fleet",
)

# ── Model distribution ──────────────────────────────────────────────
panorama_firewalls_by_model = Gauge(
    "panorama_firewalls_by_model",
    "Managed firewalls by hardware/VM model",
    ["model"],
)

# ── License & subscription ──────────────────────────────────────────
panorama_licenses_expired = Gauge(
    "panorama_licenses_expired",
    "Firewalls with at least one expired license/subscription",
)
panorama_licenses_expiring_30d = Gauge(
    "panorama_licenses_expiring_30d",
    "Firewalls with a license expiring within 30 days",
)
panorama_licenses_expiring_90d = Gauge(
    "panorama_licenses_expiring_90d",
    "Firewalls with a license expiring within 90 days",
)

# ── Threat / Content version ────────────────────────────────────────
panorama_firewalls_threat_outdated = Gauge(
    "panorama_firewalls_threat_version_outdated",
    "Firewalls NOT running the latest threat content version",
)
panorama_firewalls_antivirus_outdated = Gauge(
    "panorama_firewalls_antivirus_version_outdated",
    "Firewalls NOT running the latest antivirus content version",
)
panorama_firewalls_wildfire_outdated = Gauge(
    "panorama_firewalls_wildfire_version_outdated",
    "Firewalls NOT running the latest WildFire content version",
)

# ── GlobalProtect (VPN) ─────────────────────────────────────────────
panorama_gp_users_total = Gauge(
    "panorama_globalprotect_users_total",
    "Total GlobalProtect VPN users currently connected (summed across gateways)",
)

# ── Security policy rules ───────────────────────────────────────────
panorama_security_rules_total = Gauge(
    "panorama_security_rules_total",
    "Total security policy rules across all device groups",
)
panorama_security_rules_disabled = Gauge(
    "panorama_security_rules_disabled",
    "Disabled security policy rules (policy hygiene check)",
)
panorama_security_rules_any_any = Gauge(
    "panorama_security_rules_any_any",
    "Security rules with source=any AND destination=any (overly permissive)",
)
panorama_security_rules_no_logging = Gauge(
    "panorama_security_rules_no_logging",
    "Security rules with logging disabled",
)

# ── NAT rules ───────────────────────────────────────────────────────
panorama_nat_rules_total = Gauge(
    "panorama_nat_rules_total",
    "Total NAT rules across all device groups",
)

# ── Device groups & templates ────────────────────────────────────────
panorama_device_groups_total = Gauge(
    "panorama_device_groups_total",
    "Total device groups configured in Panorama",
)
panorama_templates_total = Gauge(
    "panorama_templates_total",
    "Total templates configured in Panorama",
)
panorama_template_stacks_total = Gauge(
    "panorama_template_stacks_total",
    "Total template stacks configured in Panorama",
)

# ── Pending commits ─────────────────────────────────────────────────
panorama_pending_changes = Gauge(
    "panorama_pending_changes",
    "1 if there are uncommitted configuration changes on Panorama, 0 otherwise",
)

# ── Log storage ─────────────────────────────────────────────────────
panorama_log_disk_usage_percent = Gauge(
    "panorama_log_disk_usage_percent",
    "Panorama log storage disk usage percentage",
)

# ── System health ───────────────────────────────────────────────────
panorama_system_uptime_days = Gauge(
    "panorama_system_uptime_days",
    "Panorama system uptime in days",
)

# ── Collection status ───────────────────────────────────────────────
panorama_collection_success = Gauge(
    "panorama_collection_success",
    "1 when the latest Panorama collection succeeded, 0 otherwise",
)
panorama_collection_duration_seconds = Gauge(
    "panorama_collection_duration_seconds",
    "Duration of the last Panorama collection run in seconds",
)


# ─── Panorama XML API helper ────────────────────────────────────────
class PanoramaAPI:
    """Thin wrapper around the Panorama XML API."""

    def __init__(self, host, api_key, timeout=30, verify_ssl=False):
        self.base_url = f"https://{host}/api"
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _request(self, params):
        params["key"] = self.api_key
        r = requests.get(
            self.base_url, params=params,
            timeout=self.timeout, verify=self.verify_ssl,
        )
        r.raise_for_status()
        return ET.fromstring(r.text)

    def op(self, cmd):
        """Execute an operational command."""
        return self._request({"type": "op", "cmd": cmd})

    def config(self, action="get", xpath="/"):
        """Get or show configuration at xpath."""
        return self._request({"type": "config", "action": action, "xpath": xpath})


# ─── Helpers ─────────────────────────────────────────────────────────
def _text(elem, path, default=""):
    """Safe text extraction from XML element."""
    if elem is None:
        return default
    child = elem.find(path)
    return child.text.strip() if child is not None and child.text else default


def _parse_uptime(uptime_str):
    """Parse '123 days, 4:05:06' → float days."""
    if not uptime_str:
        return 0.0
    try:
        parts = uptime_str.lower()
        days = 0
        if "day" in parts:
            day_part, rest = parts.split("day")
            days = int(day_part.strip().rstrip("s"))
        return float(days)
    except (ValueError, IndexError):
        return 0.0


def _parse_license_date(date_str):
    """Parse license expiry like 'January 01, 2027' or '2027/01/01'."""
    if not date_str:
        return None
    for fmt in ("%B %d, %Y", "%Y/%m/%d", "%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(date_str.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ═════════════════════════════════════════════════════════════════════
#  Main collector
# ═════════════════════════════════════════════════════════════════════
def collect_panorama():
    host = os.getenv("PANORAMA_HOST", "").strip()
    api_key = os.getenv("PANORAMA_API_KEY", "").strip()

    if not host or not api_key:
        logging.warning(
            "Panorama: PANORAMA_HOST and PANORAMA_API_KEY must be set — skipping"
        )
        return

    timeout = int(os.getenv("PANORAMA_TIMEOUT_SECONDS", "30"))
    verify_ssl = os.getenv("PANORAMA_VERIFY_SSL", "false").lower() == "true"
    start_time = datetime.now(timezone.utc)

    api = PanoramaAPI(host, api_key, timeout=timeout, verify_ssl=verify_ssl)
    now = datetime.now(timezone.utc)
    metrics = {}

    # ── 1. Managed firewalls (devices) ──────────────────────────────
    try:
        logging.info("Panorama: fetching managed devices")
        root = api.op("<show><devices><all></all></devices></show>")
        devices_elem = root.find(".//devices")
        entries = devices_elem.findall("entry") if devices_elem is not None else []

        total_fw = len(entries)
        connected = 0
        disconnected = 0
        ha_active = 0
        ha_passive = 0
        ha_none = 0
        version_counter = Counter()
        model_counter = Counter()
        threat_versions = []
        av_versions = []
        wf_versions = []

        for entry in entries:
            # Connection status
            conn = _text(entry, "connected").lower()
            if conn == "yes":
                connected += 1
            else:
                disconnected += 1

            # HA status
            ha_state = _text(entry, "ha/state").lower()
            if ha_state in ("active", "active-primary"):
                ha_active += 1
            elif ha_state in ("passive", "active-secondary"):
                ha_passive += 1
            else:
                ha_none += 1

            # PAN-OS version
            sw_ver = _text(entry, "sw-version", "unknown")
            version_counter[sw_ver] += 1

            # Model
            model = _text(entry, "model", "unknown")
            model_counter[model] += 1

            # Content versions for freshness comparison
            threat_ver = _text(entry, "threat-version")
            av_ver = _text(entry, "av-version")
            wf_ver = _text(entry, "wildfire-version")
            if threat_ver:
                threat_versions.append(threat_ver)
            if av_ver:
                av_versions.append(av_ver)
            if wf_ver:
                wf_versions.append(wf_ver)

        panorama_firewalls_total.set(total_fw)
        panorama_firewalls_connected.set(connected)
        panorama_firewalls_disconnected.set(disconnected)
        panorama_firewalls_ha_active.set(ha_active)
        panorama_firewalls_ha_passive.set(ha_passive)
        panorama_firewalls_ha_none.set(ha_none)

        for ver, count in version_counter.items():
            panorama_firewalls_by_version.labels(version=ver).set(count)

        for model, count in model_counter.items():
            panorama_firewalls_by_model.labels(model=model).set(count)

        # Outdated = not on the highest version seen in fleet
        latest_panos = max(version_counter.keys()) if version_counter else ""
        outdated_fw = sum(c for v, c in version_counter.items() if v < latest_panos) if latest_panos else 0
        panorama_firewalls_outdated.set(outdated_fw)

        # Content freshness: compare each FW to the "best" in fleet
        def _count_outdated(versions):
            if not versions:
                return 0
            best = max(versions)
            return sum(1 for v in versions if v < best)

        threat_outdated = _count_outdated(threat_versions)
        av_outdated = _count_outdated(av_versions)
        wf_outdated = _count_outdated(wf_versions)
        panorama_firewalls_threat_outdated.set(threat_outdated)
        panorama_firewalls_antivirus_outdated.set(av_outdated)
        panorama_firewalls_wildfire_outdated.set(wf_outdated)

        metrics.update(
            firewalls_total=total_fw,
            firewalls_connected=connected,
            firewalls_disconnected=disconnected,
            ha_active=ha_active,
            ha_passive=ha_passive,
            ha_standalone=ha_none,
            panos_outdated=outdated_fw,
            threat_outdated=threat_outdated,
            av_outdated=av_outdated,
            wildfire_outdated=wf_outdated,
            panos_version_distribution=dict(version_counter),
            model_distribution=dict(model_counter),
        )

        logging.info(
            "Panorama: devices total=%s connected=%s disconnected=%s "
            "outdated_panos=%s threat_outdated=%s",
            total_fw, connected, disconnected, outdated_fw, threat_outdated,
        )
    except Exception as exc:
        logging.exception("Panorama: managed devices collection failed: %s", exc)

    # ── 2. License status per firewall ──────────────────────────────
    try:
        logging.info("Panorama: checking license status")
        # Get license info from connected devices
        root = api.op("<show><devices><all></all></devices></show>")
        devices_elem = root.find(".//devices")
        entries = devices_elem.findall("entry") if devices_elem is not None else []

        expired_count = 0
        expiring_30d = 0
        expiring_90d = 0

        for entry in entries:
            serial = _text(entry, "serial")
            if not serial or _text(entry, "connected").lower() != "yes":
                continue

            try:
                lic_root = api.op(
                    f"<show><system><license><device>{serial}</device></license></system></show>"
                )
                licenses = lic_root.findall(".//entry")
                if not licenses:
                    # Try alternative path
                    licenses = lic_root.findall(".//licenses/entry")

                fw_has_expired = False
                fw_has_expiring_30 = False
                fw_has_expiring_90 = False

                for lic in licenses:
                    expires = _text(lic, "expires")
                    if not expires or expires.lower() in ("never",):
                        continue
                    exp_dt = _parse_license_date(expires)
                    if not exp_dt:
                        continue
                    days_left = (exp_dt - now).days
                    if days_left < 0:
                        fw_has_expired = True
                    elif days_left <= 30:
                        fw_has_expiring_30 = True
                    elif days_left <= 90:
                        fw_has_expiring_90 = True

                if fw_has_expired:
                    expired_count += 1
                if fw_has_expiring_30:
                    expiring_30d += 1
                if fw_has_expiring_90:
                    expiring_90d += 1

            except Exception:
                logging.debug("Panorama: could not fetch license for %s", serial)

        panorama_licenses_expired.set(expired_count)
        panorama_licenses_expiring_30d.set(expiring_30d)
        panorama_licenses_expiring_90d.set(expiring_90d)
        metrics.update(
            licenses_expired=expired_count,
            licenses_expiring_30d=expiring_30d,
            licenses_expiring_90d=expiring_90d,
        )

        logging.info(
            "Panorama: licenses expired=%s exp30=%s exp90=%s",
            expired_count, expiring_30d, expiring_90d,
        )
    except Exception as exc:
        logging.exception("Panorama: license collection failed: %s", exc)

    # ── 3. GlobalProtect users ──────────────────────────────────────
    try:
        logging.info("Panorama: fetching GlobalProtect user count")
        root = api.op(
            "<show><global-protect-gateway><current-user></current-user></global-protect-gateway></show>"
        )
        gp_entries = root.findall(".//entry")
        gp_total = len(gp_entries)
        panorama_gp_users_total.set(gp_total)
        metrics["globalprotect_users"] = gp_total
        logging.info("Panorama: GlobalProtect users=%s", gp_total)
    except Exception as exc:
        # GP may not be configured — log as debug
        logging.debug("Panorama: GlobalProtect query failed (may not be configured): %s", exc)
        panorama_gp_users_total.set(0)

    # ── 4. Device groups ────────────────────────────────────────────
    try:
        logging.info("Panorama: fetching device groups")
        root = api.config(
            xpath="/config/devices/entry[@name='localhost.localdomain']/device-group"
        )
        dg_entries = root.findall(".//device-group/entry")
        dg_total = len(dg_entries)
        panorama_device_groups_total.set(dg_total)
        metrics["device_groups_total"] = dg_total

        # Count security rules across all device groups
        sec_rules_total = 0
        sec_rules_disabled = 0
        sec_rules_any_any = 0
        sec_rules_no_log = 0
        nat_rules_total = 0

        for dg in dg_entries:
            dg_name = dg.get("name", "")

            # Security pre/post rules
            for rulebase_tag in ("pre-rulebase", "post-rulebase"):
                rules = dg.findall(f"{rulebase_tag}/security/rules/entry")
                if not rules:
                    continue

                for rule in rules:
                    sec_rules_total += 1

                    # Disabled check
                    disabled = _text(rule, "disabled").lower()
                    if disabled == "yes":
                        sec_rules_disabled += 1

                    # Any-any check (overly permissive)
                    src_members = rule.findall("source/member")
                    dst_members = rule.findall("destination/member")
                    src_any = any(
                        m.text and m.text.strip().lower() == "any"
                        for m in src_members
                    )
                    dst_any = any(
                        m.text and m.text.strip().lower() == "any"
                        for m in dst_members
                    )
                    if src_any and dst_any:
                        sec_rules_any_any += 1

                    # No logging check
                    log_end = _text(rule, "log-end").lower()
                    log_start = _text(rule, "log-start").lower()
                    if log_end != "yes" and log_start != "yes":
                        sec_rules_no_log += 1

            # NAT rules
            for rulebase_tag in ("pre-rulebase", "post-rulebase"):
                nat_entries = dg.findall(f"{rulebase_tag}/nat/rules/entry")
                nat_rules_total += len(nat_entries)

        panorama_security_rules_total.set(sec_rules_total)
        panorama_security_rules_disabled.set(sec_rules_disabled)
        panorama_security_rules_any_any.set(sec_rules_any_any)
        panorama_security_rules_no_logging.set(sec_rules_no_log)
        panorama_nat_rules_total.set(nat_rules_total)

        metrics.update(
            security_rules_total=sec_rules_total,
            security_rules_disabled=sec_rules_disabled,
            security_rules_any_any=sec_rules_any_any,
            security_rules_no_logging=sec_rules_no_log,
            nat_rules_total=nat_rules_total,
        )

        logging.info(
            "Panorama: device_groups=%s sec_rules=%s disabled=%s any_any=%s no_log=%s nat=%s",
            dg_total, sec_rules_total, sec_rules_disabled,
            sec_rules_any_any, sec_rules_no_log, nat_rules_total,
        )
    except Exception as exc:
        logging.exception("Panorama: device groups / rules collection failed: %s", exc)

    # ── 5. Templates & template stacks ──────────────────────────────
    try:
        logging.info("Panorama: fetching templates")
        root = api.config(
            xpath="/config/devices/entry[@name='localhost.localdomain']/template"
        )
        tmpl_entries = root.findall(".//template/entry")
        tmpl_total = len(tmpl_entries)
        panorama_templates_total.set(tmpl_total)
        metrics["templates_total"] = tmpl_total

        stack_root = api.config(
            xpath="/config/devices/entry[@name='localhost.localdomain']/template-stack"
        )
        stack_entries = stack_root.findall(".//template-stack/entry")
        stack_total = len(stack_entries)
        panorama_template_stacks_total.set(stack_total)
        metrics["template_stacks_total"] = stack_total

        logging.info("Panorama: templates=%s stacks=%s", tmpl_total, stack_total)
    except Exception as exc:
        logging.exception("Panorama: templates collection failed: %s", exc)

    # ── 6. Pending config changes ───────────────────────────────────
    try:
        root = api.op("<check><pending-changes></pending-changes></check>")
        result_text = _text(root, "result", "no").strip().lower()
        has_pending = 1 if result_text == "yes" else 0
        panorama_pending_changes.set(has_pending)
        metrics["pending_changes"] = has_pending
    except Exception as exc:
        logging.debug("Panorama: pending changes check failed: %s", exc)

    # ── 7. System info (uptime + log disk) ──────────────────────────
    try:
        logging.info("Panorama: fetching system info")
        root = api.op("<show><system><info></info></system></show>")
        system = root.find(".//system")

        uptime_str = _text(system, "uptime")
        uptime_days = _parse_uptime(uptime_str)
        panorama_system_uptime_days.set(uptime_days)
        metrics["system_uptime_days"] = uptime_days

        logging.info("Panorama: uptime=%.1f days", uptime_days)
    except Exception as exc:
        logging.exception("Panorama: system info failed: %s", exc)

    try:
        root = api.op("<show><system><disk-space></disk-space></show>")
        # Parse df-like output for /dev/sda* or log partition
        result_text = _text(root, "result", "")
        disk_pct = 0.0
        for line in result_text.splitlines():
            # Look for logging partition (typically /opt/panlogs or largest usage)
            if "/opt/panlogs" in line or "/dev/sda8" in line:
                parts = line.split()
                for part in parts:
                    if part.endswith("%"):
                        try:
                            disk_pct = float(part.rstrip("%"))
                        except ValueError:
                            pass
                        break
                break
        panorama_log_disk_usage_percent.set(disk_pct)
        metrics["log_disk_usage_percent"] = disk_pct
    except Exception as exc:
        logging.debug("Panorama: disk space check failed: %s", exc)

    # ── Finalize ────────────────────────────────────────────────────
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    panorama_collection_success.set(1)
    panorama_collection_duration_seconds.set(elapsed)
    logging.info("Panorama: collection completed in %.1fs", elapsed)

    store_panorama(metrics)
