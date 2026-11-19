import os
import logging
from datetime import datetime, timezone
from collections import Counter

import requests
from prometheus_client import Gauge

from es_store import store_intune

# ── Device inventory ────────────────────────────────────────────────
intune_devices_total = Gauge(
    "intune_managed_devices_total",
    "Total managed devices in Intune",
)
intune_devices_compliant = Gauge(
    "intune_devices_compliant",
    "Devices in compliant state",
)
intune_devices_noncompliant = Gauge(
    "intune_devices_noncompliant",
    "Devices in non-compliant state (security risk)",
)
intune_devices_in_grace_period = Gauge(
    "intune_devices_in_grace_period",
    "Devices in compliance grace period",
)
intune_devices_not_evaluated = Gauge(
    "intune_devices_not_evaluated",
    "Devices not yet evaluated for compliance",
)

# ── Device ownership ────────────────────────────────────────────────
intune_devices_corporate = Gauge(
    "intune_devices_corporate",
    "Corporate-owned devices",
)
intune_devices_personal = Gauge(
    "intune_devices_personal",
    "Personal (BYOD) devices",
)

# ── OS distribution ─────────────────────────────────────────────────
intune_devices_by_os = Gauge(
    "intune_devices_by_os",
    "Managed devices by operating system",
    ["os"],
)

# ── Encryption posture ──────────────────────────────────────────────
intune_devices_encrypted = Gauge(
    "intune_devices_encrypted",
    "Devices with disk encryption enabled",
)
intune_devices_not_encrypted = Gauge(
    "intune_devices_not_encrypted",
    "Devices WITHOUT disk encryption (security risk)",
)

# ── Security posture signals ────────────────────────────────────────
intune_devices_jailbroken = Gauge(
    "intune_devices_jailbroken",
    "Jailbroken or rooted devices detected",
)
intune_devices_threat_high = Gauge(
    "intune_devices_threat_level_high",
    "Devices with high threat level from MDE integration",
)
intune_devices_threat_medium = Gauge(
    "intune_devices_threat_level_medium",
    "Devices with medium threat level",
)
intune_devices_threat_low = Gauge(
    "intune_devices_threat_level_low",
    "Devices with low threat level",
)

# ── Stale devices ───────────────────────────────────────────────────
intune_devices_inactive_30d = Gauge(
    "intune_devices_inactive_30d",
    "Devices with no check-in in the last 30 days",
)
intune_devices_inactive_60d = Gauge(
    "intune_devices_inactive_60d",
    "Devices with no check-in in the last 60 days",
)
intune_devices_inactive_90d = Gauge(
    "intune_devices_inactive_90d",
    "Devices with no check-in in the last 90 days",
)

# ── OS version currency ─────────────────────────────────────────────
intune_devices_os_outdated = Gauge(
    "intune_devices_os_outdated",
    "Devices running an outdated OS version (not on latest major)",
)

# ── Compliance policies ─────────────────────────────────────────────
intune_compliance_policies_total = Gauge(
    "intune_compliance_policies_total",
    "Total device compliance policies defined",
)
intune_compliance_policies_assigned = Gauge(
    "intune_compliance_policies_assigned",
    "Compliance policies with at least one assignment",
)

# ── Configuration profiles ──────────────────────────────────────────
intune_config_profiles_total = Gauge(
    "intune_config_profiles_total",
    "Total device configuration profiles",
)
intune_config_profiles_error = Gauge(
    "intune_config_profiles_with_errors",
    "Configuration profiles that have devices reporting errors",
)

# ── Detected applications ───────────────────────────────────────────
intune_detected_apps_total = Gauge(
    "intune_detected_apps_total",
    "Total distinct applications detected across managed devices",
)

# ── Autopilot ────────────────────────────────────────────────────────
intune_autopilot_devices_total = Gauge(
    "intune_autopilot_devices_total",
    "Total Windows Autopilot registered devices",
)

# ── Collection health ───────────────────────────────────────────────
intune_collection_success = Gauge(
    "intune_collection_success",
    "1 when the latest Intune collection succeeded, 0 otherwise",
)
intune_collection_duration_seconds = Gauge(
    "intune_collection_duration_seconds",
    "Duration of the last Intune collection run in seconds",
)


# ─── Helper: OAuth2 token (same pattern as EntraID) ─────────────────
def _acquire_token(tenant_id, client_id, client_secret):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }
    r = requests.post(url, data=data, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


# ─── Helper: paginated Graph API call ───────────────────────────────
def _graph_get_all(url, headers, params=None, timeout=30, max_pages=200):
    """Follow @odata.nextLink to retrieve all pages."""
    items = []
    page = 0
    next_url = url

    while next_url and page < max_pages:
        r = requests.get(next_url, headers=headers,
                         params=params if page == 0 else None,
                         timeout=timeout)
        r.raise_for_status()
        data = r.json()
        items.extend(data.get("value", []))
        next_url = data.get("@odata.nextLink")
        page += 1

    return items


# ─── Helper: parse ISO datetime safely ──────────────────────────────
def _parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


# ═════════════════════════════════════════════════════════════════════
#  Main collector
# ═════════════════════════════════════════════════════════════════════
def collect_intune():
    tenant_id = os.getenv("INTUNE_TENANT_ID", "").strip()
    client_id = os.getenv("INTUNE_CLIENT_ID", "").strip()
    client_secret = os.getenv("INTUNE_CLIENT_SECRET", "").strip()

    if not all([tenant_id, client_id, client_secret]):
        logging.warning(
            "Intune: INTUNE_TENANT_ID, INTUNE_CLIENT_ID, and "
            "INTUNE_CLIENT_SECRET must all be set — skipping"
        )
        return

    timeout = int(os.getenv("INTUNE_TIMEOUT_SECONDS", "60"))
    start_time = datetime.now(timezone.utc)

    try:
        token = _acquire_token(tenant_id, client_id, client_secret)
    except Exception as exc:
        logging.exception("Intune: token acquisition failed: %s", exc)
        intune_collection_success.set(0)
        return

    headers = {"Authorization": f"Bearer {token}"}
    graph = "https://graph.microsoft.com/v1.0"
    beta = "https://graph.microsoft.com/beta"
    now = datetime.now(timezone.utc)

    metrics = {}

    # ── 1. Managed devices ──────────────────────────────────────────
    try:
        logging.info("Intune: fetching managed devices")
        devices = _graph_get_all(
            f"{graph}/deviceManagement/managedDevices",
            headers,
            params={
                "$select": (
                    "id,deviceName,complianceState,managedDeviceOwnerType,"
                    "operatingSystem,osVersion,isEncrypted,"
                    "jailBroken,lastSyncDateTime,"
                    "deviceThreatLevel,managementAgent"
                ),
                "$top": "999",
            },
            timeout=timeout,
        )

        total = len(devices)

        # Compliance breakdown
        compliance = Counter(d.get("complianceState", "unknown") for d in devices)
        compliant = compliance.get("compliant", 0)
        noncompliant = compliance.get("noncompliant", 0)
        in_grace = compliance.get("inGracePeriod", 0)
        not_evaluated = compliance.get("notEvaluated", 0) + compliance.get("unknown", 0)

        intune_devices_total.set(total)
        intune_devices_compliant.set(compliant)
        intune_devices_noncompliant.set(noncompliant)
        intune_devices_in_grace_period.set(in_grace)
        intune_devices_not_evaluated.set(not_evaluated)

        # Ownership
        ownership = Counter(d.get("managedDeviceOwnerType", "unknown") for d in devices)
        corporate = ownership.get("company", 0)
        personal = ownership.get("personal", 0)
        intune_devices_corporate.set(corporate)
        intune_devices_personal.set(personal)

        # OS distribution
        os_counts = Counter()
        for d in devices:
            raw_os = (d.get("operatingSystem") or "Unknown").strip()
            os_counts[raw_os] += 1

        for os_name, count in os_counts.items():
            intune_devices_by_os.labels(os=os_name).set(count)

        # Encryption
        encrypted = sum(1 for d in devices if d.get("isEncrypted"))
        not_encrypted = total - encrypted
        intune_devices_encrypted.set(encrypted)
        intune_devices_not_encrypted.set(not_encrypted)

        # Jailbroken / rooted
        jailbroken = sum(
            1 for d in devices
            if str(d.get("jailBroken", "")).lower() in ("true", "yes")
        )
        intune_devices_jailbroken.set(jailbroken)

        # Device threat level (from MDE integration)
        threat = Counter(d.get("deviceThreatLevel", "unknown") for d in devices)
        threat_high = threat.get("high", 0) + threat.get("critical", 0)
        threat_medium = threat.get("medium", 0)
        threat_low = threat.get("low", 0)
        intune_devices_threat_high.set(threat_high)
        intune_devices_threat_medium.set(threat_medium)
        intune_devices_threat_low.set(threat_low)

        # Inactive / stale devices
        thresholds = {30: 0, 60: 0, 90: 0}
        for d in devices:
            last_sync = _parse_dt(d.get("lastSyncDateTime"))
            if not last_sync:
                for t in thresholds:
                    thresholds[t] += 1
                continue
            days_since = (now - last_sync).days
            for t in thresholds:
                if days_since >= t:
                    thresholds[t] += 1

        intune_devices_inactive_30d.set(thresholds[30])
        intune_devices_inactive_60d.set(thresholds[60])
        intune_devices_inactive_90d.set(thresholds[90])

        # OS currency — flag devices not on latest known major version per OS
        os_latest = {}
        for d in devices:
            os_name = (d.get("operatingSystem") or "").strip()
            ver = (d.get("osVersion") or "").strip()
            if not os_name or not ver:
                continue
            cur_best = os_latest.get(os_name, "")
            if ver > cur_best:
                os_latest[os_name] = ver

        outdated = 0
        for d in devices:
            os_name = (d.get("operatingSystem") or "").strip()
            ver = (d.get("osVersion") or "").strip()
            if not os_name or not ver:
                continue
            best = os_latest.get(os_name, "")
            if best and ver < best:
                outdated += 1
        intune_devices_os_outdated.set(outdated)

        metrics.update(
            devices_total=total,
            devices_compliant=compliant,
            devices_noncompliant=noncompliant,
            devices_in_grace_period=in_grace,
            devices_not_evaluated=not_evaluated,
            devices_corporate=corporate,
            devices_personal=personal,
            devices_encrypted=encrypted,
            devices_not_encrypted=not_encrypted,
            devices_jailbroken=jailbroken,
            devices_threat_high=threat_high,
            devices_threat_medium=threat_medium,
            devices_threat_low=threat_low,
            devices_inactive_30d=thresholds[30],
            devices_inactive_60d=thresholds[60],
            devices_inactive_90d=thresholds[90],
            devices_os_outdated=outdated,
            os_distribution=dict(os_counts),
        )

        logging.info(
            "Intune: devices total=%s compliant=%s noncompliant=%s "
            "encrypted=%s jailbroken=%s inactive30=%s outdated_os=%s",
            total, compliant, noncompliant, encrypted,
            jailbroken, thresholds[30], outdated,
        )
    except Exception as exc:
        logging.exception("Intune: managed devices collection failed: %s", exc)

    # ── 2. Compliance policies ──────────────────────────────────────
    try:
        logging.info("Intune: fetching compliance policies")
        policies = _graph_get_all(
            f"{graph}/deviceManagement/deviceCompliancePolicies",
            headers,
            params={"$expand": "assignments", "$top": "999"},
            timeout=timeout,
        )

        pol_total = len(policies)
        pol_assigned = sum(
            1 for p in policies if p.get("assignments")
        )

        intune_compliance_policies_total.set(pol_total)
        intune_compliance_policies_assigned.set(pol_assigned)
        metrics.update(
            compliance_policies_total=pol_total,
            compliance_policies_assigned=pol_assigned,
        )

        logging.info(
            "Intune: compliance policies total=%s assigned=%s",
            pol_total, pol_assigned,
        )
    except Exception as exc:
        logging.exception("Intune: compliance policies collection failed: %s", exc)

    # ── 3. Configuration profiles + error status ────────────────────
    try:
        logging.info("Intune: fetching configuration profiles")
        profiles = _graph_get_all(
            f"{graph}/deviceManagement/deviceConfigurations",
            headers,
            params={"$top": "999"},
            timeout=timeout,
        )

        cfg_total = len(profiles)
        intune_config_profiles_total.set(cfg_total)

        # Check per-profile device status summary for errors
        cfg_with_errors = 0
        for profile in profiles:
            pid = profile.get("id")
            if not pid:
                continue
            try:
                r = requests.get(
                    f"{graph}/deviceManagement/deviceConfigurations/{pid}/deviceStatusOverview",
                    headers=headers,
                    timeout=timeout,
                )
                if r.status_code == 200:
                    overview = r.json()
                    if overview.get("errorCount", 0) > 0 or overview.get("failedCount", 0) > 0:
                        cfg_with_errors += 1
            except Exception:
                pass

        intune_config_profiles_error.set(cfg_with_errors)
        metrics.update(
            config_profiles_total=cfg_total,
            config_profiles_with_errors=cfg_with_errors,
        )

        logging.info(
            "Intune: config profiles total=%s with_errors=%s",
            cfg_total, cfg_with_errors,
        )
    except Exception as exc:
        logging.exception("Intune: config profiles collection failed: %s", exc)

    # ── 4. Detected applications ────────────────────────────────────
    try:
        logging.info("Intune: fetching detected apps count")
        r = requests.get(
            f"{graph}/deviceManagement/detectedApps",
            headers=headers,
            params={"$top": "1"},
            timeout=timeout,
        )
        r.raise_for_status()
        data = r.json()
        # Use @odata.count if present, else paginate
        detected_count = data.get("@odata.count")
        if detected_count is None:
            # Quick count from first page size hint
            apps_page = data.get("value", [])
            if data.get("@odata.nextLink"):
                # Has more — do a proper count
                all_apps = _graph_get_all(
                    f"{graph}/deviceManagement/detectedApps",
                    headers,
                    params={"$select": "id", "$top": "999"},
                    timeout=timeout,
                    max_pages=20,
                )
                detected_count = len(all_apps)
            else:
                detected_count = len(apps_page)

        intune_detected_apps_total.set(detected_count)
        metrics["detected_apps_total"] = detected_count

        logging.info("Intune: detected apps total=%s", detected_count)
    except Exception as exc:
        logging.exception("Intune: detected apps collection failed: %s", exc)

    # ── 5. Windows Autopilot devices ────────────────────────────────
    try:
        logging.info("Intune: fetching Autopilot devices")
        autopilot = _graph_get_all(
            f"{graph}/deviceManagement/windowsAutopilotDeviceIdentities",
            headers,
            params={"$select": "id", "$top": "999"},
            timeout=timeout,
            max_pages=20,
        )

        autopilot_total = len(autopilot)
        intune_autopilot_devices_total.set(autopilot_total)
        metrics["autopilot_devices_total"] = autopilot_total

        logging.info("Intune: Autopilot devices total=%s", autopilot_total)
    except Exception as exc:
        logging.exception("Intune: Autopilot collection failed: %s", exc)

    # ── Finalize ────────────────────────────────────────────────────
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    intune_collection_success.set(1)
    intune_collection_duration_seconds.set(elapsed)
    logging.info("Intune: collection completed in %.1fs", elapsed)

    store_intune(metrics)
