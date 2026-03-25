import os
import logging
from datetime import datetime, timezone, timedelta

import requests
from prometheus_client import Gauge

from es_store import store_entraid

# ── User & Account metrics ──────────────────────────────────────────
entraid_users_total = Gauge(
    "entraid_users_total",
    "Total user accounts in Entra ID",
)
entraid_users_enabled = Gauge(
    "entraid_users_enabled",
    "Enabled user accounts",
)
entraid_users_disabled = Gauge(
    "entraid_users_disabled",
    "Disabled user accounts",
)
entraid_users_guest = Gauge(
    "entraid_users_guest",
    "Guest (external) user accounts",
)
entraid_users_member = Gauge(
    "entraid_users_member",
    "Member (internal) user accounts",
)

# ── Stale / Inactive accounts ───────────────────────────────────────
entraid_users_inactive_30d = Gauge(
    "entraid_users_inactive_30d",
    "Users with no sign-in activity in the last 30 days",
)
entraid_users_inactive_60d = Gauge(
    "entraid_users_inactive_60d",
    "Users with no sign-in activity in the last 60 days",
)
entraid_users_inactive_90d = Gauge(
    "entraid_users_inactive_90d",
    "Users with no sign-in activity in the last 90 days",
)

# ── MFA metrics ─────────────────────────────────────────────────────
entraid_mfa_registered = Gauge(
    "entraid_mfa_registered_users",
    "Users registered for MFA",
)
entraid_mfa_capable = Gauge(
    "entraid_mfa_capable_users",
    "Users capable of performing MFA",
)
entraid_mfa_not_registered = Gauge(
    "entraid_mfa_not_registered_users",
    "Users NOT registered for MFA (security risk)",
)

# ── Privileged Roles ────────────────────────────────────────────────
entraid_global_admins = Gauge(
    "entraid_global_admins_total",
    "Users assigned the Global Administrator role",
)
entraid_privileged_role_assignments = Gauge(
    "entraid_privileged_role_assignments_total",
    "Total privileged directory-role assignments",
)

# ── Risky Users (Identity Protection) ───────────────────────────────
entraid_risky_users_high = Gauge(
    "entraid_risky_users_high",
    "Users with high risk level",
)
entraid_risky_users_medium = Gauge(
    "entraid_risky_users_medium",
    "Users with medium risk level",
)
entraid_risky_users_low = Gauge(
    "entraid_risky_users_low",
    "Users with low risk level",
)

# ── Conditional Access Policies ─────────────────────────────────────
entraid_ca_policies_total = Gauge(
    "entraid_conditional_access_policies_total",
    "Total conditional access policies",
)
entraid_ca_policies_enabled = Gauge(
    "entraid_conditional_access_policies_enabled",
    "Conditional access policies in 'enabled' state",
)
entraid_ca_policies_disabled = Gauge(
    "entraid_conditional_access_policies_disabled",
    "Conditional access policies in 'disabled' state",
)
entraid_ca_policies_report_only = Gauge(
    "entraid_conditional_access_policies_report_only",
    "Conditional access policies in 'report-only' state",
)

# ── Application Registrations ───────────────────────────────────────
entraid_app_registrations_total = Gauge(
    "entraid_app_registrations_total",
    "Total application registrations",
)
entraid_app_credentials_expiring_30d = Gauge(
    "entraid_app_credentials_expiring_30d",
    "App registrations with client secret/cert expiring within 30 days",
)
entraid_app_credentials_expiring_7d = Gauge(
    "entraid_app_credentials_expiring_7d",
    "App registrations with client secret/cert expiring within 7 days",
)
entraid_app_credentials_expired = Gauge(
    "entraid_app_credentials_expired",
    "App registrations with already-expired credentials",
)

# ── Service Principals ──────────────────────────────────────────────
entraid_service_principals_total = Gauge(
    "entraid_service_principals_total",
    "Total service principals",
)
entraid_sp_credentials_expiring_30d = Gauge(
    "entraid_sp_credentials_expiring_30d",
    "Service principals with credentials expiring within 30 days",
)
entraid_sp_credentials_expired = Gauge(
    "entraid_sp_credentials_expired",
    "Service principals with expired credentials",
)

# ── Groups ──────────────────────────────────────────────────────────
entraid_groups_total = Gauge(
    "entraid_groups_total",
    "Total groups in the directory",
)
entraid_groups_without_members = Gauge(
    "entraid_groups_without_members",
    "Groups with zero members (potential cleanup targets)",
)

# ── Collection status ───────────────────────────────────────────────
entraid_collection_success = Gauge(
    "entraid_collection_success",
    "1 when the latest EntraID collection succeeded, 0 otherwise",
)
entraid_collection_duration_seconds = Gauge(
    "entraid_collection_duration_seconds",
    "Duration of the last EntraID collection run in seconds",
)


# ─── Helper: OAuth2 token ───────────────────────────────────────────
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
        r = requests.get(next_url, headers=headers, params=params if page == 0 else None,
                         timeout=timeout)
        r.raise_for_status()
        data = r.json()
        items.extend(data.get("value", []))
        next_url = data.get("@odata.nextLink")
        page += 1

    return items


# ─── Credential expiry scanner ──────────────────────────────────────
def _scan_credentials(items, now):
    """Scan passwordCredentials + keyCredentials for expiry.

    Returns (total, expiring_30d, expiring_7d, expired) counts
    per parent object (app or SP).
    """
    total = len(items)
    expiring_30d = 0
    expiring_7d = 0
    expired = 0

    for item in items:
        creds = item.get("passwordCredentials", []) + item.get("keyCredentials", [])
        if not creds:
            continue

        earliest_remaining = None
        has_expired = False

        for cred in creds:
            end_str = cred.get("endDateTime")
            if not end_str:
                continue
            try:
                end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue

            days_left = (end_dt - now).total_seconds() / 86400

            if days_left < 0:
                has_expired = True
            elif earliest_remaining is None or days_left < earliest_remaining:
                earliest_remaining = days_left

        if has_expired and earliest_remaining is None:
            # All credentials expired
            expired += 1
        if earliest_remaining is not None:
            if earliest_remaining <= 30:
                expiring_30d += 1
            if earliest_remaining <= 7:
                expiring_7d += 1

    return total, expiring_30d, expiring_7d, expired


# ═════════════════════════════════════════════════════════════════════
#  Main collector
# ═════════════════════════════════════════════════════════════════════
def collect_entraid():
    tenant_id = os.getenv("ENTRAID_TENANT_ID", "").strip()
    client_id = os.getenv("ENTRAID_CLIENT_ID", "").strip()
    client_secret = os.getenv("ENTRAID_CLIENT_SECRET", "").strip()

    if not all([tenant_id, client_id, client_secret]):
        logging.warning(
            "EntraID: ENTRAID_TENANT_ID, ENTRAID_CLIENT_ID, and "
            "ENTRAID_CLIENT_SECRET must all be set — skipping"
        )
        return

    timeout = int(os.getenv("ENTRAID_TIMEOUT_SECONDS", "60"))
    start_time = datetime.now(timezone.utc)

    try:
        token = _acquire_token(tenant_id, client_id, client_secret)
    except Exception as exc:
        logging.exception("EntraID: token acquisition failed: %s", exc)
        entraid_collection_success.set(0)
        return

    headers = {"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"}
    graph = "https://graph.microsoft.com/v1.0"
    beta = "https://graph.microsoft.com/beta"
    now = datetime.now(timezone.utc)

    # Accumulators for ES store
    metrics = {}

    # ── 1. Users: total, enabled, disabled, guest, member ────────────
    try:
        logging.info("EntraID: fetching users")
        users = _graph_get_all(
            f"{graph}/users",
            headers,
            params={
                "$select": "id,accountEnabled,userType,signInActivity",
                "$top": "999",
            },
            timeout=timeout,
        )
        total = len(users)
        enabled = sum(1 for u in users if u.get("accountEnabled"))
        disabled = total - enabled
        guests = sum(1 for u in users if u.get("userType") == "Guest")
        members = total - guests

        entraid_users_total.set(total)
        entraid_users_enabled.set(enabled)
        entraid_users_disabled.set(disabled)
        entraid_users_guest.set(guests)
        entraid_users_member.set(members)
        metrics.update(users_total=total, users_enabled=enabled,
                       users_disabled=disabled, users_guest=guests,
                       users_member=members)

        # Inactive analysis
        thresholds = {30: 0, 60: 0, 90: 0}
        for u in users:
            if not u.get("accountEnabled"):
                continue
            sign_in = u.get("signInActivity", {})
            last_sign_in_str = (
                sign_in.get("lastSignInDateTime")
                or sign_in.get("lastNonInteractiveSignInDateTime")
            ) if sign_in else None

            if not last_sign_in_str:
                # Never signed in → count as inactive for all thresholds
                for d in thresholds:
                    thresholds[d] += 1
                continue

            try:
                last_dt = datetime.fromisoformat(
                    last_sign_in_str.replace("Z", "+00:00")
                )
                since = (now - last_dt).days
                for d in thresholds:
                    if since >= d:
                        thresholds[d] += 1
            except (ValueError, TypeError):
                pass

        entraid_users_inactive_30d.set(thresholds[30])
        entraid_users_inactive_60d.set(thresholds[60])
        entraid_users_inactive_90d.set(thresholds[90])
        metrics.update(users_inactive_30d=thresholds[30],
                       users_inactive_60d=thresholds[60],
                       users_inactive_90d=thresholds[90])

        logging.info(
            "EntraID: users total=%s enabled=%s disabled=%s "
            "guest=%s inactive30=%s inactive60=%s inactive90=%s",
            total, enabled, disabled, guests,
            thresholds[30], thresholds[60], thresholds[90],
        )
    except Exception as exc:
        logging.exception("EntraID: users collection failed: %s", exc)

    # ── 2. MFA registration stats ───────────────────────────────────
    try:
        logging.info("EntraID: fetching MFA registration details")
        r = requests.get(
            f"{graph}/reports/authenticationMethods/userRegistrationDetails",
            headers=headers,
            params={"$top": "999"},
            timeout=timeout,
        )
        r.raise_for_status()
        reg_details = r.json().get("value", [])
        # Follow pagination
        next_link = r.json().get("@odata.nextLink")
        while next_link:
            r2 = requests.get(next_link, headers=headers, timeout=timeout)
            r2.raise_for_status()
            reg_details.extend(r2.json().get("value", []))
            next_link = r2.json().get("@odata.nextLink")

        mfa_registered = sum(
            1 for d in reg_details if d.get("isMfaRegistered")
        )
        mfa_capable = sum(
            1 for d in reg_details if d.get("isMfaCapable")
        )
        mfa_not_registered = len(reg_details) - mfa_registered

        entraid_mfa_registered.set(mfa_registered)
        entraid_mfa_capable.set(mfa_capable)
        entraid_mfa_not_registered.set(mfa_not_registered)
        metrics.update(mfa_registered=mfa_registered, mfa_capable=mfa_capable,
                       mfa_not_registered=mfa_not_registered)

        logging.info(
            "EntraID: MFA registered=%s capable=%s not_registered=%s",
            mfa_registered, mfa_capable, mfa_not_registered,
        )
    except Exception as exc:
        logging.exception("EntraID: MFA collection failed: %s", exc)

    # ── 3. Privileged directory roles ────────────────────────────────
    try:
        logging.info("EntraID: fetching directory roles")
        roles = _graph_get_all(
            f"{graph}/directoryRoles",
            headers, params={"$expand": "members"}, timeout=timeout,
        )

        global_admin_count = 0
        total_privileged = 0

        for role in roles:
            member_count = len(role.get("members", []))
            total_privileged += member_count

            display_name = (role.get("displayName") or "").lower()
            if display_name in ("global administrator", "company administrator"):
                global_admin_count = member_count

        entraid_global_admins.set(global_admin_count)
        entraid_privileged_role_assignments.set(total_privileged)
        metrics.update(global_admins=global_admin_count,
                       privileged_role_assignments=total_privileged)

        logging.info(
            "EntraID: roles global_admins=%s total_privileged=%s",
            global_admin_count, total_privileged,
        )
    except Exception as exc:
        logging.exception("EntraID: directory roles collection failed: %s", exc)

    # ── 4. Risky users ──────────────────────────────────────────────
    try:
        logging.info("EntraID: fetching risky users")
        risky_users = _graph_get_all(
            f"{graph}/identityProtection/riskyUsers",
            headers,
            params={"$filter": "riskState eq 'atRisk'", "$top": "999"},
            timeout=timeout,
        )

        risk_high = sum(1 for u in risky_users if u.get("riskLevel") == "high")
        risk_medium = sum(1 for u in risky_users if u.get("riskLevel") == "medium")
        risk_low = sum(1 for u in risky_users if u.get("riskLevel") == "low")

        entraid_risky_users_high.set(risk_high)
        entraid_risky_users_medium.set(risk_medium)
        entraid_risky_users_low.set(risk_low)
        metrics.update(risky_users_high=risk_high, risky_users_medium=risk_medium,
                       risky_users_low=risk_low)

        logging.info(
            "EntraID: risky users high=%s medium=%s low=%s",
            risk_high, risk_medium, risk_low,
        )
    except Exception as exc:
        logging.exception("EntraID: risky users collection failed: %s", exc)

    # ── 5. Conditional Access policies ──────────────────────────────
    try:
        logging.info("EntraID: fetching conditional access policies")
        policies = _graph_get_all(
            f"{graph}/identity/conditionalAccess/policies",
            headers, timeout=timeout,
        )

        ca_total = len(policies)
        ca_enabled = sum(1 for p in policies if p.get("state") == "enabled")
        ca_disabled = sum(1 for p in policies if p.get("state") == "disabled")
        ca_report = sum(1 for p in policies
                        if p.get("state") in ("enabledForReportingButNotEnforced",
                                               "reportOnly"))

        entraid_ca_policies_total.set(ca_total)
        entraid_ca_policies_enabled.set(ca_enabled)
        entraid_ca_policies_disabled.set(ca_disabled)
        entraid_ca_policies_report_only.set(ca_report)
        metrics.update(ca_policies_total=ca_total, ca_policies_enabled=ca_enabled,
                       ca_policies_disabled=ca_disabled,
                       ca_policies_report_only=ca_report)

        logging.info(
            "EntraID: CA policies total=%s enabled=%s disabled=%s report_only=%s",
            ca_total, ca_enabled, ca_disabled, ca_report,
        )
    except Exception as exc:
        logging.exception("EntraID: conditional access collection failed: %s", exc)

    # ── 6. App Registrations + credential expiry ────────────────────
    try:
        logging.info("EntraID: fetching app registrations")
        apps = _graph_get_all(
            f"{graph}/applications",
            headers,
            params={
                "$select": "id,displayName,passwordCredentials,keyCredentials",
                "$top": "999",
            },
            timeout=timeout,
        )
        app_total, app_exp30, app_exp7, app_expired = _scan_credentials(apps, now)

        entraid_app_registrations_total.set(app_total)
        entraid_app_credentials_expiring_30d.set(app_exp30)
        entraid_app_credentials_expiring_7d.set(app_exp7)
        entraid_app_credentials_expired.set(app_expired)
        metrics.update(app_registrations_total=app_total,
                       app_credentials_expiring_30d=app_exp30,
                       app_credentials_expiring_7d=app_exp7,
                       app_credentials_expired=app_expired)

        logging.info(
            "EntraID: apps total=%s exp30=%s exp7=%s expired=%s",
            app_total, app_exp30, app_exp7, app_expired,
        )
    except Exception as exc:
        logging.exception("EntraID: app registrations collection failed: %s", exc)

    # ── 7. Service Principals + credential expiry ───────────────────
    try:
        logging.info("EntraID: fetching service principals")
        sps = _graph_get_all(
            f"{graph}/servicePrincipals",
            headers,
            params={
                "$select": "id,displayName,passwordCredentials,keyCredentials",
                "$top": "999",
            },
            timeout=timeout,
        )
        sp_total, sp_exp30, _, sp_expired = _scan_credentials(sps, now)

        entraid_service_principals_total.set(sp_total)
        entraid_sp_credentials_expiring_30d.set(sp_exp30)
        entraid_sp_credentials_expired.set(sp_expired)
        metrics.update(service_principals_total=sp_total,
                       sp_credentials_expiring_30d=sp_exp30,
                       sp_credentials_expired=sp_expired)

        logging.info(
            "EntraID: service principals total=%s exp30=%s expired=%s",
            sp_total, sp_exp30, sp_expired,
        )
    except Exception as exc:
        logging.exception("EntraID: service principals collection failed: %s", exc)

    # ── 8. Groups ───────────────────────────────────────────────────
    try:
        logging.info("EntraID: fetching groups")

        # Get total count using $count
        r = requests.get(
            f"{graph}/groups/$count",
            headers=headers,
            timeout=timeout,
        )
        if r.status_code == 200:
            try:
                groups_total = int(r.text.strip())
            except ValueError:
                groups_total = 0
        else:
            # Fallback: paginate
            groups = _graph_get_all(
                f"{graph}/groups",
                headers,
                params={"$select": "id", "$top": "999"},
                timeout=timeout,
            )
            groups_total = len(groups)

        entraid_groups_total.set(groups_total)
        metrics["groups_total"] = groups_total

        # Empty groups — sample up to 999 to avoid excessive calls
        groups_sample = _graph_get_all(
            f"{graph}/groups",
            headers,
            params={
                "$select": "id",
                "$top": "999",
                "$filter": "groupTypes/any(g:g eq 'Unified') or mailEnabled eq false",
            },
            timeout=timeout,
            max_pages=5,
        )
        empty_count = 0
        for grp in groups_sample:
            try:
                mr = requests.get(
                    f"{graph}/groups/{grp['id']}/members/$count",
                    headers=headers,
                    timeout=timeout,
                )
                if mr.status_code == 200 and mr.text.strip() == "0":
                    empty_count += 1
            except Exception:
                pass

        entraid_groups_without_members.set(empty_count)
        metrics["groups_without_members"] = empty_count

        logging.info("EntraID: groups total=%s empty=%s", groups_total, empty_count)
    except Exception as exc:
        logging.exception("EntraID: groups collection failed: %s", exc)

    # ── Finalize ────────────────────────────────────────────────────
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    entraid_collection_success.set(1)
    entraid_collection_duration_seconds.set(elapsed)
    logging.info("EntraID: collection completed in %.1fs", elapsed)

    store_entraid(metrics)
