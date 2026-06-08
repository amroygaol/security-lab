"""Builds a compact live-data context snapshot injected into the Copilot system prompt.

All data is loaded fresh on every LLM call so answers reflect the current portal state.
Each source is loaded independently — failures are silently suppressed so a single
unavailable backend (e.g. Elasticsearch down) never breaks the whole Copilot.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ...core.security import sanitize_for_llm
from ...data.portal_store import load_assets, load_budget_policies, load_budgets
from ...data.budget_analytics_store import load_budget_analytics
from ...data.pentest_store import load_pentest_tickets
from ...data.soc_ticket_store import load_soc_tickets
from ...data.public_exposure_store import load_public_exposures
from ...data.report_store import list_reports, load_report

_MAX_ASSETS = 50
_MAX_BUDGETS = 50
_MAX_EXPOSURES = 30
_MAX_PENTEST_TICKETS = 40
_MAX_SOC_TICKETS = 40
_MAX_REPORT_CHARS = 3_000  # first N chars of the most recent report


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def _fmt_assets(assets: list[dict[str, Any]]) -> str:
    if not assets:
        return "  (no assets recorded)"
    lines: list[str] = []
    for a in assets[:_MAX_ASSETS]:
        cost = a.get("annual_cost")
        cost_str = f"{cost:,.0f}" if isinstance(cost, (int, float)) else str(cost)
        lines.append(
            f"  • [{a.get('asset_id', '?')}] {a.get('asset_name', '?')}"
            f" | type={a.get('asset_type', '?')}"
            f" | env={a.get('environment', '?')}"
            f" | criticality={a.get('criticality', '?')}"
            f" | vendor={a.get('vendor', '?')}"
            f" | annual_cost={cost_str} {a.get('currency', 'USD')}"
            f" | renewal={a.get('renewal_date', '?')}"
            f" | support={a.get('support_status', '?')}"
            f" | seats={a.get('seats_used', '?')}/{a.get('license_seats', '?')}"
        )
        notes = str(a.get("notes", "")).strip()
        if notes:
            lines.append(f"    notes: {notes}")
    if len(assets) > _MAX_ASSETS:
        lines.append(f"  ... and {len(assets) - _MAX_ASSETS} more assets.")
    return "\n".join(lines)


def _fmt_budgets(budgets: list[dict[str, Any]]) -> str:
    if not budgets:
        return "  (no budget items recorded)"
    lines: list[str] = []
    for b in budgets[:_MAX_BUDGETS]:
        amount = b.get("amount")
        amount_str = f"{amount:,.0f}" if isinstance(amount, (int, float)) else str(amount)
        lines.append(
            f"  • [{b.get('budget_id', '?')}] {b.get('initiative', '?')}"
            f" | domain={b.get('domain', '?')}"
            f" | type={b.get('cost_type', '?')}"
            f" | quarter={b.get('quarter', '?')}"
            f" | amount={amount_str} {b.get('currency', 'IDR')}"
            f" | status={b.get('status', '?')}"
            f" | priority={b.get('priority', '?')}"
            f" | owner={b.get('owner', '?')}"
        )
        notes = str(b.get("notes", "")).strip()
        if notes:
            lines.append(f"    notes: {notes}")
        # Cashout entries (added via Excel upload)
        cashout_entries = b.get("cashout_entries") or []
        if cashout_entries:
            total_cashout = sum(float(e.get("cashout_amount", 0) or 0) for e in cashout_entries)
            spk_names = ", ".join(str(e.get("nama_spk", "")) for e in cashout_entries if e.get("nama_spk"))
            lines.append(
                f"    cashout: total={total_cashout:,.0f} IDR"
                f" | {len(cashout_entries)} SPK entries: {spk_names or '(unnamed)'}"
            )
    if len(budgets) > _MAX_BUDGETS:
        lines.append(f"  ... and {len(budgets) - _MAX_BUDGETS} more budget items.")
    return "\n".join(lines)


def _fmt_policies(policies: list[dict[str, Any]]) -> str:
    if not policies:
        return "  (no policies recorded)"
    return "\n".join(
        f"  • [{p.get('policy_id', '?')}] {p.get('text', '').strip()}"
        for p in policies
    )


def _fmt_exposures(exposures: list[dict[str, Any]]) -> str:
    if not exposures:
        return "  (no public exposure data — Elasticsearch may be unavailable)"
    lines: list[str] = []
    for e in exposures[:_MAX_EXPOSURES]:
        ips = ", ".join(str(ip) for ip in e.get("ip_addresses", []) if ip)
        lines.append(
            f"  • {e.get('subdomain', '?')}"
            f" | provider={e.get('provider', '?')}"
            f" | ips={ips or 'none'}"
            f" | ssl_issuer={e.get('ssl_issuer_org', '?')}"
            f" | ssl_expiry={e.get('ssl_not_after', '?')}"
            f" | has_public_ip={e.get('has_public_ip', '?')}"
        )
    if len(exposures) > _MAX_EXPOSURES:
        lines.append(f"  ... and {len(exposures) - _MAX_EXPOSURES} more exposed subdomains.")
    return "\n".join(lines)


def _fmt_pentest_tickets(tickets: list[dict[str, Any]]) -> str:
    if not tickets:
        return "  (no pentest Jira tickets found — exporter/index may be unavailable)"
    lines: list[str] = []
    for t in tickets[:_MAX_PENTEST_TICKETS]:
        labels_raw = t.get("labels") or []
        labels = ", ".join(str(v) for v in labels_raw[:6]) if isinstance(labels_raw, list) else str(labels_raw)
        lines.append(
            f"  • [{t.get('key', '?')}] {t.get('summary', '?')}"
            f" | status={t.get('status', '?')}"
            f" | priority={t.get('priority', '?')}"
            f" | assignee={t.get('assignee', 'Unassigned') or 'Unassigned'}"
            f" | reporter={t.get('reporter', '?')}"
            f" | created={t.get('created', '?')}"
            f" | updated={t.get('updated', '?')}"
        )
        if labels:
            lines.append(f"    labels: {labels}")
    if len(tickets) > _MAX_PENTEST_TICKETS:
        lines.append(f"  ... and {len(tickets) - _MAX_PENTEST_TICKETS} more pentest tickets.")
    return "\n".join(lines)


def _fmt_soc_tickets(tickets: list[dict[str, Any]]) -> str:
    if not tickets:
        return "  (no SOC Jira tickets found — exporter/index may be unavailable)"
    lines: list[str] = []
    for t in tickets[:_MAX_SOC_TICKETS]:
        lines.append(
            f"  • [{t.get('key', '?')}] {t.get('summary', '?')}"
            f" | status={t.get('status', '?')}"
            f" | severity={t.get('severity', '?')}"
            f" | risk_score={t.get('risk_score', '?')}"
            f" | detection_id={t.get('detection_id', '?')}"
            f" | alert_name={t.get('alert_name', '?')}"
            f" | start_time={t.get('start_time', '?')}"
            f" | taktik={t.get('taktik', '?')}"
            f" | teknik={t.get('teknik', '?')}"
        )
    if len(tickets) > _MAX_SOC_TICKETS:
        lines.append(f"  ... and {len(tickets) - _MAX_SOC_TICKETS} more SOC tickets.")
    return "\n".join(lines)


_MAX_ANOMALIES = 15


def _fmt_budget_analytics(analytics: dict | None) -> str:
    if not analytics:
        return "  (no budget analytics cache — run Budget Analytics from the Governance menu)"
    analysis = analytics.get("analysis", {})
    generated_at = analytics.get("generated_at", "?")
    provider = analytics.get("narrative_provider", "?")
    lines = [
        f"  Generated: {generated_at} | provider: {provider}",
        f"  Total budget: {analysis.get('total_budget', 0):,.0f} IDR"
        f" | Capex: {analysis.get('capex', 0):,.0f}"
        f" | Opex: {analysis.get('opex', 0):,.0f}"
        f" | Items: {analysis.get('total_items', 0)}",
    ]
    # Anomalies
    anomalies: list[dict] = analysis.get("anomalies", [])
    if anomalies:
        lines.append(f"  Anomalies detected: {len(anomalies)}")
        for a in anomalies[:_MAX_ANOMALIES]:
            lines.append(
                f"  ⚠ [{a.get('budget_id', '?')}] {a.get('initiative', '?')}"
                f" | domain={a.get('domain', '?')}"
                f" | type={a.get('cost_type', '?')}"
                f" | amount={a.get('amount', 0):,.0f}"
                f" | expected={a.get('expected_amount', 0):,.0f}"
                f" | variance={a.get('variance_pct', 0):+.1f}%"
                f" | z={a.get('z_score', 0):.2f}"
                f" | owner={a.get('owner', '?')}"
            )
        if len(anomalies) > _MAX_ANOMALIES:
            lines.append(f"  ... and {len(anomalies) - _MAX_ANOMALIES} more anomalies.")
    else:
        lines.append("  No anomalies flagged.")
    # Unapproved high-priority
    unapproved = analysis.get("unapproved_high_priority", [])
    if unapproved:
        lines.append(f"  Unapproved high-priority items: {len(unapproved)}")
        for u in unapproved[:10]:
            lines.append(
                f"    • [{u.get('budget_id', '?')}] {u.get('initiative', '?')}"
                f" | {u.get('cost_type', '?')} | {u.get('amount', 0):,.0f} IDR"
                f" | status={u.get('status', '?')}"
            )
    # AI narrative (truncated)
    narrative = str(analytics.get("ai_narrative", "")).strip()
    if narrative:
        excerpt = narrative[:1_500]
        if len(narrative) > 1_500:
            excerpt += "\n  [... truncated ...]"
        lines.append("")
        lines.append("  --- AI narrative excerpt ---")
        lines.append(excerpt)
        lines.append("  --- End excerpt ---")
    return "\n".join(lines)


def _fmt_recent_report(reports: list[dict[str, str]]) -> str:
    if not reports:
        return "  (no historical reports found)"
    meta = reports[0]
    lines = [
        f"  Most recent report: [{meta.get('id', '?')}]"
        f" generated {meta.get('created_at_utc', '?')}"
        f" from source \"{meta.get('source', '?')}\""
    ]
    md_path = meta.get("markdown_path", "")
    if md_path:
        try:
            content = load_report(md_path)
            excerpt = content[:_MAX_REPORT_CHARS].strip()
            if len(content) > _MAX_REPORT_CHARS:
                excerpt += "\n  [... truncated ...]"
            lines.append("")
            lines.append("  --- Report excerpt ---")
            lines.append(excerpt)
            lines.append("  --- End of excerpt ---")
        except Exception:
            lines.append("  (report file could not be read)")
    if len(reports) > 1:
        lines.append(f"\n  Older reports ({len(reports) - 1}):")
        for r in reports[1:]:
            lines.append(
                f"    • [{r.get('id', '?')}] {r.get('created_at_utc', '?')}"
                f" | source: {r.get('source', '?')}"
            )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_app_context() -> str:
    """Return a structured live-data snapshot for injection into the Copilot system prompt."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    try:
        assets = load_assets()
    except Exception:
        assets = []

    try:
        budgets = load_budgets()
    except Exception:
        budgets = []

    try:
        policies = load_budget_policies()
    except Exception:
        policies = []

    try:
        exposures = load_public_exposures()
    except Exception:
        exposures = []

    try:
        pentest_tickets = load_pentest_tickets()
    except Exception:
        pentest_tickets = []

    try:
        soc_tickets = load_soc_tickets()
    except Exception:
        soc_tickets = []

    try:
        reports = list_reports(limit=5)
    except Exception:
        reports = []

    try:
        budget_analytics = load_budget_analytics()
    except Exception:
        budget_analytics = None

    # Aggregate quick stats for easy reference
    total_cost = sum(
        float(a.get("annual_cost", 0) or 0) for a in assets
        if isinstance(a.get("annual_cost"), (int, float))
    )
    critical_assets = [a for a in assets if str(a.get("criticality", "")).lower() == "critical"]
    renewal_soon = [
        a for a in assets
        if str(a.get("support_status", "")).lower() in {"renewal soon", "expiring soon"}
    ]

    total_budget = sum(
        float(b.get("amount", 0) or 0) for b in budgets
        if isinstance(b.get("amount"), (int, float))
    )
    approved_budget = sum(
        float(b.get("amount", 0) or 0) for b in budgets
        if str(b.get("status", "")).lower() == "approved"
        and isinstance(b.get("amount"), (int, float))
    )

    open_ticket_status_keywords = ("open", "new", "progress", "todo", "pentest")
    open_pentest_tickets = [
        t for t in pentest_tickets
        if any(k in str(t.get("status", "")).lower() for k in open_ticket_status_keywords)
    ]
    open_soc_tickets = [
        t for t in soc_tickets
        if any(k in str(t.get("status", "")).lower() for k in open_ticket_status_keywords)
    ]

    sections = [
        f"╔══ LIVE PORTAL DATA SNAPSHOT ══ {now} ══╗",
        "",
        "▌ QUICK STATS",
        f"  Assets: {len(assets)} total | {len(critical_assets)} critical"
        f" | {len(renewal_soon)} renewal soon"
        f" | total annual cost {total_cost:,.0f}",
        f"  Budgets: {len(budgets)} items | total {total_budget:,.0f}"
        f" | approved {approved_budget:,.0f}",
        f"  Pentest tickets: {len(pentest_tickets)} total | {len(open_pentest_tickets)} open/in-progress",
        f"  SOC tickets: {len(soc_tickets)} total | {len(open_soc_tickets)} open/in-progress",
        f"  Public exposure records: {len(exposures)} subdomains/IPs",
        f"  Historical reports: {len(reports)} on file",
        "",
        "▌ SECURITY ASSET INVENTORY",
        sanitize_for_llm(_fmt_assets(assets)),
        "",
        "▌ BUDGET ITEMS",
        sanitize_for_llm(_fmt_budgets(budgets)),
        "",
        "▌ BUDGET ANALYTICS (ML ANOMALY DETECTION)",
        sanitize_for_llm(_fmt_budget_analytics(budget_analytics)),
        "",
        "▌ BUDGET GOVERNANCE POLICIES",
        sanitize_for_llm(_fmt_policies(policies)),
        "",
        "▌ PUBLIC IP / SUBDOMAIN EXPOSURE",
        sanitize_for_llm(_fmt_exposures(exposures)),
        "",
        "▌ PENTEST JIRA TICKETS",
        sanitize_for_llm(_fmt_pentest_tickets(pentest_tickets)),
        "",
        "▌ SOC JIRA TICKETS (CIAOT)",
        sanitize_for_llm(_fmt_soc_tickets(soc_tickets)),
        "",
        "▌ SECURITY ASSESSMENT REPORTS",
        sanitize_for_llm(_fmt_recent_report(reports)),
        "",
        "╚══ END LIVE DATA ══╝",
    ]

    return "\n".join(sections)
