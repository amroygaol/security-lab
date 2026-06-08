from __future__ import annotations

import json
import threading
import time
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any
from urllib import error, request as urllib_request

import numpy as np
import pandas as pd

from ..core.config import CONFIG
from ..core.security import sanitize_for_llm
from ..data.portal_store import load_assets, load_budget_policies, load_budgets
from ..data.soc_analytics_store import save_analytics

# ── ES helpers ────────────────────────────────────────────────────────────────

_INDEX = "security-jira-soc-tickets"
_PAGE_SIZE = 500


def _es_base() -> str:
    base = CONFIG.elasticsearch_url.rstrip("/")
    # inside Docker the service is reachable as "elasticsearch"
    for local in ("http://localhost:9200", "http://127.0.0.1:9200"):
        if base == local:
            return "http://elasticsearch:9200"
    return base


def _post(url: str, body: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib_request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib_request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _fetch_all_tickets(progress_cb: Any) -> list[dict[str, Any]]:
    """Scroll through the entire ES index using search_after + pit (or plain search_after on _id)."""
    base = _es_base()
    url = f"{base}/{_INDEX}/_search"

    # Use search_after on (created, _id) to avoid the 10k offset cap
    body: dict[str, Any] = {
        "size": _PAGE_SIZE,
        "track_total_hits": True,
        "_source": [
            "key", "summary", "status", "created", "updated",
            "reporter", "assignee", "priority",
            "detection_id", "start_time", "alert_name",
            "risk_score", "severity", "taktik", "teknik",
        ],
        "sort": [{"created": {"order": "asc"}}, {"key.keyword": {"order": "asc"}}],
    }

    all_tickets: list[dict[str, Any]] = []
    total: int | None = None

    while True:
        resp = _post(url, body)
        if total is None:
            total = resp.get("hits", {}).get("total", {}).get("value", 0)

        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            break

        for h in hits:
            all_tickets.append(h.get("_source", {}))

        progress_cb(len(all_tickets), total)

        # Prepare next page
        last_sort = hits[-1].get("sort")
        if not last_sort or len(hits) < _PAGE_SIZE:
            break
        body["search_after"] = last_sort

    return all_tickets


# ── ML Analysis ───────────────────────────────────────────────────────────────

_KNOWN_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


def _norm_severity(raw: str) -> str:
    v = (raw or "").strip().lower()
    return v.title() if v in _KNOWN_SEVERITIES else ("Unknown" if not v else raw.strip())


def _safe_float(v: Any) -> float | None:
    try:
        return float(str(v).strip())
    except (ValueError, TypeError):
        return None


def _run_ml_analysis(tickets: list[dict[str, Any]]) -> dict[str, Any]:
    """Pure pandas/numpy analysis. Returns a serialisable dict."""
    if not tickets:
        return {}

    df = pd.DataFrame(tickets)

    # Normalise severity
    df["severity_norm"] = df.get("severity", pd.Series(dtype=str)).fillna("").apply(_norm_severity)

    # ── Frequency counters ────────────────────────────────────────────────
    by_severity   = dict(Counter(df["severity_norm"]).most_common())
    by_status     = dict(Counter(df.get("status", pd.Series(dtype=str)).fillna("Unknown")).most_common())
    by_taktik     = dict(Counter(v for v in df.get("taktik", pd.Series(dtype=str)).fillna("") if v).most_common(30))
    by_teknik     = dict(Counter(v for v in df.get("teknik", pd.Series(dtype=str)).fillna("") if v).most_common(30))
    by_alert_name = dict(Counter(v for v in df.get("alert_name", pd.Series(dtype=str)).fillna("") if v).most_common(20))
    by_assignee   = dict(Counter(v for v in df.get("assignee", pd.Series(dtype=str)).fillna("") if v).most_common(15))

    # ── Risk score stats ──────────────────────────────────────────────────
    scores = pd.to_numeric(df.get("risk_score", pd.Series(dtype=str)), errors="coerce").dropna()
    risk_stats: dict[str, Any] = {}
    if not scores.empty:
        risk_stats = {
            "mean":   round(float(scores.mean()), 2),
            "median": round(float(scores.median()), 2),
            "std":    round(float(scores.std()), 2),
            "p25":    round(float(scores.quantile(0.25)), 2),
            "p75":    round(float(scores.quantile(0.75)), 2),
            "p95":    round(float(scores.quantile(0.95)), 2),
            "p99":    round(float(scores.quantile(0.99)), 2),
            "min":    round(float(scores.min()), 2),
            "max":    round(float(scores.max()), 2),
        }

    # ── Weekly timeline ───────────────────────────────────────────────────
    timeline: list[dict[str, Any]] = []
    if "created" in df.columns:
        df["date"] = pd.to_datetime(df["created"], errors="coerce").dt.date
        daily = df.groupby("date").size().reset_index(name="count")
        daily = daily.sort_values("date")
        # Aggregate to weekly for readability
        daily["date"] = pd.to_datetime(daily["date"])
        weekly = daily.set_index("date").resample("W").sum().reset_index()
        timeline = [
            {"week": str(row["date"].date()), "count": int(row["count"])}
            for _, row in weekly.iterrows()
        ]

    # ── Taktik × Severity heatmap ─────────────────────────────────────────
    heatmap: list[dict[str, Any]] = []
    if "taktik" in df.columns and "severity_norm" in df.columns:
        heat_df = df[df["taktik"].str.strip() != ""].groupby(
            ["taktik", "severity_norm"]
        ).size().reset_index(name="count")
        heatmap = heat_df.to_dict(orient="records")

    # ── Alert anomaly detection ────────────────────────────────────────────
    # Alerts whose volume is > 2 std above mean are flagged
    anomalies: list[dict[str, Any]] = []
    total = len(tickets)
    if by_alert_name:
        counts = np.array(list(by_alert_name.values()), dtype=float)
        mean_c, std_c = counts.mean(), counts.std()
        for name, cnt in by_alert_name.items():
            if std_c > 0 and cnt > mean_c + 2 * std_c:
                anomalies.append({
                    "type": "high_volume_alert",
                    "alert_name": name,
                    "count": cnt,
                    "pct_of_total": round(cnt / total * 100, 2),
                    "z_score": round((cnt - mean_c) / std_c, 2),
                })
        anomalies.sort(key=lambda x: x["z_score"], reverse=True)

    return {
        "by_severity":    by_severity,
        "by_status":      by_status,
        "by_taktik":      by_taktik,
        "by_teknik":      by_teknik,
        "by_alert_name":  by_alert_name,
        "by_assignee":    by_assignee,
        "risk_score_stats": risk_stats,
        "timeline":       timeline,
        "taktik_severity_heatmap": heatmap,
        "anomalies":      anomalies,
    }


# ── Budget Context ─────────────────────────────────────────────────────────────

# Budget initiative keywords → security domain mapping
# Matched case-insensitively as substrings against the initiative text.
# Order matters: first match wins; put more specific terms before broad ones.
_INITIATIVE_DOMAIN: dict[str, str] = {
    # IAM / Identity
    "iam":                          "IAM",
    "identity":                     "IAM",
    "brilian":                      "IAM",
    "tpim":                         "IAM",
    "entra id":                     "IAM",
    "active directory":             "IAM",
    "ldap":                         "IAM",
    "sso":                          "IAM",
    "privileged access":            "IAM",
    "pam":                          "IAM",
    "mfa":                          "IAM",
    "otp":                          "IAM",
    "notifikasi":                   "IAM",   # SMS/WA OTP notification services
    # SOC / Threat Detection
    "security operation":           "SOC",
    "soc":                          "SOC",
    "threat hunting":               "SOC",
    "threat detection":             "SOC",
    "siem":                         "SOC",
    "xsiam":                        "SOC",
    "xdr":                          "SOC",
    "soar":                         "SOC",
    "threat intelligence":          "SOC",
    "brand protection":             "SOC",
    "cyber attack simulation":      "SOC",
    "red team":                     "SOC",
    "incident response":            "SOC",
    "cyberdrill":                   "SOC",
    "security awareness":           "SOC",
    "cybersecurity maturity":       "SOC",
    "risk scoring":                 "SOC",
    "ciso":                         "SOC",
    "tata kelola":                  "SOC",   # governance
    "pci dss":                      "SOC",
    "pcidss":                       "SOC",
    "esa review":                   "SOC",
    "audit":                        "SOC",
    "compliance":                   "SOC",
    # Application Security
    "penetration test":             "Application Security",
    "pentest":                      "Application Security",
    "waf":                          "Application Security",
    "web application firewall":     "Application Security",
    "api security":                 "Application Security",
    "dast":                         "Application Security",
    "imperva":                      "Application Security",
    "ssl":                          "Application Security",
    "sertifikat":                   "Application Security",  # SSL certs
    "certificate":                  "Application Security",
    # Network Security
    "sd-wan":                       "Network Security",
    "sase":                         "Network Security",
    "firewall":                     "Network Security",
    "ngfw":                         "Network Security",
    "ddos":                         "Network Security",
    "proxy":                        "Network Security",
    "network":                      "Network Security",
    "vpn":                          "Network Security",
    # Endpoint Security
    "endpoint":                     "Endpoint Security",
    "edr":                          "Endpoint Security",
    "workstation":                  "Endpoint Security",
    "hardening":                    "Endpoint Security",
    "patch":                        "Endpoint Security",
    "fms support":                  "Endpoint Security",
    "anti-malware":                 "Endpoint Security",
    "antivirus":                    "Endpoint Security",
    # Data Security
    "dlp":                          "Data Security",
    "data loss":                    "Data Security",
    "enkripsi":                     "Data Security",
    "encryption":                   "Data Security",
    "luna":                         "Data Security",  # Luna HSM / crypto
    "hsm":                          "Data Security",
    "blancco":                      "Data Security",  # secure data erasure
    "backup":                       "Data Security",
    "elasticsearch":                "Data Security",  # log data platform
    "database":                     "Data Security",
}


def _map_initiative_to_security_domain(initiative: str) -> str | None:
    """Map a budget initiative name to a security domain via keyword matching."""
    t = (initiative or "").lower()
    for keyword, domain in _INITIATIVE_DOMAIN.items():
        if keyword in t:
            return domain
    return None


# Taktik (MITRE ATT&CK) → security domain mapping
_TAKTIK_DOMAIN: dict[str, str] = {
    "initial access":        "Application Security",
    "execution":             "Endpoint Security",
    "persistence":           "Endpoint Security",
    "privilege escalation":  "IAM",
    "defense evasion":       "SOC",
    "credential access":     "IAM",
    "discovery":             "SOC",
    "lateral movement":      "Network Security",
    "collection":            "Data Security",
    "command and control":   "Network Security",
    "exfiltration":          "Data Security",
    "impact":                "SOC",
    "reconnaissance":        "Application Security",
    "resource development":  "Application Security",
}


def _map_taktik_to_domain(taktik: str) -> str | None:
    t = taktik.lower().strip()
    for key, domain in _TAKTIK_DOMAIN.items():
        if key in t:
            return domain
    return None


def _run_combined_analytics(
    analysis: dict[str, Any],
    budgets: list[dict],
    assets: list[dict],
    policies: list[dict],
) -> dict[str, Any]:
    """Cross-correlate SOC ticket analytics with budget and asset data."""

    # ── Budget summary ────────────────────────────────────────────────────
    budget_df = pd.DataFrame(budgets) if budgets else pd.DataFrame(columns=["domain", "amount", "status", "priority", "cost_type"])
    for col in ("domain", "amount", "status", "priority", "cost_type"):
        if col not in budget_df.columns:
            budget_df[col] = "" if col != "amount" else 0.0

    domain_budget: dict[str, float] = {}
    domain_status: dict[str, dict] = {}
    domain_cost_type: dict[str, dict] = {}
    if not budget_df.empty:
        # Map each row to a security domain via initiative keywords;
        # fall back to the raw domain field if no keyword matches.
        budget_df["security_domain"] = budget_df.apply(
            lambda r: _map_initiative_to_security_domain(str(r.get("initiative", "")))
                      or str(r.get("domain", "Other")),
            axis=1,
        )
        for domain, grp in budget_df.groupby("security_domain"):
            domain_budget[str(domain)] = round(float(grp["amount"].sum()), 2)
            domain_status[str(domain)] = dict(grp["status"].value_counts().to_dict())
            domain_cost_type[str(domain)] = dict(grp["cost_type"].value_counts().to_dict())

    # ── Map SOC tickets to domains via taktik ────────────────────────────
    by_taktik: dict[str, int] = analysis.get("by_taktik", {})
    domain_tickets: dict[str, int] = {}
    for taktik, count in by_taktik.items():
        domain = _map_taktik_to_domain(taktik)
        if domain:
            domain_tickets[domain] = domain_tickets.get(domain, 0) + count

    # ── Budget gap analysis ───────────────────────────────────────────────
    all_domains = sorted(set(list(domain_budget.keys()) + list(domain_tickets.keys())))
    gap_analysis: list[dict[str, Any]] = []
    for domain in all_domains:
        tickets = domain_tickets.get(domain, 0)
        budget  = domain_budget.get(domain, 0.0)
        gap_analysis.append({
            "domain":            domain,
            "ticket_count":      tickets,
            "budget_allocated":  budget,
            "gap_flag":          tickets > 0 and budget == 0.0,
            "tickets_per_1k_budget": round(tickets / max(budget / 1000.0, 1.0), 4),
        })
    gap_analysis.sort(key=lambda x: x["ticket_count"], reverse=True)

    # ── Asset coverage ───────────────────────────────────────────────────
    asset_summary: dict[str, Any] = {}
    if assets:
        asset_df = pd.DataFrame(assets)
        total_tool_spend = float(asset_df.get("annual_cost", pd.Series(dtype=float)).fillna(0).sum())
        criticality_spend: dict[str, float] = {}
        if "criticality" in asset_df.columns and "annual_cost" in asset_df.columns:
            criticality_spend = {
                k: round(float(v), 2)
                for k, v in asset_df.groupby("criticality")["annual_cost"].sum().items()
            }
        renewal_soon = [
            str(a.get("asset_name", ""))
            for a in assets
            if "renewal" in str(a.get("support_status", "")).lower()
        ]
        asset_summary = {
            "total_tool_spend":  round(total_tool_spend, 2),
            "asset_count":       len(assets),
            "criticality_spend": criticality_spend,
            "renewal_soon":      renewal_soon,
        }

    # ── Policy-compliance: high-priority items still unapproved ──────────
    unapproved_high = [
        {"initiative": b.get("initiative", ""), "domain": b.get("domain", ""),
         "status": b.get("status", ""), "amount": b.get("amount", 0)}
        for b in budgets
        if b.get("priority") == "High" and b.get("status") in ("Draft", "Planned")
    ]

    # ── Totals ────────────────────────────────────────────────────────────
    total_budget = round(sum(domain_budget.values()), 2)
    total_capex = round(float(budget_df.loc[budget_df["cost_type"] == "Capex", "amount"].sum()), 2) if not budget_df.empty else 0.0
    total_opex  = round(float(budget_df.loc[budget_df["cost_type"] == "Opex",  "amount"].sum()), 2) if not budget_df.empty else 0.0

    return {
        "domain_budget":             domain_budget,
        "domain_status":             domain_status,
        "domain_cost_type":          domain_cost_type,
        "domain_tickets":            domain_tickets,
        "gap_analysis":              gap_analysis,
        "asset_summary":             asset_summary,
        "unapproved_high_priority":  unapproved_high,
        "budget_policies":           [p.get("text", "") for p in policies],
        "total_budget":              total_budget,
        "total_capex":               total_capex,
        "total_opex":                total_opex,
    }


# ── AI Narrative ──────────────────────────────────────────────────────────────

def _build_narrative_prompt(
    total: int,
    analysis: dict[str, Any],
    combined: dict[str, Any] | None = None,
) -> str:
    lines = [
        f"You are a senior security analyst combining SOC threat data with budget and asset intelligence.",
        f"Produce a concise executive report (max 500 words) covering {total:,} YTD SOC tickets.",
        "",
        "=== SOC THREAT ANALYTICS ===",
        f"Severity breakdown: {json.dumps(analysis.get('by_severity', {}))}",
        f"Top tactics: {json.dumps(dict(list(analysis.get('by_taktik', {}).items())[:10]))}",
        f"Top techniques: {json.dumps(dict(list(analysis.get('by_teknik', {}).items())[:10]))}",
        f"Top alert names: {json.dumps(dict(list(analysis.get('by_alert_name', {}).items())[:8]))}",
        f"Risk score stats: {json.dumps(analysis.get('risk_score_stats', {}))}",
        f"Anomalies: {json.dumps(analysis.get('anomalies', [])[:5])}",
    ]

    if combined:
        lines += [
            "",
            "=== BUDGET & ASSET CONTEXT ===",
            f"Total security budget: {combined.get('total_budget', 0):,.0f} (Capex: {combined.get('total_capex', 0):,.0f}, Opex: {combined.get('total_opex', 0):,.0f})",
            f"Budget by domain: {json.dumps(combined.get('domain_budget', {}))}",
            f"SOC tickets by security domain: {json.dumps(combined.get('domain_tickets', {}))}",
            f"Budget gap analysis (domains with ticket volume but no budget): "
            + json.dumps([g for g in combined.get('gap_analysis', []) if g.get('gap_flag')]),
            f"Asset tool spend: {json.dumps(combined.get('asset_summary', {}))}",
            f"High-priority unapproved budget items: {json.dumps(combined.get('unapproved_high_priority', []))}",
            f"Budget governance policies: {json.dumps(combined.get('budget_policies', []))}",
            "",
            "=== RECOMMENDATIONS ===",
            "Based on the above, provide:",
            "1. Overall security posture assessment",
            "2. Top 3 threat priorities derived from ticket volume and severity",
            "3. Budget alignment gaps — where threats exceed investment",
            "4. Top 3 actionable recommendations with estimated impact",
        ]
    else:
        lines += [
            "",
            "Focus on: overall posture, dominant attack patterns, risk concentration, and top 3 actionable recommendations.",
        ]

    return "\n".join(lines)


def _list_ollama_models() -> list[str]:
    """Return list of model names available in the local Ollama instance."""
    try:
        ollama_url = CONFIG.ollama_base_url.rstrip("/")
        req = urllib_request.Request(f"{ollama_url}/api/tags", method="GET")
        with urllib_request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode())
            return [m["name"] for m in payload.get("models", [])]
    except Exception:
        return []


def _detect_ollama_gpu() -> str:
    """Return 'cuda', 'rocm', 'metal', or 'cpu' based on what's available at the Ollama host."""
    try:
        base = _es_base().replace(":9200", "")  # not used for Ollama; kept for pattern
        ollama_url = CONFIG.ollama_base_url.rstrip("/")
        req = urllib_request.Request(f"{ollama_url}/api/tags", method="GET")
        with urllib_request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode())
            # Ollama /api/tags doesn't expose GPU info directly, try /api/ps
            _ = payload  # just checking connectivity
    except Exception:
        pass  # Ollama might not be reachable; fall through

    # Try to detect GPU via subprocess (nvidia-smi / rocm-smi)
    import subprocess
    for cmd, tag in [("nvidia-smi", "cuda"), ("rocm-smi", "rocm")]:
        try:
            result = subprocess.run([cmd], capture_output=True, timeout=4)
            if result.returncode == 0:
                return tag
        except Exception:
            pass

    # macOS Metal
    import platform
    if platform.system() == "Darwin":
        return "metal"

    return "cpu"


def _generate_ollama_narrative(
    total: int, analysis: dict[str, Any], model: str | None = None, combined: dict[str, Any] | None = None
) -> str:
    try:
        from langchain_ollama import ChatOllama
        gpu_backend = _detect_ollama_gpu()
        extra: dict[str, Any] = {"num_gpu": -1} if gpu_backend != "cpu" else {}
        llm = ChatOllama(
            base_url=CONFIG.ollama_base_url,
            model=model or CONFIG.ollama_llm_model,
            temperature=0.3,
            num_ctx=4096,
            timeout=None,
            **extra,
        )
        prompt = sanitize_for_llm(_build_narrative_prompt(total, analysis, combined))
        response = llm.invoke(prompt)
        return str(response.content).strip()
    except Exception as exc:
        return f"[Ollama narrative unavailable: {exc}]"


def _generate_gemini_narrative(
    total: int, analysis: dict[str, Any], combined: dict[str, Any] | None = None
) -> str:
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        llm = ChatGoogleGenerativeAI(
            model=CONFIG.gemini_model,
            google_api_key=CONFIG.gemini_api_key,
            temperature=0.3,
        )
        prompt = sanitize_for_llm(_build_narrative_prompt(total, analysis, combined))
        response = llm.invoke(prompt)
        return str(response.content).strip()
    except Exception as exc:
        return f"[Gemini narrative unavailable: {exc}]"


# ── Runner ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class SocAnalyticsRunner:
    """Background runner: fetch all SOC tickets → ML analysis → Gemini narrative → JSON."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="soc-analytics")
        self._lock = threading.Lock()
        self._future: Future | None = None
        self._state: dict[str, Any] = {
            "status": "idle",
            "stage": "idle",
            "message": "No analysis has been run yet.",
            "progress": 0.0,
            "error": "",
            "started_at": "",
            "updated_at": _utc_now(),
            "completed_at": "",
        }

    def get_state(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._state)

    def is_running(self) -> bool:
        with self._lock:
            return bool(self._future and not self._future.done())

    def _update(self, **kwargs: Any) -> None:
        with self._lock:
            self._state.update(kwargs)
            self._state["updated_at"] = _utc_now()

    def start(self, include_ai_narrative: bool = True, narrative_provider: str = "gemini", ollama_model: str | None = None) -> bool:
        with self._lock:
            if self._future and not self._future.done():
                return False
            self._state = {
                "status": "running",
                "stage": "fetching",
                "message": "Connecting to Elasticsearch…",
                "progress": 0.01,
                "error": "",
                "started_at": _utc_now(),
                "updated_at": _utc_now(),
                "completed_at": "",
            }
            self._future = self._executor.submit(self._run, include_ai_narrative, narrative_provider, ollama_model)
        return True

    def _run(self, include_ai_narrative: bool, narrative_provider: str = "gemini", ollama_model: str | None = None) -> None:
        t0 = time.time()
        try:
            # ── 1. Fetch ──────────────────────────────────────────────────
            def _progress(fetched: int, total: int) -> None:
                pct = min(0.6, 0.01 + 0.59 * (fetched / max(total, 1)))
                self._update(
                    stage="fetching",
                    message=f"Fetching tickets from Elasticsearch… {fetched:,} / {total:,}",
                    progress=pct,
                )

            tickets = _fetch_all_tickets(_progress)
            total = len(tickets)
            self._update(stage="analysing", message=f"Running ML analysis on {total:,} tickets…", progress=0.62)

            # ── 2. ML Analysis ────────────────────────────────────────────
            analysis = _run_ml_analysis(tickets)

            # ── 2b. Combined budget + asset analytics ─────────────────────
            self._update(stage="analysing", message="Cross-correlating with budget and asset data…", progress=0.72)
            try:
                budgets  = load_budgets()
                assets   = load_assets()
                policies = load_budget_policies()
                combined = _run_combined_analytics(analysis, budgets, assets, policies)
            except Exception:
                combined = {}

            self._update(stage="narrative", message="Generating AI narrative…", progress=0.82)

            # ── 3. AI narrative ───────────────────────────────────────────
            narrative = ""
            if include_ai_narrative:
                if narrative_provider == "ollama":
                    gpu = _detect_ollama_gpu()
                    gpu_label = {"cuda": "CUDA GPU", "rocm": "ROCm GPU", "metal": "Apple Metal GPU", "cpu": "CPU (no GPU)"}[gpu]
                    used_model = ollama_model or CONFIG.ollama_llm_model
                    self._update(
                        stage="narrative",
                        message=f"Generating Ollama narrative ({used_model}) on {gpu_label}…",
                        progress=0.82,
                    )
                    narrative = _generate_ollama_narrative(total, analysis, model=used_model, combined=combined or None)
                else:  # gemini
                    if CONFIG.gemini_api_key:
                        self._update(
                            stage="narrative",
                            message=f"Generating Gemini narrative ({CONFIG.gemini_model})…",
                            progress=0.82,
                        )
                        narrative = _generate_gemini_narrative(total, analysis, combined=combined or None)
                    else:
                        narrative = "[Gemini API key not configured — set GEMINI_API_KEY to enable AI narratives.]"

            self._update(stage="saving", message="Saving analytics to disk…", progress=0.95)

            # ── 4. Save ───────────────────────────────────────────────────
            payload: dict[str, Any] = {
                "generated_at": _utc_now(),
                "duration_seconds": round(time.time() - t0, 1),
                "total_tickets": total,
                "narrative_provider": narrative_provider if include_ai_narrative else "none",
                "summary": analysis,
                "budget_analysis": combined,
                "ai_narrative": narrative,
            }
            save_analytics(payload)

            self._update(
                status="completed",
                stage="done",
                message=f"Analysis complete — {total:,} tickets processed in {payload['duration_seconds']}s.",
                progress=1.0,
                completed_at=_utc_now(),
            )

        except Exception as exc:
            self._update(
                status="error",
                stage="error",
                message=f"Analysis failed: {exc}",
                progress=0.0,
                error=str(exc),
                completed_at=_utc_now(),
            )
