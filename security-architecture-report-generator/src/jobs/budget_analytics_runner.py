from __future__ import annotations

import json
import threading
import time
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any
from urllib import request as urllib_request

import numpy as np
import pandas as pd

from ..core.config import CONFIG
from ..core.security import sanitize_for_llm
from ..data.budget_analytics_store import save_budget_analytics
from ..data.portal_store import load_budget_policies, load_budgets
from .soc_analytics_runner import _detect_ollama_gpu, _list_ollama_models


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


# ── Internet enrichment (DuckDuckGo) ──────────────────────────────────────────

def _ddg_search(query: str, max_results: int = 3) -> list[str]:
    """Return brief text snippets from DuckDuckGo for the given query."""
    try:
        from duckduckgo_search import DDGS
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
        return [
            f"{r.get('title', '')}: {r.get('body', '')[:300]}"
            for r in results
            if r.get("body")
        ]
    except Exception:
        return []


def _enrich_anomalies_internet(anomalies: list[dict[str, Any]]) -> dict[str, Any]:
    """
    For each of the top-3 anomalous budget items, run a DuckDuckGo search for
    market-pricing / industry-benchmark context.  Returns a dict keyed by budget_id.
    """
    enrichment: dict[str, Any] = {}
    for anom in anomalies[:3]:
        initiative = str(anom.get("initiative", ""))
        domain     = str(anom.get("domain", ""))
        cost_type  = str(anom.get("cost_type", ""))
        query = (
            f"enterprise security {initiative} {domain} {cost_type} "
            "cost pricing benchmark typical budget"
        )
        snippets = _ddg_search(query, max_results=3)
        if snippets:
            bid = str(anom.get("budget_id", initiative[:20]))
            enrichment[bid] = {
                "initiative": initiative,
                "domain":     domain,
                "snippets":   snippets,
            }
    return enrichment


# ── Anomaly-specific narrative ────────────────────────────────────────────────

def _build_anomaly_prompt(
    anomalies: list[dict[str, Any]],
    enrichment: dict[str, Any],
    policies: list[str],
) -> str:
    lines = [
        "You are a senior security finance analyst.",
        "Review the anomalous budget items below and produce a concise assessment (max 350 words).",
        "",
        "=== ANOMALOUS BUDGET ITEMS ===",
    ]
    for a in anomalies[:5]:
        lines.append(
            f"• [{a.get('budget_id','')}] {a.get('initiative','')} | {a.get('domain','')} "
            f"| {a.get('cost_type','')} | Amount: {a.get('amount',0):,.0f} "
            f"| Expected: {a.get('expected_amount',0):,.0f} "
            f"| Variance: {a.get('variance_pct',0):+.1f}% "
            f"| Z-score: {a.get('z_score',0):.2f} | Status: {a.get('status','')}"
        )
    if enrichment:
        lines += ["", "=== MARKET CONTEXT (internet search) ==="]
        for bid, ctx in enrichment.items():
            lines.append(f"\n[{ctx['initiative']}]")
            for snippet in ctx.get("snippets", [])[:2]:
                lines.append(f"  • {snippet[:250]}")
    if policies:
        lines += ["", "=== GOVERNANCE POLICIES ===", json.dumps(policies[:5])]
    lines += [
        "",
        "=== REQUIRED OUTPUT ===",
        "For each anomaly: (1) Is this variance justifiable given market context? "
        "(2) Likely root cause? (3) Recommended action.",
        "End with a 2-sentence overall risk assessment.",
    ]
    return "\n".join(lines)


def _generate_anomaly_narrative_gemini(
    anomalies: list[dict[str, Any]],
    enrichment: dict[str, Any],
    policies: list[str],
) -> str:
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        llm = ChatGoogleGenerativeAI(
            model=CONFIG.gemini_model,
            google_api_key=CONFIG.gemini_api_key,
            temperature=0.3,
        )
        prompt = sanitize_for_llm(_build_anomaly_prompt(anomalies, enrichment, policies))
        return str(llm.invoke(prompt).content).strip()
    except Exception as exc:
        return f"[Gemini anomaly narrative unavailable: {exc}]"


def _generate_anomaly_narrative_ollama(
    anomalies: list[dict[str, Any]],
    enrichment: dict[str, Any],
    policies: list[str],
    model: str | None = None,
) -> str:
    try:
        from langchain_ollama import ChatOllama
        gpu = _detect_ollama_gpu()
        extra: dict[str, Any] = {"num_gpu": -1} if gpu != "cpu" else {}
        llm = ChatOllama(
            base_url=CONFIG.ollama_base_url,
            model=model or CONFIG.ollama_llm_model,
            temperature=0.3,
            num_ctx=4096,
            timeout=None,
            **extra,
        )
        prompt = sanitize_for_llm(_build_anomaly_prompt(anomalies, enrichment, policies))
        return str(llm.invoke(prompt).content).strip()
    except Exception as exc:
        return f"[Ollama anomaly narrative unavailable: {exc}]"

def _run_budget_ml_analysis(budgets: list[dict[str, Any]]) -> dict[str, Any]:
    if not budgets:
        return {}

    df = pd.DataFrame(budgets)
    for col in ("initiative", "domain", "cost_type", "status", "priority", "owner", "quarter"):
        if col not in df.columns:
            df[col] = ""
        df[col] = df[col].fillna("").astype(str).str.strip()
    df["cost_type"] = df["cost_type"].replace("", "Unknown")
    df["domain"]    = df["domain"].replace("", "Unknown")
    df["amount"]    = pd.to_numeric(df.get("amount", 0), errors="coerce").fillna(0.0)

    total = df["amount"].sum()

    # ── Frequency counters ─────────────────────────────────────────────────
    by_cost_type   = dict(Counter(df["cost_type"]).most_common())
    by_domain      = dict(Counter(df["domain"]).most_common())
    by_status      = dict(Counter(df["status"]).most_common())
    by_priority    = dict(Counter(df["priority"]).most_common())
    by_owner       = dict(Counter(v for v in df["owner"] if v).most_common(15))
    by_quarter     = dict(Counter(v for v in df["quarter"] if v).most_common())

    # ── Amount aggregates ──────────────────────────────────────────────────
    capex = float(df.loc[df["cost_type"] == "Capex", "amount"].sum())
    opex  = float(df.loc[df["cost_type"] == "Opex",  "amount"].sum())

    amount_by_domain = {
        str(k): round(float(v), 2)
        for k, v in df.groupby("domain")["amount"].sum().sort_values(ascending=False).items()
    }
    amount_by_cost_type = {
        str(k): round(float(v), 2)
        for k, v in df.groupby("cost_type")["amount"].sum().items()
    }
    amount_by_status = {
        str(k): round(float(v), 2)
        for k, v in df.groupby("status")["amount"].sum().items()
    }
    amount_by_quarter = {
        str(k): round(float(v), 2)
        for k, v in df.groupby("quarter")["amount"].sum().sort_index().items()
    }
    amount_by_priority = {
        str(k): round(float(v), 2)
        for k, v in df.groupby("priority")["amount"].sum().items()
    }

    # ── Domain × cost_type breakdown ──────────────────────────────────────
    domain_cost_breakdown: list[dict[str, Any]] = []
    for (domain, ctype), grp in df.groupby(["domain", "cost_type"]):
        domain_cost_breakdown.append({
            "domain":    str(domain),
            "cost_type": str(ctype),
            "amount":    round(float(grp["amount"].sum()), 2),
            "count":     int(len(grp)),
        })

    # ── Quarter × cost_type timeline ──────────────────────────────────────
    timeline: list[dict[str, Any]] = []
    for (quarter, ctype), grp in df.groupby(["quarter", "cost_type"]):
        timeline.append({
            "quarter":   str(quarter),
            "cost_type": str(ctype),
            "amount":    round(float(grp["amount"].sum()), 2),
        })
    timeline.sort(key=lambda x: (x["quarter"], x["cost_type"]))

    # ── Amount stats ───────────────────────────────────────────────────────
    amounts = df["amount"]
    amount_stats: dict[str, Any] = {}
    if not amounts.empty:
        amount_stats = {
            "total":  round(float(total), 2),
            "mean":   round(float(amounts.mean()), 2),
            "median": round(float(amounts.median()), 2),
            "std":    round(float(amounts.std()), 2),
            "p25":    round(float(amounts.quantile(0.25)), 2),
            "p75":    round(float(amounts.quantile(0.75)), 2),
            "p95":    round(float(amounts.quantile(0.95)), 2),
            "max":    round(float(amounts.max()), 2),
        }

    # ── Outlier / anomaly detection (z-score per cost_type group) ─────────
    group_mean = df.groupby("cost_type")["amount"].transform("mean")
    group_std  = df.groupby("cost_type")["amount"].transform("std").replace(0, np.nan)
    df["z_score"] = ((df["amount"] - group_mean) / group_std).replace([np.inf, -np.inf], np.nan).fillna(0.0)

    # Expected baseline per domain × cost_type
    baseline = df.groupby(["domain", "cost_type"])["amount"].transform("median")
    fallback  = df.groupby("cost_type")["amount"].transform("median")
    df["expected_amount"] = np.where(baseline > 0, baseline, fallback)
    df["expected_amount"] = np.where(df["expected_amount"] > 0, df["expected_amount"],
                                     np.maximum(1.0, amounts.median()))
    df["variance_pct"] = np.where(
        df["expected_amount"] > 0,
        (df["amount"] - df["expected_amount"]) / df["expected_amount"] * 100.0,
        0.0,
    )
    df["outlier_score"] = (np.abs(df["z_score"]) * 0.65 + np.abs(df["variance_pct"]) / 100.0 * 0.35)
    df["is_outlier"]    = (np.abs(df["z_score"]) >= 1.5) | (np.abs(df["variance_pct"]) >= 50.0)

    anomalies: list[dict[str, Any]] = []
    for _, row in df.nlargest(10, "outlier_score").iterrows():
        if abs(row["z_score"]) < 0.5:
            continue
        anomalies.append({
            "budget_id":      str(row.get("budget_id", "")),
            "initiative":     str(row.get("initiative", ""))[:120],
            "domain":         str(row.get("domain", "")),
            "cost_type":      str(row.get("cost_type", "")),
            "owner":          str(row.get("owner", "")),
            "quarter":        str(row.get("quarter", "")),
            "status":         str(row.get("status", "")),
            "priority":       str(row.get("priority", "")),
            "amount":         round(float(row.get("amount", 0)), 2),
            "expected_amount":round(float(row.get("expected_amount", 0)), 2),
            "variance_pct":   round(float(row.get("variance_pct", 0)), 2),
            "z_score":        round(float(row.get("z_score", 0)), 3),
            "outlier_score":  round(float(row.get("outlier_score", 0)), 3),
            "is_outlier":     bool(row.get("is_outlier", False)),
        })

    # ── Unapproved high-priority items ────────────────────────────────────
    unapproved_high = df[
        (df["priority"] == "High") & (df["status"].isin(["Draft", "Planned"]))
    ][["budget_id", "initiative", "domain", "cost_type", "owner", "amount", "status"]].to_dict(orient="records")

    return {
        "total_items":          len(df),
        "total_budget":         round(float(total), 2),
        "capex":                round(capex, 2),
        "opex":                 round(opex, 2),
        "by_cost_type":         by_cost_type,
        "by_domain":            by_domain,
        "by_status":            by_status,
        "by_priority":          by_priority,
        "by_owner":             by_owner,
        "by_quarter":           by_quarter,
        "amount_by_domain":     amount_by_domain,
        "amount_by_cost_type":  amount_by_cost_type,
        "amount_by_status":     amount_by_status,
        "amount_by_quarter":    amount_by_quarter,
        "amount_by_priority":   amount_by_priority,
        "domain_cost_breakdown":domain_cost_breakdown,
        "timeline":             timeline,
        "amount_stats":         amount_stats,
        "anomalies":            anomalies,
        "unapproved_high_priority": [
            {k: str(v) if not isinstance(v, (int, float)) else v for k, v in r.items()}
            for r in unapproved_high
        ],
    }


# ── AI Narrative ───────────────────────────────────────────────────────────────

def _build_budget_narrative_prompt(analysis: dict[str, Any], policies: list[str]) -> str:
    lines = [
        "You are a senior security finance analyst.",
        "Produce a concise executive budget report (max 400 words).",
        "",
        "=== BUDGET PORTFOLIO ANALYTICS ===",
        f"Total budget: {analysis.get('total_budget', 0):,.0f}  "
        f"(Capex: {analysis.get('capex', 0):,.0f} / Opex: {analysis.get('opex', 0):,.0f})",
        f"Items: {analysis.get('total_items', 0)}",
        f"By cost type (count):  {json.dumps(analysis.get('by_cost_type', {}))}",
        f"By priority (count):   {json.dumps(analysis.get('by_priority', {}))}",
        f"By status (count):     {json.dumps(analysis.get('by_status', {}))}",
        f"Amount by domain:      {json.dumps(analysis.get('amount_by_domain', {}))}",
        f"Amount by quarter:     {json.dumps(analysis.get('amount_by_quarter', {}))}",
        f"Amount stats:          {json.dumps(analysis.get('amount_stats', {}))}",
        f"Top anomalies:         {json.dumps(analysis.get('anomalies', [])[:5])}",
        f"Unapproved high-priority items: {json.dumps(analysis.get('unapproved_high_priority', [])[:5])}",
    ]
    if policies:
        lines += ["", f"=== GOVERNANCE POLICIES ===", json.dumps(policies)]
    lines += [
        "",
        "=== OUTPUT REQUIRED ===",
        "1. Overall budget posture (is spend aligned to risk domains?)",
        "2. Top 3 anomalies or concerns",
        "3. Unapproved high-priority items that need escalation",
        "4. Top 3 actionable recommendations for budget owners",
    ]
    return "\n".join(lines)


def _generate_budget_ollama_narrative(
    analysis: dict[str, Any],
    policies: list[str],
    model: str | None = None,
) -> str:
    try:
        from langchain_ollama import ChatOllama
        gpu = _detect_ollama_gpu()
        extra: dict[str, Any] = {"num_gpu": -1} if gpu != "cpu" else {}
        llm = ChatOllama(
            base_url=CONFIG.ollama_base_url,
            model=model or CONFIG.ollama_llm_model,
            temperature=0.3,
            num_ctx=4096,
            timeout=None,
            **extra,
        )
        prompt = sanitize_for_llm(_build_budget_narrative_prompt(analysis, policies))
        return str(llm.invoke(prompt).content).strip()
    except Exception as exc:
        return f"[Ollama narrative unavailable: {exc}]"


def _generate_budget_gemini_narrative(
    analysis: dict[str, Any],
    policies: list[str],
) -> str:
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        llm = ChatGoogleGenerativeAI(
            model=CONFIG.gemini_model,
            google_api_key=CONFIG.gemini_api_key,
            temperature=0.3,
        )
        prompt = sanitize_for_llm(_build_budget_narrative_prompt(analysis, policies))
        return str(llm.invoke(prompt).content).strip()
    except Exception as exc:
        return f"[Gemini narrative unavailable: {exc}]"


# ── Runner ─────────────────────────────────────────────────────────────────────

class BudgetAnalyticsRunner:
    """Background runner: load budgets → ML analysis → optional AI narrative → JSON cache."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="budget-analytics")
        self._lock = threading.Lock()
        self._future: Future | None = None
        self._state: dict[str, Any] = {
            "status":       "idle",
            "stage":        "idle",
            "message":      "No analysis has been run yet.",
            "progress":     0.0,
            "error":        "",
            "started_at":   "",
            "updated_at":   _utc_now(),
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

    def start(
        self,
        include_ai_narrative: bool = True,
        narrative_provider: str = "gemini",
        ollama_model: str | None = None,
    ) -> bool:
        with self._lock:
            if self._future and not self._future.done():
                return False
            self._state = {
                "status":       "running",
                "stage":        "loading",
                "message":      "Loading budget data…",
                "progress":     0.01,
                "error":        "",
                "started_at":   _utc_now(),
                "updated_at":   _utc_now(),
                "completed_at": "",
            }
            self._future = self._executor.submit(
                self._run, include_ai_narrative, narrative_provider, ollama_model
            )
        return True

    def _run(
        self,
        include_ai_narrative: bool,
        narrative_provider: str,
        ollama_model: str | None,
    ) -> None:
        t0 = time.time()
        try:
            self._update(stage="loading", message="Loading budget records…", progress=0.10)
            budgets  = load_budgets()
            policies = load_budget_policies()
            policy_texts = [str(p.get("text", "")).strip() for p in policies if p.get("text")]

            self._update(stage="analysing", message=f"Running ML analysis on {len(budgets)} budget items…", progress=0.35)
            analysis = _run_budget_ml_analysis(budgets)

            # ── Internet enrichment for anomalies ──────────────────────
            self._update(stage="enriching", message="Searching internet for anomaly benchmarks…", progress=0.52)
            anomalies = analysis.get("anomalies", [])
            enrichment: dict[str, Any] = {}
            if anomalies:
                enrichment = _enrich_anomalies_internet(anomalies)

            # ── Anomaly-specific narrative ──────────────────────────────
            anomaly_narrative = ""
            if include_ai_narrative and anomalies:
                if narrative_provider == "ollama":
                    gpu = _detect_ollama_gpu()
                    used_model = ollama_model or CONFIG.ollama_llm_model
                    self._update(
                        stage="anomaly_narrative",
                        message=f"Generating anomaly narrative via Ollama ({used_model})…",
                        progress=0.62,
                    )
                    anomaly_narrative = _generate_anomaly_narrative_ollama(
                        anomalies, enrichment, policy_texts, model=used_model
                    )
                else:
                    if CONFIG.gemini_api_key:
                        self._update(
                            stage="anomaly_narrative",
                            message=f"Generating anomaly narrative via Gemini…",
                            progress=0.62,
                        )
                        anomaly_narrative = _generate_anomaly_narrative_gemini(
                            anomalies, enrichment, policy_texts
                        )
                    else:
                        anomaly_narrative = "[Gemini API key not configured — set GEMINI_API_KEY.]"

            narrative = ""
            if include_ai_narrative:
                if narrative_provider == "ollama":
                    gpu = _detect_ollama_gpu()
                    gpu_label = {"cuda": "CUDA GPU", "rocm": "ROCm GPU", "metal": "Apple Metal GPU", "cpu": "CPU"}[gpu]
                    used_model = ollama_model or CONFIG.ollama_llm_model
                    self._update(
                        stage="narrative",
                        message=f"Generating Ollama narrative ({used_model}) on {gpu_label}…",
                        progress=0.72,
                    )
                    narrative = _generate_budget_ollama_narrative(analysis, policy_texts, model=used_model)
                else:
                    if CONFIG.gemini_api_key:
                        self._update(
                            stage="narrative",
                            message=f"Generating Gemini narrative ({CONFIG.gemini_model})…",
                            progress=0.72,
                        )
                        narrative = _generate_budget_gemini_narrative(analysis, policy_texts)
                    else:
                        narrative = "[Gemini API key not configured — set GEMINI_API_KEY.]"

            self._update(stage="saving", message="Saving analytics cache…", progress=0.94)
            payload: dict[str, Any] = {
                "generated_at":        _utc_now(),
                "duration_seconds":    round(time.time() - t0, 1),
                "narrative_provider":  narrative_provider if include_ai_narrative else "none",
                "analysis":            analysis,
                "ai_narrative":        narrative,
                "anomaly_enrichment":  enrichment,
                "anomaly_narrative":   anomaly_narrative,
                "policies":            policy_texts,
            }
            save_budget_analytics(payload)

            self._update(
                status="completed",
                stage="done",
                message=f"Analysis complete — {len(budgets)} items in {payload['duration_seconds']}s.",
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
