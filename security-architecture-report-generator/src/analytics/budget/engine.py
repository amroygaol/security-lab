from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama
from llama_index.core import Document, VectorStoreIndex
from llama_index.core.embeddings import MockEmbedding

from ...core.config import CONFIG
from ...data.report_store import list_reports, load_report
from ...core.security import sanitize_for_llm


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


@dataclass
class BudgetAnalyticsResult:
    analyzed_df: pd.DataFrame
    variance_by_type: pd.DataFrame
    top_anomalies: list[dict[str, Any]]
    context_snippets: list[str]
    anomaly_payload_json: str
    narrative: str
    charts: dict[str, go.Figure]


class BudgetAnalyzer:
    def __init__(self, budgets_df: pd.DataFrame) -> None:
        self.raw_df = budgets_df.copy()

    def analyze(self) -> pd.DataFrame:
        if self.raw_df.empty:
            return self.raw_df

        df = self.raw_df.copy()
        for column in ["budget_id", "initiative", "cost_type", "domain", "owner", "quarter", "status", "priority", "notes"]:
            if column not in df.columns:
                df[column] = ""
            df[column] = df[column].astype(str)

        df["cost_type"] = df["cost_type"].str.strip().replace("", "Unknown")
        df["domain"] = df["domain"].str.strip().replace("", "Unknown")
        df["quarter"] = df["quarter"].str.strip().replace("", "Unknown")
        df["amount"] = pd.to_numeric(df.get("amount", 0.0), errors="coerce").fillna(0.0)

        cost_type_baseline = df.groupby("cost_type")["amount"].transform("median")
        domain_cost_baseline = df.groupby(["domain", "cost_type"])["amount"].transform("median")
        expected_amount = np.where(domain_cost_baseline > 0, domain_cost_baseline, cost_type_baseline)
        expected_amount = np.where(expected_amount > 0, expected_amount, np.maximum(1.0, df["amount"].median()))

        df["expected_amount"] = expected_amount
        df["variance_amount"] = df["amount"] - df["expected_amount"]
        df["variance_pct"] = np.where(
            df["expected_amount"] > 0,
            (df["variance_amount"] / df["expected_amount"]) * 100.0,
            0.0,
        )

        group_mean = df.groupby("cost_type")["amount"].transform("mean")
        group_std = df.groupby("cost_type")["amount"].transform("std").replace(0, np.nan)
        df["z_score"] = ((df["amount"] - group_mean) / group_std).replace([np.inf, -np.inf], np.nan).fillna(0.0)
        df["outlier_score"] = (np.abs(df["z_score"]) * 0.65) + (np.abs(df["variance_pct"]) / 100.0 * 0.35)
        df["is_outlier"] = (np.abs(df["z_score"]) >= 1.5) | (np.abs(df["variance_pct"]) >= 50.0)

        return df.sort_values(by="outlier_score", ascending=False).reset_index(drop=True)

    @staticmethod
    def variance_summary(analyzed_df: pd.DataFrame) -> pd.DataFrame:
        if analyzed_df.empty:
            return pd.DataFrame()

        summary = (
            analyzed_df.groupby("cost_type", as_index=False)
            .agg(
                total_amount=("amount", "sum"),
                expected_total=("expected_amount", "sum"),
                avg_variance_pct=("variance_pct", "mean"),
                anomalies=("is_outlier", "sum"),
            )
            .sort_values(by="total_amount", ascending=False)
        )
        summary["variance_amount"] = summary["total_amount"] - summary["expected_total"]
        return summary

    @staticmethod
    def _severity(outlier_score: float, variance_pct: float) -> str:
        magnitude = max(abs(outlier_score), abs(variance_pct) / 100.0)
        if magnitude >= 1.6:
            return "Critical"
        if magnitude >= 1.1:
            return "High"
        if magnitude >= 0.6:
            return "Medium"
        return "Low"

    @staticmethod
    def _owner_action_trigger(status: str, severity: str) -> str:
        status_key = _safe_text(status).lower()
        if severity in {"Critical", "High"}:
            if status_key in {"draft", "planned"}:
                return "Escalate for finance + architecture approval before commitment"
            return "Open variance investigation ticket with budget owner"
        if severity == "Medium":
            return "Review baseline assumptions in next planning cycle"
        return "Monitor only"

    @staticmethod
    def top_anomalies(analyzed_df: pd.DataFrame, top_n: int = 5) -> list[dict[str, Any]]:
        if analyzed_df.empty:
            return []

        candidates = analyzed_df.sort_values(by="outlier_score", ascending=False).head(top_n)
        records: list[dict[str, Any]] = []
        for _, row in candidates.iterrows():
            outlier_score = round(_safe_float(row.get("outlier_score")), 3)
            variance_pct = round(_safe_float(row.get("variance_pct")), 2)
            severity = BudgetAnalyzer._severity(outlier_score, variance_pct)
            status = _safe_text(row.get("status"))
            records.append(
                {
                    "budget_id": _safe_text(row.get("budget_id")),
                    "initiative": _safe_text(row.get("initiative")),
                    "owner": _safe_text(row.get("owner")),
                    "cost_type": _safe_text(row.get("cost_type")),
                    "domain": _safe_text(row.get("domain")),
                    "quarter": _safe_text(row.get("quarter")),
                    "status": status,
                    "amount": round(_safe_float(row.get("amount")), 2),
                    "expected_amount": round(_safe_float(row.get("expected_amount")), 2),
                    "variance_amount": round(_safe_float(row.get("variance_amount")), 2),
                    "variance_pct": variance_pct,
                    "z_score": round(_safe_float(row.get("z_score")), 3),
                    "outlier_score": outlier_score,
                    "severity": severity,
                    "owner_action": BudgetAnalyzer._owner_action_trigger(status, severity),
                }
            )
        return records


class BudgetContextEnricher:
    def __init__(self, policy_docs: list[str] | None = None, report_limit: int = 20) -> None:
        self.policy_docs = policy_docs or []
        self.report_limit = report_limit
        self.index: VectorStoreIndex | None = None

    def build_index(self) -> None:
        docs: list[Document] = []

        for policy in self.policy_docs:
            clean = sanitize_for_llm(_safe_text(policy))
            if clean:
                docs.append(Document(text=clean, metadata={"source": "budget_policy"}))

        for report in list_reports(limit=self.report_limit):
            path = _safe_text(report.get("markdown_path"))
            if not path:
                continue
            try:
                body = load_report(path)
            except Exception:
                continue
            if not body.strip():
                continue
            docs.append(
                Document(
                    text=sanitize_for_llm(body[:5000]),
                    metadata={"source": "historical_security_report", "report_id": _safe_text(report.get("id"))},
                )
            )

        if not docs:
            self.index = None
            return

        self.index = VectorStoreIndex.from_documents(docs, embed_model=MockEmbedding(embed_dim=384))

    def retrieve_context(self, query: str, top_k: int = 5) -> list[str]:
        if self.index is None:
            return []
        retriever = self.index.as_retriever(similarity_top_k=top_k)
        try:
            nodes = retriever.retrieve(query)
        except Exception:
            return []
        snippets: list[str] = []
        for node in nodes:
            text = _safe_text(getattr(node, "text", ""))
            if text:
                snippets.append(text[:600])
        return snippets


class BudgetInsightGenerator:
    def __init__(self) -> None:
        self.llm = ChatOllama(
            base_url=CONFIG.ollama_base_url,
            model=CONFIG.ollama_llm_model,
            temperature=0.1,
            client_kwargs={"timeout": CONFIG.ollama_timeout_seconds},
        )
        self.prompt = ChatPromptTemplate.from_template(
            """
You are a senior financial analytics assistant.

Use ONLY the pre-processed analytics provided below. Do not ask for raw numbers and do not invent additional records.

Tasks:
1. Explain the top anomalies in plain language for executives.
2. Highlight OpEx and CapEx variance direction and risk.
3. Recommend 3 practical actions for budget owners.
4. Keep it concise and actionable.

Top-5 anomalies JSON:
{anomalies_json}

Variance summary by cost type:
{variance_summary}

Retrieved policy/report context:
{context_text}
"""
        )

    def explain(self, anomalies_json: str, variance_summary: str, context_text: str) -> str:
        chain = self.prompt | self.llm
        payload = {
            "anomalies_json": sanitize_for_llm(anomalies_json),
            "variance_summary": sanitize_for_llm(variance_summary),
            "context_text": sanitize_for_llm(context_text),
        }
        try:
            response = chain.invoke(payload)
            return _safe_text(getattr(response, "content", response))
        except Exception:
            return (
                "AI narrative is temporarily unavailable. Review the top anomalies and prioritize large positive variance "
                "items in Planned or Draft status, then align CapEx/Opex baseline assumptions before approval."
            )


class BudgetVisualizer:
    @staticmethod
    def build_charts(analyzed_df: pd.DataFrame, anomalies: list[dict[str, Any]]) -> dict[str, go.Figure]:
        if analyzed_df.empty:
            return {}

        quarter_rollup = (
            analyzed_df.groupby(["quarter", "cost_type"], as_index=False)
            .agg(amount=("amount", "sum"), expected=("expected_amount", "sum"))
            .sort_values(by="quarter")
        )

        fig_variance = px.bar(
            quarter_rollup,
            x="quarter",
            y="amount",
            color="cost_type",
            barmode="group",
            title="Budget by Quarter and Cost Type",
            labels={"amount": "Amount", "quarter": "Quarter", "cost_type": "Cost Type"},
        )
        expected_line = quarter_rollup.groupby("quarter", as_index=False)["expected"].sum()
        fig_variance.add_trace(
            go.Scatter(
                x=expected_line["quarter"],
                y=expected_line["expected"],
                mode="lines+markers",
                name="Expected Baseline",
            )
        )

        scatter_source = analyzed_df.copy()
        scatter_source["anomaly_flag"] = np.where(scatter_source["is_outlier"], "Outlier", "Normal")
        fig_outliers = px.scatter(
            scatter_source,
            x="expected_amount",
            y="amount",
            color="anomaly_flag",
            size=np.maximum(scatter_source["outlier_score"], 0.05),
            hover_data=["budget_id", "initiative", "cost_type", "domain", "variance_pct"],
            title="Expected vs Actual Budget (Outlier Detection)",
            labels={"expected_amount": "Expected", "amount": "Actual"},
        )

        anomaly_df = pd.DataFrame(anomalies)
        if anomaly_df.empty:
            fig_top_anomalies = go.Figure()
            fig_top_anomalies.update_layout(title="Top Anomalies")
        else:
            fig_top_anomalies = px.bar(
                anomaly_df,
                x="budget_id",
                y="variance_pct",
                color="cost_type",
                hover_data=["initiative", "quarter", "domain", "status", "outlier_score"],
                title="Top 5 Variance Anomalies",
                labels={"variance_pct": "Variance %", "budget_id": "Budget ID"},
            )

        return {
            "quarterly_budget": fig_variance,
            "outlier_scatter": fig_outliers,
            "top_anomalies": fig_top_anomalies,
        }


def default_budget_policy_documents() -> list[str]:
    return [
        "CapEx initiatives above 20% variance from baseline require architecture governance review.",
        "OpEx growth above 15% quarter-over-quarter should include operational efficiency justification.",
        "Draft and Planned items with High priority should have owner and risk notes before approval.",
        "Budget anomalies should be triaged with status, owner accountability, and expected mitigation outcome.",
    ]


def run_budget_ai_analytics(
    budgets_df: pd.DataFrame,
    policy_docs: list[str] | None = None,
    progress_callback: Callable[[str, str, float], None] | None = None,
    cancel_checker: Callable[[], bool] | None = None,
) -> BudgetAnalyticsResult:
    def _notify(stage: str, message: str, progress: float) -> None:
        if progress_callback is not None:
            progress_callback(stage, message, progress)

    def _check_cancel() -> None:
        if cancel_checker is not None and bool(cancel_checker()):
            raise RuntimeError("Budget AI analysis canceled by user")

    _notify("init", "Initializing AI analytics pipeline", 0.05)
    _check_cancel()
    analyzer = BudgetAnalyzer(budgets_df)

    _notify("analysis", "Running variance and outlier analysis with Pandas/Numpy", 0.20)
    _check_cancel()
    analyzed_df = analyzer.analyze()

    _notify("summary", "Computing OpEx/CapEx variance summary", 0.35)
    _check_cancel()
    variance_by_type = BudgetAnalyzer.variance_summary(analyzed_df)

    _notify("anomalies", "Selecting top 5 anomalies", 0.45)
    _check_cancel()
    anomalies = BudgetAnalyzer.top_anomalies(analyzed_df, top_n=5)

    anomaly_payload_json = json.dumps({"top_5_anomalies": anomalies}, indent=2)

    _notify("context_index", "Building llama-index policy/report context index", 0.60)
    _check_cancel()
    context_enricher = BudgetContextEnricher(policy_docs=policy_docs or default_budget_policy_documents(), report_limit=20)
    context_enricher.build_index()

    _notify("context_retrieve", "Retrieving contextual snippets for explanation", 0.70)
    _check_cancel()
    context_snippets = context_enricher.retrieve_context(
        "budget variance governance, capex opex control, security investment prioritization",
        top_k=5,
    )

    variance_summary_text = variance_by_type.to_json(orient="records") if not variance_by_type.empty else "[]"
    context_text = "\n\n".join(context_snippets) if context_snippets else "No policy/report context available."

    _notify("llm", "Generating narrative insight with Ollama", 0.85)
    _check_cancel()
    insight_generator = BudgetInsightGenerator()
    narrative = insight_generator.explain(
        anomalies_json=anomaly_payload_json,
        variance_summary=variance_summary_text,
        context_text=context_text,
    )

    _notify("visuals", "Rendering Plotly visualizations", 0.93)
    _check_cancel()
    charts = BudgetVisualizer.build_charts(analyzed_df, anomalies)

    _notify("complete", "AI analytics complete", 1.00)

    return BudgetAnalyticsResult(
        analyzed_df=analyzed_df,
        variance_by_type=variance_by_type,
        top_anomalies=anomalies,
        context_snippets=context_snippets,
        anomaly_payload_json=anomaly_payload_json,
        narrative=narrative,
        charts=charts,
    )

