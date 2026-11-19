from __future__ import annotations

from typing import TYPE_CHECKING

from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama

from ...core.config import CONFIG
from ...core.security import sanitize_for_llm

if TYPE_CHECKING:
    from .engine import CapacityForecast, CapacityInput


_PROMPT = ChatPromptTemplate.from_template(
    """
You are a senior security infrastructure architect and capacity planning expert.

A capacity planning analysis has been run for a {tool_name} deployment. Your task is to write
a professional, actionable planning narrative for security leadership.

== INPUT PARAMETERS ==
- Current Users         : {current_users:,}
- Annual Growth Rate    : {growth_pct:.1f}%
- Forecast Horizon      : {forecast_years} year(s)
- Avg Bandwidth/User    : {bw_per_user} Mbps
- Peak Multiplier       : {peak_mult}x
- HA Redundancy Factor  : {ha_factor}x
- Log Retention         : {retention_years} year(s)
- Compression Ratio     : {compression}:1
- ML Model Used         : {ml_model}
- Model R² Score        : {r2}

== PROJECTED SUMMARY (per year) ==
{projection_table}

== ALERTS ==
{alerts}

TASKS:
1. Summarise the capacity outlook in 2-3 sentences for an executive audience (no numbers overload).
2. Highlight the top 2-3 infrastructure risks based on the projections.
3. Recommend specific, prioritised actions (hardware procurement window, bandwidth contracts, storage tiering, HA strategy).
4. Comment on cost efficiency opportunities.
5. Keep the total response under 600 words.
"""
)


def generate_capacity_narrative(
    inp: "CapacityInput",
    forecast: "CapacityForecast",
) -> str:
    llm = ChatOllama(
        base_url=CONFIG.ollama_base_url,
        model=CONFIG.ollama_llm_model,
        temperature=0.2,
        client_kwargs={"timeout": CONFIG.ollama_timeout_seconds},
    )
    chain = _PROMPT | llm

    # Build a compact projection table string
    lines = ["Year | Users | CPU | RAM(GB) | Storage(TB) | BW-Prov(Mbps) | Nodes | Cost/mo(USD)"]
    lines.append("-" * 90)
    for p in forecast.projections:
        lines.append(
            f"{p.year} | {p.users:,} | {p.cpu_cores:.0f} | {p.ram_gb:.0f} | "
            f"{p.storage_tb:.1f} | {p.bandwidth_provisioned_mbps:.0f} | "
            f"{p.cluster_nodes:.0f} | ${p.est_monthly_cost_usd:,.0f}"
        )
    projection_table = "\n".join(lines)

    alerts_text = "\n".join(f"- {a}" for a in forecast.alert_messages) if forecast.alert_messages else "No critical alerts."

    payload = {
        "tool_name": sanitize_for_llm(inp.tool_name),
        "current_users": inp.current_users,
        "growth_pct": inp.annual_growth_pct,
        "forecast_years": inp.forecast_years,
        "bw_per_user": inp.avg_bandwidth_mbps_per_user,
        "peak_mult": inp.peak_multiplier,
        "ha_factor": inp.ha_redundancy_factor,
        "retention_years": inp.log_retention_years,
        "compression": inp.compression_ratio,
        "ml_model": sanitize_for_llm(forecast.ml_model_used),
        "r2": f"{forecast.r2_score:.4f}" if forecast.r2_score is not None else "N/A (compound growth used)",
        "projection_table": sanitize_for_llm(projection_table),
        "alerts": sanitize_for_llm(alerts_text),
    }

    try:
        response = chain.invoke(payload)
        return str(getattr(response, "content", response)).strip()
    except Exception:
        return (
            "AI narrative is temporarily unavailable. "
            "Review the projection table and alerts above. "
            "Prioritise procurement windows for the highest-growth years and confirm bandwidth contracts 12 months in advance."
        )
