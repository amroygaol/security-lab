from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd
import plotly.graph_objects as go


# ---------------------------------------------------------------------------
# Input model
# ---------------------------------------------------------------------------

@dataclass
class CapacityInput:
    """All parameters supplied by the user for capacity planning."""

    # Growth & scale
    current_users: int = 1_000
    annual_growth_pct: float = 20.0          # % per year
    forecast_years: int = 3

    # Network / bandwidth
    avg_bandwidth_mbps_per_user: float = 0.5  # Mbps
    peak_multiplier: float = 3.0             # peak / average ratio
    bandwidth_overhead_pct: float = 20.0     # headroom %

    # Compute
    avg_cpu_cores_per_1k_users: float = 4.0
    avg_ram_gb_per_1k_users: float = 8.0

    # Storage
    avg_log_gb_per_user_per_year: float = 0.5  # GB raw logs
    log_retention_years: int = 1
    compression_ratio: float = 4.0            # e.g. 4:1

    # Security tool cluster sizing
    tool_name: str = "SIEM / WAF cluster"
    nodes_per_1k_users: float = 0.5          # cluster node ratio
    ha_redundancy_factor: float = 2.0        # HA multiplier (e.g. N+1 = 2)

    # Cost inputs
    cost_per_cpu_core_usd: float = 50.0
    cost_per_ram_gb_usd: float = 8.0
    cost_per_tb_storage_usd: float = 30.0
    cost_per_bandwidth_mbps_usd: float = 5.0  # per Mbps/month

    # Regression / ML
    historical_users: list[int] = field(default_factory=list)     # optional past points
    historical_years: list[int] = field(default_factory=list)     # matching years


# ---------------------------------------------------------------------------
# Output model
# ---------------------------------------------------------------------------

@dataclass
class YearlyProjection:
    year: int
    users: int
    bandwidth_avg_mbps: float
    bandwidth_peak_mbps: float
    bandwidth_provisioned_mbps: float
    cpu_cores: float
    ram_gb: float
    storage_tb: float
    cluster_nodes: float
    est_monthly_cost_usd: float
    yoy_growth_pct: float


@dataclass
class CapacityForecast:
    projections: list[YearlyProjection]
    ml_model_used: str
    r2_score: float | None
    summary_df: pd.DataFrame
    charts: dict[str, go.Figure]
    alert_messages: list[str]


# ---------------------------------------------------------------------------
# Forecasting engine
# ---------------------------------------------------------------------------

class _GrowthModel:
    """Fits historical data (if any) with polynomial regression; otherwise uses compound growth."""

    def __init__(self, historical_years: list[int], historical_users: list[int]) -> None:
        self._has_data = len(historical_years) >= 3 and len(historical_users) == len(historical_years)
        self._coeffs: np.ndarray | None = None
        self._r2: float | None = None
        self._model_name = "Compound Annual Growth"
        self._base_year: int = 0

        if self._has_data:
            x = np.array(historical_years, dtype=float)
            y = np.array(historical_users, dtype=float)
            self._base_year = int(x[0])
            x_norm = x - self._base_year
            # fit polynomial degree 2 when we have enough points, else linear
            degree = 2 if len(x) >= 5 else 1
            self._coeffs = np.polyfit(x_norm, y, deg=degree)
            y_pred = np.polyval(self._coeffs, x_norm)
            ss_res = float(np.sum((y - y_pred) ** 2))
            ss_tot = float(np.sum((y - y.mean()) ** 2))
            self._r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else None
            self._model_name = f"Polynomial regression (degree {degree})"

    def predict(self, base_users: int, base_year: int, years_ahead: int, cagr: float) -> list[int]:
        results: list[int] = []
        for step in range(1, years_ahead + 1):
            yr = base_year + step
            if self._has_data and self._coeffs is not None:
                x_norm = float(yr - self._base_year)
                val = float(np.polyval(self._coeffs, x_norm))
                results.append(max(1, int(round(val))))
            else:
                results.append(int(round(base_users * ((1 + cagr / 100) ** step))))
        return results

    @property
    def r2(self) -> float | None:
        return self._r2

    @property
    def model_name(self) -> str:
        return self._model_name


def _current_year() -> int:
    from datetime import date
    return date.today().year


def run_capacity_forecast(inp: CapacityInput) -> CapacityForecast:
    import warnings
    warnings.filterwarnings("ignore", category=np.RankWarning)

    model = _GrowthModel(inp.historical_years, inp.historical_users)
    base_year = _current_year()
    future_users = model.predict(inp.current_users, base_year, inp.forecast_years, inp.annual_growth_pct)

    projections: list[YearlyProjection] = []
    prev_users = inp.current_users
    alerts: list[str] = []

    for i, (yr, users) in enumerate(zip(range(base_year + 1, base_year + inp.forecast_years + 1), future_users)):
        # Growth
        yoy = ((users - prev_users) / prev_users * 100) if prev_users else 0.0

        # Bandwidth
        bw_avg = users * inp.avg_bandwidth_mbps_per_user
        bw_peak = bw_avg * inp.peak_multiplier
        bw_prov = bw_peak * (1 + inp.bandwidth_overhead_pct / 100)

        # Compute (scale by kilo-users)
        ku = users / 1_000
        cpu = ku * inp.avg_cpu_cores_per_1k_users
        ram = ku * inp.avg_ram_gb_per_1k_users

        # Storage (cumulative retention)
        raw_tb = users * inp.avg_log_gb_per_user_per_year * inp.log_retention_years / 1_000
        stored_tb = raw_tb / inp.compression_ratio

        # Cluster nodes
        nodes = math.ceil(ku * inp.nodes_per_1k_users * inp.ha_redundancy_factor)

        # Monthly cost (USD)
        cost = (
            cpu * inp.cost_per_cpu_core_usd
            + ram * inp.cost_per_ram_gb_usd
            + stored_tb * 1_000 * inp.cost_per_tb_storage_usd / 12  # storage annualised
            + bw_prov * inp.cost_per_bandwidth_mbps_usd
        )

        # Alerts
        if yoy > 50:
            alerts.append(f"Year {yr}: Hyper-growth alert — {yoy:.0f}% YoY increase. Review node auto-scaling policy.")
        if bw_prov > 10_000:
            alerts.append(f"Year {yr}: Provisioned bandwidth exceeds 10 Gbps ({bw_prov:.0f} Mbps). Cloud burst or ISP upgrade advised.")
        if stored_tb > 500:
            alerts.append(f"Year {yr}: Log storage projection exceeds 500 TB ({stored_tb:.0f} TB). Tiered/cold storage required.")

        projections.append(YearlyProjection(
            year=yr,
            users=users,
            bandwidth_avg_mbps=round(bw_avg, 1),
            bandwidth_peak_mbps=round(bw_peak, 1),
            bandwidth_provisioned_mbps=round(bw_prov, 1),
            cpu_cores=round(cpu, 1),
            ram_gb=round(ram, 1),
            storage_tb=round(stored_tb, 2),
            cluster_nodes=float(nodes),
            est_monthly_cost_usd=round(cost, 2),
            yoy_growth_pct=round(yoy, 1),
        ))
        prev_users = users

    summary_df = _to_df(inp, projections)
    charts = _build_charts(inp, projections)

    return CapacityForecast(
        projections=projections,
        ml_model_used=model.model_name,
        r2_score=model.r2,
        summary_df=summary_df,
        charts=charts,
        alert_messages=alerts,
    )


def _to_df(inp: CapacityInput, projections: list[YearlyProjection]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for p in projections:
        rows.append({
            "Year": p.year,
            "Projected Users": p.users,
            "YoY Growth (%)": p.yoy_growth_pct,
            "Avg Bandwidth (Mbps)": p.bandwidth_avg_mbps,
            "Peak Bandwidth (Mbps)": p.bandwidth_peak_mbps,
            "Provisioned BW (Mbps)": p.bandwidth_provisioned_mbps,
            "CPU Cores": p.cpu_cores,
            "RAM (GB)": p.ram_gb,
            "Storage (TB)": p.storage_tb,
            f"{inp.tool_name} Nodes": p.cluster_nodes,
            "Est. Monthly Cost (USD)": p.est_monthly_cost_usd,
        })
    return pd.DataFrame(rows)


def _build_charts(inp: CapacityInput, projections: list[YearlyProjection]) -> dict[str, go.Figure]:
    years = [p.year for p in projections]
    users = [p.users for p in projections]
    cpu = [p.cpu_cores for p in projections]
    ram = [p.ram_gb for p in projections]
    storage = [p.storage_tb for p in projections]
    bw_avg = [p.bandwidth_avg_mbps for p in projections]
    bw_peak = [p.bandwidth_peak_mbps for p in projections]
    bw_prov = [p.bandwidth_provisioned_mbps for p in projections]
    cost = [p.est_monthly_cost_usd for p in projections]
    nodes = [p.cluster_nodes for p in projections]

    # --- User growth ---
    fig_users = go.Figure()
    fig_users.add_trace(go.Scatter(x=years, y=users, mode="lines+markers+text",
                                   text=[f"{u:,}" for u in users],
                                   textposition="top center",
                                   name="Projected Users",
                                   line=dict(color="#4785ff", width=3)))
    fig_users.update_layout(title="User Growth Projection", xaxis_title="Year", yaxis_title="Users")

    # --- Resource projection ---
    fig_resources = go.Figure()
    fig_resources.add_trace(go.Bar(x=years, y=cpu, name="CPU Cores", marker_color="#f4a261"))
    fig_resources.add_trace(go.Bar(x=years, y=ram, name="RAM (GB)", marker_color="#2a9d8f"))
    fig_resources.update_layout(barmode="group", title="Compute Resources", xaxis_title="Year", yaxis_title="Count / GB")

    # --- Storage projection ---
    fig_storage = go.Figure()
    fig_storage.add_trace(go.Bar(x=years, y=storage, name="Storage (TB)", marker_color="#e76f51"))
    fig_storage.update_layout(title="Log Storage Growth (TB)", xaxis_title="Year", yaxis_title="Terabytes")

    # --- Bandwidth ---
    fig_bw = go.Figure()
    fig_bw.add_trace(go.Scatter(x=years, y=bw_avg, name="Avg BW", mode="lines+markers", line=dict(color="#a8dadc")))
    fig_bw.add_trace(go.Scatter(x=years, y=bw_peak, name="Peak BW", mode="lines+markers", line=dict(color="#457b9d", dash="dash")))
    fig_bw.add_trace(go.Scatter(x=years, y=bw_prov, name="Provisioned BW", mode="lines+markers", line=dict(color="#e63946", dash="dot")))
    fig_bw.update_layout(title="Bandwidth Requirements (Mbps)", xaxis_title="Year", yaxis_title="Mbps")

    # --- Cost trend ---
    fig_cost = go.Figure()
    fig_cost.add_trace(go.Scatter(x=years, y=cost, mode="lines+markers+text",
                                   text=[f"${c:,.0f}" for c in cost],
                                   textposition="top center",
                                   name="Est. Monthly Cost (USD)",
                                   line=dict(color="#8e44ad", width=3)))
    fig_cost.update_layout(title="Estimated Monthly Platform Cost (USD)", xaxis_title="Year", yaxis_title="USD / Month")

    # --- Cluster nodes ---
    fig_nodes = go.Figure()
    fig_nodes.add_trace(go.Bar(x=years, y=nodes, name=f"{inp.tool_name} Nodes", marker_color="#1d3557"))
    fig_nodes.update_layout(title=f"{inp.tool_name} — Node Scaling", xaxis_title="Year", yaxis_title="Nodes")

    return {
        "user_growth": fig_users,
        "resources": fig_resources,
        "storage": fig_storage,
        "bandwidth": fig_bw,
        "cost": fig_cost,
        "nodes": fig_nodes,
    }
