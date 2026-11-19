from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from ...core.config import CONFIG as _CFG
from ...data.budget_analytics_store import budget_analytics_age_seconds, load_budget_analytics
from ...jobs.soc_analytics_runner import _detect_ollama_gpu, _list_ollama_models


def _idr(value: float) -> str:
    """Format a number as Indonesian Rupiah: Rp 1.234.567"""
    return "Rp " + f"{int(round(value)):,}".replace(",", ".")


# ── Chart helpers ──────────────────────────────────────────────────────────────

def _hbar(by: dict, title: str, color: str = "#6c6ef7", top_n: int = 20) -> go.Figure:
    if not by:
        return go.Figure().add_annotation(text="No data")
    items = list(by.items())[:top_n]
    names, vals = zip(*items)
    fig = go.Figure(data=[go.Bar(
        x=list(vals), y=list(names), orientation="h",
        marker=dict(color=color),
        hovertemplate="%{y}: <b>%{customdata}</b><extra></extra>",
        customdata=[_idr(v) for v in vals],
    )])
    fig.update_layout(
        title=title,
        xaxis=dict(
            title="Amount (IDR)",
            tickformat=",.0f",
            tickprefix="Rp ",
        ),
        yaxis=dict(autorange="reversed"),
        height=max(360, len(items) * 26),
        showlegend=False, margin=dict(t=40, b=20, l=10, r=10),
    )
    return fig


def _pie(by: dict, title: str) -> go.Figure:
    if not by:
        return go.Figure().add_annotation(text="No data")
    fig = go.Figure(data=[go.Pie(
        labels=list(by.keys()), values=list(by.values()), hole=0.4,
    )])
    fig.update_layout(title=title, height=370, margin=dict(t=40, b=20, l=10, r=10))
    return fig


def _stacked_bar_timeline(timeline: list[dict[str, Any]]) -> go.Figure:
    if not timeline:
        return go.Figure().add_annotation(text="No timeline data")
    df = pd.DataFrame(timeline)
    quarters = sorted(df["quarter"].unique())
    cost_types = sorted(df["cost_type"].unique())
    colors = {"Capex": "#6c6ef7", "Opex": "#3ecf8e"}
    fig = go.Figure()
    for ct in cost_types:
        sub = df[df["cost_type"] == ct].set_index("quarter")["amount"].reindex(quarters, fill_value=0)
        fig.add_trace(go.Bar(
            name=ct, x=quarters, y=sub.values,
            marker_color=colors.get(ct, "#f5a623"),
        ))
    fig.update_layout(
        title="Budget Spend — Quarter × Cost Type",
        barmode="stack",
        xaxis_title="Quarter",
        yaxis=dict(
            title="Amount (IDR)",
            tickformat=",.0f",
            tickprefix="Rp ",
        ),
        height=380, hovermode="x unified",
        legend=dict(orientation="h", y=1.08),
        margin=dict(t=60, b=20, l=10, r=10),
    )
    return fig


def _domain_heatmap(breakdown: list[dict[str, Any]]) -> go.Figure:
    if not breakdown:
        return go.Figure().add_annotation(text="No data")
    df = pd.DataFrame(breakdown)
    pivot = df.pivot_table(index="domain", columns="cost_type", values="amount", fill_value=0)
    fig = go.Figure(data=go.Heatmap(
        z=pivot.values.tolist(),
        x=list(pivot.columns),
        y=list(pivot.index),
        colorscale="Blues",
        text=[[_idr(v) for v in row] for row in pivot.values.tolist()],
        texttemplate="%{text}",
    ))
    fig.update_layout(
        title="Budget Amount — Domain × Cost Type Heatmap",
        height=max(400, len(pivot) * 30),
        margin=dict(t=40, b=20, l=10, r=10),
    )
    return fig


def _amount_stats_bar(stats: dict[str, Any]) -> go.Figure:
    if not stats:
        return go.Figure().add_annotation(text="No stats")
    keys = ["mean", "median", "p25", "p75", "p95", "max"]
    vals = [stats.get(k, 0) for k in keys]
    fig = go.Figure(data=[go.Bar(
        x=keys, y=vals, marker=dict(color="#9396fa"),
        hovertemplate="%{x}: <b>%{customdata}</b><extra></extra>",
        customdata=[_idr(v) for v in vals],
    )])
    fig.update_layout(
        title="Amount Distribution (percentiles)",
        xaxis_title="Percentile",
        yaxis=dict(
            title="IDR",
            tickformat=",.0f",
            tickprefix="Rp ",
        ),
        height=340, showlegend=False,
        margin=dict(t=40, b=20, l=10, r=10),
    )
    return fig


def _anomaly_scatter(anomalies: list[dict[str, Any]]) -> go.Figure:
    if not anomalies:
        return go.Figure().add_annotation(text="No anomalies detected")
    df = pd.DataFrame(anomalies)
    # Ensure numeric types are plain Python floats for Plotly compatibility
    df["amount"]          = pd.to_numeric(df["amount"],          errors="coerce").fillna(0.0)
    df["expected_amount"] = pd.to_numeric(df["expected_amount"], errors="coerce").fillna(0.0)
    df["outlier_score"]   = pd.to_numeric(df["outlier_score"],   errors="coerce").fillna(0.1)
    colors = {"Capex": "#6c6ef7", "Opex": "#3ecf8e"}
    fig = go.Figure()
    for ct in df["cost_type"].unique():
        sub = df[df["cost_type"] == ct]
        sizes = (sub["outlier_score"].clip(lower=0.1) * 20).tolist()
        labels = [str(s)[:30] + "…" if len(str(s)) > 30 else str(s) for s in sub["initiative"]]
        fig.add_trace(go.Scatter(
            x=sub["expected_amount"].tolist(), y=sub["amount"].tolist(),
            mode="markers+text",
            text=labels,
            textposition="top center",
            textfont=dict(size=9),
            marker=dict(
                size=sizes,
                color=colors.get(ct, "#f5a623"),
                opacity=0.8,
                line=dict(width=1, color="rgba(255,255,255,0.27)"),
            ),
            name=ct,
            hovertemplate="<b>%{text}</b><br>Expected: %{x:,.0f}<br>Actual: %{y:,.0f}<extra></extra>",
        ))
    # Diagonal reference line
    all_vals = list(df["expected_amount"]) + list(df["amount"])
    maxv = max(all_vals) if all_vals else 1
    fig.add_trace(go.Scatter(
        x=[0, maxv], y=[0, maxv],
        mode="lines",
        line=dict(color="rgba(255,255,255,0.2)", dash="dash"),
        showlegend=False,
    ))
    fig.update_layout(
        title="Expected vs Actual Spend (Top Anomalies)",
        xaxis=dict(
            title="Expected (IDR)",
            tickformat=",.0f",
            tickprefix="Rp ",
        ),
        yaxis=dict(
            title="Actual (IDR)",
            tickformat=",.0f",
            tickprefix="Rp ",
        ),
        height=420, hovermode="closest",
        margin=dict(t=40, b=20, l=10, r=10),
    )
    return fig


# ── Animation (same pattern as SOC) ───────────────────────────────────────────

def _render_analysis_animation(state: dict) -> None:
    progress = float(state.get("progress", 0.0))
    stage    = str(state.get("stage", "loading")).lower()
    message  = str(state.get("message", "Processing…"))
    pct      = int(progress * 100)

    _STAGES = {
        "loading":          ("📂", "Loading Budget Data",             "#6c6ef7"),
        "analysing":        ("🧠", "Running ML Analysis",             "#3ecf8e"),
        "enriching":        ("🌐", "Fetching Internet Benchmarks",    "#f5a623"),
        "anomaly_narrative":("🔍", "Generating Anomaly Narrative",    "#9396fa"),
        "narrative":        ("✨", "Generating AI Narrative",         "#f5a623"),
        "saving":           ("💾", "Saving Analytics Cache",          "#9396fa"),
        "done":             ("✅", "Complete",                        "#3ecf8e"),
    }
    if stage == "narrative":
        if "ollama" in message.lower():
            _STAGES["narrative"] = ("🖥", "Generating Ollama Narrative", "#f5a623")
        else:
            _STAGES["narrative"] = ("☁", "Generating Gemini Narrative", "#f5a623")

    icon, stage_label, accent = _STAGES.get(stage, ("⚙", "Processing", "#6c6ef7"))
    node_pcts   = [0, 20, 45, 65, 85, 95]
    node_icons  = ["📂", "📊", "🌐", "🔍", "✨", "💾"]
    node_labels = ["Load", "Analyse", "Enrich", "Anomaly", "Narrate", "Save"]

    def _node_html(i: int) -> str:
        lit = pct >= node_pcts[i]
        bg  = accent if lit else "#2a2a3a"
        col = "#ffffff" if lit else "#555577"
        return (
            f'<div style="display:flex;flex-direction:column;align-items:center;gap:4px;">'
            f'  <div style="width:52px;height:52px;border-radius:50%;background:{bg};'
            f'      display:flex;align-items:center;justify-content:center;font-size:22px;">'
            f'    {node_icons[i]}</div>'
            f'  <span style="font-size:10px;color:{col};font-weight:{"600" if lit else "400"};">'
            f'    {node_labels[i]}</span></div>'
        )

    def _connector(i: int) -> str:
        lit = pct >= node_pcts[i + 1]
        return (
            f'<div style="flex:1;height:3px;background:{"" + accent if lit else "#2a2a3a"};'
            f'margin:0 4px;align-self:center;border-radius:2px;"></div>'
        )

    nodes_html = "".join(
        _node_html(i) + (_connector(i) if i < len(node_icons) - 1 else "")
        for i in range(len(node_icons))
    )
    bar_html = (
        f'<div style="width:100%;background:#1e1e2e;border-radius:6px;height:8px;overflow:hidden;margin-top:16px;">'
        f'  <div style="width:{pct}%;height:100%;background:{accent};border-radius:6px;transition:width 0.4s;"></div>'
        f'</div>'
    )
    st.markdown(f"""
<style>
.ba-card {{
    background:#13131f;border:1px solid #2a2a3e;border-radius:14px;
    padding:28px 32px;margin:12px 0;
}}
</style>
<div class="ba-card">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;">
    <span style="font-size:28px;">{icon}</span>
    <div>
      <div style="font-size:1rem;font-weight:700;color:#e0e0ff;">{stage_label}</div>
      <div style="font-size:12px;color:#8888aa;">{message}</div>
    </div>
    <div style="margin-left:auto;font-size:1.4rem;font-weight:700;color:{accent};">{pct}%</div>
  </div>
  <div style="display:flex;align-items:center;gap:0;justify-content:space-between;">{nodes_html}</div>
  {bar_html}
</div>
""", unsafe_allow_html=True)


# ── Main dashboard ─────────────────────────────────────────────────────────────

def render_budget_analytics_dashboard(runner: Any) -> None:
    """Full budget analytics dashboard — mirrors SOC analytics pattern, budget data only."""
    from ...jobs.budget_analytics_runner import BudgetAnalyticsRunner

    data = load_budget_analytics() or {}

    # ── Settings expander ─────────────────────────────────────────────────
    with st.expander("⚙ Analysis Settings", expanded=not bool(data)):
        ai_flag = st.checkbox(
            "Generate AI narrative",
            value=True,
            key="ba_ai_flag",
        )
        provider = st.radio(
            "AI Provider",
            options=["gemini", "ollama"],
            format_func=lambda x: "☁ Gemini" if x == "gemini" else "🖥 Ollama (local)",
            horizontal=True,
            key="ba_ai_provider",
        )

        if provider == "ollama":
            available_models = _list_ollama_models()
            gpu = _detect_ollama_gpu()
            gpu_labels  = {"cuda": "🟢 CUDA GPU", "rocm": "🟢 ROCm GPU", "metal": "🟡 Apple Metal", "cpu": "⚪ CPU"}
            gpu_colors  = {"cuda": "#3ecf8e", "rocm": "#3ecf8e", "metal": "#f5a623", "cpu": "#888899"}
            lbl = gpu_labels.get(gpu, gpu)
            c   = gpu_colors.get(gpu, "#888899")
            if available_models:
                default = _CFG.ollama_llm_model
                idx = available_models.index(default) if default in available_models else 0
                st.selectbox("Ollama model", options=available_models, index=idx, key="ba_ollama_model")
            else:
                st.warning("No models found in Ollama. Is Ollama running?")
            st.markdown(
                f'<div style="background:{c}22;border:1px solid {c}66;border-radius:8px;'
                f'padding:8px 14px;margin-top:4px;">'
                f'<b style="color:{c};">{lbl}</b>'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            has_key = bool(_CFG.gemini_api_key)
            c   = "#3ecf8e" if has_key else "#f26464"
            lbl = "🟢 Gemini API key loaded" if has_key else "🔴 GEMINI_API_KEY not set"
            st.markdown(
                f'<div style="background:{c}22;border:1px solid {c}66;border-radius:8px;'
                f'padding:10px 14px;margin-top:4px;">'
                f'<b style="color:{c};">{lbl}</b><br>'
                f'<span style="color:#aaaacc;font-size:12px;">Model: <code>{_CFG.gemini_model}</code></span>'
                f'</div>',
                unsafe_allow_html=True,
            )

    run_col, status_col = st.columns([2, 3])
    with run_col:
        run_btn = st.button(
            "▶ Run Analysis", type="primary", key="ba_run_btn",
            disabled=(runner is not None and runner.is_running()),
            use_container_width=True,
        )
    with status_col:
        age = budget_analytics_age_seconds()
        if age is not None:
            mins = int(age // 60)
            label = f"{mins}m ago" if mins > 0 else "just now"
            st.info(
                f"Last analysis: **{label}**  |  "
                f"{data.get('analysis', {}).get('total_items', 0)} items  |  "
                f"Generated {data.get('generated_at', '')[:19]} UTC"
            )
        else:
            st.warning("No analytics file yet — click **▶ Run Analysis** to generate.")

    if run_btn and runner is not None:
        runner.start(
            include_ai_narrative=st.session_state.get("ba_ai_flag", True),
            narrative_provider=st.session_state.get("ba_ai_provider", "gemini"),
            ollama_model=st.session_state.get("ba_ollama_model") or None,
        )
        st.rerun()

    if runner is not None:
        state = runner.get_state()
        if state["status"] == "running":
            _render_analysis_animation(state)
            st.rerun()
        elif state["status"] == "error":
            st.error(f"Analysis error: {state.get('error', 'unknown')}")
        elif state["status"] == "completed" and not data:
            data = load_budget_analytics() or {}

    if not data:
        st.info("Run the analysis to populate this dashboard.")
        return

    analysis = data.get("analysis", {})
    st.divider()

    # ── KPI row ───────────────────────────────────────────────────────────
    st.markdown("### 📊 Budget Summary")
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Total Budget",  _idr(analysis.get("total_budget", 0)))
    k2.metric("Capex",         _idr(analysis.get("capex", 0)))
    k3.metric("Opex",          _idr(analysis.get("opex", 0)))
    k4.metric("Total Items",   analysis.get("total_items", 0))
    unapproved_cnt = len(analysis.get("unapproved_high_priority", []))
    k5.metric(
        "Unapproved High-Priority",
        unapproved_cnt,
        delta=f"+{unapproved_cnt} need action" if unapproved_cnt else None,
        delta_color="inverse",
    )

    # ── Timeline + amount stats ───────────────────────────────────────────
    st.plotly_chart(
        _stacked_bar_timeline(analysis.get("timeline", [])),
        use_container_width=True, key="ba_timeline",
    )

    col_pie1, col_pie2 = st.columns(2)
    with col_pie1:
        st.plotly_chart(
            _pie(analysis.get("amount_by_cost_type", {}), "Budget by Cost Type"),
            use_container_width=True, key="ba_cost_type_pie",
        )
    with col_pie2:
        st.plotly_chart(
            _pie(analysis.get("amount_by_status", {}), "Budget by Status"),
            use_container_width=True, key="ba_status_pie",
        )

    st.divider()
    st.markdown("### 🏢 Domain & Priority Breakdown")

    st.plotly_chart(
        _hbar(analysis.get("amount_by_domain", {}), "Budget Amount by Domain", "#3ecf8e"),
        use_container_width=True, key="ba_domain_hbar",
    )

    col_a, col_b = st.columns(2)
    with col_a:
        st.plotly_chart(
            _pie(analysis.get("amount_by_priority", {}), "Budget by Priority"),
            use_container_width=True, key="ba_priority_pie",
        )
    with col_b:
        st.plotly_chart(
            _amount_stats_bar(analysis.get("amount_stats", {})),
            use_container_width=True, key="ba_amount_stats",
        )

    st.plotly_chart(
        _domain_heatmap(analysis.get("domain_cost_breakdown", [])),
        use_container_width=True, key="ba_domain_heatmap",
    )

    # ── Anomaly detection ─────────────────────────────────────────────────
    anomalies = analysis.get("anomalies", [])
    enrichment = data.get("anomaly_enrichment", {})
    anomaly_narrative = data.get("anomaly_narrative", "")

    st.divider()
    st.markdown("### 🔍 Anomaly Detection (Z-Score Outliers)")

    st.plotly_chart(
        _anomaly_scatter(anomalies),
        use_container_width=True, key="ba_anomaly_scatter",
    )

    if anomalies:
        anom_df = pd.DataFrame(anomalies)[[
            "budget_id", "initiative", "domain", "cost_type",
            "amount", "expected_amount", "variance_pct", "z_score", "is_outlier",
        ]].copy()
        anom_df["amount"]          = anom_df["amount"].apply(lambda v: _idr(float(v)))
        anom_df["expected_amount"] = anom_df["expected_amount"].apply(lambda v: _idr(float(v)))
        anom_df["variance_pct"]    = anom_df["variance_pct"].apply(lambda v: f"{float(v):+.1f}%")
        anom_df["z_score"]         = anom_df["z_score"].apply(lambda v: f"{float(v):.2f}")
        anom_df.columns = [
            "ID", "Initiative", "Domain", "Cost Type",
            "Amount (IDR)", "Expected (IDR)", "Variance %", "Z-Score", "Outlier",
        ]
        st.dataframe(anom_df, use_container_width=True, hide_index=True)

        # ── Internet enrichment cards ──────────────────────────────────
        if enrichment:
            st.markdown("#### 🌐 Market Benchmark Context (Internet Search)")
            st.caption("DuckDuckGo search results for the top anomalous budget items.")
            for bid, ctx in enrichment.items():
                with st.expander(
                    f"🔎 {ctx.get('initiative', bid)} — {ctx.get('domain', '')}",
                    expanded=False,
                ):
                    for snippet in ctx.get("snippets", []):
                        st.markdown(f"- {snippet}")

        # ── Anomaly-specific AI narrative ──────────────────────────────
        if anomaly_narrative:
            st.markdown("#### 🤖 Anomaly Analysis (AI Narrative)")
            provider_used = data.get("narrative_provider", "gemini")
            prov_label = "🖥 Ollama" if provider_used == "ollama" else "☁ Gemini"
            with st.expander(f"AI anomaly assessment ({prov_label})", expanded=True):
                st.markdown(anomaly_narrative)
    else:
        st.success("✅ No significant outliers detected.")

    # ── Unapproved high-priority items ────────────────────────────────────
    unapproved = analysis.get("unapproved_high_priority", [])
    if unapproved:
        st.divider()
        st.markdown("### 🔴 High-Priority Items Not Yet Approved")
        st.warning(f"{len(unapproved)} high-priority item(s) are still in Draft/Planned status.")
        up_df = pd.DataFrame(unapproved).copy()
        if "amount" in up_df.columns:
            up_df["amount"] = up_df["amount"].apply(lambda v: _idr(float(v)))
        st.dataframe(up_df, use_container_width=True, hide_index=True)

    # ── AI Narrative ──────────────────────────────────────────────────────
    narrative = data.get("ai_narrative", "")
    if narrative:
        st.divider()
        provider_used = data.get("narrative_provider", "gemini")
        prov_label = "🖥 Ollama" if provider_used == "ollama" else "☁ Gemini"
        st.markdown(f"### AI Narrative ({prov_label})")
        with st.expander("Read executive budget summary", expanded=True):
            st.markdown(narrative)

    st.divider()
    import json as _json
    st.download_button(
        "Download analytics JSON",
        data=_json.dumps(data, indent=2, default=str),
        file_name="budget_analytics.json",
        mime="application/json",
        key="ba_json_download",
    )
