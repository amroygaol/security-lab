from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from ...data.soc_analytics_store import analytics_age_seconds, load_analytics

_SEVERITY_COLORS = {
    "Critical":      "#f26464",
    "High":          "#f5a623",
    "Medium":        "#f5e623",
    "Low":           "#3ecf8e",
    "Informational": "#8888a0",
    "Unknown":       "#55556a",
}


def _pie(by: dict[str, int], title: str, color_map: dict[str, str] | None = None) -> go.Figure:
    if not by:
        return go.Figure().add_annotation(text="No data")
    labels = list(by.keys())
    values = list(by.values())
    colors = [color_map.get(lbl, "#6c6ef7") for lbl in labels] if color_map else None
    fig = go.Figure(data=[go.Pie(
        labels=labels, values=values, hole=0.4,
        marker=dict(colors=colors) if colors else {},
    )])
    fig.update_layout(title=title, height=380, showlegend=True,
                      margin=dict(t=40, b=20, l=10, r=10))
    return fig


def _hbar(by: dict[str, int], title: str, color: str = "#6c6ef7", top_n: int = 20) -> go.Figure:
    if not by:
        return go.Figure().add_annotation(text="No data")
    items = list(by.items())[:top_n]
    names, counts = zip(*items)
    fig = go.Figure(data=[go.Bar(
        x=list(counts), y=list(names),
        orientation="h",
        marker=dict(color=color),
    )])
    fig.update_layout(
        title=title, xaxis_title="Count",
        yaxis=dict(autorange="reversed"),
        height=max(380, len(items) * 24),
        showlegend=False,
        margin=dict(t=40, b=20, l=10, r=10),
    )
    return fig


def _timeline(data: list[dict[str, Any]]) -> go.Figure:
    if not data:
        return go.Figure().add_annotation(text="No timeline data")
    dates = [d["week"] for d in data]
    counts = [d["count"] for d in data]
    fig = go.Figure(data=[go.Scatter(
        x=dates, y=counts,
        mode="lines+markers",
        line=dict(color="#6c6ef7", width=2),
        marker=dict(size=5),
        fill="tozeroy", fillcolor="rgba(108,110,247,0.15)",
    )])
    fig.update_layout(
        title="SOC Tickets -- Weekly Volume (YTD)",
        xaxis_title="Week", yaxis_title="Tickets",
        height=350, showlegend=False, hovermode="x unified",
        margin=dict(t=40, b=20, l=10, r=10),
    )
    return fig


def _risk_histogram(stats: dict[str, Any]) -> go.Figure:
    if not stats:
        return go.Figure().add_annotation(text="No risk score data")
    keys = ["min", "p25", "median", "mean", "p75", "p95", "p99", "max"]
    vals = [stats.get(k, 0) for k in keys]
    fig = go.Figure(data=[go.Bar(x=keys, y=vals, marker=dict(color="#9396fa"))])
    fig.update_layout(
        title="Risk Score Distribution (percentiles)",
        xaxis_title="Percentile", yaxis_title="Score",
        height=360, showlegend=False,
        margin=dict(t=40, b=20, l=10, r=10),
    )
    return fig


def _heatmap_fig(heatmap_rows: list[dict[str, Any]]) -> go.Figure:
    if not heatmap_rows:
        return go.Figure().add_annotation(text="No heatmap data")
    df = pd.DataFrame(heatmap_rows)
    pivot = df.pivot_table(index="taktik", columns="severity_norm", values="count", fill_value=0)
    sev_order = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]
    pivot = pivot.reindex(columns=[c for c in sev_order if c in pivot.columns])
    fig = go.Figure(data=go.Heatmap(
        z=pivot.values.tolist(),
        x=list(pivot.columns),
        y=list(pivot.index),
        colorscale="RdYlGn_r",
        text=pivot.values.tolist(),
        texttemplate="%{text}",
    ))
    fig.update_layout(
        title="Taktik x Severity Heatmap",
        height=max(400, len(pivot) * 28),
        margin=dict(t=40, b=20, l=10, r=10),
    )
    return fig


# ── Budget + SOC combined charts ──────────────────────────────────────────────

def _budget_vs_tickets_chart(gap_analysis: list[dict[str, Any]]) -> go.Figure:
    """Grouped bar: ticket count vs budget allocated per security domain."""
    if not gap_analysis:
        return go.Figure().add_annotation(text="No cross-domain data")
    domains   = [g["domain"] for g in gap_analysis]
    tickets   = [g["ticket_count"] for g in gap_analysis]
    budgets   = [g["budget_allocated"] / 1_000 for g in gap_analysis]  # display in thousands

    fig = go.Figure()
    fig.add_trace(go.Bar(name="Tickets", x=domains, y=tickets, marker_color="#f5a623",
                         yaxis="y", offsetgroup=1))
    fig.add_trace(go.Bar(name="Budget (K)", x=domains, y=budgets, marker_color="#3ecf8e",
                         yaxis="y2", offsetgroup=2))
    fig.update_layout(
        title="Threat Volume vs Budget Allocation by Security Domain",
        yaxis=dict(title="SOC Tickets", side="left"),
        yaxis2=dict(title="Budget (K)", overlaying="y", side="right"),
        barmode="group",
        height=420, hovermode="x unified",
        legend=dict(orientation="h", y=1.08),
        margin=dict(t=60, b=20, l=10, r=10),
    )
    return fig


def _gap_flag_table(gap_analysis: list[dict[str, Any]]) -> pd.DataFrame | None:
    gaps = [g for g in gap_analysis if g.get("gap_flag")]
    if not gaps:
        return None
    df = pd.DataFrame(gaps)[["domain", "ticket_count", "budget_allocated"]]
    df.columns = ["Domain", "Tickets", "Budget Allocated"]
    return df


def _domain_budget_pie(domain_budget: dict[str, float]) -> go.Figure:
    if not domain_budget:
        return go.Figure().add_annotation(text="No budget data")
    fig = go.Figure(data=[go.Pie(
        labels=list(domain_budget.keys()),
        values=list(domain_budget.values()),
        hole=0.4,
    )])
    fig.update_layout(title="Budget Distribution by Security Domain",
                      height=360, margin=dict(t=40, b=20, l=10, r=10))
    return fig


def _render_budget_soc_section(budget_analysis: dict[str, Any]) -> None:
    """Render combined SOC + budget analytics section."""
    if not budget_analysis:
        st.info("Budget correlation data not available — re-run analysis to generate.")
        return

    gap_analysis  = budget_analysis.get("gap_analysis", [])
    domain_budget = budget_analysis.get("domain_budget", {})
    asset_summary = budget_analysis.get("asset_summary", {})
    unapproved    = budget_analysis.get("unapproved_high_priority", [])
    policies      = budget_analysis.get("budget_policies", [])
    total_budget  = budget_analysis.get("total_budget", 0)
    total_capex   = budget_analysis.get("total_capex", 0)
    total_opex    = budget_analysis.get("total_opex", 0)

    # KPIs
    km1, km2, km3, km4 = st.columns(4)
    km1.metric("Total Security Budget",  f"{total_budget:,.0f}")
    km2.metric("Capex",                  f"{total_capex:,.0f}")
    km3.metric("Opex",                   f"{total_opex:,.0f}")
    km4.metric("Tool Spend (Assets)",    f"{asset_summary.get('total_tool_spend', 0):,.0f}")

    # Budget vs tickets grouped bar
    st.plotly_chart(_budget_vs_tickets_chart(gap_analysis), use_container_width=True, key="soc_budget_vs_tickets")

    col_a, col_b = st.columns(2)
    with col_a:
        st.plotly_chart(_domain_budget_pie(domain_budget), use_container_width=True, key="soc_domain_budget_pie")
    with col_b:
        # Asset criticality spend
        crit_spend = asset_summary.get("criticality_spend", {})
        if crit_spend:
            fig_crit = go.Figure(data=[go.Bar(
                x=list(crit_spend.keys()), y=list(crit_spend.values()),
                marker_color="#9396fa",
            )])
            fig_crit.update_layout(title="Asset Spend by Criticality",
                                   height=360, margin=dict(t=40, b=20, l=10, r=10))
            st.plotly_chart(fig_crit, use_container_width=True, key="soc_crit_spend")

    # Gap flags — domains under threat but with no budget
    gap_df = _gap_flag_table(gap_analysis)
    if gap_df is not None and not gap_df.empty:
        st.warning(f"⚠ **{len(gap_df)} domain(s) have active threats but zero budget allocated:**")
        st.dataframe(gap_df, use_container_width=True, hide_index=True)
    else:
        st.success("✅ All high-ticket domains have at least some budget allocated.")

    # Unapproved high-priority items
    if unapproved:
        st.markdown("**🔴 High-Priority Budget Items Not Yet Approved**")
        st.dataframe(
            pd.DataFrame(unapproved).rename(columns={
                "initiative": "Initiative", "domain": "Domain",
                "status": "Status", "amount": "Amount",
            }),
            use_container_width=True, hide_index=True,
        )

    # Assets needing renewal
    renewal_soon = asset_summary.get("renewal_soon", [])
    if renewal_soon:
        st.warning(f"🔔 **Renewals soon:** {', '.join(renewal_soon)}")

    # Governance policies
    if policies:
        with st.expander("📋 Budget Governance Policies", expanded=False):
            for i, p in enumerate(policies, 1):
                st.markdown(f"{i}. {p}")


def _render_analysis_animation(state: dict) -> None:
    """Render a rich animated processing UI during SOC analytics run."""
    progress = float(state.get("progress", 0.0))
    stage    = str(state.get("stage", "fetching")).lower()
    message  = str(state.get("message", "Processing…"))
    pct      = int(progress * 100)

    # Stage → (icon, label, color)
    _STAGES = {
        "fetching":  ("🔌", "Connecting to Elasticsearch",  "#6c6ef7"),
        "analysing": ("🧠", "Running ML Analysis",           "#3ecf8e"),
        "narrative": ("✨", "Generating AI Narrative",       "#f5a623"),
        "saving":    ("💾", "Saving Analytics Cache",        "#9396fa"),
        "done":      ("✅", "Complete",                      "#3ecf8e"),
    }
    # Override narrative label based on provider embedded in message
    if stage == "narrative":
        if "ollama" in message.lower():
            _STAGES["narrative"] = ("🖥", "Generating Ollama Narrative", "#f5a623")
        else:
            _STAGES["narrative"] = ("☁", "Generating Gemini Narrative", "#f5a623")
    icon, stage_label, accent = _STAGES.get(stage, ("⚙", "Processing", "#6c6ef7"))

    # Nodes that light up as progress advances (5 pipeline steps)
    node_pcts  = [0, 20, 45, 75, 95]
    node_icons = ["🔌", "📦", "🧠", "✨", "💾"]
    node_labels = ["Connect", "Fetch", "Analyse", "Narrate", "Save"]

    def _node_html(i: int) -> str:
        lit = pct >= node_pcts[i]
        bg  = accent if lit else "#2a2a3a"
        col = "#ffffff" if lit else "#555577"
        anim = f'animation: pulse_{i} 1.4s ease-in-out infinite;' if (lit and i == sum(1 for p in node_pcts if pct >= p) - 1) else ""
        return (
            f'<div style="display:flex;flex-direction:column;align-items:center;gap:4px;">'
            f'  <div style="width:52px;height:52px;border-radius:50%;background:{bg};'
            f'      display:flex;align-items:center;justify-content:center;font-size:22px;'
            f'      box-shadow:{("0 0 14px " + accent + "88") if lit else "none"};{anim}">'
            f'    {node_icons[i]}'
            f'  </div>'
            f'  <span style="font-size:10px;color:{col};font-weight:{"600" if lit else "400"};">{node_labels[i]}</span>'
            f'</div>'
        )

    def _connector_html(i: int) -> str:
        lit = pct >= node_pcts[i + 1]
        col = accent if lit else "#2a2a3a"
        anim = f"animation: flow 0.8s linear infinite;" if lit else ""
        return (
            f'<div style="flex:1;height:3px;background:{col};margin:0 4px;align-self:center;'
            f'    border-radius:2px;{anim}"></div>'
        )

    nodes_html = "".join(
        _node_html(i) + (_connector_html(i) if i < len(node_icons) - 1 else "")
        for i in range(len(node_icons))
    )

    # Animated fill bar
    bar_html = (
        f'<div style="width:100%;background:#1e1e2e;border-radius:6px;height:8px;overflow:hidden;margin-top:16px;">'
        f'  <div style="width:{pct}%;height:100%;background:linear-gradient(90deg,{accent},{accent}cc);'
        f'      border-radius:6px;transition:width 0.4s ease;animation:shimmer 1.6s linear infinite;'
        f'      background-size:200% 100%;background-image:linear-gradient(90deg,{accent}aa,{accent},{accent}aa);">'
        f'  </div>'
        f'</div>'
    )

    # Log-like scrolling message
    msg_safe = message.replace("<", "&lt;").replace(">", "&gt;")

    html = f"""
<style>
@keyframes shimmer {{
  0%   {{ background-position: -200% 0; }}
  100% {{ background-position:  200% 0; }}
}}
@keyframes pulse_0 {{ 0%,100% {{ box-shadow: 0 0 10px {accent}55; }} 50% {{ box-shadow: 0 0 22px {accent}cc; }} }}
@keyframes pulse_1 {{ 0%,100% {{ box-shadow: 0 0 10px {accent}55; }} 50% {{ box-shadow: 0 0 22px {accent}cc; }} }}
@keyframes pulse_2 {{ 0%,100% {{ box-shadow: 0 0 10px {accent}55; }} 50% {{ box-shadow: 0 0 22px {accent}cc; }} }}
@keyframes pulse_3 {{ 0%,100% {{ box-shadow: 0 0 10px {accent}55; }} 50% {{ box-shadow: 0 0 22px {accent}cc; }} }}
@keyframes pulse_4 {{ 0%,100% {{ box-shadow: 0 0 10px {accent}55; }} 50% {{ box-shadow: 0 0 22px {accent}cc; }} }}
@keyframes flow   {{ 0% {{ opacity:0.5; }} 50% {{ opacity:1; }} 100% {{ opacity:0.5; }} }}
@keyframes fadeIn {{ from {{ opacity:0; transform:translateY(6px); }} to {{ opacity:1; transform:translateY(0); }} }}
</style>
<div style="
    background:linear-gradient(135deg,#0f0f1a,#1a1a2e);
    border:1px solid {accent}44;
    border-radius:14px;
    padding:28px 32px 22px;
    margin:8px 0 20px;
    animation:fadeIn 0.4s ease;
">
  <!-- Header -->
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
    <span style="font-size:32px;">{icon}</span>
    <div>
      <div style="color:#ffffff;font-size:17px;font-weight:700;letter-spacing:0.3px;">{stage_label}</div>
      <div style="color:{accent};font-size:12px;font-weight:500;margin-top:2px;">SOC Analytics Pipeline · {pct}% complete</div>
    </div>
    <div style="margin-left:auto;background:{accent}22;border:1px solid {accent}44;border-radius:8px;
         padding:6px 14px;color:{accent};font-size:22px;font-weight:700;">{pct}%</div>
  </div>

  <!-- Node pipeline -->
  <div style="display:flex;align-items:flex-start;padding:0 8px;margin-bottom:4px;">
    {nodes_html}
  </div>

  <!-- Progress bar -->
  {bar_html}

  <!-- Status message -->
  <div style="
      margin-top:14px;
      background:#0d0d1a;
      border:1px solid #2a2a3a;
      border-radius:8px;
      padding:10px 14px;
      font-family:'Courier New',monospace;
      font-size:12px;
      color:#8888cc;
      display:flex;
      align-items:center;
      gap:8px;
  ">
    <span style="color:{accent};animation:flow 1s linear infinite;">▶</span>
    <span>{msg_safe}</span>
  </div>
</div>
"""
    st.markdown(html, unsafe_allow_html=True)


def render_soc_dashboard(runner: Any | None = None) -> None:
    data = load_analytics()

    from ...core.config import CONFIG as _CFG

    # ── Control panel ─────────────────────────────────────────────────────
    with st.expander("⚙ Analysis Settings", expanded=("soc_ai_provider" not in st.session_state)):
        cp1, cp2 = st.columns([2, 3])
        with cp1:
            ai_flag = st.checkbox("Include AI narrative", value=True, key="soc_ai_flag")
            provider = st.radio(
                "Narrative provider",
                options=["gemini", "ollama"],
                format_func=lambda x: "☁ Gemini (cloud)" if x == "gemini" else "🖥 Ollama (local)",
                horizontal=True,
                key="soc_ai_provider",
                disabled=not ai_flag,
            )
        with cp2:
            if provider == "ollama":
                try:
                    from src.jobs.soc_analytics_runner import _detect_ollama_gpu, _list_ollama_models
                    gpu = _detect_ollama_gpu()
                    available_models = _list_ollama_models()
                except Exception:
                    gpu = "cpu"
                    available_models = []

                gpu_colors = {"cuda": "#3ecf8e", "rocm": "#3ecf8e", "metal": "#f5a623", "cpu": "#888899"}
                gpu_labels = {"cuda": "🟢 CUDA GPU detected", "rocm": "🟢 ROCm GPU detected",
                              "metal": "🟡 Apple Metal GPU", "cpu": "🔴 No GPU — CPU only (slow)"}
                c = gpu_colors.get(gpu, "#888899")
                lbl = gpu_labels.get(gpu, gpu)

                if available_models:
                    default_model = _CFG.ollama_llm_model
                    default_idx = available_models.index(default_model) if default_model in available_models else 0
                    chosen_model = st.selectbox(
                        "Ollama model",
                        options=available_models,
                        index=default_idx,
                        key="soc_ollama_model",
                    )
                else:
                    chosen_model = _CFG.ollama_llm_model
                    st.warning("No models found in Ollama. Is Ollama running?")

                st.markdown(
                    f'<div style="background:{c}22;border:1px solid {c}66;border-radius:8px;'
                    f'padding:8px 14px;margin-top:4px;">'
                    f'<b style="color:{c};">{lbl}</b><br>'
                    f'<span style="color:#aaaacc;font-size:12px;">Timeout: <code>disabled</code> · num_gpu: <code>-1 (all layers)</code></span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            else:
                has_key = bool(_CFG.gemini_api_key)
                c = "#3ecf8e" if has_key else "#f26464"
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
            "▶ Run Analysis", type="primary", key="soc_run_btn",
            disabled=(runner is not None and runner.is_running()),
            use_container_width=True,
        )
    with status_col:
        age = analytics_age_seconds()
        if age is not None:
            mins = int(age // 60)
            label = f"{mins}m ago" if mins > 0 else "just now"
            st.info(
                f"Last analysis: **{label}**  |  "
                f"{data.get('total_tickets', 0):,} tickets  |  "
                f"Generated {data.get('generated_at', '')[:19]} UTC"
            )
        else:
            st.warning("No analytics file yet — click **▶ Run Analysis** to generate.")

    if run_btn and runner is not None:
        runner.start(
            include_ai_narrative=st.session_state.get("soc_ai_flag", True),
            narrative_provider=st.session_state.get("soc_ai_provider", "gemini"),
            ollama_model=st.session_state.get("soc_ollama_model") or None,
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
            data = load_analytics()

    if not data:
        st.info("Run the analysis to populate this dashboard.")
        return

    summary = data.get("summary", {})
    st.divider()

    st.markdown("### SOC Summary")
    by_sev = summary.get("by_severity", {})
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Tickets (YTD)", f"{data.get('total_tickets', 0):,}")
    c2.metric("Critical", by_sev.get("Critical", 0))
    c3.metric("High",     by_sev.get("High", 0))
    c4.metric("Medium",   by_sev.get("Medium", 0))
    c5.metric("Low",      by_sev.get("Low", 0))

    st.markdown("### Severity & Status")
    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(_pie(by_sev, "Tickets by Severity", _SEVERITY_COLORS),
                        use_container_width=True, key="soc_j_sev_pie")
    with col2:
        st.plotly_chart(_pie(summary.get("by_status", {}), "Tickets by Status"),
                        use_container_width=True, key="soc_j_status_pie")

    st.plotly_chart(_timeline(summary.get("timeline", [])),
                    use_container_width=True, key="soc_j_timeline")

    st.divider()
    st.markdown("### MITRE ATT&CK Coverage")
    col3, col4 = st.columns(2)
    with col3:
        st.plotly_chart(_hbar(summary.get("by_taktik", {}), "Top 20 Tactics (Taktik)", "#3ecf8e"),
                        use_container_width=True, key="soc_j_taktik")
    with col4:
        st.plotly_chart(_hbar(summary.get("by_teknik", {}), "Top 20 Techniques (Teknik)", "#f5a623"),
                        use_container_width=True, key="soc_j_teknik")

    st.plotly_chart(_heatmap_fig(summary.get("taktik_severity_heatmap", [])),
                    use_container_width=True, key="soc_j_heatmap")

    st.divider()
    st.markdown("### Alert Intelligence & Risk Scores")
    col5, col6 = st.columns(2)
    with col5:
        st.plotly_chart(_hbar(summary.get("by_alert_name", {}), "Top 20 Alert Names", "#9396fa"),
                        use_container_width=True, key="soc_j_alerts")
    with col6:
        st.plotly_chart(_risk_histogram(summary.get("risk_score_stats", {})),
                        use_container_width=True, key="soc_j_risk")

    anomalies = summary.get("anomalies", [])
    if anomalies:
        st.divider()
        st.markdown("### Detected Anomalies (High-Volume Alerts)")
        anom_df = pd.DataFrame(anomalies)[["alert_name", "count", "pct_of_total", "z_score"]]
        anom_df.columns = ["Alert Name", "Count", "% of Total", "Z-Score"]
        st.dataframe(anom_df, use_container_width=True, hide_index=True)

    # ── Budget + SOC combined section ─────────────────────────────────────
    budget_analysis = data.get("budget_analysis", {})
    st.divider()
    st.markdown("### 💰 Budget & Threat Correlation")
    _render_budget_soc_section(budget_analysis)

    narrative = data.get("ai_narrative", "")
    if narrative:
        st.divider()
        provider_used = data.get("narrative_provider", "gemini")
        prov_label = "🖥 Ollama" if provider_used == "ollama" else "☁ Gemini"
        st.markdown(f"### AI Narrative ({prov_label})")
        with st.expander("Read executive summary", expanded=True):
            st.markdown(narrative)

    st.divider()
    import json as _json
    st.download_button(
        "Download analytics JSON",
        data=_json.dumps(data, indent=2, default=str),
        file_name="soc_analytics.json",
        mime="application/json",
        key="soc_json_download",
    )
