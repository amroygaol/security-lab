from __future__ import annotations

import base64
import binascii
import re
from datetime import UTC, date, datetime, timedelta
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree

import pandas as pd
import streamlit as st
from streamlit_cookies_controller import CookieController

from src.analytics.budget.engine import run_budget_ai_analytics
from src.analytics.capacity.engine import CapacityInput, run_capacity_forecast
from src.analytics.capacity.narrative import generate_capacity_narrative
from src.app.example_data import build_example_workbook_bytes
from src.app.report_processing import build_assessment_context, parse_excel
from src.app.session_store import create_session, delete_session, get_session, renew_session
from src.auth.store import (
    authenticate_local,
    authenticate_saml_identity,
    change_local_password,
    clear_user_passkeys,
    delete_user,
    find_user,
    load_auth_config,
    load_users,
    register_local_user,
    reset_local_password,
    save_auth_config,
    update_user_profile,
    upsert_user,
)
from src.auth.passkey import (
    begin_passkey_authentication,
    begin_passkey_registration,
    finish_passkey_authentication,
    finish_passkey_registration,
    passkey_summary,
)
from src.core.config import CONFIG
from src.core.security import validate_file_name, validate_file_size
from src.data.portal_store import load_assets, load_budgets, load_budget_policies, save_assets, save_budget_policies, save_budgets
from src.data.public_exposure_store import load_public_exposures
from src.data.waf_sites_store import load_waf_sites
from src.data.report_store import list_reports, load_report, save_report
from src.export.word import markdown_to_docx_bytes
from src.jobs.budget_ai_runner import BudgetAIBackgroundRunner
from src.jobs.report_worker import BackgroundJobWorker, list_jobs, load_job_report, request_stop_job, submit_job
from src.llm.copilot import stream_copilot_response, SUGGESTED_PROMPTS, PROVIDER_LABELS, PROVIDER_OLLAMA, PROVIDER_GEMINI
from src.llm.enrichment.search import enrich_with_duckduckgo
from src.llm.rag.pipeline import generate_report, init_vector_store, retrieve_context, upsert_enrichment
from src.ui.components.webauthn_bridge import webauthn_bridge


st.set_page_config(page_title="Security Architecture Portal", layout="wide")

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
    color-scheme: dark;
    --app-bg:       #111116;
    --surface-1:    #18181f;
    --surface-2:    #1f1f28;
    --surface-3:    #26262f;
    --border:       rgba(255, 255, 255, 0.08);
    --border-focus: rgba(108, 110, 247, 0.55);
    --text-primary:   #e8e8f0;
    --text-secondary: #8888a0;
    --text-muted:     #55556a;
    --accent:         #6c6ef7;
    --accent-light:   #9396fa;
    --accent-dim:     rgba(108, 110, 247, 0.15);
    --green:    #3ecf8e;
    --amber:    #f5a623;
    --red:      #f26464;
    --radius-sm: 6px;
    --radius-md: 10px;
    --radius-lg: 14px;
    --shadow-sm: 0 1px 3px rgba(0,0,0,0.40);
    --shadow-md: 0 4px 12px rgba(0,0,0,0.45), 0 1px 3px rgba(0,0,0,0.30);
}

/* ── Base ─────────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'Inter', system-ui, sans-serif;
    background: var(--app-bg) !important;
    -webkit-font-smoothing: antialiased;
}

[data-testid="stAppViewContainer"] {
    background: var(--app-bg);
    color: var(--text-primary);
    padding-bottom: 2.6rem;
}

[data-testid="stMain"], [data-testid="stMainBlockContainer"] {
    background: transparent !important;
}

/* ── Footer ────────────────────────────────── */
footer { visibility: hidden; }
[data-testid="stAppViewContainer"]::after {
    content: 'Security Architecture Team  ·  CISO Office Group';
    position: fixed;
    bottom: 0; left: 0; right: 0;
    z-index: 999;
    text-align: center;
    padding: 0.42rem 1rem;
    font-family: 'Inter', sans-serif;
    font-size: 0.70rem;
    letter-spacing: 0.02em;
    color: var(--text-muted);
    background: rgba(17, 17, 22, 0.94);
    border-top: 1px solid var(--border);
    backdrop-filter: blur(8px);
}

/* ── Labels / text ──────────────────────────── */
[data-testid="stAppViewContainer"] [data-testid="stMarkdownContainer"] p,
[data-testid="stAppViewContainer"] label,
[data-testid="stAppViewContainer"] .stMetricLabel,
[data-testid="stAppViewContainer"] .stMetricValue {
    color: var(--text-primary);
}

/* ── Metrics ────────────────────────────────── */
[data-testid="stMetricValue"] {
    color: var(--text-primary) !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 700 !important;
    font-size: 1.45rem !important;
}
[data-testid="stMetricLabel"] {
    color: var(--text-secondary) !important;
    font-size: 0.74rem !important;
    font-weight: 500 !important;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}
[data-testid="metric-container"] {
    background: var(--surface-1) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    box-shadow: var(--shadow-sm) !important;
}
[data-testid="metric-container"]:hover {
    border-color: rgba(255,255,255,0.14) !important;
}

/* ── Inputs ─────────────────────────────────── */
[data-testid="stTextInput"] input,
[data-testid="stNumberInput"] input,
[data-testid="stTextArea"] textarea {
    background: var(--surface-2) !important;
    border: 1px solid var(--border) !important;
    color: var(--text-primary) !important;
    border-radius: var(--radius-sm) !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.875rem !important;
    box-shadow: var(--shadow-sm) !important;
    transition: border-color 0.15s !important;
}
[data-testid="stTextInput"] input:focus,
[data-testid="stNumberInput"] input:focus,
[data-testid="stTextArea"] textarea:focus {
    border-color: var(--border-focus) !important;
    box-shadow: 0 0 0 3px var(--accent-dim) !important;
}

/* ── Selects ────────────────────────────────── */
[data-testid="stSelectbox"] > div > div,
[data-testid="stMultiSelect"] > div > div {
    background: var(--surface-2) !important;
    border: 1px solid var(--border) !important;
    color: var(--text-primary) !important;
    border-radius: var(--radius-sm) !important;
}
[data-baseweb="popover"], [data-baseweb="menu"] {
    background: var(--surface-2) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    box-shadow: var(--shadow-md) !important;
}
[data-baseweb="option"]:hover {
    background: var(--accent-dim) !important;
}

/* ── Buttons ────────────────────────────────── */
.stButton > button {
    border-radius: var(--radius-sm) !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.825rem !important;
    font-weight: 500 !important;
    letter-spacing: 0.01em !important;
    transition: all 0.15s ease !important;
    box-shadow: var(--shadow-sm) !important;
}
.stButton > button[kind="primary"] {
    background: var(--accent) !important;
    border: 1px solid rgba(108, 110, 247, 0.60) !important;
    color: #fff !important;
    box-shadow: 0 1px 3px rgba(108, 110, 247, 0.30), var(--shadow-sm) !important;
}
.stButton > button[kind="primary"]:hover {
    background: var(--accent-light) !important;
    border-color: rgba(147, 150, 250, 0.70) !important;
    box-shadow: 0 2px 8px rgba(108, 110, 247, 0.35), var(--shadow-sm) !important;
}
.stButton > button:not([kind="primary"]) {
    background: var(--surface-2) !important;
    border: 1px solid var(--border) !important;
    color: var(--text-secondary) !important;
}
.stButton > button:not([kind="primary"]):hover {
    border-color: rgba(255,255,255,0.16) !important;
    background: var(--surface-3) !important;
    color: var(--text-primary) !important;
}
.stButton > button:focus-visible {
    outline: 2px solid var(--accent) !important;
    outline-offset: 2px !important;
}

/* ── Tabs ───────────────────────────────────── */
[data-testid="stTabs"] [data-baseweb="tab-list"] {
    background: transparent !important;
    border-bottom: 1px solid var(--border) !important;
    gap: 0;
}
[data-testid="stTabs"] [data-baseweb="tab"] {
    color: var(--text-secondary) !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.825rem !important;
    font-weight: 500 !important;
    padding: 0.55rem 1.1rem !important;
    border-bottom: 2px solid transparent !important;
    background: transparent !important;
}
[data-testid="stTabs"] [data-baseweb="tab"]:hover {
    color: var(--text-primary) !important;
    background: rgba(255,255,255,0.04) !important;
    border-radius: var(--radius-sm) var(--radius-sm) 0 0 !important;
}
[data-testid="stTabs"] [data-baseweb="tab"][aria-selected="true"] {
    color: var(--accent-light) !important;
    border-bottom-color: var(--accent) !important;
}
[data-testid="stTabs"] [data-baseweb="tab-panel"] {
    background: transparent !important;
    border: none !important;
    padding: 1rem 0 !important;
}

/* ── DataFrames / data editor ───────────────── */
[data-testid="stDataFrame"],
[data-testid="stDataEditor"] {
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    overflow: hidden !important;
    box-shadow: var(--shadow-sm) !important;
}

/* ── Expanders ──────────────────────────────── */
[data-testid="stExpander"] {
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    background: var(--surface-1) !important;
    box-shadow: var(--shadow-sm) !important;
}
[data-testid="stExpander"] summary {
    color: var(--text-primary) !important;
    font-weight: 600 !important;
    font-size: 0.85rem !important;
}

/* ── Forms ──────────────────────────────────── */
[data-testid="stForm"] {
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    background: var(--surface-1) !important;
    padding: 1rem !important;
    box-shadow: var(--shadow-sm) !important;
}

/* ── Alerts ─────────────────────────────────── */
[data-testid="stAlert"] {
    border-radius: var(--radius-sm) !important;
    font-size: 0.825rem !important;
}

/* ── Typography ─────────────────────────────── */
h1 { font-size: 1.55rem !important; font-weight: 700 !important; color: var(--text-primary) !important; }
h2 { font-size: 1.20rem !important; font-weight: 600 !important; color: var(--text-primary) !important; }
h3 { font-size: 1.00rem !important; font-weight: 600 !important; color: var(--text-primary) !important; }
h4, h5, h6 { color: var(--text-secondary) !important; }
hr { border-color: var(--border) !important; margin: 1rem 0 !important; }
p  { color: var(--text-primary); line-height: 1.6; }

/* ── Scrollbar ──────────────────────────────── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.12); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.20); }

/* ── Portal hero ────────────────────────────── */
.portal-hero {
    padding: 1.5rem 1.75rem;
    border-radius: var(--radius-lg);
    border: 1px solid var(--border);
    background: linear-gradient(135deg, #1a1a24 0%, #1e1e2c 100%);
    box-shadow: var(--shadow-md);
    margin-bottom: 1.25rem;
    position: relative;
    overflow: hidden;
}
.portal-hero::after {
    content: '';
    position: absolute;
    top: 0; right: -80px;
    width: 280px; height: 140px;
    background: radial-gradient(ellipse, rgba(108,110,247,0.12) 0%, transparent 70%);
    pointer-events: none;
}
.portal-hero h1 { margin: 0; font-size: 1.45rem; color: var(--text-primary); font-weight: 700; }
.portal-hero p  { margin: 0.35rem 0 0; color: var(--text-secondary); font-size: 0.875rem; max-width: 60rem; line-height: 1.6; }

.feature-strip {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 0.75rem;
    margin: 1rem 0 1.25rem;
}
.feature-card {
    border: 1px solid var(--border);
    background: var(--surface-1);
    border-radius: var(--radius-md);
    padding: 1rem 1.05rem;
    min-height: 112px;
    box-shadow: var(--shadow-sm);
    transition: border-color 0.15s, background 0.15s;
}
.feature-card:hover {
    border-color: rgba(108,110,247,0.30);
    background: var(--surface-2);
}
.feature-card h3 { margin: 0 0 0.3rem; font-size: 0.90rem; color: var(--text-primary); font-weight: 600; }
.feature-card p  { margin: 0; color: var(--text-secondary); font-size: 0.82rem; line-height: 1.5; }

.eyebrow {
    font-size: 0.70rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--accent-light);
    margin-bottom: 0.4rem;
}

.section-note {
    border-left: 3px solid var(--accent);
    padding: 0.65rem 0.9rem;
    background: var(--surface-1);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
    margin-bottom: 1rem;
    color: var(--text-secondary);
    font-size: 0.85rem;
}

.page-header {
    padding: 0.6rem 0.9rem;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    background: var(--surface-1);
    margin-bottom: 1rem;
    box-shadow: var(--shadow-sm);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}
.page-header .path {
    font-size: 0.72rem;
    color: var(--text-muted);
    margin-bottom: 0.1rem;
}
.page-header .title { font-size: 0.95rem; color: var(--text-primary); font-weight: 600; }

/* ── Sidebar ─────────────────────────────────── */
[data-testid="stSidebar"] { border-right: 1px solid var(--border); }
[data-testid="stSidebar"] > div:first-child { background: var(--surface-1); }
[data-testid="stSidebar"] * { color: var(--text-primary); }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color: var(--text-secondary); }

[data-testid="stSidebar"] .stButton > button {
    width: 100%;
    border-radius: var(--radius-sm);
    margin-bottom: 0.18rem;
    border: 1px solid transparent;
    background: transparent;
    color: var(--text-secondary);
    text-align: left;
    justify-content: flex-start;
    font-size: 0.825rem !important;
    font-weight: 500 !important;
    transition: all 0.15s ease;
    box-shadow: none !important;
}
[data-testid="stSidebar"] .stButton > button:hover {
    border-color: var(--border);
    background: var(--surface-2);
    color: var(--text-primary);
    transform: none;
}
[data-testid="stSidebar"] .stButton > button[kind="primary"] {
    background: var(--accent-dim) !important;
    border-color: rgba(108,110,247,0.30) !important;
    color: var(--accent-light) !important;
    box-shadow: none !important;
}
[data-testid="stSidebar"] .stButton > button[kind="primary"]:hover {
    background: rgba(108,110,247,0.22) !important;
    border-color: rgba(108,110,247,0.42) !important;
    color: #fff !important;
}
[data-testid="stSidebar"] .stButton > button:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
}

.nav-panel-title {
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 0.3rem;
}
.nav-current {
    border: 1px solid rgba(108,110,247,0.28);
    background: var(--accent-dim);
    border-radius: var(--radius-md);
    padding: 0.5rem 0.7rem;
    margin-bottom: 0.6rem;
}
.nav-current .path { font-size: 0.66rem; color: var(--text-muted); }
.nav-current .name { font-size: 0.88rem; color: var(--text-primary); font-weight: 600; }

.nav-pill {
    display: inline-block;
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 0.12rem 0.48rem;
    font-size: 0.64rem;
    font-weight: 500;
    color: var(--text-secondary);
    margin-bottom: 0.36rem;
    background: var(--surface-2);
}

[data-testid="stSidebar"] [data-testid="stExpander"] {
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    background: var(--surface-2) !important;
    margin-bottom: 0.3rem !important;
    overflow: hidden;
    box-shadow: none !important;
}
[data-testid="stSidebar"] [data-testid="stExpander"] details summary {
    padding: 0.3rem 0.5rem;
    font-size: 0.82rem;
    font-weight: 600;
    color: var(--text-secondary);
    background: transparent;
}
[data-testid="stSidebar"] [data-testid="stExpander"] details[open] summary {
    border-bottom: 1px solid var(--border);
    color: var(--text-primary);
}
</style>
""",
    unsafe_allow_html=True,
)


def _render_dashboard_header() -> None:
        st.markdown(
                """
<div class="portal-hero">
    <div class="eyebrow">Security Architecture Portal</div>
    <h1>Your unified security operations cockpit</h1>
    <p>Generate architecture reports, track assets &amp; licensing, manage budgets, monitor threat activity, and surface public exposure — all in one place.</p>
</div>
<div class="feature-strip">
    <div class="feature-card"><div style="font-size:1.4rem;margin-bottom:0.35rem;">&#x1F4C4;</div><h3>Report Generation</h3><p>Excel → architecture report with background jobs and export history.</p></div>
    <div class="feature-card"><div style="font-size:1.4rem;margin-bottom:0.35rem;">&#x1F6E1;&#xFE0F;</div><h3>Asset Inventory</h3><p>Track security tools, seats, renewals, and annual licensing spend.</p></div>
    <div class="feature-card"><div style="font-size:1.4rem;margin-bottom:0.35rem;">&#x1F4B0;</div><h3>Budget Tracking</h3><p>Manage Opex &amp; Capex by domain, quarter, owner, and approval status.</p></div>
    <div class="feature-card"><div style="font-size:1.4rem;margin-bottom:0.35rem;">&#x1F310;</div><h3>Public Exposure</h3><p>Subdomains, public IPs, certificate validity, and provider footprint.</p></div>
    <div class="feature-card"><div style="font-size:1.4rem;margin-bottom:0.35rem;">&#x1F4CA;</div><h3>SOC Analytics</h3><p>171K+ ticket ML analysis with MITRE coverage, budget correlation, and AI narrative.</p></div>
</div>
""",
                unsafe_allow_html=True,
        )


def _render_concise_header(current_page: str) -> None:
        st.markdown(
                f"""
<div class="page-header">
    <div>
        <div class="path">Security Architecture Portal / {current_page}</div>
        <div class="title">{current_page}</div>
    </div>
</div>
""",
                unsafe_allow_html=True,
        )


@st.cache_resource
def get_vector_store():
    return init_vector_store()


@st.cache_resource
def get_background_worker() -> BackgroundJobWorker:
    worker = BackgroundJobWorker(get_vector_store())
    worker.start()
    return worker


vector_store = get_vector_store()
job_worker = get_background_worker()


@st.cache_resource
def get_budget_ai_runner() -> BudgetAIBackgroundRunner:
    return BudgetAIBackgroundRunner()


budget_ai_runner = get_budget_ai_runner()


# Cookie name: __Host- prefix enforces Secure + no Domain + Path=/ per RFC 6265bis
_SESSION_COOKIE = "__Host-sid"
_COOKIE_MAX_AGE = CONFIG.auth_session_timeout_minutes * 60


def _get_cookie_controller() -> CookieController:
    """Return a per-render CookieController instance (cached in session state)."""
    if "_cookie_ctrl" not in st.session_state:
        st.session_state["_cookie_ctrl"] = CookieController()
    return st.session_state["_cookie_ctrl"]


def _set_authenticated_user(user: dict[str, object], method: str) -> None:
    now = datetime.now(UTC)
    st.session_state["auth_user"] = user
    st.session_state["auth_method"] = method
    st.session_state["auth_login_at_utc"] = now.isoformat()
    st.session_state["auth_expires_at_utc"] = (now + timedelta(minutes=CONFIG.auth_session_timeout_minutes)).isoformat()
    # Create server-side session and persist token in a Secure; SameSite=Strict cookie
    # (HttpOnly requires a reverse proxy — document this in deployment guide)
    token = create_session(user, method)
    st.session_state["auth_session_token"] = token
    try:
        ctrl = _get_cookie_controller()
        ctrl.set(
            _SESSION_COOKIE,
            token,
            max_age=_COOKIE_MAX_AGE,
            secure=True,
            same_site="strict",
            path="/",
        )
    except Exception:
        pass


def _clear_authenticated_user() -> None:
    token = str(st.session_state.get("auth_session_token", "")).strip()
    if token:
        delete_session(token)
    for key in ["auth_user", "auth_method", "auth_login_at_utc", "auth_expires_at_utc", "auth_session_token"]:
        st.session_state.pop(key, None)
    # Remove the session cookie
    try:
        ctrl = _get_cookie_controller()
        ctrl.remove(_SESSION_COOKIE)
    except Exception:
        pass


def _current_user() -> dict[str, object] | None:
    user = st.session_state.get("auth_user")
    return user if isinstance(user, dict) else None


def _refresh_session_user(updated_user: dict[str, object] | None) -> None:
    current_user = _current_user()
    if not updated_user or not current_user:
        return
    if str(current_user.get("username", "")).strip().lower() != str(updated_user.get("username", "")).strip().lower():
        return
    _set_authenticated_user(updated_user, str(st.session_state.get("auth_method", "local")).lower())


def _set_passkey_ceremony(prefix: str, ceremony: dict[str, str], username: str = "") -> None:
    st.session_state[f"{prefix}_options_json"] = ceremony.get("options_json", "")
    st.session_state[f"{prefix}_challenge"] = ceremony.get("challenge", "")
    st.session_state[f"{prefix}_username"] = username.strip().lower()


def _get_passkey_ceremony(prefix: str) -> dict[str, str] | None:
    options_json = str(st.session_state.get(f"{prefix}_options_json", "")).strip()
    challenge = str(st.session_state.get(f"{prefix}_challenge", "")).strip()
    username = str(st.session_state.get(f"{prefix}_username", "")).strip().lower()
    if not options_json or not challenge:
        return None
    return {
        "options_json": options_json,
        "challenge": challenge,
        "username": username,
    }


def _clear_passkey_ceremony(prefix: str) -> None:
    for suffix in ["options_json", "challenge", "username"]:
        st.session_state.pop(f"{prefix}_{suffix}", None)


def _is_session_valid() -> bool:
    expires = st.session_state.get("auth_expires_at_utc", "")
    if not isinstance(expires, str) or not expires.strip():
        return False
    try:
        expires_at = datetime.fromisoformat(expires)
    except ValueError:
        return False
    return datetime.now(UTC) < expires_at


def _render_login_page() -> None:
    auth_config = load_auth_config()
    providers = auth_config.get("providers", {}) if isinstance(auth_config, dict) else {}
    saml_cfg = auth_config.get("saml", {}) if isinstance(auth_config, dict) else {}
    passkey_cfg = auth_config.get("passkey", {}) if isinstance(auth_config, dict) else {}

    # ── Login page layout ── hide sidebar, center to ~820 px box
    st.markdown(
        """
<style>
[data-testid="stSidebar"] { display: none !important; }
[data-testid="stHeader"]  { background: transparent !important; }
[data-testid="stMainBlockContainer"] {
    max-width: 820px !important;
    margin: 0 auto !important;
    padding-top: 5vh !important;
}
.login-box {
    background: #18181f;
    border: 1px solid rgba(255, 255, 255, 0.09);
    border-radius: 14px;
    padding: 1.75rem 1.8rem 1.25rem;
    box-shadow: 0 4px 24px rgba(0,0,0,0.50), 0 1px 4px rgba(0,0,0,0.30);
    position: relative;
    overflow: hidden;
    margin-bottom: 1rem;
}
.login-box::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, transparent 0%, rgba(108,110,247,0.80) 50%, transparent 100%);
}
.login-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    color: #9396fa;
    border: 1px solid rgba(108, 110, 247, 0.28);
    border-radius: 999px;
    padding: 0.16rem 0.60rem;
    margin-bottom: 0.75rem;
    background: rgba(108, 110, 247, 0.10);
}
.login-title {
    font-size: 1.22rem;
    font-weight: 700;
    color: #e8e8f0;
    margin: 0 0 0.25rem 0;
    line-height: 1.3;
    font-family: 'Inter', sans-serif;
}
.login-subtitle {
    font-size: 0.825rem;
    color: #8888a0;
    font-family: 'Inter', sans-serif;
    line-height: 1.5;
}
</style>
<div class="login-box">
    <div class="login-badge">&#x25CF; Access Control</div>
    <div class="login-title">Sign in to Security Architecture Portal</div>
    <div class="login-subtitle">Use Local User, SAML, or Passkey based on your tenant policy.</div>
</div>
""",
        unsafe_allow_html=True,
    )

    local_enabled = bool(providers.get("local", True))
    saml_enabled = bool(providers.get("saml", True)) and bool(saml_cfg.get("enabled", False))
    passkey_enabled = bool(providers.get("passkey", True))

    available_methods = [
        method
        for method, enabled in [
            ("Local User", local_enabled),
            ("SAML", saml_enabled),
            ("Passkey", passkey_enabled),
        ]
        if enabled
    ]

    if not available_methods:
        st.error("No login method is enabled. Use bootstrap admin credentials after enabling Local User in auth config.")
        return

    tabs = st.tabs(available_methods)
    tab_idx = 0

    if local_enabled:
        with tabs[tab_idx]:
            st.markdown("#### Local Account Access")
            local_action_tabs = st.tabs(["Sign In", "Register", "Change Password", "Forgot Password"])

            with local_action_tabs[0]:
                with st.form("login_local_form"):
                    username = st.text_input("Username")
                    password = st.text_input("Password", type="password")
                    submitted = st.form_submit_button("Sign in with Local User", type="primary")

                if submitted:
                    user = authenticate_local(username, password)
                    if not user:
                        st.error("Invalid username or password.")
                    else:
                        _set_authenticated_user(user, "local")
                        st.success("Login successful.")
                        st.rerun()

            with local_action_tabs[1]:
                with st.form("register_local_form"):
                    reg_full_name = st.text_input("Full Name", key="local_register_full_name")
                    reg_email = st.text_input("Email", key="local_register_email")
                    reg_username = st.text_input("Username", key="local_register_username")
                    reg_password = st.text_input("Password", type="password", key="local_register_password")
                    reg_password_confirm = st.text_input(
                        "Confirm Password",
                        type="password",
                        key="local_register_password_confirm",
                    )
                    reg_submitted = st.form_submit_button("Register Local User")

                if reg_submitted:
                    if reg_password != reg_password_confirm:
                        st.error("Password confirmation does not match.")
                    else:
                        try:
                            created_user = register_local_user(
                                username=reg_username,
                                password=reg_password,
                                full_name=reg_full_name,
                                email=reg_email,
                            )
                        except ValueError as exc:
                            st.error(str(exc))
                        else:
                            _set_authenticated_user(created_user, "local")
                            st.success("Registration successful. You are now signed in.")
                            st.rerun()

            with local_action_tabs[2]:
                with st.form("change_local_password_form"):
                    cp_username = st.text_input("Username", key="change_password_username")
                    cp_current_password = st.text_input(
                        "Current Password",
                        type="password",
                        key="change_password_current",
                    )
                    cp_new_password = st.text_input(
                        "New Password",
                        type="password",
                        key="change_password_new",
                    )
                    cp_confirm_password = st.text_input(
                        "Confirm New Password",
                        type="password",
                        key="change_password_confirm",
                    )
                    cp_submitted = st.form_submit_button("Change Password")

                if cp_submitted:
                    if cp_new_password != cp_confirm_password:
                        st.error("New password confirmation does not match.")
                    else:
                        try:
                            updated_user = change_local_password(cp_username, cp_current_password, cp_new_password)
                        except ValueError as exc:
                            st.error(str(exc))
                        else:
                            if not updated_user:
                                st.error("Unable to change password. Verify username and current password.")
                            else:
                                _set_authenticated_user(updated_user, "local")
                                st.success("Password changed successfully.")
                                st.rerun()

            with local_action_tabs[3]:
                st.caption("Forgot password recovery requires a registered browser passkey or authenticator app.")
                with st.form("forgot_password_form"):
                    fp_username = st.text_input("Username", key="forgot_password_username")
                    fp_new_password = st.text_input("New Password", type="password", key="forgot_password_new")
                    fp_confirm_password = st.text_input(
                        "Confirm New Password",
                        type="password",
                        key="forgot_password_confirm",
                    )
                    fp_submitted = st.form_submit_button("Begin Passkey Verification")

                if fp_submitted:
                    if fp_new_password != fp_confirm_password:
                        st.error("New password confirmation does not match.")
                    else:
                        ceremony = begin_passkey_authentication(fp_username)
                        if not ceremony:
                            st.error("Password reset failed. Verify the username and confirm a browser passkey is registered.")
                        else:
                            _set_passkey_ceremony("forgot_password_passkey", ceremony, fp_username)
                            st.info("Approve the password reset with your browser authenticator.")

                forgot_password_ceremony = _get_passkey_ceremony("forgot_password_passkey")
                if forgot_password_ceremony:
                    recovery_result = webauthn_bridge(
                        mode="authenticate",
                        options_json=forgot_password_ceremony["options_json"],
                        button_label="Verify Browser Passkey",
                        key="forgot_password_webauthn",
                    )
                    if isinstance(recovery_result, dict):
                        if not bool(recovery_result.get("ok", False)):
                            st.error(str(recovery_result.get("error", "Passkey verification failed.")))
                        elif fp_new_password != fp_confirm_password:
                            st.error("New password confirmation does not match.")
                        else:
                            verified_user = finish_passkey_authentication(
                                credential=recovery_result.get("credential", {}),
                                expected_challenge=forgot_password_ceremony["challenge"],
                                username=forgot_password_ceremony["username"],
                            )
                            if not verified_user:
                                st.error("Passkey verification failed. Unable to validate the authenticator response.")
                            else:
                                try:
                                    updated_user = reset_local_password(
                                        forgot_password_ceremony["username"],
                                        fp_new_password,
                                    )
                                except ValueError as exc:
                                    st.error(str(exc))
                                else:
                                    if not updated_user:
                                        st.error("Password reset failed after passkey verification.")
                                    else:
                                        _clear_passkey_ceremony("forgot_password_passkey")
                                        _set_authenticated_user(updated_user, "passkey")
                                        st.success("Password reset successful. You are now signed in.")
                                        st.rerun()

            st.caption(
                "Bootstrap admin defaults: "
                f"{CONFIG.auth_bootstrap_admin_user} / {CONFIG.auth_bootstrap_admin_password}"
            )
        tab_idx += 1

    if saml_enabled:
        with tabs[tab_idx]:
            st.markdown("#### SAML Login")
            st.caption("SAML assertion mapping. Paste Base64 SAMLResponse or enter subject/email manually.")
            with st.form("login_saml_form"):
                saml_response_b64 = st.text_area("SAMLResponse (Base64, optional)", height=120)
                saml_subject = st.text_input("SAML Subject (NameID)")
                saml_email = st.text_input("Email")
                saml_full_name = st.text_input("Full Name")
                submitted = st.form_submit_button("Sign in with SAML", type="primary")

            if submitted:
                parse_failed = False
                if saml_response_b64.strip():
                    try:
                        decoded = base64.b64decode(saml_response_b64.strip())
                        root = ElementTree.fromstring(decoded)
                        ns = {
                            "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
                        }
                        nameid = root.find(".//saml2:NameID", ns)
                        saml_subject = (nameid.text or "").strip() if nameid is not None else saml_subject

                        for attr in root.findall(".//saml2:Attribute", ns):
                            key = str(attr.attrib.get("Name", "")).strip().lower()
                            attr_val = attr.find(".//saml2:AttributeValue", ns)
                            val = (attr_val.text or "").strip() if attr_val is not None and attr_val.text else ""
                            if not val:
                                continue
                            if key in {"email", "mail", "emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"}:
                                saml_email = val
                            if key in {"name", "displayname", "cn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"}:
                                saml_full_name = val
                    except (binascii.Error, ElementTree.ParseError, ValueError):
                        st.error("Unable to parse SAMLResponse. Please verify Base64 payload or use manual fields.")
                        parse_failed = True

                if parse_failed:
                    user = None
                else:
                    user = authenticate_saml_identity(saml_subject, saml_email, saml_full_name)
                if not user:
                    st.error("SAML login was rejected. Verify domain policy, user mapping, and SAML config.")
                else:
                    _set_authenticated_user(user, "saml")
                    st.success("SAML login successful.")
                    st.rerun()
        tab_idx += 1

    if passkey_enabled:
        with tabs[tab_idx]:
            st.markdown("#### Passkey Access")
            st.caption("Use a browser or device authenticator. No typed passkey secrets are accepted.")

            passkey_login_col, passkey_register_col = st.columns(2)

            with passkey_login_col:
                st.markdown("**Login with Passkey**")
                with st.form("login_passkey_form"):
                    username_hint = st.text_input(
                        "Username (optional)",
                        key="passkey_login_user_hint",
                        help="Leave blank for usernameless passkey login if your authenticator supports discoverable credentials.",
                    )
                    submitted = st.form_submit_button("Begin Passkey Sign In", type="primary")

                if submitted:
                    ceremony = begin_passkey_authentication(username_hint)
                    if not ceremony:
                        st.error("Passkey login is not ready for that account. Ensure the user has a registered browser passkey.")
                    else:
                        _set_passkey_ceremony("login_passkey_auth", ceremony, username_hint)
                        st.info("Confirm the sign-in using your browser, device, or third-party passkey app.")

                login_ceremony = _get_passkey_ceremony("login_passkey_auth")
                if login_ceremony:
                    login_result = webauthn_bridge(
                        mode="authenticate",
                        options_json=login_ceremony["options_json"],
                        button_label="Use Browser Passkey",
                        key="login_passkey_webauthn",
                    )
                    if isinstance(login_result, dict):
                        if not bool(login_result.get("ok", False)):
                            st.error(str(login_result.get("error", "Passkey authentication failed.")))
                        else:
                            user = finish_passkey_authentication(
                                credential=login_result.get("credential", {}),
                                expected_challenge=login_ceremony["challenge"],
                                username=login_ceremony["username"],
                            )
                            if not user:
                                st.error("Passkey login failed. The authenticator response could not be verified.")
                            else:
                                _clear_passkey_ceremony("login_passkey_auth")
                                _set_authenticated_user(user, "passkey")
                                st.success("Passkey login successful.")
                                st.rerun()

            with passkey_register_col:
                st.markdown("**Create Passkey**")
                with st.form("register_passkey_form"):
                    reg_username = st.text_input("Username", key="passkey_register_user")
                    reg_password = st.text_input("Local Password", type="password", key="passkey_register_password")
                    reg_submitted = st.form_submit_button("Prepare Passkey Registration")

                if reg_submitted:
                    verified_user = authenticate_local(reg_username, reg_password)
                    if not verified_user:
                        st.error("Local credential verification failed. Unable to register browser passkey.")
                    else:
                        ceremony = begin_passkey_registration(verified_user)
                        _set_passkey_ceremony("login_passkey_register", ceremony, str(verified_user.get("username", "")))
                        st.info("Finish passkey registration with your browser or authenticator app.")

                registration_ceremony = _get_passkey_ceremony("login_passkey_register")
                if registration_ceremony:
                    registration_result = webauthn_bridge(
                        mode="register",
                        options_json=registration_ceremony["options_json"],
                        button_label="Register Browser Passkey",
                        key="register_passkey_webauthn",
                    )
                    if isinstance(registration_result, dict):
                        if not bool(registration_result.get("ok", False)):
                            st.error(str(registration_result.get("error", "Passkey registration failed.")))
                        else:
                            verified_user = find_user(registration_ceremony["username"])
                            try:
                                updated_user = finish_passkey_registration(
                                    user=verified_user or {},
                                    credential=registration_result.get("credential", {}),
                                    expected_challenge=registration_ceremony["challenge"],
                                )
                            except Exception as _reg_exc:
                                st.error(f"Passkey registration error: {_reg_exc}")
                                updated_user = None
                            if not updated_user:
                                st.error("Passkey registration failed. Unable to save the authenticator credential.")
                            else:
                                _clear_passkey_ceremony("login_passkey_register")
                                st.success("Browser passkey registered. You can now sign in with your passkey.")
                                st.rerun()


def _is_admin() -> bool:
    user = _current_user()
    if not user:
        return False
    return str(user.get("role", "")).strip().lower() == "admin"


def _render_user_management() -> None:
    if not _is_admin():
        st.warning("User Management is restricted to administrators.")
        return

    auth_config = load_auth_config()
    users_df = pd.DataFrame(load_users())
    st.subheader("Authentication & User Management")

    config_tab, users_tab = st.tabs(["Authentication Providers", "Users"])

    with config_tab:
        providers = auth_config.get("providers", {}) if isinstance(auth_config, dict) else {}
        saml_cfg = auth_config.get("saml", {}) if isinstance(auth_config, dict) else {}
        passkey_cfg = auth_config.get("passkey", {}) if isinstance(auth_config, dict) else {}

        with st.form("auth_provider_config_form"):
            auth_enabled = st.toggle("Enable Authentication", value=bool(auth_config.get("auth_enabled", True)))

            st.markdown("**Enabled Login Methods**")
            local_enabled = st.checkbox("Local User", value=bool(providers.get("local", True)))
            saml_provider_enabled = st.checkbox("SAML", value=bool(providers.get("saml", True)))
            passkey_provider_enabled = st.checkbox("Passkey", value=bool(providers.get("passkey", True)))

            st.markdown("**SAML Settings**")
            saml_enabled = st.checkbox("SAML Flow Active", value=bool(saml_cfg.get("enabled", False)))
            saml_auto_provision = st.checkbox(
                "Auto-provision SAML users",
                value=bool(saml_cfg.get("auto_provision", True)),
            )
            saml_allowed_domains_text = st.text_input(
                "Allowed Email Domains (comma-separated)",
                value=", ".join(saml_cfg.get("allowed_domains", [])),
            )
            saml_entity_id = st.text_input("SAML Entity ID", value=str(saml_cfg.get("entity_id", "")))
            saml_idp_sso_url = st.text_input("IdP SSO URL", value=str(saml_cfg.get("idp_sso_url", "")))
            saml_idp_metadata_url = st.text_input("IdP Metadata URL", value=str(saml_cfg.get("idp_metadata_url", "")))

            st.markdown("**Passkey Settings**")
            passkey_enabled = st.checkbox("Passkey Flow Active", value=bool(passkey_cfg.get("enabled", False)))
            passkey_auto_provision = st.checkbox(
                "Auto-provision Passkey users",
                value=bool(passkey_cfg.get("auto_provision", False)),
            )
            passkey_display_name = st.text_input(
                "Passkey Provider Name",
                value=str(passkey_cfg.get("display_name", CONFIG.auth_passkey_rp_name)),
            )
            passkey_rp_id = st.text_input(
                "Passkey RP ID",
                value=str(passkey_cfg.get("rp_id", CONFIG.auth_passkey_rp_id)),
                help="Use the host name users see in the browser, for example localhost or portal.example.com.",
            )
            passkey_origin = st.text_input(
                "Passkey Origin",
                value=str(passkey_cfg.get("origin", CONFIG.auth_passkey_origin)),
                help="Full browser origin, for example http://localhost:8501 or https://portal.example.com.",
            )
            passkey_note = st.text_area(
                "Passkey Provider Notes",
                value=str(passkey_cfg.get("note", "")),
                height=100,
            )

            saved = st.form_submit_button("Save Authentication Configuration", type="primary")

        if saved:
            updated_config = {
                "auth_enabled": auth_enabled,
                "providers": {
                    "local": local_enabled,
                    "saml": saml_provider_enabled,
                    "passkey": passkey_provider_enabled,
                },
                "saml": {
                    "enabled": saml_enabled,
                    "auto_provision": saml_auto_provision,
                    "allowed_domains": [
                        domain.strip().lower()
                        for domain in saml_allowed_domains_text.split(",")
                        if domain.strip()
                    ],
                    "entity_id": saml_entity_id.strip(),
                    "idp_sso_url": saml_idp_sso_url.strip(),
                    "idp_metadata_url": saml_idp_metadata_url.strip(),
                },
                "passkey": {
                    "enabled": passkey_enabled,
                    "auto_provision": passkey_auto_provision,
                    "display_name": passkey_display_name.strip() or CONFIG.auth_passkey_rp_name,
                    "rp_id": passkey_rp_id.strip() or CONFIG.auth_passkey_rp_id,
                    "origin": passkey_origin.strip() or CONFIG.auth_passkey_origin,
                    "note": passkey_note.strip(),
                },
            }
            save_auth_config(updated_config)
            st.success("Authentication configuration updated.")
            st.rerun()

    with users_tab:
        st.caption("Edit users inline, reset credentials, and enable or disable access per account.")
        if users_df.empty:
            st.info("No users found.")
        else:
            st.dataframe(
                users_df[["username", "full_name", "email", "role", "enabled", "saml_subject", "updated_at_utc"]],
                use_container_width=True,
                hide_index=True,
            )

            st.markdown("**Editable User List**")
            for row in load_users():
                username_value = str(row.get("username", "")).strip()
                role_value = str(row.get("role", "viewer")).strip().lower()
                enabled_value = bool(row.get("enabled", True))
                status_text = "Enabled" if enabled_value else "Disabled"

                with st.expander(f"{username_value} | {role_value} | {status_text}"):
                    edit_col, password_col, passkey_col = st.columns(3)

                    with edit_col:
                        with st.form(f"edit_user_{username_value}"):
                            edit_full_name = st.text_input(
                                "Full Name",
                                value=str(row.get("full_name", "")),
                                key=f"edit_full_name_{username_value}",
                            )
                            edit_email = st.text_input(
                                "Email",
                                value=str(row.get("email", "")),
                                key=f"edit_email_{username_value}",
                            )
                            role_index = ["admin", "analyst", "viewer"].index(role_value) if role_value in {"admin", "analyst", "viewer"} else 2
                            edit_role = st.selectbox(
                                "Role",
                                ["admin", "analyst", "viewer"],
                                index=role_index,
                                key=f"edit_role_{username_value}",
                            )
                            edit_enabled = st.checkbox(
                                "Enabled",
                                value=enabled_value,
                                key=f"edit_enabled_{username_value}",
                            )
                            edit_saml_subject = st.text_input(
                                "SAML Subject",
                                value=str(row.get("saml_subject", "")),
                                key=f"edit_saml_subject_{username_value}",
                            )
                            save_profile = st.form_submit_button("Save Profile", type="primary")

                        if save_profile:
                            try:
                                updated_user = update_user_profile(
                                    username_value,
                                    full_name=edit_full_name,
                                    email=edit_email,
                                    role=edit_role,
                                    enabled=edit_enabled,
                                    saml_subject=edit_saml_subject,
                                )
                            except ValueError as exc:
                                st.error(str(exc))
                            else:
                                if not updated_user:
                                    st.error("Unable to update the selected user.")
                                else:
                                    _refresh_session_user(updated_user)
                                    st.success(f"Updated {username_value}.")
                                    st.rerun()

                    with password_col:
                        with st.form(f"reset_password_{username_value}"):
                            new_password = st.text_input(
                                "New Password",
                                type="password",
                                key=f"admin_reset_password_{username_value}",
                            )
                            confirm_password = st.text_input(
                                "Confirm Password",
                                type="password",
                                key=f"admin_reset_password_confirm_{username_value}",
                            )
                            reset_password_button = st.form_submit_button("Reset Password")

                        if reset_password_button:
                            if new_password != confirm_password:
                                st.error("Password confirmation does not match.")
                            else:
                                try:
                                    updated_user = reset_local_password(username_value, new_password)
                                except ValueError as exc:
                                    st.error(str(exc))
                                else:
                                    if not updated_user:
                                        st.error("Unable to reset password for the selected user.")
                                    else:
                                        _refresh_session_user(updated_user)
                                        st.success(f"Password reset for {username_value}.")
                                        st.rerun()

                    with passkey_col:
                        passkey_details = passkey_summary(row)
                        st.caption(f"Registered passkeys: {passkey_details['count']}")
                        if passkey_details["labels"]:
                            for detail in passkey_details["labels"]:
                                st.write(detail)
                        else:
                            st.write("No browser passkeys registered.")

                        if st.button(f"Revoke Passkeys for {username_value}", key=f"revoke_passkey_{username_value}"):
                            updated_user = clear_user_passkeys(username_value)
                            if not updated_user:
                                st.error("Unable to revoke passkeys for the selected user.")
                            else:
                                _refresh_session_user(updated_user)
                                st.success(f"Passkeys revoked for {username_value}.")
                                st.rerun()

                    if st.button(
                        f"Delete {username_value}",
                        key=f"delete_user_button_{username_value}",
                        disabled=username_value.strip().lower() == str(CONFIG.auth_bootstrap_admin_user).strip().lower(),
                    ):
                        if delete_user(username_value):
                            st.success(f"User {username_value} deleted.")
                            st.rerun()
                        else:
                            st.warning("Unable to delete the selected user.")

        with st.form("user_upsert_form", clear_on_submit=True):
            st.markdown("**Create / Update User**")
            col_1, col_2, col_3 = st.columns(3)
            username = col_1.text_input("Username")
            full_name = col_2.text_input("Full Name")
            email = col_3.text_input("Email")

            col_4, col_5, col_6 = st.columns(3)
            role = col_4.selectbox("Role", ["admin", "analyst", "viewer"], index=2)
            enabled = col_5.checkbox("Enabled", value=True)
            saml_subject = col_6.text_input("SAML Subject")

            col_7, col_8 = st.columns(2)
            password = col_7.text_input("Local Password (optional for update)", type="password")
            st.caption("Browser passkeys are registered by the user through the passkey flows, not by typing a shared secret.")

            submitted = st.form_submit_button("Save User", type="primary")

        if submitted:
            try:
                upsert_user(
                    {
                        "username": username,
                        "full_name": full_name,
                        "email": email,
                        "role": role,
                        "enabled": enabled,
                        "saml_subject": saml_subject,
                    },
                    password=password,
                )
            except ValueError as exc:
                st.error(str(exc))
            else:
                st.success("User saved.")
                st.rerun()

        delete_options = [str(row.get("username", "")) for row in load_users()]
        delete_target = st.selectbox("Delete User", options=[""] + delete_options)
        if st.button("Delete Selected User", disabled=not bool(delete_target.strip())):
            if delete_user(delete_target):
                st.success(f"User {delete_target} deleted.")
                st.rerun()
            else:
                st.warning("Unable to delete the selected user.")


def _enforce_authentication() -> bool:
    auth_config = load_auth_config()
    if not bool(auth_config.get("auth_enabled", True)):
        return True

    if not _is_session_valid():
        _clear_authenticated_user()

    # If no live in-memory session, try to restore from the session cookie
    if not _current_user():
        try:
            ctrl = _get_cookie_controller()
            _cookie_token = str(ctrl.get(_SESSION_COOKIE) or "").strip()
        except Exception:
            _cookie_token = ""

        if _cookie_token:
            _record = get_session(_cookie_token)
            if _record:
                _uname = str(_record.get("username", "")).strip()
                _method = str(_record.get("method", "local")).strip()
                _stored_user = find_user(_uname)
                if _stored_user and bool(_stored_user.get("enabled", True)):
                    now = datetime.now(UTC)
                    st.session_state["auth_user"] = _stored_user
                    st.session_state["auth_method"] = _method
                    st.session_state["auth_login_at_utc"] = now.isoformat()
                    st.session_state["auth_expires_at_utc"] = (
                        now + timedelta(minutes=CONFIG.auth_session_timeout_minutes)
                    ).isoformat()
                    st.session_state["auth_session_token"] = _cookie_token
                    renew_session(_cookie_token)
                else:
                    # Token references a disabled / deleted user — invalidate cookie
                    delete_session(_cookie_token)
                    try:
                        _get_cookie_controller().remove(_SESSION_COOKIE)
                    except Exception:
                        pass
            else:
                # Expired or unknown token — remove stale cookie
                try:
                    _get_cookie_controller().remove(_SESSION_COOKIE)
                except Exception:
                    pass

    user = _current_user()
    if user and bool(user.get("enabled", True)):
        return True

    _render_login_page()
    return False


def _assets_df() -> pd.DataFrame:
    rows = load_assets()
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["annual_cost"] = pd.to_numeric(df["annual_cost"], errors="coerce").fillna(0.0)
    df["license_seats"] = pd.to_numeric(df["license_seats"], errors="coerce").fillna(0)
    df["seats_used"] = pd.to_numeric(df["seats_used"], errors="coerce").fillna(0)
    df["renewal_date"] = pd.to_datetime(df["renewal_date"], errors="coerce")
    df["days_to_renewal"] = (df["renewal_date"] - pd.Timestamp(date.today())).dt.days
    return df


def _budgets_df() -> pd.DataFrame:
    df = pd.DataFrame(load_budgets())
    if df.empty:
        return df
    df["amount"] = pd.to_numeric(df["amount"], errors="coerce").fillna(0.0)
    if "cashout_entries" not in df.columns:
        df["cashout_entries"] = [[] for _ in range(len(df))]
    df["cashout_entries"] = df["cashout_entries"].apply(lambda v: v if isinstance(v, list) else [])
    df["total_cashout"] = df["cashout_entries"].apply(
        lambda entries: sum(float(e.get("cashout", 0) or 0) for e in entries)
    )
    df["grand_total"] = df["amount"] - df["total_cashout"]
    df["nama_spk"] = df["cashout_entries"].apply(
        lambda entries: "; ".join(str(e.get("nama_spk", "")) for e in entries if e.get("nama_spk"))
    )
    return df


@st.cache_data(ttl=120)
def _public_exposure_df() -> pd.DataFrame:
    df = pd.DataFrame(load_public_exposures())
    if df.empty:
        return df

    df["ip_addresses"] = df["ip_addresses"].apply(
        lambda value: value if isinstance(value, list) else ([] if pd.isna(value) else [str(value)])
    )
    df["ip_count"] = df["ip_addresses"].apply(len)
    df = df[df["ip_count"] > 0].copy()
    if df.empty:
        return df

    df["Provider"] = df["provider"].replace("", "Unknown")
    df["ssl_issuer_org"] = df["ssl_issuer_org"].fillna("").replace("", "Unknown")
    df["ip_addresses_display"] = df["ip_addresses"].apply(lambda values: ", ".join(values))
    df["ssl_not_after"] = pd.to_datetime(df["ssl_not_after"], errors="coerce", utc=True)
    now = pd.Timestamp.utcnow()
    df["ssl_days_remaining"] = (df["ssl_not_after"] - now).dt.days
    return df.sort_values(by=["subdomain", "ip_count"], ascending=[True, False]).reset_index(drop=True)


@st.cache_data(ttl=120)
def _waf_sites_df() -> pd.DataFrame:
    rows = load_waf_sites()
    if not rows:
        return pd.DataFrame(columns=["domain", "ips", "ips_display", "status", "ddos_protection", "waf_mode", "timestamp"])
    df = pd.DataFrame(rows)
    df["ips"] = df["ips"].apply(
        lambda v: v if isinstance(v, list) else ([] if pd.isna(v) else [str(v)])
    )
    df["ips_display"] = df["ips"].apply(lambda v: ", ".join(v) if v else "-")
    df["ddos_protection"] = df["ddos_protection"].apply(
        lambda v: bool(v) if not isinstance(v, bool) else v
    )
    df["status"] = df["status"].fillna("").astype(str)
    df["waf_mode"] = df["waf_mode"].fillna("").astype(str)
    df["domain"] = df["domain"].fillna("").astype(str)
    return df.sort_values("domain").reset_index(drop=True)


def _format_money(value: float) -> str:
    # Indonesian Rupiah: dot as thousands separator, no decimal
    return "Rp " + f"{int(value):,}".replace(",", ".")


def _parse_money(value: object) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)

    text = str(value).strip()
    if not text:
        return 0.0

    normalized = text.lower().replace("rp", "")
    normalized = re.sub(r"[^\d,.-]", "", normalized)
    if not normalized or normalized in {"-", ".", ","}:
        return 0.0

    if "," in normalized:
        normalized = normalized.replace(".", "").replace(",", ".")
    else:
        normalized = normalized.replace(".", "")

    amount = float(normalized)
    if amount < 0:
        raise ValueError("Amount must be zero or greater.")
    return amount


def _render_dashboard() -> None:
    assets_df = _assets_df()
    budgets_df = _budgets_df()
    exposure_df = _public_exposure_df()
    reports = list_reports(limit=500)
    jobs = list_jobs(limit=500)

    expiring_soon       = int(((assets_df["days_to_renewal"] <= 90) & (assets_df["days_to_renewal"] >= 0)).sum()) if not assets_df.empty else 0
    annual_license_spend = float(assets_df["annual_cost"].sum()) if not assets_df.empty else 0.0
    capex_total         = float(budgets_df.loc[budgets_df["cost_type"] == "Capex", "amount"].sum()) if not budgets_df.empty else 0.0
    opex_total          = float(budgets_df.loc[budgets_df["cost_type"] == "Opex",  "amount"].sum()) if not budgets_df.empty else 0.0
    active_jobs         = sum(1 for job in jobs if str(job.get("status", "")).lower() in {"queued", "running", "cancel_requested"})
    public_exposure_count = int(len(exposure_df.index)) if not exposure_df.empty else 0
    total_budget        = capex_total + opex_total
    unapproved_high     = int(budgets_df[(budgets_df["priority"] == "High") & (budgets_df["status"].isin(["Draft", "Planned"]))].shape[0]) if not budgets_df.empty else 0

    # ── KPI row ───────────────────────────────────────────────────────────
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("Managed Assets",        int(len(assets_df.index)),     help="Total tracked security tools and platforms")
    k2.metric("Renewals \u226490d",        expiring_soon,                 delta=None if expiring_soon == 0 else f"{expiring_soon} urgent", delta_color="inverse")
    k3.metric("License Spend / yr",    _format_money(annual_license_spend))
    k4.metric("Total Budget",          _format_money(total_budget),   help=f"Capex {_format_money(capex_total)} + Opex {_format_money(opex_total)}")
    k5.metric("Active Jobs",           active_jobs,                   delta=None if active_jobs == 0 else "running", delta_color="normal")
    k6.metric("Public Exposures",      public_exposure_count,         help="Subdomains and IPs indexed from Elasticsearch")

    st.divider()

    # ── Row 1: Budget portfolio + Asset urgency ───────────────────────────
    col_budget, col_assets = st.columns([1.2, 1])

    with col_budget:
        st.markdown("**Budget Portfolio**")
        if budgets_df.empty:
            st.info("No budget records.")
        else:
            quarter_view = budgets_df.groupby(["quarter", "cost_type"], as_index=False)["amount"].sum()
            st.bar_chart(quarter_view, x="quarter", y="amount", color="cost_type", height=220)
            if unapproved_high:
                st.warning(f"\u26a0 {unapproved_high} high-priority item(s) still Draft/Planned")
            st.dataframe(
                budgets_df[["initiative", "domain", "cost_type", "quarter", "amount", "status", "priority"]]
                    .sort_values(["priority", "amount"], ascending=[True, False])
                    .head(8),
                use_container_width=True, hide_index=True,
            )

    with col_assets:
        st.markdown("**Asset Coverage**")
        if assets_df.empty:
            st.info("No asset records.")
        else:
            crit_view = assets_df.groupby("criticality", as_index=False)["asset_id"].count().rename(columns={"asset_id": "count"})
            st.bar_chart(crit_view, x="criticality", y="count", height=220)
            if expiring_soon:
                st.warning(f"\u26a0 {expiring_soon} asset(s) renewing within 90 days")
            spotlight = assets_df.sort_values(by=["days_to_renewal", "annual_cost"], ascending=[True, False]).head(6)
            st.dataframe(
                spotlight[["asset_name", "owner", "annual_cost", "days_to_renewal", "support_status"]],
                use_container_width=True, hide_index=True,
            )

    st.divider()

    # ── Row 2: Report jobs + Quick navigation ────────────────────────────
    col_jobs, col_nav = st.columns([1.1, 1])

    with col_jobs:
        st.markdown("**Recent Background Jobs**")
        st.caption(f"{len(reports)} historical reports saved")
        recent_jobs = pd.DataFrame(jobs[:8]) if jobs else pd.DataFrame()
        if recent_jobs.empty:
            st.info("No background jobs yet. Upload an Excel file to queue one.")
        else:
            display_cols = [c for c in ["source_name", "status", "created_at_utc"] if c in recent_jobs.columns]
            st.dataframe(recent_jobs[display_cols], use_container_width=True, hide_index=True)

    with col_nav:
        st.markdown("**Quick Navigation**")
        nav_items = [
            ("\U0001f4ca", "SOC Analytics",       "Monitoring Operation",        "171K+ tickets · MITRE · AI narrative"),
            ("\U0001f310", "Public Exposure",     "Monitoring Operation",        "Subdomains · IPs · certificates"),
            ("\U0001f4b0", "Budget Management",   "Governance",                  "Capex · Opex · approval pipeline"),
            ("\U0001f6e1\ufe0f", "Asset Inventory", "Governance",               "Tools · seats · renewals"),
            ("\U0001f4c4", "Generate Report",    "Copilot",                     "Excel \u2192 architecture report"),
        ]
        for icon, label, page, caption in nav_items:
            if st.button(f"{icon}  {label}", key=f"dash_nav_{label}", use_container_width=True,
                         help=caption):
                st.session_state["selected_page"] = page
                st.rerun()


def run_pipeline(file_obj, file_name: str, max_retrieval_docs: int):
    if not validate_file_name(file_name):
        st.error("Invalid file type. Please upload a .xlsx file only.")
        return

    file_size = getattr(file_obj, "size", None)
    if file_size is None and hasattr(file_obj, "getbuffer"):
        file_size = len(file_obj.getbuffer())
    if file_size is None:
        file_size = 1

    if not validate_file_size(file_size, CONFIG.max_upload_mb):
        st.error(f"File exceeds size limit of {CONFIG.max_upload_mb} MB.")
        return

    with st.spinner("Parsing uploaded assessment..."):
        sheets = parse_excel(file_obj)
        assessment = build_assessment_context(sheets)

    left, mid, right, ctrl = st.columns(4)
    left.metric("Technologies", len(assessment.technologies))
    mid.metric("Findings", len(assessment.findings))
    right.metric("Sheets", len(sheets))
    ctrl.metric("Controls", len(assessment.controls))

    if st.session_state.get("internet_enrichment_enabled", CONFIG.enable_internet_enrichment):
        with st.spinner("Enriching with latest internet intelligence..."):
            enriched_docs = enrich_with_duckduckgo(
                assessment.technologies,
                max_results=CONFIG.enrichment_results_per_tech,
            )
    else:
        enriched_docs = []

    if enriched_docs:
        upsert_enrichment(vector_store, [d.as_text() for d in enriched_docs], source="duckduckgo")

    retrieval_query = " ".join(assessment.technologies[:20]) or assessment.summary_text
    kb_context = retrieve_context(vector_store, retrieval_query, k=max_retrieval_docs)

    with st.spinner("Generating structured report..."):
        report = generate_report(
            excel_summary=assessment.summary_text,
            enriched_context=kb_context,
            controls_context=assessment.controls_text,
        )

    st.subheader("Generated Security Architecture Recommendation")
    st.markdown(report)

    report_meta = save_report(report, source_name=file_name)
    docx_bytes = markdown_to_docx_bytes(report)

    st.download_button(
        label="Download Report (.md)",
        data=report,
        file_name=f"{report_meta['id']}.md",
        mime="text/markdown",
    )
    st.download_button(
        label="Download Report (.docx)",
        data=docx_bytes,
        file_name=f"{report_meta['id']}.docx",
        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )

    with st.expander("Assessment Summary"):
        st.text_area("Extracted Context", assessment.summary_text, height=220)

    if assessment.controls:
        with st.expander(f"Security Controls Inventory ({len(assessment.controls)} controls)"):
            st.text_area("Controls extracted from workbook", assessment.controls_text, height=320)

    with st.expander("Enrichment Evidence"):
        if not enriched_docs:
            st.info("No internet enrichment results were returned. The report used stored/local context only.")
        for idx, doc in enumerate(enriched_docs[:30], start=1):
            st.markdown(f"**{idx}. {doc.technology}**")
            st.write(doc.title)
            st.write(doc.url)
            st.write(doc.snippet)
            st.divider()


def _render_report_generation(max_retrieval_docs: int) -> None:
    with st.expander("Portal Configuration", expanded=True):
        st.write(f"LLM Model: {CONFIG.ollama_llm_model}")
        st.write(f"Embedding Model: {CONFIG.ollama_embed_model}")
        st.write(f"Ollama URL: {CONFIG.ollama_base_url}")
        st.write(f"Portal Data Dir: {CONFIG.portal_data_dir}")
        st.write(f"Report History Dir: {CONFIG.report_history_dir}")
        st.write(f"Internet Enrichment Default: {'On' if CONFIG.enable_internet_enrichment else 'Off'}")
        st.write(f"Fake Embeddings: {'On' if CONFIG.use_fake_embeddings else 'Off'}")
        st.write(f"LLM Fallback: {'On' if CONFIG.enable_demo_report_fallback else 'Off'}")

        st.slider(
            "Retrieved KB docs",
            min_value=3,
            max_value=15,
            value=max_retrieval_docs,
            key="max_retrieval_docs",
        )
        st.toggle(
            "Enable Internet Enrichment",
            value=st.session_state.get("internet_enrichment_enabled", CONFIG.enable_internet_enrichment),
            key="internet_enrichment_enabled",
            help="Disable this for fully offline report generation using local context and local LLM.",
        )

    max_retrieval_docs = int(st.session_state.get("max_retrieval_docs", max_retrieval_docs))

    uploaded_file = st.file_uploader("Upload Excel Assessment", type=["xlsx"])
    col_a, col_b, col_c, col_d = st.columns([1, 1, 1, 1])
    with col_a:
        run_uploaded = st.button("Generate from Uploaded File", type="primary", disabled=uploaded_file is None)
    with col_b:
        run_demo = st.button("Run End-to-End with Built-in Example")
    with col_c:
        queue_uploaded = st.button("Queue Uploaded as Background Job", disabled=uploaded_file is None)
    with col_d:
        queue_demo = st.button("Queue Built-in Example as Job")

    if run_uploaded and uploaded_file is not None:
        st.success(f"File accepted: {uploaded_file.name} ({uploaded_file.size} bytes)")
        run_pipeline(uploaded_file, uploaded_file.name, max_retrieval_docs)

    if run_demo:
        example_bytes = build_example_workbook_bytes()
        sample_file = BytesIO(example_bytes)
        sample_file.name = "sample_assessment.xlsx"
        sample_file.size = len(example_bytes)
        st.info("Running the full pipeline with built-in sample data.")
        run_pipeline(sample_file, sample_file.name, max_retrieval_docs)

    if queue_uploaded and uploaded_file is not None:
        job = submit_job(
            file_bytes=uploaded_file.getvalue(),
            source_name=uploaded_file.name,
            max_retrieval_docs=max_retrieval_docs,
            internet_enrichment_enabled=st.session_state.get(
                "internet_enrichment_enabled", CONFIG.enable_internet_enrichment
            ),
        )
        st.success(
            f"Background job queued: {job['id']}. It will continue running even if this browser tab is closed."
        )

    if queue_demo:
        example_bytes = build_example_workbook_bytes()
        job = submit_job(
            file_bytes=example_bytes,
            source_name="sample_assessment.xlsx",
            max_retrieval_docs=max_retrieval_docs,
            internet_enrichment_enabled=st.session_state.get(
                "internet_enrichment_enabled", CONFIG.enable_internet_enrichment
            ),
        )
        st.success(
            f"Demo background job queued: {job['id']}. It will continue running even if this browser tab is closed."
        )


def _render_asset_inventory() -> None:
    assets_df = _assets_df()
    if "asset_show_add_form" not in st.session_state:
        st.session_state["asset_show_add_form"] = False
    if "asset_selected_id" not in st.session_state:
        st.session_state["asset_selected_id"] = ""

    renewals = 0
    annual_spend = 0.0
    avg_utilization = 0.0
    if not assets_df.empty:
        renewals = int(((assets_df["days_to_renewal"] <= 90) & (assets_df["days_to_renewal"] >= 0)).sum())
        annual_spend = float(assets_df["annual_cost"].sum())
        util_df = assets_df[assets_df["license_seats"] > 0].copy()
        if not util_df.empty:
            avg_utilization = float((util_df["seats_used"] / util_df["license_seats"]).mean() * 100.0)

    top_1, top_2, top_3, top_4 = st.columns(4)
    top_1.metric("Tracked Assets", int(len(assets_df.index)))
    top_2.metric("Renewing <=90d", renewals)
    top_3.metric("Annual License Spend", _format_money(annual_spend))
    top_4.metric("Avg Seat Utilization", f"{avg_utilization:.0f}%")

    st.subheader("Inventory Register")
    if assets_df.empty:
        st.info("No assets registered yet.")
    else:
        filter_col_1, filter_col_2, filter_col_3 = st.columns(3)
        owner_filter = filter_col_1.multiselect("Filter by Owner", sorted(assets_df["owner"].dropna().unique().tolist()))
        criticality_filter = filter_col_2.multiselect(
            "Filter by Criticality", sorted(assets_df["criticality"].dropna().unique().tolist())
        )
        search_filter = filter_col_3.text_input("Search Asset", placeholder="Name, ID, vendor, or license")

        view_df = assets_df.copy()
        if owner_filter:
            view_df = view_df[view_df["owner"].isin(owner_filter)]
        if criticality_filter:
            view_df = view_df[view_df["criticality"].isin(criticality_filter)]
        if search_filter.strip():
            query = search_filter.strip().lower()
            view_df = view_df[
                view_df["asset_id"].astype(str).str.lower().str.contains(query)
                | view_df["asset_name"].astype(str).str.lower().str.contains(query)
                | view_df["vendor"].astype(str).str.lower().str.contains(query)
                | view_df["license_name"].astype(str).str.lower().str.contains(query)
            ]

        list_cols = [
            "asset_id",
            "asset_name",
            "asset_type",
            "owner",
            "criticality",
            "license_name",
            "seats_used",
            "license_seats",
            "annual_cost",
            "renewal_date",
            "days_to_renewal",
        ]
        clickable_df = view_df[list_cols].reset_index(drop=True)

        event = st.dataframe(
            clickable_df,
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key="asset_inventory_table",
        )

        selected_rows: list[int] = []
        if isinstance(event, dict):
            selected_rows = event.get("selection", {}).get("rows", [])
        elif hasattr(event, "selection") and hasattr(event.selection, "rows"):
            selected_rows = list(event.selection.rows)

        if selected_rows:
            row_idx = int(selected_rows[0])
            if 0 <= row_idx < len(clickable_df.index):
                st.session_state["asset_selected_id"] = str(clickable_df.iloc[row_idx]["asset_id"])

    action_col_1, action_col_2, action_col_3 = st.columns([1, 1, 4])
    if action_col_1.button("Add New Asset", type="primary", use_container_width=True):
        st.session_state["asset_show_add_form"] = True

    has_selected_asset = bool(st.session_state.get("asset_selected_id", ""))
    if action_col_2.button(
        "Delete Selected",
        disabled=not has_selected_asset,
        use_container_width=True,
    ):
        selected_id = st.session_state["asset_selected_id"]
        rows = load_assets()
        before = len(rows)
        rows = [row for row in rows if str(row.get("asset_id", "")) != selected_id]
        save_assets(rows)
        st.session_state["asset_selected_id"] = ""
        if len(rows) < before:
            st.success(f"Asset {selected_id} deleted.")
        else:
            st.warning("Selected asset was not found.")
        st.rerun()

    if st.session_state.get("asset_show_add_form", False):
        with st.form("asset_form", clear_on_submit=True):
            st.subheader("Add Security Asset")
            col_1, col_2, col_3 = st.columns(3)
            asset_id = col_1.text_input("Asset ID", value=f"AST-{len(assets_df.index) + 1:03d}")
            asset_name = col_2.text_input("Asset Name")
            asset_type = col_3.selectbox("Asset Type", ["Security Tool", "Platform", "Service", "Infrastructure", "Application"])

            col_4, col_5, col_6 = st.columns(3)
            owner = col_4.text_input("Owner")
            environment = col_5.selectbox("Environment", ["Production", "Non-Production", "Shared", "Cloud"])
            criticality = col_6.selectbox("Criticality", ["Critical", "High", "Medium", "Low"])

            col_7, col_8, col_9 = st.columns(3)
            vendor = col_7.text_input("Vendor")
            license_name = col_8.text_input("License / Contract")
            license_type = col_9.selectbox("License Type", ["Subscription", "Perpetual", "Enterprise Support", "Consumption"])

            col_10, col_11, col_12 = st.columns(3)
            license_seats = col_10.number_input("Licensed Seats", min_value=0, value=1, step=1)
            seats_used = col_11.number_input("Seats Used", min_value=0, value=1, step=1)
            annual_cost = col_12.number_input("Annual Cost (IDR)", min_value=0.0, value=0.0, step=1000.0)

            col_13, col_14 = st.columns(2)
            renewal_date = col_13.date_input("Renewal Date", value=date.today())
            support_status = col_14.selectbox("Support Status", ["Active", "Renewal Soon", "Expired", "Under Review"])
            notes = st.text_area("Notes")

            save_col, cancel_col = st.columns(2)
            submitted = save_col.form_submit_button("Save Asset", type="primary")
            canceled = cancel_col.form_submit_button("Cancel")

        if canceled:
            st.session_state["asset_show_add_form"] = False
            st.rerun()

        if submitted:
            if not asset_name.strip() or not owner.strip():
                st.error("Asset Name and Owner are required.")
            else:
                rows = load_assets()
                rows.append(
                    {
                        "asset_id": asset_id.strip(),
                        "asset_name": asset_name.strip(),
                        "asset_type": asset_type,
                        "environment": environment,
                        "owner": owner.strip(),
                        "criticality": criticality,
                        "vendor": vendor.strip(),
                        "license_name": license_name.strip(),
                        "license_type": license_type,
                        "license_seats": int(license_seats),
                        "seats_used": int(seats_used),
                        "annual_cost": float(annual_cost),
                        "renewal_date": str(renewal_date),
                        "support_status": support_status,
                        "notes": notes.strip(),
                    }
                )
                save_assets(rows)
                st.session_state["asset_show_add_form"] = False
                st.success("Asset saved.")
                st.rerun()

    selected_id = st.session_state.get("asset_selected_id", "")
    if selected_id and not assets_df.empty:
        match = assets_df[assets_df["asset_id"].astype(str) == str(selected_id)]
        if not match.empty:
            row = match.iloc[0]
            st.subheader(f"Asset Details: {row['asset_name']}")
            dcol_1, dcol_2, dcol_3 = st.columns(3)
            dcol_1.metric("Asset ID", str(row["asset_id"]))
            dcol_2.metric("Criticality", str(row["criticality"]))
            dcol_3.metric("Support Status", str(row["support_status"]))

            st.write(
                f"**Owner:** {row['owner']} | **Environment:** {row['environment']} | "
                f"**Type:** {row['asset_type']} | **Vendor:** {row['vendor']}"
            )
            st.write(
                f"**License:** {row['license_name']} ({row['license_type']}) | "
                f"**Seats:** {int(row['seats_used'])}/{int(row['license_seats'])} | "
                f"**Annual Cost:** {_format_money(float(row['annual_cost']))}"
            )
            st.write(f"**Renewal Date:** {row['renewal_date']} | **Days to Renewal:** {int(row['days_to_renewal'])}")
            if str(row.get("notes", "")).strip():
                st.info(str(row["notes"]))

    st.download_button(
        label="Download Inventory CSV",
        data=assets_df.to_csv(index=False).encode("utf-8") if not assets_df.empty else b"",
        file_name="security_asset_inventory.csv",
        mime="text/csv",
    )


def _render_budget_tracking() -> None:
    budgets_df = _budgets_df()
    if "budget_show_add_form" not in st.session_state:
        st.session_state["budget_show_add_form"] = False
    if "budget_show_import_form" not in st.session_state:
        st.session_state["budget_show_import_form"] = False
    if "budget_show_edit_form" not in st.session_state:
        st.session_state["budget_show_edit_form"] = False
    if "budget_selected_id" not in st.session_state:
        st.session_state["budget_selected_id"] = ""
    if "budget_selected_ids" not in st.session_state:
        st.session_state["budget_selected_ids"] = []
    if "budget_show_excel_upload" not in st.session_state:
        st.session_state["budget_show_excel_upload"] = False

    total_capex = float(budgets_df.loc[budgets_df["cost_type"] == "Capex", "amount"].sum()) if not budgets_df.empty else 0.0
    total_opex = float(budgets_df.loc[budgets_df["cost_type"] == "Opex", "amount"].sum()) if not budgets_df.empty else 0.0
    approved = float(budgets_df.loc[budgets_df["status"] == "Approved", "amount"].sum()) if not budgets_df.empty else 0.0

    total = total_capex + total_opex
    total_cashout = float(budgets_df["total_cashout"].sum()) if not budgets_df.empty and "total_cashout" in budgets_df.columns else 0.0
    grand_total_sum = total - total_cashout
    unapproved_high = int(budgets_df[(budgets_df["priority"] == "High") & (budgets_df["status"].isin(["Draft", "Planned"]))].shape[0]) if not budgets_df.empty else 0

    top_1, top_2, top_3, top_4, top_5, top_6 = st.columns(6)
    top_1.metric("Total Budget", _format_money(total))
    top_2.metric("Capex", _format_money(total_capex))
    top_3.metric("Opex", _format_money(total_opex))
    top_4.metric("Total Cashout", _format_money(total_cashout))
    top_5.metric("Grand Total", _format_money(grand_total_sum))
    top_6.metric("Unapproved High-Priority", unapproved_high, delta=f"+{unapproved_high}" if unapproved_high else None, delta_color="inverse")

    if not budgets_df.empty:
        import plotly.graph_objects as _go
        col_chart1, col_chart2 = st.columns(2)
        with col_chart1:
            qt = budgets_df.groupby(["quarter", "cost_type"], as_index=False)["amount"].sum().sort_values("quarter")
            fig_q = _go.Figure()
            for ct, color in (("Capex", "#6c6ef7"), ("Opex", "#3ecf8e")):
                sub = qt[qt["cost_type"] == ct]
                fig_q.add_trace(_go.Bar(name=ct, x=sub["quarter"], y=sub["amount"], marker_color=color))
            fig_q.update_layout(title="Budget by Quarter", barmode="stack", height=280,
                                xaxis_title="Quarter", yaxis_title="IDR",
                                legend=dict(orientation="h", y=1.1),
                                margin=dict(t=50, b=20, l=10, r=10))
            st.plotly_chart(fig_q, use_container_width=True, key="bt_quarter_chart")
        with col_chart2:
            dom = budgets_df.groupby("domain")["amount"].sum().sort_values(ascending=False).head(10)
            fig_d = _go.Figure(data=[_go.Bar(
                x=dom.values, y=dom.index, orientation="h", marker_color="#f5a623",
            )])
            fig_d.update_layout(title="Top 10 Domains by Amount", height=280,
                                yaxis=dict(autorange="reversed"),
                                margin=dict(t=40, b=20, l=10, r=10), showlegend=False)
            st.plotly_chart(fig_d, use_container_width=True, key="bt_domain_chart")

    st.caption("For deep ML analytics and AI narrative, visit **Governance → Budget Analytics**.")

    st.subheader("Budget Register")
    if budgets_df.empty:
        st.info("No budget data registered yet.")
    else:
        col_1, col_2, col_3 = st.columns(3)
        type_filter = col_1.multiselect("Filter by Cost Type", sorted(budgets_df["cost_type"].dropna().unique().tolist()))
        status_filter = col_2.multiselect("Filter by Status", sorted(budgets_df["status"].dropna().unique().tolist()))
        search_filter = col_3.text_input("Search Budget", placeholder="Initiative, ID, domain, owner")

        view_df = budgets_df.copy()
        if type_filter:
            view_df = view_df[view_df["cost_type"].isin(type_filter)]
        if status_filter:
            view_df = view_df[view_df["status"].isin(status_filter)]
        if search_filter.strip():
            query = search_filter.strip().lower()
            view_df = view_df[
                view_df["budget_id"].astype(str).str.lower().str.contains(query)
                | view_df["initiative"].astype(str).str.lower().str.contains(query)
                | view_df["domain"].astype(str).str.lower().str.contains(query)
                | view_df["owner"].astype(str).str.lower().str.contains(query)
            ]

        list_cols = [
            "budget_id",
            "initiative",
            "cost_type",
            "domain",
            "owner",
            "quarter",
            "amount",
            "total_cashout",
            "grand_total",
            "nama_spk",
            "status",
            "priority",
        ]
        clickable_df = view_df[list_cols].reset_index(drop=True)
        clickable_df["amount"] = pd.to_numeric(clickable_df["amount"], errors="coerce").fillna(0.0)
        clickable_df["amount"] = clickable_df["amount"].apply(_format_money)
        clickable_df["total_cashout"] = pd.to_numeric(clickable_df["total_cashout"], errors="coerce").fillna(0.0)
        clickable_df["total_cashout"] = clickable_df["total_cashout"].apply(_format_money)
        clickable_df["grand_total"] = pd.to_numeric(clickable_df["grand_total"], errors="coerce").fillna(0.0)
        clickable_df["grand_total"] = clickable_df["grand_total"].apply(_format_money)
        clickable_df["nama_spk"] = clickable_df["nama_spk"].fillna("").astype(str)

        # Add checkbox column for row selection (delete)
        edit_df = clickable_df.copy()
        edit_df.insert(0, "_sel", False)

        _BUDGET_QUARTERS = [
            "2026-Q1", "2026-Q2", "2026-Q3", "2026-Q4",
            "2027-Q1", "2027-Q2", "2027-Q3", "2027-Q4",
        ]
        edited = st.data_editor(
            edit_df,
            use_container_width=True,
            hide_index=True,
            num_rows="fixed",
            key="budget_register_table",
            column_config={
                "_sel": st.column_config.CheckboxColumn("☑", default=False, width="small"),
                "budget_id": st.column_config.TextColumn("Budget ID", disabled=True),
                "initiative": st.column_config.TextColumn("Initiative"),
                "cost_type": st.column_config.SelectboxColumn("Cost Type", options=["Capex", "Opex"]),
                "domain": st.column_config.TextColumn("Domain"),
                "owner": st.column_config.TextColumn("Owner"),
                "quarter": st.column_config.SelectboxColumn("Quarter", options=_BUDGET_QUARTERS),
                "amount": st.column_config.TextColumn("Amount (IDR)", help="Example: Rp 125.000.000"),
                "total_cashout": st.column_config.TextColumn("Cashout (IDR)", disabled=True),
                "grand_total": st.column_config.TextColumn("Grand Total (IDR)", disabled=True),
                "nama_spk": st.column_config.TextColumn("Nama SPK", disabled=True),
                "status": st.column_config.SelectboxColumn("Status", options=["Draft", "Planned", "Approved", "Committed", "Deferred"]),
                "priority": st.column_config.SelectboxColumn("Priority", options=["High", "Medium", "Low"]),
            },
        )

        # Rows checked for deletion
        selected_ids = edited.loc[edited["_sel"] == True, "budget_id"].astype(str).tolist()  # noqa: E712
        st.session_state["budget_selected_ids"] = selected_ids
        st.session_state["budget_selected_id"] = selected_ids[0] if selected_ids else ""

        # Detect inline edits (compare non-checkbox columns against original)
        _data_cols = list_cols
        _edited_data = edited[_data_cols].reset_index(drop=True)
        _original_data = edit_df[_data_cols].reset_index(drop=True)
        _has_inline_changes = not _edited_data.equals(_original_data)

        if _has_inline_changes:
            chg_info, chg_save, chg_discard = st.columns([3, 1, 1])
            chg_info.info("Unsaved changes detected. Click **Save Changes** to apply or **Discard** to revert.", icon="✏️")
            if chg_save.button("Save Changes", type="primary", use_container_width=True, key="budget_inline_save"):
                _rows = load_budgets()
                _invalid_amounts: list[str] = []
                for _, _erow in _edited_data.iterrows():
                    _bid = str(_erow["budget_id"])
                    try:
                        _amount = _parse_money(_erow.get("amount"))
                    except (TypeError, ValueError):
                        _invalid_amounts.append(_bid)
                        continue
                    _patch = {
                        "initiative": str(_erow.get("initiative", "") or ""),
                        "cost_type": str(_erow.get("cost_type", "Opex") or "Opex"),
                        "domain": str(_erow.get("domain", "") or ""),
                        "owner": str(_erow.get("owner", "") or ""),
                        "quarter": str(_erow.get("quarter", "") or ""),
                        "amount": _amount,
                        "status": str(_erow.get("status", "Draft") or "Draft"),
                        "priority": str(_erow.get("priority", "Medium") or "Medium"),
                    }
                    _rows = [{**r, **_patch} if str(r.get("budget_id", "")) == _bid else r for r in _rows]
                if _invalid_amounts:
                    joined_ids = ", ".join(_invalid_amounts)
                    st.error(f"Invalid amount format for: {joined_ids}. Use Rupiah format like Rp 125.000.000")
                    return
                save_budgets(_rows)
                st.success("Changes saved.")
                st.rerun()
            if chg_discard.button("Discard", use_container_width=True, key="budget_inline_discard"):
                st.rerun()

        # ── Cashout details ───────────────────────────────────────────────
        _cashout_rows: list[dict] = []
        for _, _brow in view_df.iterrows():
            _entries = _brow.get("cashout_entries", [])
            if isinstance(_entries, list):
                for _entry in _entries:
                    _cashout_rows.append({
                        "Budget ID":  str(_brow["budget_id"]),
                        "Initiative": str(_brow["initiative"]),
                        "Nama SPK":   str(_entry.get("nama_spk", "")),
                        "Cashout":    _entry.get("cashout", 0.0),
                    })
        if _cashout_rows:
            with st.expander(f"📋 Cashout Details ({len(_cashout_rows)} SPK entries)", expanded=False):
                _cd_df = pd.DataFrame(_cashout_rows)
                _cd_df["Cashout"] = pd.to_numeric(_cd_df["Cashout"], errors="coerce").fillna(0.0).apply(_format_money)
                st.dataframe(_cd_df, use_container_width=True, hide_index=True)

    action_col_1, action_col_2, action_col_3, action_col_4, action_col_5 = st.columns([1, 1, 1, 1, 1])
    if action_col_1.button("Add Budget Line", type="primary", use_container_width=True):
        st.session_state["budget_show_add_form"] = True
        st.session_state["budget_show_import_form"] = False
        st.session_state["budget_show_excel_upload"] = False

    _selected_ids = st.session_state.get("budget_selected_ids", [])
    _sel_label = f"Delete Selected ({len(_selected_ids)})" if _selected_ids else "Delete Selected"
    if action_col_2.button(
        _sel_label,
        disabled=not _selected_ids,
        use_container_width=True,
    ):
        id_set = set(_selected_ids)
        rows = load_budgets()
        before = len(rows)
        rows = [row for row in rows if str(row.get("budget_id", "")) not in id_set]
        save_budgets(rows)
        st.session_state["budget_selected_ids"] = []
        st.session_state["budget_selected_id"] = ""
        removed = before - len(rows)
        st.success(f"Deleted {removed} budget line(s).")
        st.rerun()

    if action_col_3.button(
        "Delete All",
        disabled=budgets_df.empty,
        use_container_width=True,
    ):
        st.session_state["budget_confirm_delete_all"] = True

    if st.session_state.get("budget_confirm_delete_all", False):
        st.warning(f"Are you sure you want to delete **all {len(budgets_df.index)} budget lines**? This cannot be undone.")
        conf_col_1, conf_col_2 = st.columns(2)
        if conf_col_1.button("Yes, Delete All", type="primary", use_container_width=True, key="budget_delete_all_confirm"):
            save_budgets([])
            st.session_state["budget_confirm_delete_all"] = False
            st.session_state["budget_selected_ids"] = []
            st.session_state["budget_selected_id"] = ""
            st.success("All budget lines deleted.")
            st.rerun()
        if conf_col_2.button("Cancel", use_container_width=True, key="budget_delete_all_cancel"):
            st.session_state["budget_confirm_delete_all"] = False
            st.rerun()

    if action_col_4.button("Import CSV", use_container_width=True):
        st.session_state["budget_show_import_form"] = not st.session_state.get("budget_show_import_form", False)
        st.session_state["budget_show_add_form"] = False
        st.session_state["budget_show_excel_upload"] = False

    if action_col_5.button("📊 Upload Cashout Excel", use_container_width=True):
        st.session_state["budget_show_excel_upload"] = not st.session_state.get("budget_show_excel_upload", False)
        st.session_state["budget_show_add_form"] = False
        st.session_state["budget_show_import_form"] = False

    if st.session_state.get("budget_show_import_form", False):
        with st.expander("Import Budget Lines from CSV", expanded=True):
            st.caption(
                "Upload a comma **or semicolon** delimited CSV file. Required columns: **initiative**, **cost_type**, **domain**, **owner**, **quarter**, **amount**. "
                "Optional: budget_id, currency, status, priority, notes. "
                "Duplicate budget_id values will be skipped. Use `-` for empty cells."
            )
            uploaded_file = st.file_uploader(
                "Choose CSV file",
                type=["csv"],
                key="budget_csv_upload",
            )
            import_mode = st.radio(
                "If budget_id already exists:",
                ["Skip duplicates", "Overwrite existing"],
                horizontal=True,
                key="budget_import_mode",
            )
            if uploaded_file is not None:
                try:
                    import io as _io
                    import csv as _csv
                    _csv_bytes = uploaded_file.read()
                    # Detect encoding
                    for _enc in ("utf-8", "utf-8-sig", "latin-1"):
                        try:
                            _csv_text = _csv_bytes.decode(_enc)
                            break
                        except UnicodeDecodeError:
                            continue
                    else:
                        _csv_text = _csv_bytes.decode("latin-1", errors="replace")
                    # Auto-detect delimiter (semicolon vs comma)
                    try:
                        _dialect = _csv.Sniffer().sniff(_csv_text[:4096], delimiters=",;\t|")
                        _sep = _dialect.delimiter
                    except _csv.Error:
                        _sep = ","
                    raw_df = pd.read_csv(_io.StringIO(_csv_text), sep=_sep, engine="python")
                    raw_df.columns = [c.strip().lower().replace(" ", "_") for c in raw_df.columns]
                    # Treat "-" or blank as empty string for text cols; NaN stays for numeric
                    raw_df.replace({"-": "", "—": ""}, inplace=True)

                    required_cols = {"initiative", "cost_type", "domain", "owner", "quarter", "amount"}
                    missing = required_cols - set(raw_df.columns)
                    if missing:
                        st.error(f"CSV is missing required columns: {', '.join(sorted(missing))}")
                    else:
                        st.dataframe(raw_df.head(10), use_container_width=True, hide_index=True)
                        st.caption(f"{len(raw_df)} row(s) in file — showing first 10.")

                        if st.button("Confirm Import", type="primary", key="budget_import_confirm"):
                            existing_rows = load_budgets()
                            next_id = len(existing_rows) + 1
                            existing_ids = {str(r.get("budget_id", "")) for r in existing_rows}

                            added, skipped, overwritten = 0, 0, 0
                            new_rows = list(existing_rows)

                            for _, r in raw_df.iterrows():
                                bid = str(r.get("budget_id", "")).strip() if "budget_id" in raw_df.columns and str(r.get("budget_id", "")).strip() else f"BDG-{next_id:03d}"
                                next_id += 1

                                record = {
                                    "budget_id": bid,
                                    "initiative": str(r.get("initiative", "")).strip(),
                                    "cost_type": str(r.get("cost_type", "Opex")).strip(),
                                    "domain": str(r.get("domain", "")).strip(),
                                    "owner": str(r.get("owner", "")).strip(),
                                    "quarter": str(r.get("quarter", "")).strip(),
                                    "amount": (lambda v: float(str(v).strip().replace(".", "").replace(",", ".")) if str(v).strip() not in ("", "-", "nan") else 0.0)(r.get("amount", 0)),
                                    "currency": str(r.get("currency", "IDR")).strip() if "currency" in raw_df.columns else "IDR",
                                    "status": str(r.get("status", "Draft")).strip() if "status" in raw_df.columns else "Draft",
                                    "priority": str(r.get("priority", "Medium")).strip() if "priority" in raw_df.columns else "Medium",
                                    "notes": str(r.get("notes", "")).strip() if "notes" in raw_df.columns else "",
                                }

                                if bid in existing_ids:
                                    if import_mode == "Overwrite existing":
                                        new_rows = [rec if str(rec.get("budget_id", "")) != bid else record for rec in new_rows]
                                        overwritten += 1
                                    else:
                                        skipped += 1
                                else:
                                    new_rows.append(record)
                                    existing_ids.add(bid)
                                    added += 1

                            save_budgets(new_rows)
                            st.session_state["budget_show_import_form"] = False
                            parts = []
                            if added:
                                parts.append(f"{added} added")
                            if overwritten:
                                parts.append(f"{overwritten} overwritten")
                            if skipped:
                                parts.append(f"{skipped} skipped (duplicate)")
                            st.success(f"Import complete: {', '.join(parts)}.")
                            st.rerun()

                except Exception as exc:
                    st.error(f"Failed to parse CSV: {exc}")

    if st.session_state.get("budget_show_excel_upload", False):
        with st.expander("📊 Upload Cashout from Excel", expanded=True):
            st.caption(
                "Upload an Excel file (.xlsx / .xls) that contains cashout data. "
                "Required columns: **ID RKAP TI** (matches Budget ID), **Nama SPK**, **Grand Total** (cashout amount). "
                "Multiple rows with the same ID RKAP TI are stored as separate cashout entries."
            )
            uploaded_xl = st.file_uploader(
                "Choose Excel file",
                type=["xlsx", "xls"],
                key="budget_excel_upload",
            )
            if uploaded_xl is not None:
                try:
                    import io as _io
                    xl_bytes = uploaded_xl.read()
                    xl_df = pd.read_excel(_io.BytesIO(xl_bytes), engine="openpyxl")
                    xl_df.columns = [str(c).strip() for c in xl_df.columns]

                    # Auto-detect column mapping
                    def _detect_col(candidates: list[str]) -> str | None:
                        for c in xl_df.columns:
                            cl = c.lower()
                            if any(kw in cl for kw in candidates):
                                return c
                        return xl_df.columns[0] if len(xl_df.columns) > 0 else None

                    _default_id    = _detect_col(["id rkap ti", "id rkap", "rkap"])
                    _default_spk   = _detect_col(["nama spk", "spk"])
                    _default_grand = _detect_col(["grand total", "grand"])

                    col_options = xl_df.columns.tolist()
                    xl_mc1, xl_mc2, xl_mc3 = st.columns(3)
                    id_col    = xl_mc1.selectbox("ID RKAP TI → Budget ID", col_options,
                                                  index=col_options.index(_default_id) if _default_id in col_options else 0,
                                                  key="xl_id_col")
                    spk_col   = xl_mc2.selectbox("Nama SPK", col_options,
                                                  index=col_options.index(_default_spk) if _default_spk in col_options else 0,
                                                  key="xl_spk_col")
                    grand_col = xl_mc3.selectbox("Grand Total → Cashout", col_options,
                                                  index=col_options.index(_default_grand) if _default_grand in col_options else 0,
                                                  key="xl_grand_col")

                    preview_df = xl_df[[id_col, spk_col, grand_col]].copy()
                    preview_df.columns = ["Budget ID", "Nama SPK", "Cashout (raw)"]
                    st.dataframe(preview_df.head(10), use_container_width=True, hide_index=True)
                    st.caption(f"{len(xl_df)} row(s) in file — showing first 10.")

                    xl_import_mode = st.radio(
                        "Cashout import mode:",
                        ["Replace existing cashout", "Append to existing cashout"],
                        horizontal=True,
                        key="budget_xl_import_mode",
                    )

                    if st.button("Confirm Excel Import", type="primary", key="budget_xl_import_confirm"):
                        existing_rows = load_budgets()
                        id_to_idx = {str(r.get("budget_id", "")): i for i, r in enumerate(existing_rows)}

                        # Group Excel rows by budget_id
                        from collections import defaultdict as _defaultdict
                        entries_by_id: dict[str, list[dict]] = _defaultdict(list)
                        for _, xr in xl_df.iterrows():
                            bid = str(xr[id_col]).strip()
                            if not bid or bid.lower() == "nan":
                                continue
                            try:
                                cashout_val = _parse_money(xr[grand_col])
                            except (TypeError, ValueError):
                                cashout_val = 0.0
                            spk_val = str(xr[spk_col]).strip()
                            entries_by_id[bid].append({
                                "nama_spk": spk_val if spk_val.lower() != "nan" else "",
                                "cashout":  cashout_val,
                            })

                        matched, unmatched = 0, 0
                        for bid, new_entries in entries_by_id.items():
                            if bid in id_to_idx:
                                idx = id_to_idx[bid]
                                if xl_import_mode == "Replace existing cashout":
                                    existing_rows[idx]["cashout_entries"] = new_entries
                                else:
                                    old = existing_rows[idx].get("cashout_entries", [])
                                    existing_rows[idx]["cashout_entries"] = (old if isinstance(old, list) else []) + new_entries
                                matched += 1
                            else:
                                unmatched += 1

                        save_budgets(existing_rows)
                        st.session_state["budget_show_excel_upload"] = False
                        parts = [f"{matched} budget record(s) updated"]
                        if unmatched:
                            parts.append(f"{unmatched} ID(s) not found in register (skipped)")
                        st.success("Excel import complete: " + ", ".join(parts) + ".")
                        st.rerun()

                except Exception as exc:
                    st.error(f"Failed to read Excel file: {exc}")

    if st.session_state.get("budget_show_add_form", False):
        with st.form("budget_form", clear_on_submit=True):
            st.subheader("Add Budget Line")
            col_1, col_2, col_3 = st.columns(3)
            budget_id = col_1.text_input("Budget ID", value=f"BDG-{len(budgets_df.index) + 1:03d}")
            initiative = col_2.text_input("Initiative")
            cost_type = col_3.selectbox("Cost Type", ["Capex", "Opex"])

            col_4, col_5, col_6 = st.columns(3)
            domain = col_4.text_input("Domain")
            owner = col_5.text_input("Owner")
            quarter = col_6.selectbox("Quarter", ["2026-Q2", "2026-Q3", "2026-Q4", "2027-Q1"])

            col_7, col_8, col_9 = st.columns(3)
            amount = col_7.text_input("Amount (IDR)", value="Rp 0", help="Example: Rp 125.000.000")
            status = col_8.selectbox("Status", ["Draft", "Planned", "Approved", "Committed", "Deferred"])
            priority = col_9.selectbox("Priority", ["High", "Medium", "Low"])

            notes = st.text_area("Notes")

            save_col, cancel_col = st.columns(2)
            submitted = save_col.form_submit_button("Save Budget Line", type="primary")
            canceled = cancel_col.form_submit_button("Cancel")

        if canceled:
            st.session_state["budget_show_add_form"] = False
            st.rerun()

        if submitted:
            if not initiative.strip() or not owner.strip() or not domain.strip():
                st.error("Initiative, Domain, and Owner are required.")
            else:
                try:
                    parsed_amount = _parse_money(amount)
                except (TypeError, ValueError):
                    st.error("Amount must use a valid Rupiah format, for example: Rp 125.000.000")
                    return
                rows = load_budgets()
                rows.append(
                    {
                        "budget_id": budget_id.strip(),
                        "initiative": initiative.strip(),
                        "cost_type": cost_type,
                        "domain": domain.strip(),
                        "owner": owner.strip(),
                        "quarter": quarter,
                        "amount": parsed_amount,
                        "currency": "IDR",
                        "status": status,
                        "priority": priority,
                        "notes": notes.strip(),
                    }
                )
                save_budgets(rows)
                st.session_state["budget_show_add_form"] = False
                st.success("Budget line saved.")
                st.rerun()

    selected_id = st.session_state.get("budget_selected_id", "")
    if selected_id and not budgets_df.empty:
        match = budgets_df[budgets_df["budget_id"].astype(str) == str(selected_id)]
        if not match.empty:
            row = match.iloc[0]
            st.subheader(f"Budget Details: {row['initiative']}")
            dcol_1, dcol_2, dcol_3 = st.columns(3)
            dcol_1.metric("Budget ID", str(row["budget_id"]))
            dcol_2.metric("Cost Type", str(row["cost_type"]))
            dcol_3.metric("Amount", _format_money(float(row["amount"])))

            st.write(
                f"**Domain:** {row['domain']} | **Owner:** {row['owner']} | "
                f"**Quarter:** {row['quarter']} | **Status:** {row['status']} | **Priority:** {row['priority']}"
            )
            if str(row.get("notes", "")).strip():
                st.info(str(row["notes"]))

    st.download_button(
        label="Download Budget CSV",
        data=budgets_df.to_csv(index=False).encode("utf-8") if not budgets_df.empty else b"",
        file_name="security_budget_register.csv",
        mime="text/csv",
    )


def _render_public_exposure() -> None:
    exposure_df = _public_exposure_df()
    if "public_exposure_selected_subdomain" not in st.session_state:
        st.session_state["public_exposure_selected_subdomain"] = ""

    if exposure_df.empty:
        st.warning(
            f"No public exposure records were loaded from {CONFIG.security_assets_index} at {CONFIG.elasticsearch_url}."
        )
        return

    cert_expiring_30d = int(
        ((exposure_df["ssl_days_remaining"] <= 30) & (exposure_df["ssl_days_remaining"] >= 0)).sum()
    )
    unique_public_ips = int(exposure_df["ip_addresses"].explode().dropna().astype(str).nunique())
    unique_providers = int(exposure_df["Provider"].nunique())
    ssl_coverage = int(exposure_df["ssl_not_after"].notna().sum())

    top_1, top_2, top_3, top_4 = st.columns(4)
    top_1.metric("Exposed Subdomains", int(len(exposure_df.index)))
    top_2.metric("Unique Public IPs", unique_public_ips)
    top_3.metric("Providers", unique_providers)
    top_4.metric("SSL Coverage", ssl_coverage)

    st.subheader("Public Exposure Register")
    filter_col_1, filter_col_2, filter_col_3 = st.columns(3)
    provider_filter = filter_col_1.multiselect(
        "Filter by Provider",
        sorted(exposure_df["Provider"].dropna().unique().tolist()),
    )
    issuer_filter = filter_col_2.multiselect(
        "Filter by SSL Issuer",
        sorted(exposure_df["ssl_issuer_org"].dropna().unique().tolist()),
    )
    search_filter = filter_col_3.text_input("Search Exposure", placeholder="Subdomain, cname, or IP")

    view_df = exposure_df.copy()
    if provider_filter:
        view_df = view_df[view_df["Provider"].isin(provider_filter)]
    if issuer_filter:
        view_df = view_df[view_df["ssl_issuer_org"].isin(issuer_filter)]
    if search_filter.strip():
        query = search_filter.strip().lower()
        view_df = view_df[
            view_df["subdomain"].astype(str).str.lower().str.contains(query)
            | view_df["cname"].astype(str).str.lower().str.contains(query)
            | view_df["ip_addresses_display"].astype(str).str.lower().str.contains(query)
        ]

    clickable_df = view_df[["subdomain", "cname", "ip_addresses_display", "Provider", "ssl_issuer_org", "ssl_not_after"]].copy()
    clickable_df["ssl_not_after"] = clickable_df["ssl_not_after"].dt.strftime("%Y-%m-%d")
    clickable_df = clickable_df.rename(columns={"ip_addresses_display": "ip_addresses"}).reset_index(drop=True)

    event = st.dataframe(
        clickable_df,
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key="public_exposure_table",
    )

    selected_rows: list[int] = []
    if isinstance(event, dict):
        selected_rows = event.get("selection", {}).get("rows", [])
    elif hasattr(event, "selection") and hasattr(event.selection, "rows"):
        selected_rows = list(event.selection.rows)

    if selected_rows:
        row_idx = int(selected_rows[0])
        if 0 <= row_idx < len(clickable_df.index):
            st.session_state["public_exposure_selected_subdomain"] = str(clickable_df.iloc[row_idx]["subdomain"])

    selected_subdomain = st.session_state.get("public_exposure_selected_subdomain", "")
    if selected_subdomain:
        match = exposure_df[exposure_df["subdomain"].astype(str) == selected_subdomain]
        if not match.empty:
            row = match.iloc[0]
            st.subheader(f"Exposure Details: {row['subdomain']}")
            dcol_1, dcol_2, dcol_3 = st.columns(3)
            dcol_1.metric("Provider", str(row["Provider"]))
            dcol_2.metric("Public IP Count", int(row["ip_count"]))
            dcol_3.metric(
                "SSL Expiring <=30d",
                "Yes" if pd.notna(row["ssl_days_remaining"]) and int(row["ssl_days_remaining"]) <= 30 else "No",
            )

            st.write(f"**CNAME:** {row['cname'] or '-'}")
            st.write(f"**IP Addresses:** {row['ip_addresses_display']}")
            st.write(f"**SSL Issuer Org:** {row['ssl_issuer_org'] or '-'}")
            st.write(
                f"**SSL Not After:** {'-' if pd.isna(row['ssl_not_after']) else row['ssl_not_after'].strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )
            if str(row.get('timestamp', '')).strip():
                st.caption(f"Last indexed: {row['timestamp']}")

    export_df = exposure_df[["subdomain", "cname", "ip_addresses_display", "Provider", "ssl_issuer_org", "ssl_not_after"]].copy()
    export_df["ssl_not_after"] = export_df["ssl_not_after"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    export_df = export_df.rename(columns={"ip_addresses_display": "ip_addresses"})
    st.download_button(
        label="Download Public Exposure CSV",
        data=export_df.to_csv(index=False).encode("utf-8"),
        file_name="public_exposure_register.csv",
        mime="text/csv",
    )


def _render_waf_sites() -> None:
    waf_df = _waf_sites_df()

    if waf_df.empty:
        st.warning(
            f"No WAF site records found in index 'security-imperva-sites' at {CONFIG.elasticsearch_url}. "
            "Ensure the Imperva exporter is running and has indexed data."
        )
        return

    # ── Metrics ──────────────────────────────────────────────────────────────
    total_sites = len(waf_df)
    active_sites = int((waf_df["status"].str.lower() == "active").sum())
    ddos_protected = int(waf_df["ddos_protection"].sum())
    waf_modes = waf_df["waf_mode"].replace("", "Unknown")
    monitor_count = int((waf_modes.str.lower() == "monitor").sum())
    block_count = int((waf_modes.str.lower() == "block").sum())

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Sites", total_sites)
    m2.metric("Active Sites", active_sites)
    m3.metric("DDoS Protected", ddos_protected)
    m4.metric("WAF: Block Mode", block_count)
    m5.metric("WAF: Monitor Mode", monitor_count)

    # ── Analytics ─────────────────────────────────────────────────────────────
    st.subheader("Analytics")
    chart_col1, chart_col2, chart_col3 = st.columns(3)

    with chart_col1:
        st.caption("WAF Mode Distribution")
        mode_counts = waf_df["waf_mode"].replace("", "Unknown").value_counts().reset_index()
        mode_counts.columns = ["WAF Mode", "Count"]
        st.bar_chart(mode_counts.set_index("WAF Mode"), use_container_width=True, height=200)

    with chart_col2:
        st.caption("Site Status Distribution")
        status_counts = waf_df["status"].replace("", "Unknown").value_counts().reset_index()
        status_counts.columns = ["Status", "Count"]
        st.bar_chart(status_counts.set_index("Status"), use_container_width=True, height=200)

    with chart_col3:
        st.caption("DDoS Protection Coverage")
        ddos_counts = pd.DataFrame(
            {"Protection": ["Protected", "Unprotected"], "Count": [ddos_protected, total_sites - ddos_protected]}
        ).set_index("Protection")
        st.bar_chart(ddos_counts, use_container_width=True, height=200)

    st.divider()

    # ── Filters ───────────────────────────────────────────────────────────────
    st.subheader("WAF Protected Apps Register")
    f1, f2, f3, f4 = st.columns(4)

    status_opts = sorted(waf_df["status"].replace("", "Unknown").unique().tolist())
    mode_opts = sorted(waf_df["waf_mode"].replace("", "Unknown").unique().tolist())

    status_filter = f1.multiselect("Filter by Status", status_opts)
    mode_filter = f2.multiselect("Filter by WAF Mode", mode_opts)
    ddos_filter = f3.selectbox("DDoS Protection", ["All", "Protected", "Unprotected"])
    search_filter = f4.text_input("Search", placeholder="Domain or IP…")

    view_df = waf_df.copy()
    if status_filter:
        view_df = view_df[view_df["status"].isin(status_filter)]
    if mode_filter:
        view_df = view_df[view_df["waf_mode"].isin(mode_filter)]
    if ddos_filter == "Protected":
        view_df = view_df[view_df["ddos_protection"] == True]
    elif ddos_filter == "Unprotected":
        view_df = view_df[view_df["ddos_protection"] == False]
    if search_filter.strip():
        q = search_filter.strip().lower()
        view_df = view_df[
            view_df["domain"].str.lower().str.contains(q, na=False)
            | view_df["ips_display"].str.lower().str.contains(q, na=False)
        ]

    table_df = view_df[["domain", "ips_display", "status", "ddos_protection", "waf_mode"]].copy()
    table_df = table_df.rename(columns={"ips_display": "IPs"})
    table_df["ddos_protection"] = table_df["ddos_protection"].map({True: "✔ Yes", False: "✘ No"})

    event = st.dataframe(
        table_df,
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key="waf_sites_table",
    )

    selected_rows: list[int] = []
    if isinstance(event, dict):
        selected_rows = event.get("selection", {}).get("rows", [])
    elif hasattr(event, "selection") and hasattr(event.selection, "rows"):
        selected_rows = list(event.selection.rows)

    if selected_rows:
        row_idx = int(selected_rows[0])
        if 0 <= row_idx < len(view_df):
            row = view_df.iloc[row_idx]
            st.subheader(f"Site Details: {row['domain']}")
            d1, d2, d3, d4 = st.columns(4)
            d1.metric("Status", str(row["status"]) or "—")
            d2.metric("WAF Mode", str(row["waf_mode"]) or "—")
            d3.metric("DDoS Protection", "Yes" if row["ddos_protection"] else "No")
            d4.metric("IP Count", len(row["ips"]))
            st.write(f"**IPs:** {row['ips_display'] or '—'}")
            if str(row.get("timestamp", "")).strip():
                st.caption(f"Last indexed: {row['timestamp']}")

    # ── Export ────────────────────────────────────────────────────────────────
    export_df = view_df[["domain", "ips_display", "status", "ddos_protection", "waf_mode"]].copy()
    export_df = export_df.rename(columns={"ips_display": "ips"})
    st.download_button(
        label="Download WAF Sites CSV",
        data=export_df.to_csv(index=False).encode("utf-8"),
        file_name="waf_protected_apps.csv",
        mime="text/csv",
    )


def _render_knowledge_base(max_retrieval_docs: int) -> None:
    st.subheader("Persistent Knowledge Base")
    search_text = st.text_input("Search Stored Context", value="zero trust api gateway keycloak tls")
    if st.button("Query Knowledge Base"):
        hits = retrieve_context(vector_store, search_text, k=max_retrieval_docs)
        if not hits:
            st.warning("No entries found yet. Run report generation first to populate the KB.")
        for i, hit in enumerate(hits, start=1):
            st.markdown(f"**Result {i}**")
            st.write(hit)
            st.divider()


def _render_jobs() -> None:
    _ = job_worker
    st.subheader("Background Report Jobs")
    st.caption("Jobs run in the server worker and keep running after the browser tab is closed.")
    if st.button("Refresh Jobs"):
        st.rerun()

    jobs = list_jobs(limit=200)
    if not jobs:
        st.info("No background jobs yet. Queue one from Report Generation tab.")
        return

    labels = [
        f"{j.get('created_at_utc', 'unknown')} | {j.get('status', 'unknown')} | {j.get('source_name', 'unknown')} | {j.get('id', 'unknown')}"
        for j in jobs
    ]
    selected = st.selectbox("Select a background job", options=labels)
    row = jobs[labels.index(selected)]

    col_1, col_2, col_3 = st.columns(3)
    col_1.metric("Status", str(row.get("status", "unknown")).upper())
    col_2.metric("Created", str(row.get("created_at_utc", "-")))
    col_3.metric("Updated", str(row.get("updated_at_utc", "-")))

    st.text_input("Job ID", value=str(row.get("id", "")), disabled=True)
    stop_allowed = str(row.get("status", "")).lower() in {"queued", "running", "cancel_requested"}
    if st.button("Stop Selected Job", disabled=not stop_allowed, key=f"stop_job_{row.get('id', '')}"):
        updated = request_stop_job(str(row.get("id", "")))
        if not updated:
            st.error("Unable to stop job: not found.")
        elif str(updated.get("status", "")).lower() == "canceled":
            st.success("Job canceled.")
        else:
            st.warning("Stop requested. The worker will cancel this job at the next safe checkpoint.")
        st.rerun()

    if row.get("error"):
        st.error(str(row.get("error")))
    if row.get("status") == "failed" and row.get("traceback"):
        with st.expander("Failure Traceback"):
            st.text(str(row.get("traceback", "")))
    if row.get("status") in {"cancel_requested", "canceled"}:
        st.info("This job was stopped by user request.")

    if row.get("status") == "completed":
        report_md = load_job_report(row)
        if report_md:
            st.text_area("Generated Report", report_md, height=330)
            st.download_button(
                label="Download Job Report (.md)",
                data=report_md,
                file_name=f"{row.get('report_id', row.get('id', 'report'))}.md",
                mime="text/markdown",
            )
            st.download_button(
                label="Download Job Report (.docx)",
                data=markdown_to_docx_bytes(report_md),
                file_name=f"{row.get('report_id', row.get('id', 'report'))}.docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
    elif row.get("status") == "canceled":
        st.warning("No report output was saved because the job was canceled.")
    else:
        st.info("This job has not completed yet. Refresh to check latest status.")


def _render_history() -> None:
    st.subheader("Historical Reports")
    history = list_reports(limit=200)
    if not history:
        st.info("No report history yet. Generate a report first.")
        return

    labels = [f"{r['created_at_utc']} | {r['source']} | {r['id']}" for r in history]
    selected = st.selectbox("Select a report", options=labels)
    selected_row = history[labels.index(selected)]
    markdown_text = load_report(selected_row["markdown_path"])

    st.caption(f"Saved file: {Path(selected_row['markdown_path']).name}")
    st.text_area("Report Preview", markdown_text, height=350)
    st.download_button(
        label="Download Selected (.md)",
        data=markdown_text,
        file_name=f"{selected_row['id']}.md",
        mime="text/markdown",
    )
    st.download_button(
        label="Download Selected (.docx)",
        data=markdown_to_docx_bytes(markdown_text),
        file_name=f"{selected_row['id']}.docx",
        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )


def _render_demo() -> None:
    st.subheader("Download Example Assessment Workbook")
    demo_bytes = build_example_workbook_bytes()
    st.download_button(
        label="Download sample_assessment.xlsx",
        data=demo_bytes,
        file_name="sample_assessment.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    st.caption("Use this sample to quickly test the upload flow, enrichment, RAG retrieval, and report generation.")


# ---------------------------------------------------------------------------
# Copilot page
# ---------------------------------------------------------------------------

def _render_copilot() -> None:
    st.subheader("Security Architecture Copilot")

    # ── Model selector ─────────────────────────────────────────────────────
    with st.expander("⚙ Model Settings", expanded="copilot_provider" not in st.session_state):
        provider_options = list(PROVIDER_LABELS.keys())
        provider_labels = list(PROVIDER_LABELS.values())
        current_provider = st.session_state.get("copilot_provider", PROVIDER_OLLAMA)
        selected_index = provider_options.index(current_provider) if current_provider in provider_options else 0

        chosen = st.radio(
            "LLM Provider",
            options=provider_options,
            format_func=lambda k: PROVIDER_LABELS[k],
            index=selected_index,
            horizontal=True,
            key="copilot_provider_radio",
        )
        if chosen != st.session_state.get("copilot_provider"):
            st.session_state["copilot_provider"] = chosen
            st.session_state["copilot_history"] = []  # clear history on provider switch

        provider = st.session_state.get("copilot_provider", PROVIDER_OLLAMA)

        # Gemini API key input (only shown when Gemini selected and no env key)
        gemini_api_key = ""
        if provider == PROVIDER_GEMINI:
            from src.core.config import CONFIG as _CFG
            if _CFG.gemini_api_key:
                st.success(f"Gemini API key loaded from environment. Model: `{_CFG.gemini_model}`")
            else:
                gemini_api_key = st.text_input(
                    "Gemini API Key",
                    type="password",
                    placeholder="AIza...",
                    help="Get a key at https://aistudio.google.com/app/apikey — stored in session only, never persisted.",
                    key="copilot_gemini_key_input",
                )
                st.session_state["copilot_gemini_key"] = gemini_api_key
        else:
            from src.core.config import CONFIG as _CFG
            st.caption(f"Using local Ollama at `{_CFG.ollama_base_url}` · model `{_CFG.ollama_llm_model}`")

    provider = st.session_state.get("copilot_provider", PROVIDER_OLLAMA)
    gemini_api_key = str(st.session_state.get("copilot_gemini_key", "")).strip()

    st.caption(
        "Chat is grounded in your live portal data — assets, budgets, public exposure, pentest Jira tickets, and reports. "
        "All data stays on-premise; only the message text is sent to a cloud provider if selected."
    )

    # ── Session state ──────────────────────────────────────────────────────
    if "copilot_history" not in st.session_state:
        st.session_state["copilot_history"] = []

    history: list[dict[str, str]] = st.session_state["copilot_history"]

    # ── Render existing messages ───────────────────────────────────────────
    for msg in history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # ── Suggested prompts when empty ───────────────────────────────────────
    if not history:
        st.markdown("**Suggested prompts — click one to get started:**")
        cols = st.columns(2)
        for i, suggestion in enumerate(SUGGESTED_PROMPTS):
            if cols[i % 2].button(suggestion, key=f"suggest_{i}", use_container_width=True):
                st.session_state["copilot_prefill"] = suggestion
                st.rerun()

    prefill = st.session_state.pop("copilot_prefill", None)

    # ── Chat input ─────────────────────────────────────────────────────────
    user_input = st.chat_input("Ask the Copilot anything about security architecture…") or prefill

    if user_input:
        history.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        with st.chat_message("assistant"):
            response_placeholder = st.empty()
            full_response = ""
            for token in stream_copilot_response(
                history,
                user_input,
                provider=provider,
                gemini_api_key=gemini_api_key,
            ):
                full_response += token
                response_placeholder.markdown(full_response + "▌")
            response_placeholder.markdown(full_response)

        history.append({"role": "assistant", "content": full_response})
        st.session_state["copilot_history"] = history

    # ── Clear conversation ─────────────────────────────────────────────────
    if history:
        if st.button("🗑 Clear conversation", key="copilot_clear"):
            st.session_state["copilot_history"] = []
            st.rerun()


# ---------------------------------------------------------------------------
# Application Security - Pentest Tickets
# ---------------------------------------------------------------------------

def _render_pentest_tickets() -> None:
    from src.analytics.appsec.pentest import render_pentest_dashboard
    
    st.subheader("Pentest Ticketing Dashboard")
    st.caption("Real-time monitoring and analytics of security penetration testing tickets from Jira.")
    
    try:
        render_pentest_dashboard()
    except Exception as e:
        st.error(f"Error loading pentest dashboard: {str(e)}")
        with st.expander("Debug Information"):
            st.code(str(e))


# ---------------------------------------------------------------------------
# SOC Tickets
# ---------------------------------------------------------------------------

def _render_soc_tickets() -> None:
    from src.analytics.appsec.soc import render_soc_dashboard
    from src.jobs.soc_analytics_runner import SocAnalyticsRunner

    if "soc_analytics_runner" not in st.session_state:
        st.session_state["soc_analytics_runner"] = SocAnalyticsRunner()
    runner: SocAnalyticsRunner = st.session_state["soc_analytics_runner"]

    st.subheader("SOC Ticketing Dashboard")
    st.caption("AI/ML analytics of SOC (CIAOT) tickets — severity, MITRE ATT&CK tactics/techniques, alert intelligence. Data is pre-analysed and cached as JSON.")

    try:
        render_soc_dashboard(runner=runner)
    except Exception as e:
        st.error(f"Error loading SOC dashboard: {str(e)}")
        with st.expander("Debug Information"):
            st.code(str(e))


# ---------------------------------------------------------------------------
# Budget Analytics
# ---------------------------------------------------------------------------

def _render_budget_analytics_page() -> None:
    from src.analytics.budget.dashboard import render_budget_analytics_dashboard
    from src.jobs.budget_analytics_runner import BudgetAnalyticsRunner

    if "budget_analytics_runner" not in st.session_state:
        st.session_state["budget_analytics_runner"] = BudgetAnalyticsRunner()
    runner: BudgetAnalyticsRunner = st.session_state["budget_analytics_runner"]

    st.subheader("Budget Analytics Dashboard")
    st.caption(
        "Pure budget-data analytics — variance detection, outlier scoring, quarter timeline, "
        "domain breakdown, and AI narrative. Runs independently from SOC ticket data."
    )
    try:
        render_budget_analytics_dashboard(runner=runner)
    except Exception as e:
        st.error(f"Error loading Budget Analytics dashboard: {e}")
        with st.expander("Debug Information"):
            st.code(str(e))


# ---------------------------------------------------------------------------
# Section summary pages
# ---------------------------------------------------------------------------

def _nav_btn(label: str, page: str) -> None:
    """Small helper: a button that navigates to a child page."""
    if st.button(f"Open → {label}", key=f"summary_nav_{page}", use_container_width=False):
        st.session_state["selected_page"] = page
        st.rerun()


def _render_governance_summary() -> None:
    st.caption("Aggregated snapshot across all Governance sub-modules.")

    assets_df   = _assets_df()
    budgets_df  = _budgets_df()
    reports     = list_reports(limit=500)
    jobs        = list_jobs(limit=500)

    expiring_90d   = int(((assets_df["days_to_renewal"] <= 90) & (assets_df["days_to_renewal"] >= 0)).sum()) if not assets_df.empty else 0
    annual_spend   = float(assets_df["annual_cost"].sum()) if not assets_df.empty else 0.0
    capex_total    = float(budgets_df.loc[budgets_df["cost_type"] == "Capex", "amount"].sum()) if not budgets_df.empty else 0.0
    active_jobs    = sum(1 for j in jobs if str(j.get("status", "")).lower() in {"queued", "running"})

    # ── Report Generation ─────────────────────────────────────────────────
    st.markdown("#### 📄 Report Generation")
    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Historical Reports", len(reports))
    r2.metric("Active Jobs", active_jobs)
    r3.metric("Total Jobs", len(jobs))
    with r4:
        _nav_btn("Report Generation", "Report Generation")

    st.divider()

    # ── Security Asset Inventory ──────────────────────────────────────────
    st.markdown("#### 🖥 Security Asset Inventory")
    a1, a2, a3, a4 = st.columns(4)
    a1.metric("Total Assets", int(len(assets_df)))
    a2.metric("Renewing ≤ 90d", expiring_90d)
    a3.metric("Annual Licence Spend", _format_money(annual_spend))
    with a4:
        _nav_btn("Asset Inventory", "Security Asset Inventory")

    if not assets_df.empty:
        spotlight = assets_df.sort_values("days_to_renewal", ascending=True).head(5)
        st.dataframe(
            spotlight[["asset_name", "owner", "license_name", "annual_cost", "renewal_date", "days_to_renewal"]],
            use_container_width=True, hide_index=True,
        )

    st.divider()

    # ── Budget Tracking ───────────────────────────────────────────────────
    st.markdown("#### 💰 Budget Tracking")
    b1, b2, b3, b4 = st.columns(4)
    b1.metric("Budget Items", int(len(budgets_df)))
    b2.metric("Capex Total", _format_money(capex_total))
    total_budget = float(budgets_df["amount"].sum()) if not budgets_df.empty else 0.0
    b3.metric("All Budget Total", _format_money(total_budget))
    with b4:
        _nav_btn("Budget Tracking", "Budget Tracking")

    st.divider()

    # ── Capacity Planning & Knowledge Base ────────────────────────────────
    st.markdown("#### 📈 Capacity Planning  ·  📚 Knowledge Base")
    c1, c2 = st.columns(2)
    with c1:
        _nav_btn("Capacity Planning", "Capacity Planning")
    with c2:
        _nav_btn("Knowledge Base", "Knowledge Base")


def _render_infrastructure_summary() -> None:
    st.caption("Aggregated snapshot across Infrastructure Management sub-modules.")

    waf_df = _waf_sites_df()

    # ── WAF Protected Apps ────────────────────────────────────────────────
    st.markdown("#### 🛡 WAF Protected Apps")
    total_sites   = int(len(waf_df))
    active_sites  = int((waf_df["status"].str.lower() == "active").sum()) if not waf_df.empty else 0
    block_mode    = int((waf_df["waf_mode"].str.lower() == "block").sum()) if not waf_df.empty else 0
    ddos_prot     = int(waf_df["ddos_protection"].sum()) if not waf_df.empty else 0

    w1, w2, w3, w4, w5 = st.columns(5)
    w1.metric("Total Sites",    total_sites)
    w2.metric("Active Sites",   active_sites)
    w3.metric("DDoS Protected", ddos_prot)
    w4.metric("Block Mode",     block_mode)
    with w5:
        _nav_btn("WAF Protected Apps", "WAF Protected Apps")

    if not waf_df.empty:
        st.dataframe(
            waf_df[["domain", "ips_display", "status", "ddos_protection", "waf_mode"]].head(8),
            use_container_width=True, hide_index=True,
        )

    st.divider()

    # ── Pentest Tickets ───────────────────────────────────────────────────
    st.markdown("#### 🔍 Pentest Tickets")
    try:
        from src.data.pentest_store import get_pentest_statistics
        stats = get_pentest_statistics()
        p1, p2, p3, p4, p5 = st.columns(5)
        p1.metric("Total Tickets", stats.get("total_tickets", 0))
        p2.metric("Open",         stats.get("open_tickets", 0))
        p3.metric("In Progress",  stats.get("in_progress", 0))
        p4.metric("Completed",    stats.get("completed", 0))
        with p5:
            _nav_btn("Pentest Tickets", "Pentest Tickets")
        by_pri = stats.get("by_priority", {})
        if by_pri:
            import plotly.graph_objects as go
            fig = go.Figure(data=[go.Bar(
                x=list(by_pri.keys()), y=list(by_pri.values()),
                marker=dict(color=["#f26464", "#f5a623", "#3ecf8e"]),
            )])
            fig.update_layout(title="Pentest by Priority", height=260, showlegend=False,
                              margin=dict(t=30, b=10, l=10, r=10))
            st.plotly_chart(fig, use_container_width=True, key="infra_pentest_pri")
    except Exception as exc:
        st.info(f"Pentest data unavailable: {exc}")
        _nav_btn("Pentest Tickets", "Pentest Tickets")


def _render_monitoring_summary() -> None:
    st.caption("Aggregated snapshot across Monitoring Operation sub-modules.")

    exposure_df = _public_exposure_df()

    # ── Public Exposure ───────────────────────────────────────────────────
    st.markdown("#### 🌐 Public Exposure")
    total_subs   = int(len(exposure_df)) if not exposure_df.empty else 0
    expiring_30d = int(((exposure_df["ssl_days_remaining"] <= 30) & (exposure_df["ssl_days_remaining"] >= 0)).sum()) if not exposure_df.empty else 0
    unique_ips   = int(exposure_df["ip_addresses"].explode().dropna().astype(str).nunique()) if not exposure_df.empty else 0

    e1, e2, e3, e4 = st.columns(4)
    e1.metric("Exposed Subdomains", total_subs)
    e2.metric("Unique Public IPs",  unique_ips)
    e3.metric("SSL Expiring ≤ 30d", expiring_30d)
    with e4:
        _nav_btn("Public Exposure", "Public Exposure")

    st.divider()

    # ── SOC Tickets ───────────────────────────────────────────────────────
    st.markdown("#### 🚨 SOC Tickets (CIAOT)")
    from src.data.soc_analytics_store import load_analytics, analytics_age_seconds
    data = load_analytics()
    if data:
        summary = data.get("summary", {})
        by_sev  = summary.get("by_severity", {})
        age     = analytics_age_seconds()
        age_lbl = (f"{int(age // 60)}m ago" if age and age >= 60 else "just now") if age else "unknown"

        s1, s2, s3, s4, s5 = st.columns(5)
        s1.metric("Total YTD",  f"{data.get('total_tickets', 0):,}")
        s2.metric("Critical",   by_sev.get("Critical", 0))
        s3.metric("High",       by_sev.get("High", 0))
        s4.metric("Medium",     by_sev.get("Medium", 0))
        s5.metric("Last Analysis", age_lbl)

        top_taktik = list(summary.get("by_taktik", {}).items())[:5]
        if top_taktik:
            import plotly.graph_objects as go
            names, counts = zip(*top_taktik)
            fig = go.Figure(data=[go.Bar(
                x=list(counts), y=list(names),
                orientation="h", marker=dict(color="#3ecf8e"),
            )])
            fig.update_layout(title="Top 5 Tactics", height=220,
                              yaxis=dict(autorange="reversed"),
                              showlegend=False, margin=dict(t=30, b=10, l=10, r=10))
            st.plotly_chart(fig, use_container_width=True, key="mon_soc_taktik")
    else:
        st.info("No SOC analytics yet — run the analysis from the SOC Tickets page.")

    _nav_btn("SOC Tickets", "SOC Tickets")


def _render_configuration_summary() -> None:
    st.caption("Aggregated snapshot across Configuration sub-modules.")
    st.markdown("#### 👤 User Management")
    try:
        users = load_users()
        from collections import Counter
        roles = Counter(str(u.get("role", "unknown")) for u in users)
        u1, u2 = st.columns([1, 3])
        u1.metric("Total Users", len(users))
        with u2:
            _nav_btn("User Management", "User Management")
        if roles:
            role_data = pd.DataFrame(roles.most_common(), columns=["Role", "Count"])
            st.dataframe(role_data, use_container_width=False, hide_index=True)
    except Exception as exc:
        st.info(f"User data unavailable: {exc}")
        _nav_btn("User Management", "User Management")


# ---------------------------------------------------------------------------
# Capacity Planning page
# ---------------------------------------------------------------------------

def _render_capacity_planning() -> None:
    st.subheader("Security Platform Capacity Planning")
    st.caption(
        "Model future infrastructure requirements for your security tools using multi-parameter "
        "forecasting (compound growth or ML polynomial regression when historical data is provided). "
        "Then generate an AI narrative via Ollama."
    )

    # ── Parameter panel ────────────────────────────────────────────────────
    with st.expander("Platform & Tool Parameters", expanded=True):
        c1, c2, c3 = st.columns(3)
        tool_name = c1.text_input("Security Tool / Platform Name", value="SIEM / WAF Cluster", key="cap_tool_name")
        current_users = c2.number_input("Current Active Users", min_value=1, value=5_000, step=100, key="cap_users")
        forecast_years = c3.slider("Forecast Horizon (years)", min_value=1, max_value=10, value=3, key="cap_years")

    with st.expander("Growth Parameters", expanded=True):
        g1, g2 = st.columns(2)
        annual_growth_pct = g1.slider("Annual User Growth Rate (%)", min_value=1.0, max_value=200.0, value=25.0, step=1.0, key="cap_growth")
        st.caption(
            "If you provide **3 or more historical data points** below the ML engine will fit a "
            "polynomial regression instead of the compound growth formula."
        )
        hist_input = g2.text_area(
            "Historical Users (optional, comma-separated, oldest first)",
            placeholder="e.g. 1000, 1500, 2200, 3000",
            key="cap_hist",
        )
        hist_years_input = st.text_area(
            "Corresponding Historical Years (comma-separated)",
            placeholder="e.g. 2021, 2022, 2023, 2024",
            key="cap_hist_years",
        )

    with st.expander("Network / Bandwidth Parameters"):
        n1, n2, n3 = st.columns(3)
        bw_per_user = n1.number_input("Avg Bandwidth per User (Mbps)", min_value=0.01, value=0.5, step=0.05, key="cap_bw")
        peak_mult = n2.number_input("Peak / Average Ratio", min_value=1.0, value=3.0, step=0.5, key="cap_peak")
        bw_overhead = n3.slider("Bandwidth Headroom (%)", min_value=5, max_value=100, value=20, key="cap_bw_overhead")

    with st.expander("Compute & Storage Parameters"):
        comp1, comp2, comp3, comp4 = st.columns(4)
        cpu_per_ku = comp1.number_input("CPU Cores per 1,000 Users", min_value=0.1, value=4.0, step=0.5, key="cap_cpu")
        ram_per_ku = comp2.number_input("RAM (GB) per 1,000 Users", min_value=0.1, value=8.0, step=1.0, key="cap_ram")
        log_gb_per_user = comp3.number_input("Log Storage (GB/user/year)", min_value=0.01, value=0.5, step=0.05, key="cap_log")
        retention = comp4.slider("Log Retention (years)", min_value=1, max_value=7, value=1, key="cap_retention")
        comp_row2_1, comp_row2_2 = st.columns(2)
        compression = comp_row2_1.number_input("Compression Ratio (e.g. 4 = 4:1)", min_value=1.0, value=4.0, step=0.5, key="cap_compress")
        ha_factor = comp_row2_2.number_input("HA Redundancy Factor (N+1 = 2)", min_value=1.0, value=2.0, step=0.5, key="cap_ha")

    with st.expander("Cluster Sizing"):
        cs1, cs2 = st.columns(2)
        nodes_per_ku = cs1.number_input("Nodes per 1,000 Users", min_value=0.1, value=0.5, step=0.1, key="cap_nodes")

    with st.expander("Cost Parameters (USD)"):
        cost1, cost2, cost3, cost4 = st.columns(4)
        cost_cpu = cost1.number_input("Cost per CPU Core / mo", min_value=0.0, value=50.0, step=5.0, key="cap_cost_cpu")
        cost_ram = cost2.number_input("Cost per RAM GB / mo", min_value=0.0, value=8.0, step=1.0, key="cap_cost_ram")
        cost_tb = cost3.number_input("Cost per TB Storage / mo", min_value=0.0, value=30.0, step=5.0, key="cap_cost_tb")
        cost_bw = cost4.number_input("Cost per Mbps BW / mo", min_value=0.0, value=5.0, step=1.0, key="cap_cost_bw")

    # ── Parse historical data ───────────────────────────────────────────────
    historical_users: list[int] = []
    historical_years: list[int] = []
    if hist_input.strip():
        try:
            historical_users = [int(v.strip()) for v in hist_input.split(",") if v.strip()]
        except ValueError:
            st.warning("Historical users must be comma-separated integers — field ignored.")
    if hist_years_input.strip():
        try:
            historical_years = [int(v.strip()) for v in hist_years_input.split(",") if v.strip()]
        except ValueError:
            st.warning("Historical years must be comma-separated integers — field ignored.")

    # ── Run Forecast ────────────────────────────────────────────────────────
    run_col, _ = st.columns([1, 5])
    run_clicked = run_col.button("Run Forecast", type="primary", use_container_width=True)

    if run_clicked or st.session_state.get("cap_result") is not None:
        if run_clicked:
            inp = CapacityInput(
                tool_name=str(tool_name),
                current_users=int(current_users),
                annual_growth_pct=float(annual_growth_pct),
                forecast_years=int(forecast_years),
                avg_bandwidth_mbps_per_user=float(bw_per_user),
                peak_multiplier=float(peak_mult),
                bandwidth_overhead_pct=float(bw_overhead),
                avg_cpu_cores_per_1k_users=float(cpu_per_ku),
                avg_ram_gb_per_1k_users=float(ram_per_ku),
                avg_log_gb_per_user_per_year=float(log_gb_per_user),
                log_retention_years=int(retention),
                compression_ratio=float(compression),
                nodes_per_1k_users=float(nodes_per_ku),
                ha_redundancy_factor=float(ha_factor),
                cost_per_cpu_core_usd=float(cost_cpu),
                cost_per_ram_gb_usd=float(cost_ram),
                cost_per_tb_storage_usd=float(cost_tb),
                cost_per_bandwidth_mbps_usd=float(cost_bw),
                historical_users=historical_users,
                historical_years=historical_years,
            )
            with st.spinner("Running capacity forecast…"):
                forecast = run_capacity_forecast(inp)
            st.session_state["cap_result"] = forecast
            st.session_state["cap_input"] = inp

        forecast = st.session_state.get("cap_result")
        inp = st.session_state.get("cap_input")
        if forecast is None or inp is None:
            return

        # ── Alerts ─────────────────────────────────────────────────────────
        if forecast.alert_messages:
            for alert in forecast.alert_messages:
                st.warning(f"⚠ {alert}")

        # ── Model info ─────────────────────────────────────────────────────
        r2_text = f"  |  R² = {forecast.r2_score:.4f}" if forecast.r2_score is not None else ""
        st.caption(f"Forecast model: **{forecast.ml_model_used}**{r2_text}")

        # ── Summary table ─────────────────────────────────────────────────
        st.subheader("Projection Summary")
        st.dataframe(forecast.summary_df, use_container_width=True, hide_index=True)

        # ── Charts in a 2-column grid ──────────────────────────────────────
        st.subheader("Visual Projections")
        chart_keys = ["user_growth", "resources", "storage", "bandwidth", "cost", "nodes"]
        for i in range(0, len(chart_keys), 2):
            col_a, col_b = st.columns(2)
            key_a = chart_keys[i]
            if key_a in forecast.charts:
                col_a.plotly_chart(forecast.charts[key_a], use_container_width=True)
            if i + 1 < len(chart_keys):
                key_b = chart_keys[i + 1]
                if key_b in forecast.charts:
                    col_b.plotly_chart(forecast.charts[key_b], use_container_width=True)

        # ── AI Narrative ──────────────────────────────────────────────────
        st.subheader("AI Planning Narrative")
        st.caption("Generated by Ollama — based on your inputs and projections.")
        ai_col, _ = st.columns([1, 5])
        generate_narrative = ai_col.button("Generate AI Narrative", use_container_width=True, key="cap_gen_narrative")
        if generate_narrative:
            with st.spinner("Generating narrative via Ollama…"):
                narrative = generate_capacity_narrative(inp, forecast)
            st.session_state["cap_narrative"] = narrative

        narrative = st.session_state.get("cap_narrative", "")
        if narrative:
            st.markdown(narrative)


if not _enforce_authentication():
    st.stop()


with st.sidebar:
    user = _current_user() or {}
    user_name = str(user.get("full_name") or user.get("username") or "Unknown User")
    user_role = str(user.get("role", "viewer")).upper()
    login_method = str(st.session_state.get("auth_method", "unknown")).upper()

    st.markdown('<div class="nav-panel-title">Session</div>', unsafe_allow_html=True)
    st.write(f"Signed in: {user_name}")
    st.write(f"Role: {user_role}")
    st.write(f"Method: {login_method}")
    sidebar_auth_config = load_auth_config()
    sidebar_providers = sidebar_auth_config.get("providers", {}) if isinstance(sidebar_auth_config, dict) else {}
    if bool(sidebar_providers.get("passkey", True)):
        with st.expander("Self Passkey Generation"):
            sidebar_passkey = passkey_summary(user)
            st.caption(f"Register or rotate your browser passkey. Current credentials: {sidebar_passkey['count']}")
            if st.button("Prepare My Browser Passkey", key="sidebar_prepare_passkey"):
                ceremony = begin_passkey_registration(user)
                _set_passkey_ceremony("sidebar_self_passkey", ceremony, str(user.get("username", "")))
                st.info("Continue with your browser, device, or third-party passkey manager.")

            sidebar_ceremony = _get_passkey_ceremony("sidebar_self_passkey")
            if sidebar_ceremony:
                sidebar_result = webauthn_bridge(
                    mode="register",
                    options_json=sidebar_ceremony["options_json"],
                    button_label="Register My Browser Passkey",
                    key="sidebar_passkey_webauthn",
                )
                if isinstance(sidebar_result, dict):
                    if not bool(sidebar_result.get("ok", False)):
                        st.error(str(sidebar_result.get("error", "Passkey registration failed.")))
                    else:
                        refreshed_user = find_user(sidebar_ceremony["username"])
                        try:
                            updated_user = finish_passkey_registration(
                                user=refreshed_user or {},
                                credential=sidebar_result.get("credential", {}),
                                expected_challenge=sidebar_ceremony["challenge"],
                            )
                        except Exception as _sreg_exc:
                            st.error(f"Passkey registration error: {_sreg_exc}")
                            updated_user = None
                        if not updated_user:
                            st.error("Unable to register passkey for current user.")
                        else:
                            _clear_passkey_ceremony("sidebar_self_passkey")
                            _refresh_session_user(updated_user)
                            st.success("Your browser passkey has been registered.")
                            st.rerun()
    if st.button("Sign Out", use_container_width=True):
        _clear_authenticated_user()
        st.rerun()
    st.divider()

    nav_tree = {
        "Dashboard Showcase": [],
        "Governance": [
            "Report Generation",
            "Background Jobs",
            "Historical Reports",
            "Security Asset Inventory",
            "Budget Tracking",
            "Budget Analytics",
            "Capacity Planning",
            "Knowledge Base",
        ],
        "Infrastructure Management": [
            "WAF Protected Apps",
            "Pentest Tickets",
        ],
        "Monitoring Operation": [
            "Public Exposure",
            "SOC Tickets",
        ],
        "Configuration": [
            "User Management",
        ],
        "Copilot": [],
    }
    page_icons = {
        "Dashboard Showcase":        "🏠",
        "Governance":                "🏛",
        "Report Generation":         "📄",
        "Background Jobs":           "⏳",
        "Historical Reports":        "🗂",
        "Security Asset Inventory":  "🖥",
        "Budget Tracking":           "💰",
        "Capacity Planning":         "📈",
        "Knowledge Base":            "📚",
        "Infrastructure Management": "🔧",
        "WAF Protected Apps":        "🛡",
        "Pentest Tickets":           "🔍",
        "Monitoring Operation":      "🔭",
        "Public Exposure":           "🌐",
        "SOC Tickets":               "🚨",
        "Budget Analytics":          "💹",
        "Configuration":             "⚙",
        "User Management":           "👤",
        "Copilot":                   "🤖",
    }
    default_page = "Dashboard Showcase"
    if "selected_page" not in st.session_state:
        st.session_state["selected_page"] = default_page
    active_parent = next(
        (
            parent
            for parent, children in nav_tree.items()
            if st.session_state["selected_page"] == parent or st.session_state["selected_page"] in children
        ),
        default_page,
    )

    st.markdown('<div class="nav-panel-title">Portal Navigation</div>', unsafe_allow_html=True)
    st.markdown(
        f"""
<div class="nav-current">
  <div class="path">Current Path</div>
  <div class="name">{active_parent} / {st.session_state['selected_page']}</div>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown('<div class="nav-pill">Feature tree</div>', unsafe_allow_html=True)
    nav_filter = st.text_input("Find module", placeholder="Type module name...")

    query = nav_filter.strip().lower()
    btn_idx = 0
    for parent, children in nav_tree.items():
        matched_parent = not query or query in parent.lower()
        matched_children = [child for child in children if not query or query in child.lower()]
        if not matched_parent and not matched_children:
            continue

        if not children:
            active = st.session_state["selected_page"] == parent
            clicked = st.button(
                f"{page_icons.get(parent, 'Module')}  {parent}",
                key=f"nav_btn_{btn_idx}",
                use_container_width=True,
                type="primary" if active else "secondary",
            )
            btn_idx += 1
            if clicked:
                st.session_state["selected_page"] = parent
            continue

        with st.expander(f"{page_icons.get(parent, 'Module')}  {parent}", expanded=(parent == active_parent) or bool(query)):
            parent_active = st.session_state["selected_page"] == parent
            parent_clicked = st.button(
                f"Open {parent}",
                key=f"nav_btn_{btn_idx}",
                use_container_width=True,
                type="primary" if parent_active else "secondary",
            )
            btn_idx += 1
            if parent_clicked:
                st.session_state["selected_page"] = parent

            for child in matched_children:
                icon = page_icons.get(child, "Module")
                active = st.session_state["selected_page"] == child
                label = f"   {icon}  {child}"
                clicked = st.button(
                    label,
                    key=f"nav_btn_{btn_idx}",
                    use_container_width=True,
                    type="primary" if active else "secondary",
                )
                btn_idx += 1
                if clicked:
                    st.session_state["selected_page"] = child

    selected_page = st.session_state["selected_page"]

if "max_retrieval_docs" not in st.session_state:
    st.session_state["max_retrieval_docs"] = 8
if "internet_enrichment_enabled" not in st.session_state:
    st.session_state["internet_enrichment_enabled"] = CONFIG.enable_internet_enrichment

max_retrieval_docs = int(st.session_state.get("max_retrieval_docs", 8))


if selected_page == "Dashboard Showcase":
    _render_dashboard_header()
    _render_dashboard()

elif selected_page == "Governance":
    _render_concise_header(selected_page)
    _render_governance_summary()

elif selected_page == "Infrastructure Management":
    _render_concise_header(selected_page)
    _render_infrastructure_summary()

elif selected_page == "Monitoring Operation":
    _render_concise_header(selected_page)
    _render_monitoring_summary()

elif selected_page == "Configuration":
    _render_concise_header(selected_page)
    _render_configuration_summary()

elif selected_page == "Report Generation":
    _render_concise_header(selected_page)
    _render_report_generation(max_retrieval_docs)

elif selected_page == "Security Asset Inventory":
    _render_concise_header(selected_page)
    _render_asset_inventory()

elif selected_page == "Public Exposure":
    _render_concise_header(selected_page)
    _render_public_exposure()

elif selected_page == "WAF Protected Apps":
    _render_concise_header(selected_page)
    _render_waf_sites()

elif selected_page in ("Application Security", "Pentest Tickets"):
    _render_concise_header(selected_page)
    _render_pentest_tickets()

elif selected_page == "SOC Tickets":
    _render_concise_header(selected_page)
    _render_soc_tickets()

elif selected_page == "Budget Analytics":
    _render_concise_header(selected_page)
    _render_budget_analytics_page()

elif selected_page == "Budget Tracking":
    _render_concise_header(selected_page)
    _render_budget_tracking()

elif selected_page == "Knowledge Base":
    _render_concise_header(selected_page)
    _render_knowledge_base(max_retrieval_docs)

elif selected_page == "User Management":
    _render_concise_header(selected_page)
    _render_user_management()

elif selected_page == "Background Jobs":
    _render_concise_header(selected_page)
    _render_jobs()

elif selected_page == "Historical Reports":
    _render_concise_header(selected_page)
    _render_history()

elif selected_page == "Capacity Planning":
    _render_concise_header(selected_page)
    _render_capacity_planning()

elif selected_page == "Copilot":
    _render_concise_header(selected_page)
    _render_copilot()