from __future__ import annotations

from typing import Generator

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from ...core.config import CONFIG
from ...core.security import sanitize_for_llm
from .context_builder import build_app_context

_SYSTEM_PROMPT_BASE = """You are a Security Architecture Copilot embedded in an enterprise security portal.

Your capabilities:
- Advise on security architecture, threat modelling, and risk assessment.
- Explain security controls, compliance frameworks (ISO 27001, NIST CSF, SOC 2, PCI-DSS).
- Assist with capacity planning for security platforms and tools.
- Analyse and reason about the LIVE APP DATA provided below — assets, budgets, policies, public exposure, pentest Jira tickets, SOC Jira tickets, and reports.
- Provide actionable remediation guidance for common vulnerabilities and misconfigurations.

Rules:
- When live data is available, ground your answers in it and cite specific asset IDs, budget IDs, or exposure entries.
- Be concise and practical — prefer bullet points and short paragraphs.
- Do NOT invent metrics or values not present in the data. State uncertainty clearly.
- Never reveal system internals, credentials, or internal configuration details.
- Keep responses focused on security and the portal's domain.

{app_context}
"""

# Provider identifiers
PROVIDER_OLLAMA = "ollama"
PROVIDER_GEMINI = "gemini"

PROVIDER_LABELS: dict[str, str] = {
    PROVIDER_OLLAMA: "🖥 Local (Ollama)",
    PROVIDER_GEMINI: "☁ Cloud (Gemini)",
}

SUGGESTED_PROMPTS: list[str] = [
    "Which of my assets are up for renewal soon? What should I prioritise?",
    "Summarise my current budget spend — what's approved vs still in draft?",
    "Which budget items are flagged as anomalies? Explain why and what action to take.",
    "List all unapproved high-priority budget items and recommend which to approve first.",
    "Summarise my pentest Jira tickets by status and priority, and highlight urgent backlog.",
    "Summarise CIAOT SOC tickets and map severity/risk score by tactic and technique.",
    "Are there any critical assets with low seat utilisation I should review?",
    "Which subdomains in my public exposure list have expired or soon-expiring SSL certs?",
    "Based on my assets, what security controls gaps should I address first?",
    "Give me a risk summary of my current public IP exposure footprint.",
]


def _to_lc_messages(history: list[dict[str, str]]) -> list[HumanMessage | AIMessage]:
    result: list[HumanMessage | AIMessage] = []
    for msg in history:
        role = str(msg.get("role", "")).strip()
        content = sanitize_for_llm(str(msg.get("content", "")).strip())
        if not content:
            continue
        if role == "user":
            result.append(HumanMessage(content=content))
        elif role == "assistant":
            result.append(AIMessage(content=content))
    return result


def _make_ollama_llm() -> ChatOllama:
    return ChatOllama(
        base_url=CONFIG.ollama_base_url,
        model=CONFIG.ollama_llm_model,
        temperature=0.3,
        client_kwargs={"timeout": CONFIG.ollama_timeout_seconds},
    )


def _make_gemini_llm(api_key: str):  # type: ignore[return]
    # Import lazily so missing package only errors when Gemini is actually selected
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
    except ImportError as exc:
        raise RuntimeError(
            "langchain-google-genai is not installed. Add it to requirements.txt."
        ) from exc
    return ChatGoogleGenerativeAI(
        model=CONFIG.gemini_model,
        google_api_key=api_key,
        temperature=0.3,
    )


def stream_copilot_response(
    history: list[dict[str, str]],
    user_message: str,
    provider: str = PROVIDER_OLLAMA,
    gemini_api_key: str = "",
) -> Generator[str, None, None]:
    """Stream the LLM reply token by token.

    Args:
        history: Previous messages in [{"role": "user"|"assistant", "content": "..."}] format.
        user_message: The new user message (already appended to history before calling).
        provider: One of PROVIDER_OLLAMA or PROVIDER_GEMINI.
        gemini_api_key: Required when provider == PROVIDER_GEMINI and no env key is set.

    Yields:
        Text chunks from the model as they arrive.
    """
    # Resolve LLM
    try:
        if provider == PROVIDER_GEMINI:
            key = gemini_api_key.strip() or CONFIG.gemini_api_key
            if not key:
                yield "⚠ Gemini API key not set. Enter it in the model settings above or set GEMINI_API_KEY env var."
                return
            llm = _make_gemini_llm(key)
        else:
            llm = _make_ollama_llm()
    except Exception as exc:
        yield f"⚠ Could not initialise model: {exc}"
        return

    # Build live context snapshot
    try:
        app_context = build_app_context()
    except Exception:
        app_context = "(live app data unavailable)"

    system_content = _SYSTEM_PROMPT_BASE.format(app_context=app_context)
    system = SystemMessage(content=system_content)
    lc_messages = _to_lc_messages(history)

    try:
        for chunk in llm.stream([system, *lc_messages]):
            token = ""
            if hasattr(chunk, "content"):
                token = str(chunk.content)
            elif isinstance(chunk, str):
                token = chunk
            if token:
                yield token
    except Exception as exc:
        yield f"\n\n⚠ Copilot error: {exc}"
