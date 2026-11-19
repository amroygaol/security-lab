from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


def _bool_env(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AppConfig:
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_llm_model: str = os.getenv("OLLAMA_LLM_MODEL", "llama3.2:3b")
    ollama_embed_model: str = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
    ollama_timeout_seconds: int = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "5000"))
    elasticsearch_url: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    security_assets_index: str = os.getenv("SECURITY_ASSETS_INDEX", "security-assets")
    security_assets_fetch_size: int = int(os.getenv("SECURITY_ASSETS_FETCH_SIZE", "1000"))
    chroma_persist_dir: str = os.getenv("CHROMA_PERSIST_DIR", "./data/chroma")
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "10"))
    enrichment_results_per_tech: int = int(os.getenv("ENRICHMENT_RESULTS_PER_TECH", "4"))
    report_history_dir: str = os.getenv("REPORT_HISTORY_DIR", "./data/reports")
    portal_data_dir: str = os.getenv("PORTAL_DATA_DIR", "./data/portal")
    auth_bootstrap_admin_user: str = os.getenv("AUTH_BOOTSTRAP_ADMIN_USER", "admin")
    auth_bootstrap_admin_password: str = os.getenv("AUTH_BOOTSTRAP_ADMIN_PASSWORD", "admin123")
    auth_session_timeout_minutes: int = int(os.getenv("AUTH_SESSION_TIMEOUT_MINUTES", "480"))
    auth_passkey_rp_id: str = os.getenv("AUTH_PASSKEY_RP_ID", "localhost")
    auth_passkey_origin: str = os.getenv("AUTH_PASSKEY_ORIGIN", "http://localhost:8501")
    auth_passkey_rp_name: str = os.getenv("AUTH_PASSKEY_RP_NAME", "Security Architecture Portal")
    job_queue_dir: str = os.getenv("JOB_QUEUE_DIR", "./data/jobs")
    job_poll_interval_seconds: float = float(os.getenv("JOB_POLL_INTERVAL_SECONDS", "2.0"))
    job_max_runtime_seconds: int = int(os.getenv("JOB_MAX_RUNTIME_SECONDS", "900"))
    enable_internet_enrichment: bool = _bool_env("ENABLE_INTERNET_ENRICHMENT", "0")
    use_fake_embeddings: bool = _bool_env("USE_FAKE_EMBEDDINGS", "1")
    enable_demo_report_fallback: bool = _bool_env("ENABLE_DEMO_REPORT_FALLBACK", "1")
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "AIzaSyB1WWCYyfPuDDDN6HFKiIa-LKVQJBUk41c")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")


CONFIG = AppConfig()

