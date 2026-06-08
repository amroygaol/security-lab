# Security Architecture Report Generator

A unified security operations portal built on Streamlit that combines **ML-driven threat analytics**, **LLM narrative generation**, **budget intelligence**, and **architecture reporting** into a single self-hosted platform. All AI/ML processing runs fully on-premise — no data leaves your infrastructure.

---

## What This Portal Does

| Capability | What it analyses | AI/ML used |
|---|---|---|
| **SOC Analytics** | 170,000+ Jira SOC tickets from Elasticsearch | Pandas/NumPy ML pipeline + LLM narrative |
| **Budget Intelligence** | Security Opex/Capex vs threat volume correlation | Statistical gap analysis + LLM recommendations |
| **Architecture Reports** | Excel compliance/control inventories | RAG pipeline (ChromaDB + LLM) |
| **Budget Anomaly Detection** | Budget line variance and outlier detection | NumPy z-score + LLM explanation |
| **Asset Tracking** | Licensed security tools, renewal dates, seats | Rule-based risk scoring |
| **Public Exposure** | Subdomains, IPs, certificates from Elasticsearch | Data aggregation + provider fingerprinting |

---

## AI / ML Architecture

### 1. SOC Ticket Analytics Pipeline (`src/jobs/soc_analytics_runner.py`)

This is the most data-intensive module. It processes the full Jira SOC ticket corpus from Elasticsearch using a multi-stage background pipeline:

```
Elasticsearch (170k+ tickets)
        │
        ▼
   Fetch Stage          search_after pagination, 500 tickets/page
        │               fields: key, summary, status, severity, risk_score,
        │               taktik (MITRE tactic), teknik (MITRE technique),
        │               alert_name, assignee, created
        ▼
   ML Analysis Stage    pure pandas + numpy, no model weights
        │
        ├── Frequency counters          Counter() on severity, status, taktik,
        │                               teknik, alert_name, assignee
        ├── Risk score statistics       mean, median, std, p25/p75/p95/p99
        ├── Weekly timeline             resample('W').sum() on created date
        ├── Taktik × Severity heatmap   pivot_table groupby
        └── Anomaly detection           z-score: alerts where count > mean + 2σ
                                        flagged as high_volume_alert anomalies
        │
        ▼
   Budget Correlation Stage    cross-references portal budget + asset data
        │
        ├── Domain mapping      MITRE ATT&CK tactic → security domain
        │                       (e.g. "credential access" → IAM,
        │                             "lateral movement" → Network Security)
        ├── Gap analysis        domains with ticket volume but zero budget
        ├── Budget KPIs         total / capex / opex breakdown by domain
        ├── Asset spend         criticality-weighted tool spend from asset inventory
        └── Policy compliance   High-priority items still in Draft/Planned status
        │
        ▼
   AI Narrative Stage    LLM generates executive report (configurable provider)
        │
        ├── Provider: Ollama (local)   ChatOllama, timeout=None, num_gpu=-1
        │   Model: llama3.2:3b         num_ctx=4096, temperature=0.3
        │   GPU detection: nvidia-smi / rocm-smi / macOS Metal / CPU fallback
        │
        └── Provider: Gemini (cloud)   ChatGoogleGenerativeAI
            Model: gemini-2.5-flash-lite   temperature=0.3
        │
        ▼
   Save Stage           JSON cache to disk (soc_analytics.json)
                        includes: summary, budget_analysis, ai_narrative,
                        narrative_provider, duration_seconds
```

**Anomaly detection detail:**

```python
counts = np.array(list(by_alert_name.values()), dtype=float)
mean_c, std_c = counts.mean(), counts.std()
# Flag alerts with z-score > 2
anomalies = [alert for alert in alerts if (count - mean_c) / std_c > 2]
```

**AI narrative prompt structure** — the LLM receives:
- SOC threat analytics (severity, top tactics/techniques, risk score stats, anomalies)
- Budget by domain (allocated vs. threat volume)
- Gap flags (domains under attack with no budget)
- Asset tool spend by criticality
- Unapproved high-priority budget items
- Governance policies

The LLM is asked to produce: overall posture assessment · top 3 threat priorities · budget alignment gaps · top 3 actionable recommendations.

---

### 2. Budget AI Analytics (`src/analytics/budget/engine.py`, `src/jobs/budget_ai_runner.py`)

Runs as a separate background job against the portal budget dataset:

```
Budget JSON (portal/budgets.json)
        │
        ▼
   Variance Analysis     per-initiative deviation from mean spend
   Outlier Detection     z-score flagging on amount column
   Quarter-over-Quarter  period comparison for Opex growth
        │
        ▼
   LLM Narrative         top anomalies serialised to JSON → Ollama prompt
                         explains each anomaly with business context
        │
        ▼
   Plotly Visualisation  bar charts, trend lines rendered in Streamlit
```

---

### 3. Architecture Report RAG Pipeline (`src/llm/rag/pipeline.py`)

Classic Retrieval-Augmented Generation over uploaded Excel assessments:

```
Excel Upload (.xlsx)
        │
        ▼
   Parser              auto-detects columns by keyword matching
                       (technology, finding, control, severity, owner, etc.)
                       supports multi-sheet workbooks
        │
        ▼
   Internet Enrichment (opt-in)
        │               DuckDuckGo queries per detected technology
        │               results stored in ChromaDB vector store
        ▼
   Retrieval           ChromaDB similarity search
                       embeddings: SHA-256 hash embeddings (deterministic,
                       no model required) or nomic-embed-text via Ollama
        │
        ▼
   LLM Generation      Ollama (llama3.2:3b) or Gemini narrative
                       prompt includes: assessment summary, enriched context,
                       retrieved KB context, controls inventory
        │
        ▼
   Report              8-section structured output:
                       Executive Summary · Key Findings · Architecture Risks
                       Recommended Controls · Remediation Roadmap (30/60/90d)
                       CVE Notes · Control Coverage Review · Validation Checklist
        │
        ▼
   Export              .md download, .docx (python-docx), history JSON metadata
```

---

### 4. Model Selection & GPU Acceleration

The portal supports **Ollama (local)** and **Gemini (cloud)** as narrative providers. Provider is selectable per-run from the Analysis Settings panel.

#### Ollama (local inference)

| Setting | Value | Purpose |
|---|---|---|
| `base_url` | `http://ollama:11434` | Docker-internal endpoint |
| `model` | selectable from live `/api/tags` | shows only pulled models |
| `temperature` | `0.3` | low randomness for factual analysis |
| `num_ctx` | `4096` | context window |
| `timeout` | `None` (disabled) | prevents cutoff on large datasets |
| `num_gpu` | `-1` (all layers) | auto-offload to GPU when available |

**GPU auto-detection sequence:**

```python
# 1. nvidia-smi present and exit code 0  → "cuda"
# 2. rocm-smi present and exit code 0   → "rocm"
# 3. platform.system() == "Darwin"      → "metal" (Apple Silicon)
# 4. fallback                           → "cpu"
```

When GPU is detected, `num_gpu=-1` offloads all model layers to the accelerator, dramatically reducing generation time on large contexts.

#### Recommended models

| Model | Size | Use case |
|---|---|---|
| `llama3.2:3b` | ~2 GB | Default — fast, low VRAM, good for summaries |
| `llama3.1:8b` | ~5 GB | Better reasoning for complex budget/threat correlation |
| `mistral:7b` | ~4 GB | Strong instruction-following for structured reports |
| `gemma3:4b` | ~3 GB | Efficient alternative with good analytical output |

Pull any model:
```bash
docker exec -it ollama ollama pull llama3.1:8b
```
The model selector in the UI will automatically show the newly pulled model.

#### Gemini (cloud)

| Setting | Value |
|---|---|
| `model` | `gemini-2.5-flash-lite` |
| `temperature` | `0.3` |
| `api_key` | `GEMINI_API_KEY` env var |

Gemini is the cloud fallback when Ollama is unavailable or for faster generation without local GPU hardware.

---

## Portal Navigation

```
Dashboard Showcase          KPI overview · budget charts · quick nav
│
├── Governance
│   ├── Asset Inventory     security tools, seats, renewal dates, annual spend
│   ├── Budget Management   Opex/Capex by domain, quarter, approval pipeline
│   ├── Budget Analytics    AI anomaly detection + Ollama/Gemini narrative
│   ├── Public Exposure     subdomains, IPs, certificate validity
│   ├── WAF Sites           web application firewall site inventory
│   ├── Generate Report     Excel → RAG → architecture report
│   └── Report History      browse/download past reports
│
├── Infrastructure Management
│   ├── Background Jobs     async report queue
│   └── Knowledge Base      ChromaDB vector store search
│
├── Monitoring Operation
│   ├── SOC Analytics       ML pipeline + MITRE coverage + budget correlation
│   └── Public Exposure     internet-facing asset monitoring
│
├── Configuration
│   └── User Management     local users, SAML, WebAuthn passkeys, RBAC
│
└── Copilot                 AI-assisted report generation with enrichment
```

---

## Tech Stack

| Layer | Technology | Detail |
|---|---|---|
| UI | Streamlit | dark-themed, sidebar navigation |
| Local LLM | Ollama | `llama3.2:3b` default, GPU auto-detected |
| Cloud LLM | Google Gemini | `gemini-2.5-flash-lite`, opt-in |
| LLM framework | LangChain | `langchain-ollama`, `langchain-google-genai` |
| ML / data | pandas + NumPy | statistical analysis, anomaly detection |
| Visualisation | Plotly | interactive charts, heatmaps, dual-axis bars |
| Vector store | ChromaDB | persistent, similarity search for RAG |
| Embeddings | SHA-256 hash (default) | deterministic, no model download |
| Threat data | Elasticsearch 8.x | `security-jira-soc-tickets` index (170k+ docs) |
| Word export | python-docx | `.docx` report download |
| Auth | bcrypt + WebAuthn | local users, SAML mapping, passkeys |
| Containerisation | Docker Compose | part of `security-lab` stack |

---

## Folder Structure

```text
security-architecture-report-generator/
├── app.py                        # Streamlit entrypoint + all page routing
├── run_example.py                # CLI runner for end-to-end demo
├── requirements.txt
├── Dockerfile
├── data/
│   ├── chroma/                   # ChromaDB vector store (auto-created)
│   ├── reports/                  # Historical report files (.md + .json)
│   ├── jobs/                     # Background job queue (.json + .xlsx)
│   └── portal/                   # assets.json, budgets.json, users, auth config
├── examples/
│   ├── sample_assessment.xlsx
│   └── generated_report.md
└── src/
    ├── analytics/
    │   ├── appsec/soc.py         # SOC dashboard UI + budget correlation charts
    │   └── budget/engine.py      # Budget AI analytics engine
    ├── jobs/
    │   ├── soc_analytics_runner.py   # Background ML + LLM SOC pipeline
    │   └── budget_ai_runner.py       # Background budget anomaly runner
    ├── data/
    │   ├── portal_store.py       # assets, budgets, budget policies CRUD
    │   └── soc_analytics_store.py    # SOC analytics JSON cache
    ├── llm/rag/pipeline.py       # RAG report generation
    ├── auth/                     # Local user, SAML, WebAuthn passkey facades
    ├── core/
    │   ├── config.py             # All env var bindings (Pydantic Settings)
    │   └── security.py           # Prompt sanitisation, file validation
    └── export/                   # Markdown → .docx converter
```

---

## Quick Start (local)

```powershell
cd security-architecture-report-generator
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env

# Start Ollama and pull a model
ollama pull llama3.2:3b

streamlit run app.py
```

Open `http://localhost:8501`.

---

## Run with Docker (security-lab stack)

```powershell
# From the security-lab folder
docker compose up -d --build security-architecture-report-generator

# First-time: pull a model into the Ollama container
docker exec -it ollama ollama pull llama3.2:3b
```

Rebuild after code changes:

```powershell
docker rm -f security-architecture-report-generator
docker compose up -d --build security-architecture-report-generator
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://ollama:11434` | Ollama API endpoint (Docker: `ollama` hostname) |
| `OLLAMA_LLM_MODEL` | `llama3.2:3b` | Default LLM model (overridable per-run in UI) |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text` | Embedding model when `USE_FAKE_EMBEDDINGS=0` |
| `OLLAMA_TIMEOUT_SECONDS` | `5000` | Per-request timeout (SOC runner disables this entirely) |
| `GEMINI_API_KEY` | _(unset)_ | Google Gemini API key for cloud narrative |
| `GEMINI_MODEL` | `gemini-2.5-flash-lite` | Gemini model name |
| `ELASTICSEARCH_URL` | `http://elasticsearch:9200` | ES endpoint for SOC tickets and exposure data |
| `MAX_UPLOAD_MB` | `10` | Maximum Excel upload size |
| `CHROMA_PERSIST_DIR` | `./data/chroma` | ChromaDB storage path |
| `REPORT_HISTORY_DIR` | `./data/reports` | Historical report storage |
| `PORTAL_DATA_DIR` | `./data/portal` | Portal datasets (assets, budgets, auth) |
| `AUTH_BOOTSTRAP_ADMIN_USER` | `admin` | Initial admin username |
| `AUTH_BOOTSTRAP_ADMIN_PASSWORD` | `admin123` | Initial admin password |
| `AUTH_SESSION_TIMEOUT_MINUTES` | `480` | Session validity |
| `AUTH_PASSKEY_RP_ID` | `localhost` | WebAuthn relying-party ID |
| `AUTH_PASSKEY_ORIGIN` | `http://localhost:8501` | Full browser origin for passkey ceremonies |
| `AUTH_PASSKEY_RP_NAME` | `Security Architecture Portal` | Passkey display name |
| `JOB_QUEUE_DIR` | `./data/jobs` | Background job storage |
| `JOB_MAX_RUNTIME_SECONDS` | `900` | Max job runtime before auto-fail |
| `ENRICHMENT_RESULTS_PER_TECH` | `4` | DuckDuckGo results per technology |
| `ENABLE_INTERNET_ENRICHMENT` | `0` | Enable internet enrichment by default |
| `USE_FAKE_EMBEDDINGS` | `1` | SHA-256 hash embeddings (no model needed) |
| `ENABLE_DEMO_REPORT_FALLBACK` | `1` | Structured fallback if LLM unreachable |

---

## Offline Operation

All AI/ML features are designed to work without internet access:

- `USE_FAKE_EMBEDDINGS=1` — deterministic SHA-256 embeddings, no model download required.
- `ENABLE_INTERNET_ENRICHMENT=0` — no DuckDuckGo queries.
- `ENABLE_DEMO_REPORT_FALLBACK=1` — structured template report when Ollama is unreachable.
- SOC analytics, budget correlation, and anomaly detection are all pure pandas/NumPy — no network needed.
- The Ollama container runs on the same `security-lab_default` Docker network as the app.

---

## Security Controls

- Strict `.xlsx`-only file type validation with MIME and extension checks.
- Upload size enforcement (`MAX_UPLOAD_MB`).
- Prompt input sanitisation: control-character stripping, markdown code-fence neutralisation, length capping.
- LLM instruction-hierarchy hardening: uploaded data is treated as untrusted evidence; embedded prompt-injection instructions are explicitly ignored.
- All credentials via environment variables — no secrets in source code.
- WebAuthn passkey support for phishing-resistant authentication.

---

## Passkey Notes

- Passkeys use WebAuthn — browser, OS, hardware security keys, or compatible passkey managers.
- `AUTH_PASSKEY_ORIGIN` must match the exact URL users open in the browser (scheme + hostname + port).
- `AUTH_PASSKEY_RP_ID` must match the hostname portion of that origin.
- For production behind a reverse proxy, set both to the public HTTPS hostname.
