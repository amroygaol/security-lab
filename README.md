# Security Lab

A security monitoring and analytics platform that aggregates data from multiple security tools into a unified observability stack using Prometheus, Elasticsearch, and Grafana.

## Architecture

```
┌──────────────────────┐     ┌────────────┐     ┌─────────┐
│  Security Tools APIs │────▶│  Exporter  │────▶│ Elastic │
│  (DigiCert, Rapid7,  │     │  (Python)  │     │ Search  │
│   Cortex, DefectDojo │     │  :9105     │     │  :9200  │
│   Subdomain/IP scan) │     └─────┬──────┘     └────┬────┘
└──────────────────────┘           │                  │
                            ┌──────▼──────┐     ┌────▼────┐
                            │ Prometheus  │     │ Kibana  │
                            │   :9090     │     │  :5601  │
                            └──────┬──────┘     └─────────┘
                            ┌──────▼──────┐
                            │  Grafana    │
                            │   :3000     │
                            └─────────────┘
```

## Stack

| Layer | Technology |
|---|---|
| Data Collection | Python 3.11, requests, ThreadPoolExecutor |
| Metrics | Prometheus client library (Gauge metrics) |
| Storage | Prometheus (metrics), Elasticsearch 8.13.4 (documents) |
| Visualization | Grafana, Kibana |
| Orchestration | Docker Compose |
| AI (Experimental) | Ollama (local LLMs), Qdrant (vector DB) |

## Collectors

The exporter runs on a **15-minute cycle** and collects data from these security tools:

| Collector | Purpose |
|---|---|
| `Net_subdomain_exporter` | DNS enumeration from public sources |
| `Net_ip_exposure_exporter` | Resolve IPs from subdomains, Shodan enrichment |
| `Net_digicert_exporter` | SSL certificate inventory and expiry tracking |
| `GRC_rapid7_exporter` | Vulnerability management (assets, vulns by severity) |
| `EP_cortex_exporter` | Endpoint detection & response (Palo Alto Cortex XDR) |
| `App_defectdojo_exporter` | Application security findings and SLA tracking |

Additional collectors available (disabled by default): EntraID, Intune, Panorama, BMC CMDB, Imperva, Apigee, Webmethods, IBM Maximo.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- API credentials for the security tools you want to collect from

### Run

```bash
# Create .env file with your API credentials
cp .env.example .env

# Start all services
docker-compose up -d
```

### Access

| Service | URL |
|---|---|
| Grafana | http://localhost:3000 (admin/admin) |
| Prometheus | http://localhost:9090 |
| Elasticsearch | http://localhost:9200 |
| Kibana | http://localhost:5601 |

## Project Structure

```
security-lab/
├── docker-compose.yml          # Service orchestration
├── exporters/
│   └── security-tools-exporter/
│       ├── exporter.py         # Main orchestrator (15-min cycle)
│       ├── es_store.py         # Elasticsearch indexing
│       ├── collectors/         # Modular security tool collectors
│       └── Dockerfile
├── prometheus/
│   └── prometheus.yml          # Scrape config
├── alertmanager/
│   └── alertmanager.yml        # Alert routing (placeholder)
├── grafana/
│   └── provisioning/           # Auto-provisioned datasources
├── scripts/
│   └── backfill_es.py          # Historical data import
├── ai/
│   └── test_ai_prometheus.py   # LLM-powered security analysis (experimental)
└── data/                       # Snapshot storage for subdomains & IP exposure
```

## Environment Variables

The exporter requires API credentials set as environment variables. See `docker-compose.yml` for the full list. Key variables include:

- `DIGICERT_API_KEY` — DigiCert CertCentral API key
- `RAPID7_API_KEY`, `RAPID7_BASE_URL` — Rapid7 InsightVM credentials
- `CORTEX_API_KEY`, `CORTEX_BASE_URL` — Palo Alto Cortex XDR credentials
- `DEFECTDOJO_API_KEY`, `DEFECTDOJO_BASE_URL` — DefectDojo credentials
- `SHODAN_API_KEY` — Shodan API key for IP enrichment
- `ES_HOST` — Elasticsearch host (default: `http://elasticsearch:9200`)
