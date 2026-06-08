# Source Layout

This directory is organized by domain to reduce coupling and navigation overhead.

## Folders

- app
  - Page orchestration helpers and input processing used by Streamlit pages.
- auth
  - User authentication, authorization, and passkey authentication services.
- analytics
  - Domain analytics engines and AI orchestration logic.
- jobs
  - Background workers and async job runners.
- data
  - Data persistence adapters and file-backed stores.
- llm
  - LLM and retrieval-related pipelines, enrichment, and embeddings.
- ui
  - Streamlit custom components and UI integration helpers.
- core
  - Shared config and security utilities.
- export
  - Output formatters and report exporters.

## Compatibility Note

Legacy flat modules under src are still present and operational. New modules in this structure currently bridge to existing implementations so migration can happen incrementally without breaking runtime behavior.

When adding new features, prefer imports from the new domain folders.
