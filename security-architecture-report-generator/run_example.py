from __future__ import annotations

from io import BytesIO
from pathlib import Path

from src.app.example_data import build_example_workbook_bytes
from src.app.report_processing import build_assessment_context, parse_excel
from src.llm.enrichment.search import enrich_with_duckduckgo
from src.llm.rag.pipeline import generate_report, init_vector_store, retrieve_context, upsert_enrichment


def main() -> None:
    root = Path(__file__).resolve().parent
    examples_dir = root / "examples"
    examples_dir.mkdir(parents=True, exist_ok=True)

    sample_bytes = build_example_workbook_bytes()
    sample_path = examples_dir / "sample_assessment.xlsx"
    sample_path.write_bytes(sample_bytes)

    sheets = parse_excel(BytesIO(sample_bytes))
    assessment = build_assessment_context(sheets)

    enriched_docs = enrich_with_duckduckgo(assessment.technologies, max_results=3)

    store = init_vector_store()
    if enriched_docs:
        upsert_enrichment(store, [d.as_text() for d in enriched_docs], source="duckduckgo")

    query = " ".join(assessment.technologies) or assessment.summary_text
    kb_context = retrieve_context(store, query, k=8)

    report = generate_report(assessment.summary_text, kb_context)
    report_path = examples_dir / "generated_report.md"
    report_path.write_text(report, encoding="utf-8")

    print("Example run completed.")
    print(f"Sample workbook: {sample_path}")
    print(f"Generated report: {report_path}")
    print(f"Technologies found: {len(assessment.technologies)}")
    print(f"Findings found: {len(assessment.findings)}")
    print(f"Enrichment docs: {len(enriched_docs)}")
    print(f"KB context docs: {len(kb_context)}")


if __name__ == "__main__":
    main()
