from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pandas as pd

from ..core.security import sanitize_for_llm


_TECH_COL_HINTS = ("technology", "component", "platform", "stack", "application", "service")
_FINDING_COL_HINTS = (
	"finding",
	"issue",
	"gap",
	"risk",
	"severity",
	"status",
	"recommendation",
)
_CONTROL_DOMAIN_HINTS = ("control domain", "domain")
_CONTROL_OBJ_HINTS = ("control objective", "objective")
_CONTROL_REQ_HINTS = ("control requirement", "requirements", "requirement")
_CONTROL_EVIDENCE_HINTS = ("evidence", "artifact")
_CONTROL_RESPONSE_HINTS = ("response", "status", "state", "maturity")


@dataclass
class AssessmentContext:
	technologies: list[str]
	findings: list[dict[str, Any]]
	controls: list[dict[str, Any]]
	controls_text: str
	summary_text: str


def parse_excel(uploaded_file) -> dict[str, pd.DataFrame]:
	xls = pd.ExcelFile(uploaded_file)
	return {sheet: xls.parse(sheet).fillna("") for sheet in xls.sheet_names}


def _pick_columns(columns: list[str], hints: tuple[str, ...]) -> list[str]:
	selected: list[str] = []
	for col in columns:
		low = col.lower()
		if any(h in low for h in hints):
			selected.append(col)
	return selected


def _is_control_sheet(columns: list[str]) -> bool:
	low = [c.lower() for c in columns]
	has_domain = any(any(h in col for h in _CONTROL_DOMAIN_HINTS) for col in low)
	has_obj_or_req = any(any(h in col for h in _CONTROL_OBJ_HINTS + _CONTROL_REQ_HINTS) for col in low)
	return has_domain and has_obj_or_req


def _extract_controls(df: pd.DataFrame, sheet_name: str) -> list[dict[str, Any]]:
	columns = [str(c) for c in df.columns]
	low = [c.lower() for c in columns]

	def _first_col(hints: tuple[str, ...]) -> str | None:
		for i, col in enumerate(low):
			if any(h in col for h in hints):
				return columns[i]
		return None

	domain_col = _first_col(_CONTROL_DOMAIN_HINTS)
	obj_col = _first_col(_CONTROL_OBJ_HINTS)
	req_col = _first_col(_CONTROL_REQ_HINTS)
	evid_col = _first_col(_CONTROL_EVIDENCE_HINTS)
	resp_col = _first_col(_CONTROL_RESPONSE_HINTS)

	controls: list[dict[str, Any]] = []
	for _, row in df.iterrows():
		domain = sanitize_for_llm(str(row.get(domain_col, "")).strip()) if domain_col else ""
		if not domain:
			continue
		controls.append(
			{
				"sheet": sheet_name,
				"domain": domain,
				"objective": sanitize_for_llm(str(row.get(obj_col, "")).strip()) if obj_col else "",
				"requirements": sanitize_for_llm(str(row.get(req_col, "")).strip()) if req_col else "",
				"evidence": sanitize_for_llm(str(row.get(evid_col, "")).strip()) if evid_col else "",
				"response": sanitize_for_llm(str(row.get(resp_col, "")).strip()) if resp_col else "",
			}
		)
	return controls


def _build_controls_text(controls: list[dict[str, Any]]) -> str:
	if not controls:
		return "No structured control inventory provided."
	lines = [f"Total controls in inventory: {len(controls)}\\n"]
	for ctrl in controls:
		lines.append(f"Domain: {ctrl['domain']}")
		if ctrl["objective"]:
			lines.append(f"  Objective: {ctrl['objective']}")
		if ctrl["requirements"]:
			req = ctrl["requirements"].replace("\\n", " ").replace("\\\\n", " ")[:400]
			lines.append(f"  Requirements: {req}")
		if ctrl["evidence"]:
			lines.append(f"  Expected Evidence: {ctrl['evidence']}")
		if ctrl["response"]:
			lines.append(f"  Status/Response: {ctrl['response']}")
		lines.append("")
	return "\\n".join(lines)


def build_assessment_context(sheets: dict[str, pd.DataFrame]) -> AssessmentContext:
	technologies: set[str] = set()
	findings: list[dict[str, Any]] = []
	controls: list[dict[str, Any]] = []

	for sheet_name, df in sheets.items():
		if df.empty:
			continue

		columns = [str(c) for c in df.columns]
		if _is_control_sheet(columns):
			controls.extend(_extract_controls(df, sheet_name))
			continue

		tech_cols = _pick_columns(columns, _TECH_COL_HINTS)
		finding_cols = _pick_columns(columns, _FINDING_COL_HINTS)

		for _, row in df.iterrows():
			for tc in tech_cols:
				val = str(row.get(tc, "")).strip()
				if val:
					technologies.add(val)

			finding_record = {"sheet": sheet_name}
			for fc in finding_cols:
				finding_record[fc] = str(row.get(fc, "")).strip()
			if len(finding_record) > 1:
				findings.append(finding_record)

	tech_list = sorted({sanitize_for_llm(t) for t in technologies if t})[:50]
	finding_preview = findings[:150]
	controls_preview = controls[:100]
	controls_text = _build_controls_text(controls_preview)

	summary_chunks = [
		f"Technologies identified: {', '.join(tech_list) if tech_list else 'None'}",
		"Findings:",
	]
	for item in finding_preview:
		parts = [f"{k}={sanitize_for_llm(v)}" for k, v in item.items() if str(v).strip()]
		summary_chunks.append("; ".join(parts))

	summary_text = "\\n".join(summary_chunks)

	return AssessmentContext(
		technologies=tech_list,
		findings=finding_preview,
		controls=controls_preview,
		controls_text=controls_text,
		summary_text=summary_text,
	)
