from __future__ import annotations

import json
import threading
import time
import traceback
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..core.config import CONFIG
from ..llm.enrichment.search import enrich_with_duckduckgo
from ..app.report_processing import build_assessment_context, parse_excel
from ..llm.rag.pipeline import generate_report, retrieve_context, upsert_enrichment
from ..data.report_store import save_report


def _utc_now() -> str:
	return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _parse_utc(value: str) -> datetime | None:
	try:
		return datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=UTC)
	except Exception:
		return None


def _queue_dir() -> Path:
	root = Path(CONFIG.job_queue_dir)
	root.mkdir(parents=True, exist_ok=True)
	return root


def _sanitize_source(source_name: str) -> str:
	return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in source_name)[:80] or "report"


def _job_meta_path(job_id: str) -> Path:
	return _queue_dir() / f"{job_id}.json"


def _job_input_path(job_id: str) -> Path:
	return _queue_dir() / f"{job_id}.xlsx"


def submit_job(
	file_bytes: bytes,
	source_name: str,
	max_retrieval_docs: int,
	internet_enrichment_enabled: bool,
) -> dict[str, Any]:
	job_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}_{_sanitize_source(source_name)}_{uuid4().hex[:8]}"
	payload = {
		"id": job_id,
		"status": "queued",
		"source_name": source_name,
		"created_at_utc": _utc_now(),
		"updated_at_utc": _utc_now(),
		"max_retrieval_docs": int(max_retrieval_docs),
		"internet_enrichment_enabled": bool(internet_enrichment_enabled),
		"error": "",
		"report_id": "",
		"report_markdown_path": "",
	}

	_job_input_path(job_id).write_bytes(file_bytes)
	_job_meta_path(job_id).write_text(json.dumps(payload, indent=2), encoding="utf-8")
	return payload


def _load_meta(path: Path) -> dict[str, Any] | None:
	try:
		return json.loads(path.read_text(encoding="utf-8"))
	except Exception:
		return None


def list_jobs(limit: int = 200) -> list[dict[str, Any]]:
	rows: list[dict[str, Any]] = []
	for meta_path in sorted(_queue_dir().glob("*.json"), reverse=True):
		data = _load_meta(meta_path)
		if not data:
			continue
		rows.append(data)
		if len(rows) >= limit:
			break
	return rows


def load_job(job_id: str) -> dict[str, Any] | None:
	return _load_meta(_job_meta_path(job_id))


def load_job_report(job: dict[str, Any]) -> str:
	md_path = str(job.get("report_markdown_path", "")).strip()
	if not md_path:
		return ""
	path = Path(md_path)
	if not path.exists():
		return ""
	return path.read_text(encoding="utf-8")


def request_stop_job(job_id: str) -> dict[str, Any] | None:
	job = load_job(job_id)
	if not job:
		return None

	status = str(job.get("status", "")).lower()
	if status in {"completed", "failed", "canceled"}:
		return job

	if status == "queued":
		job["status"] = "canceled"
		job["updated_at_utc"] = _utc_now()
		job["canceled_at_utc"] = _utc_now()
		job["error"] = "Canceled by user before execution"
		_job_meta_path(job_id).write_text(json.dumps(job, indent=2), encoding="utf-8")
		return job

	job["status"] = "cancel_requested"
	job["updated_at_utc"] = _utc_now()
	job["cancel_requested_at_utc"] = _utc_now()
	job["error"] = "Stop requested by user"
	_job_meta_path(job_id).write_text(json.dumps(job, indent=2), encoding="utf-8")
	return job


class BackgroundJobWorker:
	def __init__(self, vector_store):
		self.vector_store = vector_store
		self._thread: threading.Thread | None = None
		self._stop_event = threading.Event()

	def start(self) -> None:
		if self._thread and self._thread.is_alive():
			return
		self._thread = threading.Thread(target=self._run_loop, name="report-job-worker", daemon=True)
		self._thread.start()

	def stop(self) -> None:
		self._stop_event.set()

	def _run_loop(self) -> None:
		while not self._stop_event.is_set():
			try:
				if not self._run_one_job():
					time.sleep(max(CONFIG.job_poll_interval_seconds, 0.5))
			except Exception:
				time.sleep(max(CONFIG.job_poll_interval_seconds, 0.5))

	def _run_one_job(self) -> bool:
		self._mark_stale_running_jobs()
		queued_jobs = [j for j in list_jobs(limit=500) if j.get("status") == "queued"]
		if not queued_jobs:
			return False

		job = queued_jobs[0]
		job_id = str(job["id"])
		job["status"] = "running"
		job["started_at_utc"] = _utc_now()
		job["updated_at_utc"] = _utc_now()
		_job_meta_path(job_id).write_text(json.dumps(job, indent=2), encoding="utf-8")

		if self._is_cancel_requested(job_id):
			self._mark_job_canceled(job_id, "Canceled before parsing")
			return True

		try:
			file_bytes = _job_input_path(job_id).read_bytes()
			input_file = BytesIO(file_bytes)
			input_file.name = str(job.get("source_name", "uploaded.xlsx"))

			sheets = parse_excel(input_file)
			assessment = build_assessment_context(sheets)

			if self._is_cancel_requested(job_id):
				self._mark_job_canceled(job_id, "Canceled after parsing")
				return True

			enriched_docs = []
			if bool(job.get("internet_enrichment_enabled", False)):
				enriched_docs = enrich_with_duckduckgo(
					assessment.technologies,
					max_results=CONFIG.enrichment_results_per_tech,
				)

			if self._is_cancel_requested(job_id):
				self._mark_job_canceled(job_id, "Canceled during enrichment")
				return True

			if enriched_docs:
				upsert_enrichment(self.vector_store, [d.as_text() for d in enriched_docs], source="duckduckgo")

			retrieval_query = " ".join(assessment.technologies[:20]) or assessment.summary_text
			kb_context = retrieve_context(self.vector_store, retrieval_query, k=int(job.get("max_retrieval_docs", 8)))

			if self._is_cancel_requested(job_id):
				self._mark_job_canceled(job_id, "Canceled before report generation")
				return True

			report = generate_report(
				excel_summary=assessment.summary_text,
				enriched_context=kb_context,
				controls_context=assessment.controls_text,
			)

			if self._is_cancel_requested(job_id):
				self._mark_job_canceled(job_id, "Canceled while generating report")
				return True

			report_meta = save_report(report, source_name=str(job.get("source_name", "uploaded.xlsx")))

			job["status"] = "completed"
			job["updated_at_utc"] = _utc_now()
			job["completed_at_utc"] = _utc_now()
			job["report_id"] = report_meta["id"]
			job["report_markdown_path"] = str(Path(CONFIG.report_history_dir) / report_meta["markdown_file"])
			job["stats"] = {
				"technologies": len(assessment.technologies),
				"findings": len(assessment.findings),
				"controls": len(assessment.controls),
				"sheets": len(sheets),
				"enrichment_docs": len(enriched_docs),
			}
			_job_meta_path(job_id).write_text(json.dumps(job, indent=2), encoding="utf-8")
			return True
		except Exception as ex:
			job["status"] = "failed"
			job["updated_at_utc"] = _utc_now()
			job["failed_at_utc"] = _utc_now()
			job["error"] = f"{type(ex).__name__}: {ex}"
			job["traceback"] = traceback.format_exc(limit=25)
			_job_meta_path(job_id).write_text(json.dumps(job, indent=2), encoding="utf-8")
			return True

	def _is_cancel_requested(self, job_id: str) -> bool:
		job = load_job(job_id)
		if not job:
			return False
		return str(job.get("status", "")).lower() in {"cancel_requested", "canceled"}

	def _mark_job_canceled(self, job_id: str, message: str) -> None:
		job = load_job(job_id)
		if not job:
			return
		job["status"] = "canceled"
		job["updated_at_utc"] = _utc_now()
		job["canceled_at_utc"] = _utc_now()
		job["error"] = message
		_job_meta_path(job_id).write_text(json.dumps(job, indent=2), encoding="utf-8")

	def _mark_stale_running_jobs(self) -> None:
		now = datetime.now(UTC)
		for job in list_jobs(limit=500):
			if job.get("status") != "running":
				continue

			started_at = _parse_utc(str(job.get("started_at_utc", "")))
			if not started_at:
				continue

			elapsed = (now - started_at).total_seconds()
			if elapsed <= CONFIG.job_max_runtime_seconds:
				continue

			job["status"] = "failed"
			job["updated_at_utc"] = _utc_now()
			job["failed_at_utc"] = _utc_now()
			job["error"] = (
				f"TimeoutError: job exceeded max runtime of {CONFIG.job_max_runtime_seconds} seconds"
			)
			_job_meta_path(str(job["id"])).write_text(json.dumps(job, indent=2), encoding="utf-8")

