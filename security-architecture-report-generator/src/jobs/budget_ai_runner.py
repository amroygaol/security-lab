from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import pandas as pd

from ..analytics.budget.engine import BudgetAnalyticsResult, run_budget_ai_analytics


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class BudgetAIBackgroundRunner:
    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="budget-ai")
        self._lock = threading.Lock()
        self._future: Future | None = None
        self._cancel_requested = False
        self._latest_result: BudgetAnalyticsResult | None = None
        self._state: dict[str, Any] = {
            "status": "idle",
            "stage": "idle",
            "message": "No analysis has been started.",
            "progress": 0.0,
            "error": "",
            "started_at_utc": "",
            "updated_at_utc": _utc_now_iso(),
            "completed_at_utc": "",
            "log": [],
        }

    def get_state(self) -> dict[str, Any]:
        with self._lock:
            state_copy = dict(self._state)
            state_copy["log"] = list(self._state.get("log", []))
            return state_copy

    def get_latest_result(self) -> BudgetAnalyticsResult | None:
        with self._lock:
            return self._latest_result

    def is_running(self) -> bool:
        with self._lock:
            return bool(self._future and not self._future.done())

    def request_stop(self) -> bool:
        with self._lock:
            if not self._future or self._future.done():
                return False
            self._cancel_requested = True
            self._state["message"] = "Cancellation requested. Waiting for safe checkpoint..."
            self._state["updated_at_utc"] = _utc_now_iso()
            log = list(self._state.get("log", []))
            log.append("[cancel] Stop requested by user")
            self._state["log"] = log[-60:]
            return True

    def start(self, budgets_df: pd.DataFrame, policy_docs: list[str]) -> bool:
        with self._lock:
            if self._future and not self._future.done():
                return False
            self._cancel_requested = False
            self._state = {
                "status": "running",
                "stage": "init",
                "message": "Initializing AI analytics pipeline",
                "progress": 0.01,
                "error": "",
                "started_at_utc": _utc_now_iso(),
                "updated_at_utc": _utc_now_iso(),
                "completed_at_utc": "",
                "log": ["[1%] Initializing AI analytics pipeline"],
            }

            df_copy = budgets_df.copy(deep=True)
            policy_copy = [str(text).strip() for text in policy_docs if str(text).strip()]
            self._future = self._executor.submit(self._run_job, df_copy, policy_copy)
            return True

    def _run_job(self, budgets_df: pd.DataFrame, policy_docs: list[str]) -> None:
        def progress_callback(stage: str, message: str, progress: float) -> None:
            pct = int(max(0.0, min(1.0, float(progress))) * 100)
            with self._lock:
                self._state["stage"] = stage
                self._state["message"] = message
                self._state["progress"] = max(0.0, min(1.0, float(progress)))
                self._state["updated_at_utc"] = _utc_now_iso()
                log = list(self._state.get("log", []))
                log.append(f"[{pct}%] {message}")
                self._state["log"] = log[-120:]

        def cancel_checker() -> bool:
            with self._lock:
                return bool(self._cancel_requested)

        try:
            result = run_budget_ai_analytics(
                budgets_df,
                policy_docs=policy_docs,
                progress_callback=progress_callback,
                cancel_checker=cancel_checker,
            )
            with self._lock:
                self._latest_result = result
                self._state["status"] = "completed"
                self._state["stage"] = "complete"
                self._state["message"] = "AI analytics completed successfully"
                self._state["progress"] = 1.0
                self._state["updated_at_utc"] = _utc_now_iso()
                self._state["completed_at_utc"] = _utc_now_iso()
        except Exception as exc:
            with self._lock:
                canceled = self._cancel_requested
                self._state["status"] = "canceled" if canceled else "failed"
                self._state["stage"] = "canceled" if canceled else "failed"
                self._state["message"] = "AI analytics canceled" if canceled else "AI analytics failed"
                self._state["error"] = "" if canceled else f"{type(exc).__name__}: {exc}"
                self._state["updated_at_utc"] = _utc_now_iso()
                self._state["completed_at_utc"] = _utc_now_iso()



