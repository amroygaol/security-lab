import json
import logging
import os
import re
from datetime import datetime, timedelta

import requests
from prometheus_client import Gauge

from es_store import store_soc_jira_tickets

# Prometheus metrics
soc_jira_tickets_total = Gauge(
    "soc_jira_tickets_total",
    "Total number of SOC Jira tickets collected in this cycle",
)

soc_jira_tickets_last_collection_success = Gauge(
    "soc_jira_tickets_last_collection_success",
    "1 when latest SOC Jira collection succeeded, otherwise 0",
)

# State file to track last collection timestamp
_STATE_DIR = os.getenv("JIRA_STATE_DIR", "/data")
_STATE_FILE = os.path.join(_STATE_DIR, "soc_jira_last_collection.json")

_FIELD_PATTERNS = {
    "detection_id": re.compile(r"^\s*Detection\s*ID\s*:\s*(.*)$", re.IGNORECASE),
    "start_time": re.compile(r"^\s*Start\s*Time\s*:\s*(.*)$", re.IGNORECASE),
    "alert_name": re.compile(r"^\s*Alert\s*Name\s*:\s*(.*)$", re.IGNORECASE),
    "risk_score": re.compile(r"^\s*Risk\s*Score\s*:\s*(.*)$", re.IGNORECASE),
    "severity": re.compile(r"^\s*Severity\s*:\s*(.*)$", re.IGNORECASE),
    "taktik": re.compile(r"^\s*Taktik\s*:\s*(.*)$", re.IGNORECASE),
    "teknik": re.compile(r"^\s*Teknik\s*:\s*(.*)$", re.IGNORECASE),
}


def _load_last_collection_time():
    if os.path.isfile(_STATE_FILE):
        try:
            with open(_STATE_FILE, "r", encoding="utf-8") as handle:
                data = json.load(handle)
                return data.get("last_collection_time")
        except Exception as exc:
            logging.warning("SOC Jira collector: could not read state file: %s", exc)
    return None


def _save_collection_time(timestamp):
    os.makedirs(os.path.dirname(_STATE_FILE) if os.path.dirname(_STATE_FILE) else ".", exist_ok=True)
    try:
        with open(_STATE_FILE, "w", encoding="utf-8") as handle:
            json.dump({"last_collection_time": timestamp}, handle)
    except Exception as exc:
        logging.warning("SOC Jira collector: could not write state file: %s", exc)


def _flatten_description(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = [_flatten_description(item) for item in value]
        return "\n".join(part for part in parts if part)
    if isinstance(value, dict):
        parts = []
        text = value.get("text")
        if isinstance(text, str) and text.strip():
            parts.append(text.strip())
        for key in ("content", "paragraph", "items"):
            nested = value.get(key)
            if nested is not None:
                nested_text = _flatten_description(nested)
                if nested_text:
                    parts.append(nested_text)
        return "\n".join(part for part in parts if part)
    return str(value)


def _extract_soc_fields(description_text):
    extracted = {
        "detection_id": "",
        "start_time": "",
        "alert_name": "",
        "risk_score": "",
        "severity": "",
        "taktik": "",
        "teknik": "",
    }
    if not description_text:
        return extracted

    for line in description_text.splitlines():
        for field_name, pattern in _FIELD_PATTERNS.items():
            match = pattern.match(line)
            if match:
                extracted[field_name] = (match.group(1) or "").strip()
    return extracted


def _build_day_windows(year: int):
    """Return daily [start, end) windows as Jira date strings for current YTD."""
    now = datetime.now()
    cursor = datetime(year, 1, 1, 0, 0)
    windows = []
    while cursor < now:
        next_cursor = min(cursor + timedelta(days=1), now)
        windows.append((cursor.strftime("%Y/%m/%d %H:%M"), next_cursor.strftime("%Y/%m/%d %H:%M")))
        cursor = next_cursor
    return windows


def collect_soc_jira_tickets():
    jira_url = os.getenv("JIRA_API_URL", "").strip()
    jira_api_key = os.getenv("JIRA_API_KEY", "").strip()
    jira_email = os.getenv("JIRA_EMAIL", "").strip()
    jira_issue_key = os.getenv("JIRA_SOC_ISSUE_KEY", "CIAOT").strip()
    timeout_seconds = int(os.getenv("JIRA_TIMEOUT_SECONDS", "30").strip())

    if not all([jira_url, jira_api_key, jira_email, jira_issue_key]):
        logging.warning("SOC Jira collector: missing required environment variables")
        soc_jira_tickets_last_collection_success.set(0)
        return

    current_year = datetime.now().year
    ytd_start = f"{current_year}-01-01"
    # Always fetch full YTD dataset because ES storage replaces index each cycle.
    # Jira can reject deep pagination in large windows, so split by day.
    windows = _build_day_windows(current_year)
    logging.info("SOC Jira collector: fetching full YTD tickets in %d daily windows", len(windows))

    url = f"{jira_url.rstrip('/')}/rest/api/2/search"
    project_url = f"{jira_url.rstrip('/')}/rest/api/2/project/{jira_issue_key}"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {jira_api_key}",
    }

    try:
        project_resp = requests.get(project_url, headers=headers, timeout=timeout_seconds)
        if project_resp.status_code != 200:
            logging.error(
                "SOC Jira collector: project '%s' not accessible (status=%s). "
                "Check JIRA_SOC_ISSUE_KEY and API token project permissions.",
                jira_issue_key,
                project_resp.status_code,
            )
            soc_jira_tickets_last_collection_success.set(0)
            return

        all_issues = {}
        page_size = int(os.getenv("JIRA_PAGE_SIZE", "200").strip())

        for window_start, window_end in windows:
            start_at = 0
            window_jql = (
                f'project = {jira_issue_key} '
                f'AND created >= "{window_start}" '
                f'AND created < "{window_end}" '
                f'ORDER BY created DESC'
            )

            while True:
                params = {
                    "jql": window_jql,
                    "maxResults": page_size,
                    "startAt": start_at,
                    "fields": "key,summary,description,status,created,updated,reporter,assignee,priority,issuetype,labels",
                }
                response = requests.get(url, headers=headers, params=params, timeout=timeout_seconds)
                response.raise_for_status()

                data = response.json()
                batch = data.get("issues", [])
                for issue in batch:
                    key = issue.get("key")
                    if key:
                        all_issues[key] = issue

                total = int(data.get("total", 0) or 0)
                current_page_size = int(data.get("maxResults", page_size) or page_size)
                if not batch or (start_at + len(batch)) >= total:
                    break

                start_at += current_page_size

            logging.info(
                "SOC Jira collector: window %s -> %s fetched so far: %d",
                window_start,
                window_end,
                len(all_issues),
            )

        issues = list(all_issues.values())
        logging.info("SOC Jira collector: fetched %d unique YTD tickets from Jira", len(issues))
        tickets = []

        for issue in issues:
            raw_description = issue.get("fields", {}).get("description")
            description_text = _flatten_description(raw_description)
            parsed = _extract_soc_fields(description_text)

            ticket = {
                "key": issue.get("key", ""),
                "summary": issue.get("fields", {}).get("summary", ""),
                "description": description_text,
                "status": issue.get("fields", {}).get("status", {}).get("name", ""),
                "created": issue.get("fields", {}).get("created"),
                "updated": issue.get("fields", {}).get("updated"),
                "reporter": issue.get("fields", {}).get("reporter", {}).get("displayName", "") if issue.get("fields", {}).get("reporter") else "",
                "assignee": issue.get("fields", {}).get("assignee", {}).get("displayName", "") if issue.get("fields", {}).get("assignee") else "",
                "priority": issue.get("fields", {}).get("priority", {}).get("name", "") if issue.get("fields", {}).get("priority") else "",
                "issue_type": issue.get("fields", {}).get("issuetype", {}).get("name", ""),
                "labels": issue.get("fields", {}).get("labels", []),
                "detection_id": parsed["detection_id"],
                "start_time": parsed["start_time"],
                "alert_name": parsed["alert_name"],
                "risk_score": parsed["risk_score"],
                "severity": parsed["severity"],
                "taktik": parsed["taktik"],
                "teknik": parsed["teknik"],
            }
            tickets.append(ticket)

        soc_jira_tickets_total.set(len(tickets))
        soc_jira_tickets_last_collection_success.set(1)

        if tickets:
            store_soc_jira_tickets(tickets)
            logging.info("SOC Jira collector: stored %d YTD tickets for project %s", len(tickets), jira_issue_key)
        else:
            logging.info("SOC Jira collector: no YTD tickets found for project %s", jira_issue_key)
    except requests.HTTPError as exc:
        response_text = ""
        if exc.response is not None:
            response_text = exc.response.text[:1000]
        logging.error("SOC Jira collector failed: %s | response=%s", exc, response_text)
        soc_jira_tickets_last_collection_success.set(0)
    except Exception as exc:
        logging.error("SOC Jira collector failed: %s", exc)
        soc_jira_tickets_last_collection_success.set(0)
