from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..core.config import CONFIG


def _portal_dir() -> Path:
    path = Path(CONFIG.portal_data_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _dataset_path(name: str) -> Path:
    return _portal_dir() / name


def _read_or_seed(path: Path, seed_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    if not path.exists():
        path.write_text(json.dumps(seed_rows, indent=2), encoding="utf-8")
        return seed_rows

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        data = seed_rows
        path.write_text(json.dumps(seed_rows, indent=2), encoding="utf-8")
    return data if isinstance(data, list) else seed_rows


def _seed_assets() -> list[dict[str, object]]:
    today = datetime.now(UTC).date()
    return [
        {
            "asset_id": "AST-001",
            "asset_name": "Internet Banking API Gateway",
            "asset_type": "Platform",
            "environment": "Production",
            "owner": "Security Architecture",
            "criticality": "Critical",
            "vendor": "F5",
            "license_name": "F5 Advanced WAF",
            "license_type": "Subscription",
            "license_seats": 4,
            "seats_used": 4,
            "annual_cost": 185000.0,
            "renewal_date": str(today + timedelta(days=45)),
            "support_status": "Active",
            "notes": "Protects north-south traffic for payment and customer APIs.",
        },
        {
            "asset_id": "AST-002",
            "asset_name": "Identity and Access Platform",
            "asset_type": "Security Tool",
            "environment": "Shared",
            "owner": "IAM Team",
            "criticality": "High",
            "vendor": "Keycloak",
            "license_name": "Red Hat Build Support",
            "license_type": "Enterprise Support",
            "license_seats": 12,
            "seats_used": 9,
            "annual_cost": 72000.0,
            "renewal_date": str(today + timedelta(days=120)),
            "support_status": "Active",
            "notes": "Covers SSO, MFA, and privileged admin federation.",
        },
        {
            "asset_id": "AST-003",
            "asset_name": "Cloud CSPM",
            "asset_type": "Security Tool",
            "environment": "Cloud",
            "owner": "Cloud Security",
            "criticality": "High",
            "vendor": "Wiz",
            "license_name": "Wiz Enterprise",
            "license_type": "Subscription",
            "license_seats": 150,
            "seats_used": 123,
            "annual_cost": 96000.0,
            "renewal_date": str(today + timedelta(days=20)),
            "support_status": "Renewal Soon",
            "notes": "Integrated with asset discovery and vulnerability workflows.",
        },
    ]


def _seed_budgets() -> list[dict[str, object]]:
    return [
        {
            "budget_id": "BDG-001",
            "initiative": "API Security Modernization",
            "cost_type": "Capex",
            "domain": "Application Security",
            "owner": "Security Architecture",
            "quarter": "2026-Q2",
            "amount": 240000.0,
            "currency": "IDR",
            "status": "Planned",
            "priority": "High",
            "notes": "Gateway hardening, token protection, and API discovery expansion.",
        },
        {
            "budget_id": "BDG-002",
            "initiative": "Identity Platform Support",
            "cost_type": "Opex",
            "domain": "IAM",
            "owner": "IAM Team",
            "quarter": "2026-Q2",
            "amount": 72000.0,
            "currency": "IDR",
            "status": "Approved",
            "priority": "High",
            "notes": "Annual support and integration engineering.",
        },
        {
            "budget_id": "BDG-003",
            "initiative": "Threat Detection Uplift",
            "cost_type": "Opex",
            "domain": "SOC",
            "owner": "Cyber Defense",
            "quarter": "2026-Q3",
            "amount": 58000.0,
            "currency": "IDR",
            "status": "Draft",
            "priority": "Medium",
            "notes": "Detection engineering backlog and log retention uplift.",
        },
    ]


def _seed_budget_policies() -> list[dict[str, object]]:
    return [
        {
            "policy_id": "POL-001",
            "text": "CapEx initiatives above 20% variance from baseline require architecture governance review.",
        },
        {
            "policy_id": "POL-002",
            "text": "OpEx growth above 15% quarter-over-quarter should include operational efficiency justification.",
        },
        {
            "policy_id": "POL-003",
            "text": "Draft and Planned items with High priority should have owner and risk notes before approval.",
        },
        {
            "policy_id": "POL-004",
            "text": "Budget anomalies should be triaged with status, owner accountability, and expected mitigation outcome.",
        },
    ]


def load_assets() -> list[dict[str, object]]:
    return _read_or_seed(_dataset_path("assets.json"), _seed_assets())


def save_assets(rows: list[dict[str, object]]) -> None:
    _dataset_path("assets.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")


def load_budgets() -> list[dict[str, object]]:
    return _read_or_seed(_dataset_path("budgets.json"), _seed_budgets())


def save_budgets(rows: list[dict[str, object]]) -> None:
    _dataset_path("budgets.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")


def load_budget_policies() -> list[dict[str, object]]:
    return _read_or_seed(_dataset_path("budget_policies.json"), _seed_budget_policies())


def save_budget_policies(rows: list[dict[str, object]]) -> None:
    cleaned: list[dict[str, object]] = []
    for idx, row in enumerate(rows, start=1):
        text = str(row.get("text", "")).strip()
        if not text:
            continue
        policy_id = str(row.get("policy_id", "")).strip() or f"POL-{idx:03d}"
        cleaned.append({"policy_id": policy_id, "text": text})
    _dataset_path("budget_policies.json").write_text(json.dumps(cleaned, indent=2), encoding="utf-8")
