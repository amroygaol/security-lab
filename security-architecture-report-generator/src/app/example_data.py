from __future__ import annotations

from io import BytesIO

import pandas as pd


def build_example_workbook_bytes() -> bytes:
	checks = pd.DataFrame(
		[
			{
				"Application": "payments-api",
				"Technology": "nginx",
				"Finding": "TLS 1.0 allowed",
				"Severity": "High",
				"Status": "Open",
				"Recommendation": "Enforce TLS 1.2+ and modern ciphers",
			},
			{
				"Application": "payments-api",
				"Technology": "postgresql",
				"Finding": "No row-level audit trail",
				"Severity": "Medium",
				"Status": "Open",
				"Recommendation": "Enable pgaudit and forward logs to SIEM",
			},
			{
				"Application": "customer-portal",
				"Technology": "react",
				"Finding": "Missing strict CSP",
				"Severity": "High",
				"Status": "Open",
				"Recommendation": "Deploy nonce-based CSP and remove unsafe-inline",
			},
			{
				"Application": "identity-service",
				"Technology": "keycloak",
				"Finding": "Admin endpoints exposed internally without MFA",
				"Severity": "High",
				"Status": "Open",
				"Recommendation": "Require MFA and network ACL restrictions for admin paths",
			},
		]
	)

	architecture = pd.DataFrame(
		[
			{"Component": "API Gateway", "Control": "WAF", "Status": "Partial", "Risk": "Injection"},
			{"Component": "Identity", "Control": "MFA", "Status": "Missing", "Risk": "Account takeover"},
			{"Component": "Data Layer", "Control": "Encryption at Rest", "Status": "Enabled", "Risk": "Data theft"},
		]
	)

	app_sec_controls = pd.DataFrame(
		[
			{
				"Control Domain": "Inventory of Enterprise Assets",
				"Control Objective": "Maintain full visibility of assets",
				"Control Requirements": "Establish and maintain an authoritative inventory of all system components (servers, DBs, HSMs, middleware, DR).",
				"Evidence / Artifact": "CMDB, asset inventory reports, architecture diagrams",
				"Response": "",
			},
			{
				"Control Domain": "Inventory of Software Assets",
				"Control Objective": "Prevent unauthorized software execution",
				"Control Requirements": "List all 3rd party libraries used.",
				"Evidence / Artifact": "Software inventory, allow-list configs, integrity reports",
				"Response": "",
			},
			{
				"Control Domain": "Data Protection",
				"Control Objective": "Protect confidentiality, integrity, availability of data",
				"Control Requirements": "Classify data by sensitivity (PII, transactional). Encrypt data at rest and in transit. Enforce key management procedures.",
				"Evidence / Artifact": "Data classification policy, encryption configs, key management procedures",
				"Response": "",
			},
			{
				"Control Domain": "Secure Configuration",
				"Control Objective": "Reduce system attack surface",
				"Control Requirements": "Establish secure baseline configurations for OS, DB, middleware, and application.",
				"Evidence / Artifact": "Baseline standards, hardening checklists, patch records",
				"Response": "",
			},
			{
				"Control Domain": "Account Management",
				"Control Objective": "Ensure controlled user lifecycle",
				"Control Requirements": "Define account types and privileges. Enforce Joiner-Mover-Leaver processes.",
				"Evidence / Artifact": "IAM records, access reviews, de-provisioning logs",
				"Response": "",
			},
			{
				"Control Domain": "Access Control Management",
				"Control Objective": "Enforce least privilege and SoD",
				"Control Requirements": "Implement role-based access aligned with business functions. Enforce separation of duties (maker-checker) for financial operations.",
				"Evidence / Artifact": "Role matrix, SoD documentation, MFA configs",
				"Response": "",
			},
			{
				"Control Domain": "Continuous Vulnerability Management",
				"Control Objective": "Identify and remediate weaknesses",
				"Control Requirements": "Conduct vulnerability scans at defined intervals. Prioritize remediation based on risk.",
				"Evidence / Artifact": "Scan reports, remediation tracking, risk registers",
				"Response": "",
			},
			{
				"Control Domain": "Audit Log Management",
				"Control Objective": "Enable accountability and non-repudiation",
				"Control Requirements": "Define events to be logged (at least financial transactions and admin actions). Protect audit logs from unauthorized modification.",
				"Evidence / Artifact": "SIEM logs, log retention policy, review records",
				"Response": "",
			},
			{
				"Control Domain": "Application Software Security",
				"Control Objective": "Secure applications and APIs",
				"Control Requirements": "Integrate security into SDLC. Perform static and dynamic testing. Secure API endpoints.",
				"Evidence / Artifact": "SDLC docs, test results, API configs",
				"Response": "",
			},
			{
				"Control Domain": "Incident Response Management",
				"Control Objective": "Respond effectively to incidents",
				"Control Requirements": "Establish incident response procedures. Define roles and escalation paths.",
				"Evidence / Artifact": "IR plans, incident reports",
				"Response": "",
			},
			{
				"Control Domain": "Penetration Testing",
				"Control Objective": "Validate control effectiveness",
				"Control Requirements": "Conduct penetration testing covering infrastructure and applications. Track remediation.",
				"Evidence / Artifact": "Pentest reports, remediation plans",
				"Response": "",
			},
		]
	)

	output = BytesIO()
	with pd.ExcelWriter(output, engine="openpyxl") as writer:
		checks.to_excel(writer, index=False, sheet_name="Compliance_Checks")
		architecture.to_excel(writer, index=False, sheet_name="Architecture_Controls")
		app_sec_controls.to_excel(writer, index=False, sheet_name="App_Sec_Controls")

	output.seek(0)
	return output.getvalue()
