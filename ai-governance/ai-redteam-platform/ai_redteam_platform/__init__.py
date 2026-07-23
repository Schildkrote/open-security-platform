"""ai-redteam-platform: authorized AI red teaming control plane."""
from .db import connect, file_db
from .registry import register_target, get_target, list_targets, set_authorization
from .testlib import TEST_LIBRARY, TestCase, all_cases, cases_for_category, cases_by_owasp, categories
from .engine import Target, MockTarget, HttpTarget, CaseOutcome, run_case, run_cases, redteam_available, run_via_redteam
from .scoring import score_campaign, CampaignScore, Finding
from .evidence import store_evidence, list_evidence, verify_chain, redact, purge_older_than
from .compliance import compliance_coverage, FRAMEWORKS
from .reports import technical_report, executive_report, compliance_report, json_report
from .runner import SafeRunner, CampaignResult, ScopeViolation
from .audit import AuditLog
from .api import Platform, serve

__all__ = [
    "connect", "file_db",
    "register_target", "get_target", "list_targets", "set_authorization",
    "TEST_LIBRARY", "TestCase", "all_cases", "cases_for_category", "cases_by_owasp", "categories",
    "Target", "MockTarget", "HttpTarget", "CaseOutcome", "run_case", "run_cases",
    "redteam_available", "run_via_redteam",
    "score_campaign", "CampaignScore", "Finding",
    "store_evidence", "list_evidence", "verify_chain", "redact", "purge_older_than",
    "compliance_coverage", "FRAMEWORKS",
    "technical_report", "executive_report", "compliance_report", "json_report",
    "SafeRunner", "CampaignResult", "ScopeViolation",
    "AuditLog", "Platform", "serve",
]
