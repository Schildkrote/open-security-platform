"""ai-redteam-platform: authorized AI red teaming control plane."""
from .api import Platform, serve
from .audit import AuditLog
from .compliance import FRAMEWORKS, compliance_coverage
from .db import connect, file_db
from .engine import (
    CaseOutcome,
    HttpTarget,
    MockTarget,
    Target,
    redteam_available,
    run_case,
    run_cases,
    run_via_redteam,
)
from .evidence import list_evidence, purge_older_than, redact, store_evidence, verify_chain
from .registry import get_target, list_targets, register_target, set_authorization
from .reports import compliance_report, executive_report, json_report, technical_report
from .runner import CampaignResult, SafeRunner, ScopeViolation
from .scoring import CampaignScore, Finding, score_campaign
from .testlib import (
    TEST_LIBRARY,
    TestCase,
    all_cases,
    cases_by_owasp,
    cases_for_category,
    categories,
)

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
