"""Safe runner: executes campaigns only against authorized targets, with scope
controls, rate limits, timeouts, a kill switch, evidence capture and audit.

Safety model (per the product brief): authorized scope only, no external calls,
no destructive payloads, no real exfiltration, full auditability.
"""
from __future__ import annotations

import sqlite3
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import compliance as compliance_mod
from . import evidence as evidence_mod
from . import registry
from .audit import AuditLog
from .engine import CaseOutcome, Target, run_case
from .scoring import CampaignScore, score_campaign
from .testlib import TestCase, all_cases


class ScopeViolation(Exception):
    pass


@dataclass
class CampaignResult:
    campaign_id: str
    target_id: str
    score: CampaignScore
    compliance: dict
    outcomes: list[CaseOutcome] = field(default_factory=list)
    aborted: bool = False


class SafeRunner:
    def __init__(
        self,
        conn: sqlite3.Connection,
        audit: AuditLog | None = None,
        max_runs_per_minute: int = 600,
        per_case_timeout: float = 5.0,
        allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "::1"),
    ) -> None:
        self.conn = conn
        self.audit = audit or AuditLog()
        self.max_runs_per_minute = max_runs_per_minute
        self.per_case_timeout = per_case_timeout
        self.allowed_hosts = allowed_hosts
        self._kill = False
        self._window_start = time.monotonic()
        self._window_count = 0

    # -- safety controls -------------------------------------------------
    def abort(self) -> None:
        """Kill switch: stop the campaign as soon as possible."""
        self._kill = True

    def _check_rate_limit(self) -> None:
        now = time.monotonic()
        if now - self._window_start > 60:
            self._window_start, self._window_count = now, 0
        if self._window_count >= self.max_runs_per_minute:
            raise ScopeViolation("rate limit exceeded")
        self._window_count += 1

    def _authorize(self, target_id: str) -> dict:
        t = registry.get_target(self.conn, target_id)
        if not t:
            raise ScopeViolation("unknown target")
        if t["authorization"] != "authorized":
            raise ScopeViolation(f"target not authorized (status={t['authorization']})")
        if t.get("endpoint"):
            host = urlparse(t["endpoint"]).hostname or ""
            if host not in self.allowed_hosts:
                raise ScopeViolation(f"endpoint host '{host}' not in allowed scope")
        return t

    def _run_one(self, target: Target, case: TestCase) -> CaseOutcome:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(run_case, target, case)
            try:
                return future.result(timeout=self.per_case_timeout)
            except FutureTimeout:
                return CaseOutcome(
                    case_id=case.id, category=case.category, name=case.name,
                    passed=False, reason="timeout (safety limit)", response="", detector=case.detector,
                )

    # -- campaign --------------------------------------------------------
    def run_campaign(self, target_id: str, target: Target, cases: list[TestCase] | None = None) -> CampaignResult:
        cases = cases if cases is not None else all_cases()
        t = self._authorize(target_id)          # authorization + scope gate
        self._kill = False
        campaign_id = str(uuid.uuid4())
        self.audit.log("campaign_started", target_id=target_id, target=t["name"], cases=len(cases))

        outcomes: list[CaseOutcome] = []
        aborted = False
        for case in cases:
            if self._kill:
                aborted = True
                self.audit.log("campaign_aborted", target_id=target_id, at_case=case.id)
                break
            self._check_rate_limit()
            outcome = self._run_one(target, case)
            outcomes.append(outcome)
            evidence_mod.store_evidence(
                self.conn, campaign_id, case.id, target_id,
                case.prompt, outcome.response, outcome.passed, outcome.reason,
            )
            self.audit.log("case_run", target_id=target_id, case=case.id, passed=outcome.passed)

        score = score_campaign(t["name"], cases, outcomes)
        compliance = compliance_mod.compliance_coverage(cases, outcomes)

        self.conn.execute(
            "INSERT INTO campaigns (id,target_id,status,score,passed,total) VALUES (?,?,?,?,?,?)",
            (campaign_id, target_id, "aborted" if aborted else "complete",
             score.score, score.passed, score.total),
        )
        self.conn.commit()
        self.audit.log("campaign_complete", target_id=target_id, score=score.score, risk=score.risk_score)

        return CampaignResult(campaign_id=campaign_id, target_id=target_id, score=score,
                              compliance=compliance, outcomes=outcomes, aborted=aborted)
