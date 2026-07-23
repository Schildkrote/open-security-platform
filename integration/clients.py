"""Thin HTTP clients + field mappers for the five Phase-2 components.

Each client wraps a component's existing public HTTP API (no component changes
required). The mapper functions bridge the differing data models, e.g. an
ai-redteam-platform Finding -> a pentest-manager FindingInput, and a finding /
sandbox record -> an ai-compliance-hub evidence row.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Optional


def _request(method: str, url: str, body: Optional[dict[str, Any]] = None, timeout: float = 20.0) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:  # surface the server's error body
        raise RuntimeError(f"{method} {url} -> {e.code}: {e.read().decode(errors='replace')}") from e
    return json.loads(raw) if raw else {}


class RedteamClient:
    """ai-governance/ai-redteam-platform."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def health(self) -> Any:
        return _request("GET", f"{self.base}/healthz")

    def register_target(self, **kwargs: Any) -> Any:
        return _request("POST", f"{self.base}/targets", kwargs)

    def authorize(self, target_id: str, status: str = "authorized") -> Any:
        return _request("POST", f"{self.base}/targets/{target_id}/authorize", {"status": status})

    def run_campaign(self, target_id: str, guarded: bool = False) -> Any:
        return _request("POST", f"{self.base}/campaigns", {"target_id": target_id, "guarded": guarded})


class PentestClient:
    """offensive/pentest-manager."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def health(self) -> Any:
        return _request("GET", f"{self.base}/healthz")

    def create_client(self, name: str, contact: Optional[str] = None) -> Any:
        return _request("POST", f"{self.base}/clients", {"name": name, "contact": contact})

    def create_engagement(self, client_id: str, name: str) -> Any:
        return _request("POST", f"{self.base}/engagements", {"client_id": client_id, "name": name})

    def add_finding(self, engagement_id: str, finding_input: dict[str, Any]) -> Any:
        return _request("POST", f"{self.base}/engagements/{engagement_id}/findings", finding_input)

    def list_findings(self, engagement_id: str) -> Any:
        return _request("GET", f"{self.base}/engagements/{engagement_id}/findings")

    def verify_evidence(self) -> Any:
        return _request("GET", f"{self.base}/evidence/verify")


class ComplianceClient:
    """ai-governance/ai-compliance-hub."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def health(self) -> Any:
        return _request("GET", f"{self.base}/healthz")

    def register_system(self, **kwargs: Any) -> Any:
        return _request("POST", f"{self.base}/systems", kwargs)

    def add_control(self, **kwargs: Any) -> Any:
        return _request("POST", f"{self.base}/controls", kwargs)

    def collect_evidence(self, **kwargs: Any) -> Any:
        return _request("POST", f"{self.base}/evidence", kwargs)

    def list_evidence(self) -> Any:
        return _request("GET", f"{self.base}/evidence")

    def verify_evidence(self) -> Any:
        return _request("GET", f"{self.base}/evidence/verify")


class PamClient:
    """identity/open-pam-jit."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def health(self) -> Any:
        return _request("GET", f"{self.base}/healthz")

    def add_target(self, target_id: str, name: str, type: str) -> Any:
        return _request("POST", f"{self.base}/targets", {"id": target_id, "name": name, "type": type})

    def request_access(self, requester: str, target_id: str, justification: str, duration_sec: int) -> Any:
        return _request(
            "POST",
            f"{self.base}/requests",
            {
                "requester": requester,
                "target_id": target_id,
                "justification": justification,
                "duration_sec": duration_sec,
            },
        )

    def approve(self, request_id: str, approver: str) -> Any:
        return _request("POST", f"{self.base}/requests/{request_id}/approve", {"approver": approver})

    def verify_audit(self) -> Any:
        return _request("GET", f"{self.base}/audit/verify")


# --- Field mappers ---------------------------------------------------------


def redteam_finding_to_pentest(finding: dict[str, Any], asset: str) -> dict[str, Any]:
    """Map an ai-redteam-platform Finding onto a pentest-manager FindingInput.

    redteam: case_id, name, category, severity, confidence, reason, remediation,
             owasp[], atlas[], compliance{}
    pentest: title, vuln_class, cwe, asset, severity, cvss, epss, kev,
             business_impact, description, remediation
    Severity vocab overlaps (low/medium/high/critical) so it passes through.
    CVSS/EPSS/KEV/CWE have no redteam source and are left unset.
    """
    severity = finding.get("severity", "medium")
    return {
        "title": finding.get("name", "AI red-team finding"),
        "vuln_class": finding.get("category"),
        "severity": severity,
        "asset": asset,
        "description": finding.get("reason"),
        "remediation": finding.get("remediation") or None,
        "business_impact": f"{severity} severity AI red-team finding "
        f"({finding.get('category', 'uncategorized')})",
    }


def redteam_finding_to_evidence(
    finding: dict[str, Any], system_id: str, control_id: Optional[str] = None
) -> dict[str, Any]:
    """Map a redteam finding onto an ai-compliance-hub collect_evidence payload."""
    content = json.dumps(
        {
            "case_id": finding.get("case_id"),
            "name": finding.get("name"),
            "category": finding.get("category"),
            "severity": finding.get("severity"),
            "reason": finding.get("reason"),
            "owasp": finding.get("owasp", []),
            "atlas": finding.get("atlas", []),
            "compliance": finding.get("compliance", {}),
        },
        sort_keys=True,
    )
    return {
        "content": content,
        "control_id": control_id,
        "system_id": system_id,
        "source": "ai-redteam-platform",
    }


def sandbox_record_to_evidence(
    record: dict[str, Any], system_id: str, control_id: Optional[str] = None
) -> dict[str, Any]:
    """Map an agent-sandbox SessionRecord onto a compliance evidence payload."""
    content = json.dumps(
        {
            "command": record.get("command"),
            "allowed": record.get("allowed"),
            "exit_code": record.get("exit_code"),
            "duration_s": record.get("duration_s"),
        },
        sort_keys=True,
    )
    return {
        "content": content,
        "control_id": control_id,
        "system_id": system_id,
        "source": "agent-sandbox",
    }
