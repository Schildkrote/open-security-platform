"""End-to-end Phase-2 integration flow (the control plane).

Wires the five components over HTTP using their existing public APIs:

    ai-redteam-platform  --(findings)-->  pentest-manager
                         --(evidence)-->  ai-compliance-hub
    privileged action    --(brokered)-->  open-pam-jit  --(executed)-->  agent-sandbox

Every step is recorded on the common hash-chained integration-event schema
(``events.EventChain``). ``run_flow`` returns a structured result with all ids
and the verification outcomes; it raises ``FlowError`` if the flow cannot
produce the expected artifacts.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from .clients import (
    ComplianceClient,
    PamClient,
    PentestClient,
    RedteamClient,
    redteam_finding_to_evidence,
    redteam_finding_to_pentest,
    sandbox_record_to_evidence,
)
from .events import EventChain, new_event


class FlowError(RuntimeError):
    """Raised when the integration flow cannot produce an expected artifact."""


def run_flow(
    redteam_base: str,
    pentest_base: str,
    compliance_base: str,
    pam_base: str,
    sandbox_run: Optional[Callable[[str], Any]] = None,
    pam_target_id: str = "prod-db",
) -> dict[str, Any]:
    rt = RedteamClient(redteam_base)
    pt = PentestClient(pentest_base)
    ch = ComplianceClient(compliance_base)
    pam = PamClient(pam_base)
    chain = EventChain()
    result: dict[str, Any] = {}

    # 1. Red-team campaign (unguarded mock target -> deterministic findings).
    target = rt.register_target(name="Range Chatbot", app_type="llm", risk_tier="high")
    rt.authorize(target["id"], "authorized")
    campaign = rt.run_campaign(target["id"], guarded=False)
    findings = campaign["score"]["findings"]
    chain.append(
        new_event(
            "campaign.complete",
            "ai-redteam-platform",
            "run_campaign",
            subject=target["id"],
            refs={"campaign_id": campaign["campaign_id"]},
            findings=len(findings),
            score=campaign["score"]["score"],
            risk_score=campaign["score"]["risk_score"],
        )
    )
    if not findings:
        raise FlowError("red-team campaign produced no findings")
    result["campaign_id"] = campaign["campaign_id"]
    result["target_name"] = target["name"]
    result["findings"] = findings

    # 2. Findings -> pentest-manager.
    client = pt.create_client(name="Acme Corp", contact="security@acme.example")
    engagement = pt.create_engagement(
        client_id=client["id"], name=f"AI red-team {campaign['campaign_id'][:8]}"
    )
    pentest_findings = []
    for finding in findings:
        created = pt.add_finding(
            engagement["id"], redteam_finding_to_pentest(finding, asset=target["name"])
        )
        pentest_findings.append(created)
        chain.append(
            new_event(
                "finding.created",
                "pentest-manager",
                "add_finding",
                subject=created["id"],
                refs={"engagement_id": engagement["id"], "redteam_case": finding["case_id"]},
                severity=created.get("severity"),
            )
        )
    result["client_id"] = client["id"]
    result["engagement_id"] = engagement["id"]
    result["pentest_findings"] = pentest_findings

    # 3. Evidence -> ai-compliance-hub.
    system = ch.register_system(
        name=target["name"],
        system_type="ai",
        risk_level="high",
        description="AI system under red-team evaluation",
    )
    control = ch.add_control(
        title="AI Red-Team Evidence",
        family="Assurance",
        description="Evidence captured from AI red-team campaigns.",
        mappings={"NIST_AI_RMF": ["MANAGE-3"], "EU_AI_ACT": ["Article 12"]},
    )
    evidence_rows = []
    for finding in findings:
        ev = ch.collect_evidence(
            **redteam_finding_to_evidence(finding, system_id=system["id"], control_id=control["id"])
        )
        evidence_rows.append(ev)
        chain.append(
            new_event(
                "evidence.collected",
                "ai-compliance-hub",
                "collect_evidence",
                subject=ev["id"],
                refs={
                    "system_id": system["id"],
                    "control_id": control["id"],
                    "redteam_case": finding["case_id"],
                },
            )
        )
    result["system_id"] = system["id"]
    result["control_id"] = control["id"]
    result["evidence"] = evidence_rows

    # 4. Privileged action brokered by open-pam-jit (uses a seeded target).
    access_request = pam.request_access(
        requester="redteam-orchestrator",
        target_id=pam_target_id,
        justification=f"remediation verification for campaign {campaign['campaign_id'][:8]}",
        duration_sec=600,
    )
    credential = pam.approve(access_request["id"], approver="security-lead")
    chain.append(
        new_event(
            "access.granted",
            "open-pam-jit",
            "approve",
            subject=credential["id"],
            refs={"request_id": access_request["id"], "target_id": pam_target_id},
            requester="redteam-orchestrator",
            approver="security-lead",
        )
    )
    result["pam_request_id"] = access_request["id"]
    result["pam_credential_id"] = credential["id"]

    # 5. Execute the (simulated) privileged action inside agent-sandbox.
    if sandbox_run is not None:
        record = sandbox_run(f"echo remediation-verified campaign={campaign['campaign_id'][:8]}")
        record_dict = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        sandbox_evidence = ch.collect_evidence(
            **sandbox_record_to_evidence(
                record_dict, system_id=system["id"], control_id=control["id"]
            )
        )
        chain.append(
            new_event(
                "action.executed",
                "agent-sandbox",
                "run",
                subject=sandbox_evidence["id"],
                refs={"system_id": system["id"], "credential_id": credential["id"]},
                allowed=record_dict.get("allowed"),
                exit_code=record_dict.get("exit_code"),
            )
        )
        result["sandbox_record"] = record_dict
        result["sandbox_evidence"] = sandbox_evidence

    # 6. Verify every tamper-evident trail involved in the flow.
    result["verifications"] = {
        "compliance_evidence": ch.verify_evidence(),
        "pentest_evidence": pt.verify_evidence(),
        "pam_audit": pam.verify_audit(),
        "integration_chain": chain.verify(),
    }
    result["events"] = chain.events
    return result
