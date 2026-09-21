"""AI control library and cross-framework mapping engine.

The shipped library (``DEFAULT_CONTROLS``) is validated against
``compliance_hub.frameworks`` by ``tests/test_frameworks.py``: every EU AI Act
article and every ISO/IEC 42001 Annex A control cited below must exist in that
registry. If you add a control, register any new reference there first - the
test will fail otherwise. This is deliberate: a compliance product that
mis-cites a regulation produces evidence packages auditors reject.
"""
from __future__ import annotations

import sqlite3
import uuid
from typing import Any, Iterable, Optional


def add_control(
    conn: sqlite3.Connection,
    title: str,
    family: Optional[str] = None,
    description: Optional[str] = None,
    mappings: Optional[dict[str, list[str]]] = None,
) -> dict[str, Any]:
    cid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO controls (id,title,family,description) VALUES (?,?,?,?)",
        (cid, title, family, description),
    )
    for framework, refs in (mappings or {}).items():
        for ref in refs:
            conn.execute(
                "INSERT OR IGNORE INTO control_mappings (control_id,framework,reference) "
                "VALUES (?,?,?)",
                (cid, framework, ref),
            )
    conn.commit()
    return get_control(conn, cid)

def get_control(conn: sqlite3.Connection, cid: str) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM controls WHERE id=?", (cid,)).fetchone()
    if not row:
        return None
    ctrl = dict(row)
    ctrl["mappings"] = mappings_for(conn, cid)
    return ctrl

def mappings_for(conn: sqlite3.Connection, cid: str) -> dict[str, list[str]]:
    rows = conn.execute(
        "SELECT framework, reference FROM control_mappings WHERE control_id=?", (cid,)
    ).fetchall()
    out: dict[str, list[str]] = {}
    for r in rows:
        out.setdefault(r["framework"], []).append(r["reference"])
    return out

def list_controls(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [get_control(conn, r["id"]) for r in conn.execute("SELECT id FROM controls ORDER BY family, title")]

def controls_for_framework(conn: sqlite3.Connection, framework: str) -> list[dict[str, Any]]:
    """The control-mapping engine: one control -> many frameworks. Given a
    framework, return every control that maps to it."""
    rows = conn.execute(
        "SELECT DISTINCT c.id FROM controls c "
        "JOIN control_mappings m ON m.control_id=c.id WHERE m.framework=? "
        "ORDER BY c.family, c.title",
        (framework,),
    ).fetchall()
    return [get_control(conn, r["id"]) for r in rows]


# ---------------------------------------------------------------------------
# Built-in AI control library, mapped across EU AI Act (Regulation (EU)
# 2024/1689, OJ-published numbering), NIST AI RMF 1.0, ISO/IEC 42001:2023
# (Annex A controls + management-system clauses), SOC 2 TSC and the OWASP Top
# 10 for LLM Applications.
#
# Scope is honest: this is a *working library* covering the controls an AI
# team is most often asked about, not a complete transcription of any
# framework. EU AI Act high-risk requirements (Arts 8-15), provider and
# deployer obligations, transparency and post-market duties are covered;
# ISO 42001 objectives A.2-A.10 are covered at the control level; NIST AI RMF
# subcategories are cited where a control has a real equivalent. Gaps are
# tracked in NEXT_STEPS.md.
# ---------------------------------------------------------------------------
DEFAULT_CONTROLS: list[dict[str, Any]] = [
    # --- Governance -------------------------------------------------------
    {
        "title": "AI Policy",
        "family": "Governance",
        "description": (
            "Maintain an approved AI policy setting out how the organisation develops, "
            "provides and uses AI systems, aligned with privacy, security, risk, "
            "procurement and HR policies."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 17", "Article 8"],
            "NIST_AI_RMF": ["GOVERN-1.1", "GOVERN-2.1"],
            "ISO_42001": ["A.2.2", "A.2.3", "Clause 5.2"],
            "SOC2_AI": ["CC1.3"],
        },
    },
    {
        "title": "AI Policy Review",
        "family": "Governance",
        "description": (
            "Review the AI policy at planned intervals and after significant technical, "
            "organisational, regulatory or operational change, with management sign-off."
        ),
        "mappings": {
            "ISO_42001": ["A.2.4", "Clause 9.3"],
            "NIST_AI_RMF": ["GOVERN-2.1"],
            "SOC2_AI": ["CC1.3", "CC4.1"],
        },
    },
    {
        "title": "AI Roles, Responsibilities and Accountability",
        "family": "Governance",
        "description": (
            "Assign authority, accountability and operational responsibility for AI "
            "activities across the life cycle, with documented lines of communication "
            "and top-management ownership."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 16", "Article 26"],
            "NIST_AI_RMF": ["GOVERN-2.1", "GOVERN-3.2"],
            # A.3.2 is the Annex A control for AI roles and responsibilities.
            # Top-management responsibility is an ISO 42001 Clause 5 (Leadership)
            # management-system duty, not an Annex A control - an earlier draft
            # here cited a non-existent "A.3.4" for it. The Clause 5 reference is
            # deliberately omitted until it is verified and registered; see
            # NEXT_STEPS.md.
            "ISO_42001": ["A.3.2"],
            "SOC2_AI": ["CC1.4"],
        },
    },
    {
        "title": "AI Literacy and Competence",
        "family": "Governance",
        "description": (
            "Ensure providers, deployers, operators and oversight staff have sufficient "
            "AI literacy and documented competence for the systems they handle."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 4"],
            "NIST_AI_RMF": ["GOVERN-2.1"],
            "ISO_42001": ["A.4.6", "Clause 7.5"],
            "SOC2_AI": ["CC1.4"],
        },
    },
    {
        "title": "AI System Inventory and Registration",
        "family": "Governance",
        "description": (
            "Maintain a register of all AI systems with owner, intended purpose, risk "
            "classification and lifecycle status; register high-risk systems where "
            "required and document the resources each system depends on."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 6", "Article 49", "Annex IV"],
            "NIST_AI_RMF": ["MAP-1.1", "GOVERN-1.1"],
            "ISO_42001": ["A.4.2", "Clause 8.1"],
            "SOC2_AI": ["CC2.1"],
        },
    },
    {
        "title": "Reporting of AI Concerns",
        "family": "Governance",
        "description": (
            "Provide a confidential, non-retaliatory channel for staff, contractors, "
            "users and external parties to raise concerns about how AI is developed, "
            "provided or used, with defined investigation and escalation steps. "
            "Art 87 imports the EU Whistleblower Directive (2019/1937) protection for "
            "reporters of infringements; Art 85 is the separate right of any affected "
            "person to lodge a complaint with a market surveillance authority."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 87", "Article 85"],
            "NIST_AI_RMF": ["GOVERN-5.1"],
            "ISO_42001": ["A.3.3", "A.8.3"],
        },
    },

    # --- Risk -------------------------------------------------------------
    {
        "title": "AI Risk Management System",
        "family": "Risk",
        "description": (
            "Operate a continuous, documented risk management system across the whole "
            "life cycle of each high-risk AI system: identify, analyse, evaluate and "
            "mitigate risks, with a feedback loop from post-market monitoring."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 9"],
            "NIST_AI_RMF": ["MAP-2.1", "MANAGE-1.3"],
            "ISO_42001": ["Clause 6.1", "Clause 8.2"],
            "SOC2_AI": ["CC3.1"],
        },
    },
    {
        "title": "Risk Classification of AI Systems",
        "family": "Risk",
        "description": (
            "Determine whether a system is prohibited, high-risk, limited-risk or "
            "minimal-risk before deployment, and re-assess on material change of "
            "purpose or context."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 5", "Article 6", "Annex III"],
            "NIST_AI_RMF": ["MAP-1.1", "MAP-2.1"],
            "ISO_42001": ["Clause 8.2", "A.9.4"],
            "SOC2_AI": ["CC3.2"],
        },
    },
    {
        "title": "AI System Impact Assessment",
        "family": "Risk",
        "description": (
            "Run a repeatable impact assessment before deployment: scope, affected "
            "parties, foreseeable misuse, predictable failures, treatment decisions, "
            "documented and retained for audit."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 9", "Article 27"],
            "NIST_AI_RMF": ["MAP-2.3", "GOVERN-4.2"],
            "ISO_42001": ["A.5.2", "A.5.3", "Clause 8.4"],
            "SOC2_AI": ["CC4.1"],
        },
    },
    {
        "title": "Fundamental Rights Impact Assessment",
        "family": "Risk",
        "description": (
            "For deployers of high-risk systems in scope, assess impact on fundamental "
            "rights of affected persons and groups before first use, including "
            "categories of persons, period of use, human oversight and complaint routes."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 27", "Article 26"],
            "NIST_AI_RMF": ["MAP-2.3", "MAP-5.1"],
            "ISO_42001": ["A.5.4", "A.5.5"],
        },
    },
    {
        "title": "Societal and Environmental Impact Assessment",
        "family": "Risk",
        "description": (
            "Evaluate broader societal, democratic, environmental and safety "
            "consequences of an AI system, not only individual-level effects."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 9", "Article 27"],
            "NIST_AI_RMF": ["MAP-2.3"],
            "ISO_42001": ["A.5.5", "A.5.3"],
        },
    },
    {
        "title": "Risk Treatment and Residual Risk Acceptance",
        "family": "Risk",
        "description": (
            "Prioritise documented risks by impact, likelihood and resources; implement "
            "mitigations; record residual risk and obtain explicit acceptance before "
            "proceeding to deployment."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 9"],
            "NIST_AI_RMF": ["MANAGE-1.2", "MANAGE-1.3", "MANAGE-1.4"],
            "ISO_42001": ["Clause 8.3", "Clause 6.1"],
            "SOC2_AI": ["CC3.3"],
        },
    },

    # --- Data -------------------------------------------------------------
    {
        "title": "Data Governance and Data Quality",
        "family": "Data",
        "description": (
            "Govern training, validation and testing data with defined quality criteria "
            "(accuracy, completeness, currency, representativeness) and verify the data "
            "actually meets them, including bias examination."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 10"],
            "NIST_AI_RMF": ["MEASURE-2.5"],
            "ISO_42001": ["A.7.2", "A.7.4"],
            "SOC2_AI": ["CC6.1"],
        },
    },
    {
        "title": "Data Acquisition and Lawful Basis",
        "family": "Data",
        "description": (
            "Document where each dataset comes from and how it was obtained (internal, "
            "purchased, licensed, shared, open, synthetic), including data rights, prior "
            "uses and known biases."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 10"],
            "NIST_AI_RMF": ["MAP-4.1"],
            "ISO_42001": ["A.7.3", "A.4.3"],
            "SOC2_AI": ["CC6.1"],
        },
    },
    {
        "title": "Data Provenance and Preparation",
        "family": "Data",
        "description": (
            "Track lineage of each dataset across its life cycle (origin, ownership, "
            "transformations, transfers, updates) and document cleaning, labelling, "
            "filtering and augmentation."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 10", "Article 11"],
            "NIST_AI_RMF": ["MEASURE-2.5"],
            "ISO_42001": ["A.7.5", "A.7.6"],
            "SOC2_AI": ["CC6.1"],
        },
    },
    {
        "title": "Privacy and Personal Data Protection",
        "family": "Data",
        "description": (
            "Examine and mitigate privacy risk of the AI system: data minimisation, "
            "redaction or pseudonymisation, access control on corpora, and retention "
            "limits."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 10", "Article 15"],
            "NIST_AI_RMF": ["MEASURE-2.10", "MEASURE-2.8"],
            "ISO_42001": ["A.7.2", "A.7.4"],
            "SOC2_AI": ["CC6.1", "P3.1"],
        },
    },

    # --- Lifecycle --------------------------------------------------------
    {
        "title": "Responsible Design and Development",
        "family": "Lifecycle",
        "description": (
            "Operate documented processes for responsible AI design and development "
            "with measurable objectives for fairness, safety, privacy, transparency, "
            "robustness, security and human oversight."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 9", "Article 15"],
            "NIST_AI_RMF": ["GOVERN-4.1"],
            "ISO_42001": ["A.6.1.2", "A.6.1.3"],
            "SOC2_AI": ["CC8.1"],
        },
    },
    {
        "title": "System Requirements and Specification",
        "family": "Lifecycle",
        "description": (
            "Define functional, performance, safety, security, compliance and "
            "responsible-AI requirements before build, and keep them versioned."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 11", "Annex IV"],
            "NIST_AI_RMF": ["MAP-1.1"],
            "ISO_42001": ["A.6.2.2"],
            "SOC2_AI": ["CC8.1"],
        },
    },
    {
        "title": "Verification and Validation",
        "family": "Lifecycle",
        "description": (
            "Verify the system meets its defined requirements and validate its "
            "suitability for the intended purpose, with TEVV results retained as "
            "evidence."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 9", "Article 15"],
            "NIST_AI_RMF": ["MEASURE-2.6", "MEASURE-2.9"],
            "ISO_42001": ["A.6.2.4"],
            "SOC2_AI": ["CC4.1"],
        },
    },
    {
        "title": "Deployment Approval and Rollback",
        "family": "Lifecycle",
        "description": (
            "Control production deployment through approvals, release criteria, "
            "environment checks and documented rollback arrangements."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 16", "Article 20"],
            "NIST_AI_RMF": ["MANAGE-1.1", "MANAGE-4.1"],
            "ISO_42001": ["A.6.2.5"],
            "SOC2_AI": ["CC8.1"],
        },
    },
    {
        "title": "Operation and Continuous Monitoring",
        "family": "Lifecycle",
        "description": (
            "Monitor deployed systems for performance drift, failures, misuse, security "
            "threats and changing operating conditions, and feed findings back into risk "
            "management."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 72", "Article 9"],
            "NIST_AI_RMF": ["MANAGE-4.1", "MEASURE-3.1"],
            "ISO_42001": ["A.6.2.6", "Clause 9.1"],
            "SOC2_AI": ["CC7.1"],
        },
    },
    {
        "title": "Post-Market Monitoring Plan",
        "family": "Lifecycle",
        "description": (
            "Establish and document a post-market monitoring system proportionate to "
            "risk, based on a plan that forms part of the technical documentation."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 72", "Annex IV"],
            "NIST_AI_RMF": ["MANAGE-4.1", "MEASURE-3.1"],
            "ISO_42001": ["A.6.2.6", "Clause 9.1"],
        },
    },
    {
        "title": "Corrective Actions and Duty of Information",
        "family": "Lifecycle",
        "description": (
            "Take corrective action when a system is non-compliant or poses risk, and "
            "inform distributors, deployers, affected persons and authorities as "
            "required."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 20", "Article 21"],
            "NIST_AI_RMF": ["MANAGE-1.3"],
            "ISO_42001": ["Clause 10.1"],
            "SOC2_AI": ["CC7.4"],
        },
    },
    {
        "title": "Change Management",
        "family": "Lifecycle",
        "description": (
            "Plan and control changes to AI systems, re-assessing risk classification "
            "and impact where a change is material."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 6", "Article 9"],
            "NIST_AI_RMF": ["MANAGE-4.1"],
            "ISO_42001": ["Clause 8.1", "A.6.2.5"],
            "SOC2_AI": ["CC8.1"],
        },
    },

    # --- Technical documentation & transparency ---------------------------
    {
        "title": "Technical Documentation",
        "family": "Transparency",
        "description": (
            "Draw up and keep current the technical documentation for high-risk systems "
            "before placing on market, in the required form, and retain it for the "
            "prescribed period."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 11", "Article 18", "Annex IV"],
            "NIST_AI_RMF": ["GOVERN-4.2"],
            "ISO_42001": ["A.6.2.7", "A.6.2.3", "Clause 7.5"],
        },
    },
    {
        "title": "Instructions for Use and Deployer Information",
        "family": "Transparency",
        "description": (
            "Provide deployers with understandable information about purpose, "
            "capabilities, limitations, inputs, outputs, human-oversight measures and "
            "proper use."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 13"],
            "NIST_AI_RMF": ["GOVERN-4.2"],
            "ISO_42001": ["A.8.2", "A.8.5"],
            "SOC2_AI": ["CC2.2"],
        },
    },
    {
        "title": "Interaction and Output Transparency",
        "family": "Transparency",
        "description": (
            "Disclose AI interaction to natural persons, mark synthetic or manipulated "
            "content, and disclose emotion-recognition or biometric-categorisation use "
            "where the Act requires it."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 50"],
            "NIST_AI_RMF": ["GOVERN-4.2"],
            "ISO_42001": ["A.8.2", "A.8.5"],
        },
    },
    {
        "title": "Explainability and Output Interpretation",
        "family": "Transparency",
        "description": (
            "Explain, validate and document the model and interpret outputs within their "
            "context to inform responsible use; support a right to explanation of "
            "individual decisions."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 13", "Article 86"],
            "NIST_AI_RMF": ["MEASURE-2.9"],
            "ISO_42001": ["A.6.2.3", "A.8.2"],
        },
    },

    # --- Human oversight --------------------------------------------------
    {
        "title": "Human Oversight",
        "family": "Governance",
        "description": (
            "Design and operate human oversight measures for high-risk systems so that "
            "risks are prevented or minimised, including the ability to intervene, "
            "override or stop the system."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 14"],
            "NIST_AI_RMF": ["GOVERN-3.2"],
            "ISO_42001": ["A.9.2", "A.9.3"],
            "SOC2_AI": ["CC5.1"],
        },
    },
    {
        "title": "Responsible Use and Intended-Purpose Boundaries",
        "family": "Governance",
        "description": (
            "Define acceptable use, operator training, escalation and suspension rules, "
            "and ensure the system stays within its approved purpose, user group, "
            "operating conditions and decision context."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 26", "Article 4"],
            "NIST_AI_RMF": ["GOVERN-3.2", "MANAGE-1.1"],
            "ISO_42001": ["A.9.2", "A.9.4"],
            "SOC2_AI": ["CC5.1"],
        },
    },

    # --- Security & robustness --------------------------------------------
    {
        "title": "Accuracy, Robustness and Cybersecurity",
        "family": "Security",
        "description": (
            "Achieve and declare appropriate accuracy and robustness, and protect "
            "against unauthorised exploitation of vulnerabilities, including data and "
            "model poisoning and adversarial inputs."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 15"],
            "NIST_AI_RMF": ["MEASURE-2.3", "MEASURE-2.7", "MEASURE-2.6"],
            "ISO_42001": ["A.6.2.4", "A.6.2.6"],
            "SOC2_AI": ["CC6.6", "CC6.7"],
            "OWASP_LLM_TOP10": ["LLM04"],
        },
    },
    {
        "title": "Prompt Injection and Output Handling Defences",
        "family": "Security",
        "description": (
            "Mitigate prompt injection and unsafe output handling: input/output "
            "guardrails, tool and function allowlisting, least-privilege agency, and "
            "treatment of model output as untrusted before it reaches downstream systems."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 15", "Article 9"],
            "NIST_AI_RMF": ["MEASURE-2.7", "MEASURE-2.3"],
            "ISO_42001": ["A.6.2.6"],
            "OWASP_LLM_TOP10": ["LLM01", "LLM05", "LLM06"],
        },
    },
    {
        "title": "Sensitive Information Disclosure Prevention",
        "family": "Security",
        "description": (
            "Prevent disclosure of sensitive data through model outputs, system prompts, "
            "vectors/embeddings or RAG retrieval: redaction, prompt isolation, "
            "access-controlled retrieval and sanitised logging."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 10", "Article 15"],
            "NIST_AI_RMF": ["MEASURE-2.8", "MEASURE-2.5"],
            "ISO_42001": ["A.7.4"],
            "SOC2_AI": ["CC6.1"],
            "OWASP_LLM_TOP10": ["LLM02", "LLM07", "LLM08"],
        },
    },
    {
        "title": "AI Supply Chain and Third-Party Model Risk",
        "family": "Third-Party",
        "description": (
            "Assess and manage suppliers whose data, models, tools, platforms or services "
            "affect AI development or use; allocate responsibilities contractually; "
            "monitor third-party risk continuously."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 25", "Article 53"],
            "NIST_AI_RMF": ["GOVERN-1.1", "MAP-4.1", "MANAGE-3.1"],
            "ISO_42001": ["A.10.2", "A.10.3", "A.10.4"],
            "SOC2_AI": ["CC9.2"],
            "OWASP_LLM_TOP10": ["LLM03"],
        },
    },
    {
        "title": "Resource and Tooling Inventory",
        "family": "Third-Party",
        "description": (
            "Document the models, algorithms, frameworks, libraries, tools, platforms, "
            "compute and human resources an AI system depends on, to support "
            "reproducibility and supply-chain risk assessment."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 11", "Annex IV"],
            "NIST_AI_RMF": ["MANAGE-3.1"],
            "ISO_42001": ["A.4.4", "A.4.5", "A.4.6"],
        },
    },
    {
        "title": "Consumption Limits and Resource Budgets",
        "family": "Third-Party",
        "description": (
            "Enforce budget caps, rate limits and quota controls per workspace and key, "
            "with provider fallback, to prevent unbounded consumption and cost "
            "runaway."
        ),
        "mappings": {
            "NIST_AI_RMF": ["MANAGE-2.3"],
            "ISO_42001": ["A.8.4", "A.6.2.6"],
            "SOC2_AI": ["A1.1"],
            "OWASP_LLM_TOP10": ["LLM10"],
        },
    },

    # --- Assurance --------------------------------------------------------
    {
        "title": "Logging and Traceability",
        "family": "Assurance",
        "description": (
            "Record AI system events sufficient for traceability, monitoring, "
            "investigation, incident response and audit, and retain automatically "
            "generated logs for the required period."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 12", "Article 19"],
            "NIST_AI_RMF": ["GOVERN-1.5", "MEASURE-2.11"],
            "ISO_42001": ["A.6.2.8"],
            "SOC2_AI": ["CC7.2"],
        },
    },
    {
        "title": "Tamper-Evident Audit Trail",
        "family": "Assurance",
        "description": (
            "Keep audit records tamper-evident (hash-chained or equivalently verifiable) "
            "so evidence integrity can be demonstrated to an auditor."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 19", "Article 12"],
            "NIST_AI_RMF": ["GOVERN-1.5", "MEASURE-2.11"],
            "ISO_42001": ["Clause 9.2", "A.6.2.8"],
            "SOC2_AI": ["CC7.2"],
        },
    },
    {
        "title": "Internal Audit",
        "family": "Assurance",
        "description": (
            "Audit the AI management system at planned intervals to verify controls are "
            "implemented and effective, with findings tracked to closure."
        ),
        "mappings": {
            "ISO_42001": ["Clause 9.2"],
            "NIST_AI_RMF": ["GOVERN-4.1"],
            "SOC2_AI": ["CC4.1"],
        },
    },
    {
        "title": "Management Review",
        "family": "Assurance",
        "description": (
            "Review the AI management system periodically at management level for "
            "continuing suitability, adequacy and effectiveness, with recorded decisions "
            "and actions."
        ),
        "mappings": {
            "ISO_42001": ["Clause 9.3", "Clause 10.2"],
            "NIST_AI_RMF": ["GOVERN-2.1"],
            "SOC2_AI": ["CC4.2"],
        },
    },
    {
        "title": "Serious Incident Reporting",
        "family": "Assurance",
        "description": (
            "Report serious incidents to market surveillance authorities within the "
            "applicable deadline (immediately, and no later than 15 days by default; "
            "10 days for death; 2 days for widespread infringement or serious "
            "irreversible disruption of critical infrastructure), then investigate and "
            "apply corrective action."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 73", "Article 26"],
            "NIST_AI_RMF": ["MANAGE-4.1"],
            "ISO_42001": ["A.8.4", "Clause 10.1"],
            "SOC2_AI": ["CC7.3"],
        },
    },
    {
        "title": "AI Red-Team Evaluation",
        "family": "Assurance",
        "description": (
            "Evaluate systems against a maintained attack library, score and regress "
            "results, retain evidence, and map findings to frameworks so guardrail and "
            "detection effectiveness is measured, not assumed."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 9", "Article 15", "Article 55"],
            "NIST_AI_RMF": ["MEASURE-2.3", "MEASURE-2.7", "GOVERN-4.3"],
            "ISO_42001": ["A.6.2.4"],
            "OWASP_LLM_TOP10": ["LLM01", "LLM04"],
        },
    },

    # --- Conformity & GPAI ------------------------------------------------
    {
        "title": "Quality Management System",
        "family": "Assurance",
        "description": (
            "Operate a documented quality management system covering strategy for "
            "regulatory compliance, design and development processes, testing and "
            "validation, data management, documentation control and post-market "
            "monitoring."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 17"],
            "NIST_AI_RMF": ["GOVERN-1.1", "GOVERN-2.1"],
            "ISO_42001": ["Clause 8.1", "Clause 9.1"],
            "SOC2_AI": ["CC1.1"],
        },
    },
    {
        "title": "Conformity Assessment and CE Marking",
        "family": "Assurance",
        "description": (
            "Carry out the applicable conformity assessment before placing a high-risk "
            "system on the market, draw up the EU declaration of conformity, affix the "
            "CE marking and register the system."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 43", "Article 47", "Article 48", "Article 49"],
            "ISO_42001": ["Clause 8.1"],
        },
    },
    {
        "title": "GPAI Model Obligations",
        "family": "Governance",
        "description": (
            "For general-purpose AI model providers: maintain technical documentation "
            "and information for downstream providers, implement a copyright policy and "
            "publish a training-content summary; for systemic-risk models add "
            "evaluation, adversarial testing, incident reporting and cybersecurity "
            "protection."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 53", "Article 55", "Article 56"],
            "NIST_AI_RMF": ["GOVERN-1.1", "MEASURE-2.3"],
        },
    },
    {
        "title": "Regulatory Sandbox Participation",
        "family": "Governance",
        "description": (
            "Where available, use AI regulatory sandboxes to test innovative systems "
            "under supervisory oversight before wider deployment."
        ),
        "mappings": {
            "EU_AI_ACT": ["Article 57", "Article 58"],
            "ISO_42001": ["Clause 8.1"],
        },
    },
]


def controls_by_family(conn: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
    """Group the stored control library by family (used by reports and the API)."""
    out: dict[str, list[dict[str, Any]]] = {}
    for control in list_controls(conn):
        out.setdefault(control.get("family") or "General", []).append(control)
    return out


def framework_coverage(conn: sqlite3.Connection) -> dict[str, int]:
    """How many stored controls map to each framework - a quick gap indicator."""
    coverage: dict[str, int] = {}
    for control in list_controls(conn):
        for framework, refs in (control.get("mappings") or {}).items():
            if refs:
                coverage[framework] = coverage.get(framework, 0) + 1
    return coverage


def coverage_gaps(conn: sqlite3.Connection, frameworks: Optional[Iterable[str]] = None) -> dict[str, list[str]]:
    """For each framework, list control titles that have NO mapping to it.

    This is the honest gap report: what the library does not yet cover, rather
    than a claim of completeness.
    """
    from . import frameworks as fw

    wanted = list(frameworks) if frameworks else list(fw.FRAMEWORKS)
    controls = list_controls(conn)
    gaps: dict[str, list[str]] = {name: [] for name in wanted}
    for control in controls:
        mapped = control.get("mappings") or {}
        for name in wanted:
            if not mapped.get(name):
                gaps[name].append(control["title"])
    return gaps
