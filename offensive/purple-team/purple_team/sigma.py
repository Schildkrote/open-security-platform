"""Mapping from MITRE ATT&CK techniques to Sigma detection rules (Phase 4).

Sigma (SigmaHQ) is the vendor-neutral detection-rule format. This maps the
purple-team technique library to representative Sigma rules so detection coverage
can be reasoned about ('technique T has no rule' = a detection gap) and rules can
be exported. The rule set is a curated subset; extend SIGMA_RULES to broaden it.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SigmaRule:
    id: str
    title: str
    technique: str  # ATT&CK technique id (e.g. "T1566")
    logsource: str  # "<product>/<category>"
    status: str = "experimental"


# A curated subset of representative Sigma rules keyed to the technique library.
SIGMA_RULES: list[SigmaRule] = [
    SigmaRule("3d1c4b8a", "Phishing Attachment Execution", "T1566", "windows/process_creation"),
    SigmaRule("7a2e9f1b", "Suspicious Scripting Interpreter Spawn", "T1059", "windows/process_creation"),
    SigmaRule("b5c8d2e4", "Scheduled Task Creation", "T1053", "windows/security"),
    SigmaRule("c9f1a3d7", "Valid Account Abuse - Unusual Logon", "T1078", "windows/security"),
    SigmaRule("e2b4c6a8", "Security Tool Disabled", "T1562", "windows/process_creation"),
    SigmaRule("f1a3b5c7", "Brute Force - Multiple Failed Logons", "T1110", "windows/security"),
    SigmaRule("a4c6e8b2", "Network Service Scanning", "T1046", "network/connection"),
    SigmaRule("d8f2a4c6", "Remote Service Lateral Movement", "T1021", "windows/security"),
    SigmaRule("b6d8f2a4", "Data Archived Before Exfiltration", "T1560", "windows/process_creation"),
    SigmaRule("c2e4a6b8", "Exfiltration Over Alternative Protocol", "T1048", "network/connection"),
    SigmaRule("e6a8c2d4", "Ransomware File Encryption Activity", "T1486", "windows/file_event"),
    SigmaRule("f4b6d8e2", "C2 Application Layer Beaconing", "T1071", "network/proxy"),
]

_BY_TECHNIQUE: dict[str, list[SigmaRule]] = {}
for _rule in SIGMA_RULES:
    _BY_TECHNIQUE.setdefault(_rule.technique, []).append(_rule)


def rules_for(technique_id: str) -> list[SigmaRule]:
    """All Sigma rules covering a technique."""
    return list(_BY_TECHNIQUE.get(technique_id, []))


def techniques_with_rules() -> set[str]:
    """Technique ids that have at least one Sigma rule."""
    return set(_BY_TECHNIQUE)


def coverage(technique_ids: list[str]) -> dict[str, bool]:
    """For each technique, whether at least one Sigma rule covers it."""
    return {tid: tid in _BY_TECHNIQUE for tid in technique_ids}


def gaps(technique_ids: list[str]) -> list[str]:
    """Techniques with no Sigma rule (detection coverage gaps)."""
    return [tid for tid in technique_ids if tid not in _BY_TECHNIQUE]


def to_sigma_yaml(rule: SigmaRule) -> str:
    """Render a minimal Sigma-rule YAML stub."""
    product, _, category = rule.logsource.partition("/")
    return (
        f"title: {rule.title}\n"
        f"id: {rule.id}\n"
        f"status: {rule.status}\n"
        f"tags:\n"
        f"  - attack.{rule.technique.lower()}\n"
        f"logsource:\n"
        f"  product: {product}\n"
        f"  category: {category}\n"
    )
