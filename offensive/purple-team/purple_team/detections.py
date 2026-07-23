"""Detection rules and a mock SIEM that evaluates whether tests are detected.

The mock SIEM stands in for a real SIEM/EDR: a rule "fires" when a test maps to
the rule's technique and produces telemetry the rule consumes. Techniques with
no rule (or no matching telemetry) are detection gaps.
"""
from __future__ import annotations

from dataclasses import dataclass

from .tests import SafeTest


@dataclass(frozen=True)
class DetectionRule:
    id: str
    name: str
    technique_id: str
    platform: str               # "SIEM" | "EDR"
    logic: str
    data_sources: tuple[str, ...]


# Deliberately incomplete: techniques without a rule here are detection gaps.
DETECTION_RULES: list[DetectionRule] = [
    DetectionRule("DR-01", "Suspicious process creation", "T1059", "EDR",
                  "Alert on shell spawning from unusual parents.", ("Process Creation", "Command Execution")),
    DetectionRule("DR-02", "Scheduled task creation", "T1053", "EDR",
                  "Alert on new scheduled tasks/jobs.", ("Scheduled Job Creation",)),
    DetectionRule("DR-03", "Brute-force auth pattern", "T1110", "SIEM",
                  "Alert on repeated failed logins for one account.", ("Authentication Logs",)),
    DetectionRule("DR-04", "Network service scanning", "T1046", "SIEM",
                  "Alert on horizontal port/service scans.", ("Network Traffic",)),
    DetectionRule("DR-05", "Outbound data to rare destination", "T1048", "SIEM",
                  "Alert on large outbound transfers to uncategorized hosts.", ("Network Traffic",)),
    DetectionRule("DR-06", "Mass file modification", "T1486", "EDR",
                  "Alert on rapid bulk file modification/renames.", ("File Modification",)),
    DetectionRule("DR-07", "Periodic HTTPS beaconing", "T1071", "SIEM",
                  "Alert on regular-interval beacons to a single host.", ("Network Traffic",)),
]


def rules_for_technique(technique_id: str) -> list[DetectionRule]:
    return [r for r in DETECTION_RULES if r.technique_id == technique_id]


class MockSIEM:
    """Evaluates which detection rules fire for a given safe test."""

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self.rules = rules if rules is not None else DETECTION_RULES

    def evaluate(self, test: SafeTest) -> list[str]:
        fired: list[str] = []
        for rule in self.rules:
            if rule.technique_id != test.technique_id:
                continue
            if set(rule.data_sources) & set(test.expected_telemetry):
                fired.append(rule.id)
        return fired
