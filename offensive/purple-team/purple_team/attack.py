"""A structured subset of the MITRE ATT&CK technique library."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    description: str
    data_sources: tuple[str, ...] = ()  # telemetry needed to detect it


TECHNIQUES: list[Technique] = [
    Technique("T1566", "Phishing", "Initial Access",
              "Adversaries send phishing messages to gain access.",
              ("Email Gateway", "Endpoint", "Network Traffic")),
    Technique("T1059", "Command and Scripting Interpreter", "Execution",
              "Adversaries abuse command/script interpreters to execute commands.",
              ("Process Creation", "Command Execution")),
    Technique("T1053", "Scheduled Task/Job", "Persistence",
              "Adversaries abuse task scheduling to maintain persistence.",
              ("Scheduled Job Creation", "Process Creation")),
    Technique("T1078", "Valid Accounts", "Privilege Escalation",
              "Adversaries obtain and abuse credentials of existing accounts.",
              ("Authentication Logs", "Logon Session")),
    Technique("T1562", "Impair Defenses", "Defense Evasion",
              "Adversaries disable or interfere with security tooling.",
              ("Process Creation", "Service Metadata", "Windows Registry")),
    Technique("T1110", "Brute Force", "Credential Access",
              "Adversaries attempt to gain credentials via brute force.",
              ("Authentication Logs", "Network Traffic")),
    Technique("T1046", "Network Service Discovery", "Discovery",
              "Adversaries scan for open network services.",
              ("Network Traffic", "Command Execution")),
    Technique("T1021", "Remote Services", "Lateral Movement",
              "Adversaries use remote services to move laterally.",
              ("Logon Session", "Network Traffic", "Process Creation")),
    Technique("T1560", "Archive Collected Data", "Collection",
              "Adversaries compress/encrypt data prior to exfiltration.",
              ("File Creation", "Process Creation", "Command Execution")),
    Technique("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration",
              "Adversaries exfiltrate data over a non-C2 protocol.",
              ("Network Traffic", "Network Connection Creation")),
    Technique("T1486", "Data Encrypted for Impact", "Impact",
              "Adversaries encrypt data to interrupt availability (ransomware).",
              ("File Modification", "Process Creation", "Network Share Access")),
    Technique("T1071", "Application Layer Protocol", "Command and Control",
              "Adversaries communicate using application-layer protocols.",
              ("Network Traffic", "Network Connection Creation")),
]


def by_id(technique_id: str) -> Technique | None:
    return next((t for t in TECHNIQUES if t.id == technique_id), None)


def tactics() -> list[str]:
    seen: list[str] = []
    for t in TECHNIQUES:
        if t.tactic not in seen:
            seen.append(t.tactic)
    return seen
