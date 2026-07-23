"""Safe, authorized test cases mapped to ATT&CK techniques.

These describe how to *safely* exercise a technique (benign/canary actions, no
destructive payloads) so the blue team can confirm detections fire. Modeled on
the Atomic Red Team approach but constrained to non-destructive actions.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SafeTest:
    id: str
    technique_id: str
    name: str
    description: str
    safe_command: str                 # benign action that generates telemetry
    expected_telemetry: tuple[str, ...]  # log sources that should be produced


SAFE_TESTS: list[SafeTest] = [
    SafeTest("PT-1566", "T1566", "Send benign test phishing email",
             "Send a clearly-labeled simulation email to a consented test mailbox.",
             "send-simulated-phish --to test-user --label TRAINING",
             ("Email Gateway",)),
    SafeTest("PT-1059", "T1059", "Spawn benign shell command",
             "Run a harmless command to generate process-creation telemetry.",
             "echo purple-team-canary",
             ("Process Creation", "Command Execution")),
    SafeTest("PT-1053", "T1053", "Create canary scheduled task",
             "Create a no-op scheduled task tagged for the exercise, then remove it.",
             "create-scheduled-task --name pt-canary --action echo",
             ("Scheduled Job Creation",)),
    SafeTest("PT-1078", "T1078", "Log in with a test account",
             "Authenticate using a dedicated test account to produce logon telemetry.",
             "login --user pt-test-account",
             ("Authentication Logs",)),
    SafeTest("PT-1562", "T1562", "Attempt to query security service status",
             "Read (not modify) the status of a security service to test monitoring.",
             "query-service-status --name edr-agent",
             ("Process Creation", "Service Metadata")),
    SafeTest("PT-1110", "T1110", "Low-rate auth attempts against test account",
             "Generate a few failed logins against a locked-down test account.",
             "auth-attempts --user pt-test-account --count 3",
             ("Authentication Logs",)),
    SafeTest("PT-1046", "T1046", "Scan a lab subnet for services",
             "Perform a service scan limited to the authorized lab subnet.",
             "scan-services --scope lab-subnet",
             ("Network Traffic",)),
    SafeTest("PT-1021", "T1021", "Initiate a benign remote session to lab host",
             "Open an authorized remote session to a designated lab host.",
             "remote-session --host lab-target",
             ("Logon Session", "Network Traffic")),
    SafeTest("PT-1560", "T1560", "Archive a canary file",
             "Compress a small canary file to generate archive telemetry.",
             "archive --file canary.txt",
             ("File Creation", "Process Creation")),
    SafeTest("PT-1048", "T1048", "Upload canary to authorized endpoint",
             "Send a canary file to an authorized internal collection endpoint.",
             "upload-canary --to authorized-sink",
             ("Network Traffic",)),
    SafeTest("PT-1486", "T1486", "Simulate file-rename activity (no encryption)",
             "Generate file-modification telemetry without encrypting real data.",
             "simulate-file-activity --dir lab-share --canary",
             ("File Modification", "Process Creation")),
    SafeTest("PT-1071", "T1071", "Beacon to an authorized C2 sink",
             "Send periodic HTTPS check-ins to an authorized lab C2 sink.",
             "beacon --sink authorized-c2 --interval 60",
             ("Network Traffic",)),
]


def tests_for_technique(technique_id: str) -> list[SafeTest]:
    return [t for t in SAFE_TESTS if t.technique_id == technique_id]
