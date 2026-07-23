# Next Steps — purple-team

## Real detection validation
- Integrate real **SIEM/EDR** (Splunk, Elastic, Wazuh, Sentinel) to confirm
  detections actually fire, replacing the mock SIEM.
- Correlate test timestamps with real alerts/logs to compute true detection rate
  and mean-time-to-detect.
- Execute safe tests via `agent-sandbox` and **Atomic Red Team** runners.

## Coverage engineering
- Import the **full ATT&CK** matrix (techniques, sub-techniques, data sources).
- Map existing detection rules (Sigma/SPL/KQL) to techniques automatically.
- **Detection-as-code** workflow: author, test, and tune rules with CI.
- ATT&CK Navigator export (layer JSON).

## Exercises
- Multi-day exercise orchestration, roles, approvals, and scheduling.
- **AI red-team integration**: run `ai-redteam-platform` attacks and validate
  that AI guardrails/SIEM detect them (AI purple teaming).
- Metrics over time: coverage trend, detection-rate trend, tuning backlog.

## Platform
- Web dashboard, Postgres backend, multi-tenant workspaces.
- Link gaps to findings in `pentest-manager` and cases in `open-soar`.
