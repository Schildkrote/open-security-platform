# Next Steps — attack-path

## Real data ingestion
- **Cloud connectors** (AWS/GCP/Azure IAM, asset inventory, security groups) to
  build the graph from live environments instead of JSON.
- **Active Directory / Entra / Okta** ingestion for identity attack paths
  (BloodHound-style analysis).
- Vulnerability + exposure feeds (CVEs, internet-facing scans) and data
  classification labels.

## Analysis depth
- **Weighted/shortest-path** and probabilistic (Bayesian) path scoring.
- **Lateral movement** modeling, credential-reuse edges, and multi-stage paths.
- **What-if simulation**: show how remediating a node/edge changes the path set.
- Map paths to MITRE ATT&CK (integrate `purple-team`) and findings in
  `pentest-manager`.

## Visualization & ops
- Interactive graph UI (Cytoscape/D3) and ATT&CK Navigator overlays.
- Continuous graph rebuild + drift alerts; attack-path trend over time.
- Export remediation as tickets to `open-soar` / Jira.

## Platform
- Graph database backend (Neo4j) for very large estates, multi-tenant, RBAC.
- Prioritize paths by business criticality and compensating controls.
