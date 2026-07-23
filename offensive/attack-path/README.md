# attack-path

An open **Attack Path Management Platform**: model exposures, identities,
permissions, vulnerabilities, data stores and crown-jewel assets as a directed
graph, then find realistic **attack paths**, score their risk, and identify the
**choke points** whose remediation breaks the most paths. Pure Go standard
library; scenarios are plain JSON (no cloud APIs required).

## Features (MVP)

- **Graph engine** — typed nodes (exposure/asset/identity/permission/vuln/
  data/critical) and weighted directed edges
- **JSON scenario ingestion** with validation
- **Path finding** — enumerates simple paths from exposures to critical assets
  (depth-bounded, cycle-safe), ranked by risk
- **Risk scoring** — multiplies edge traversal likelihoods and node
  exploitability, so longer/harder paths score lower (0..1)
- **Choke-point & remediation analysis** — ranks nodes/edges by how many attack
  paths they lie on (cutting a high-count choke point breaks the most paths)
- **Output** — human-readable text, JSON report, and Graphviz **DOT**

## Quickstart

```bash
go run . -scenario examples/scenario.json -format text
go run . -scenario examples/scenario.json -format json
go run . -scenario examples/scenario.json -format dot > attack_path.dot
```

Flags: `-scenario`, `-format text|json|dot`, `-maxdepth`, `-top`.

The bundled scenario models a cloud IAM privilege-escalation chain (public web
app → RCE → service account → secrets/IAM misconfig → cloud admin → prod DB /
domain admin). Analysis surfaces `cloud-admin` as the top choke point.

## Tests

```bash
go test ./...
```

## License

Apache-2.0
