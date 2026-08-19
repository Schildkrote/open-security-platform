# Palantir Ontology → open-decision-platform

Your research brief is the design north star. Mapping:

| Palantir concept | ODP now | Later |
|---|---|---|
| Object Types / Links | `platform/ontology` Registry + Store | schema migration UI |
| OMS | `Registry` | versioned type registry service |
| Object DB (Phonograph) | in-memory + JSON snapshot | SQLite/Postgres/Iceberg |
| Object Set Service | `QueryObjects`, `Expand`, `Path` | live subscriptions |
| Actions | `platform/actions` | writeback connectors (ITSM, CAD) |
| Security | `platform/policy` purpose×role×class | ABAC + classification lattices |
| Pipeline Builder | `apps/ingest` fixtures | Spark/Flink jobs |
| AIP on Ontology | ContextBundle export (planned) | agent tool APIs |
| Graph / Dossier | `apps/graph`, `apps/dossier` | Workshop-like web |
| Apollo | `deploy/` notes | air-gap helm |

## Why a **new repo** (not inside OSP)

- OSP = security product monorepo (identity, offensive, AI sec, SOC).
- OBP = biometric special-category regime.
- **ODP** = cross-domain decision OS that *connects* both + ALPR/case systems.
  Different abstraction (digital twin + actions), different customers (LE
  fusion / corporate security ops / client-protection SOC).

## Tool graph

```
open-security-platform          open-biometric-platform
 (findings, attack-path,         (match hits, person graph,
  credential-intel, …)            enrol status, CCTV auth)
         \                         /
          \                       /
           v                     v
            open-decision-platform
         ontology ← policy ← actions ← audit
                    ^
                    |
              connectors/alpr
           (agency-owned sensors)
```

Events flow **into** ODP; ODP does not replace OSP/OBP CLIs.
