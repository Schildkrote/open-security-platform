# open-decision-platform

> Decision-centric **ontology operating system**: a governed, typed knowledge
> graph + pipelines + permissioned actions + AI-ready context.
> Inspired by the *shape* of Palantir’s Ontology (Gotham/Foundry) — not a clone,
> not affiliated.

> [!WARNING]
> Experimental / **v0.1 scaffold**. Mock-first. Law-enforcement and biometric connectors require a
> documented lawful basis (warrant / statutory authority / consent depending on
> jurisdiction). Do not deploy without independent legal review.

> [!NOTE]
> Independent open-source project. Connects to
> [open-security-platform](https://github.com/Schildkrote/open-security-platform)
> and
> [open-biometric-platform](https://github.com/Schildkrote/open-biometric-platform)
> via adapters — it does not re-implement their internals.

## What this is (and is not)

| Is | Is not |
|---|---|
| Typed objects + links (digital twin nouns) | A data lake or pure SQL warehouse |
| Permissioned **actions** that change state | A BI dashboard only |
| Purpose-aware **policy** on every read/write | A bag of OSINT scrapers |
| Connector fabric into OSP / OBP / ALPR / case systems | A Palantir product or drop-in replacement |
| Audit + provenance first | Untargeted mass surveillance |

Palantir’s product insight (from public docs / your research brief): the Ontology
models **decisions** as Data + Logic + Action + Security. This repo implements a
minimal open core of that pattern so humans and agents can reason on the same
governed graph.

## Architecture

```
                 ┌─────────────────────────────────────────┐
                 │     open-decision-platform (ODP)        │
                 │  ontology · policy · actions · audit    │
                 └───────────────┬─────────────────────────┘
           ┌─────────────────────┼─────────────────────┐
           v                     v                     v
    connectors/osp         connectors/obp        connectors/alpr
    (attack-path,          (match hits,          (vehicle plate
     credential-intel,      person graph,         events, hotlist
     live-recon events)     enrol status)         alerts — LE basis)
           │                     │                     │
           └─────────────────────┴─────────────────────┘
                                 v
                    apps/graph · apps/dossier · AIP-ready exports
```

## Components

| Path | Lang | Role |
|---|---|---|
| `platform/ontology` | Go | Object types, properties, link types, object store, queries |
| `platform/policy` | Go | Purpose / role / classification gates (decision-time) |
| `platform/actions` | Go | Permissioned verbs with writeback + audit |
| `platform/audit` | Go | Hash-chained decision/action log |
| `platform/events` | Go | OSP IntegrationEvent webhook receiver + hash helpers |
| `platform/packs` | Go | Jurisdiction pack loader (US 4A, GDPR, AI Act) — **enforced in tests/e2e demos; not default alpr/actions/webhook path yet** |
| `platform/aip` | Go | ContextBundle export for LLM/agents |
| `connectors/osp` | Go | Ingest IntegrationEvents / OSINT findings from OSP |
| `connectors/obp` | Go | Ingest biometric match hits + person nodes from OBP |
| `connectors/alpr` | Go | Vehicle plate events + hotlist (Flock-like *capability*, LE-gated) |
| `connectors/osint` | Go | Generic finding envelope |
| `apps/graph` | Go | Link analysis CLI (paths, expand, export) |
| `apps/dossier` | Go | Object dossier renderer (JSON/Markdown) |
| `apps/ingest` | Go | Batch hydrate objects from connector payloads |
| `apps/webhook` | Go | HTTP server: POST /hooks/osp → ontology |
| `apps/contextbundle` | Go | Export redacted agent ContextBundle |
| `packs/*.json` | JSON | Jurisdiction overlays |
| `integration/` | Go | End-to-end mock: OSP+OBP+ALPR → ontology → action |

## Docs

- [OSP webhook](docs/osp-webhook.md)
- [Policy packs](docs/policy-packs.md)
- [AIP ContextBundle](docs/aip-contextbundle.md)
- [Flock notes](docs/flock-safety.md)
- [Ontology ecosystem](docs/ontology-and-ecosystem.md)

## Quickstart

```bash
make verify

# Hydrate a tiny twin and run a hotlist action (all mock)
go run ./apps/ingest -fixture integration/fixtures/demo.json
go run ./apps/graph -store /tmp/odp-store.json -from person:alice -depth 2
go run ./apps/dossier -store /tmp/odp-store.json -id person:alice
go run ./apps/contextbundle -store /tmp/odp-store.json -root vehicle:ABC123 -purpose investigation -role agent -case
# OSP webhook (separate terminal): go run ./apps/webhook -addr 127.0.0.1:8091 -token dev
```

## Lawful basis (short)

| Domain | Typical basis in this design |
|---|---|
| Client protection biometrics (OBP) | Explicit client consent |
| LE ALPR hotlist match | Statutory LE authority + case/warrant where required |
| Cross-agency graph share | MoU + purpose limitation + need-to-know |
| Commercial OSP findings | Contract + legitimate interest / consent per regime |

`platform/policy` evaluates purpose × role × object classification on every
read and action. ALPR bulk historical queries default to **requires_warrant**
outside an active case context (see Norfolk-style ALPR warrant rulings in the
US — jurisdiction packs are data, not hard-coded US law).

## Flock Safety → what we build (lawful)

Public picture of Flock: fixed ALPR cams (“vehicle fingerprint”), gunshot
detection, drones, searchable network for police/HOA, NCIC/hotlist alerts.
Critics frame it as mass surveillance; some courts treat long-term ALPR
location DBs as Fourth Amendment searches needing warrants.

**We do not build a shadow Flock network.** We build the *capability modules*
agencies or authorized operators would run **on their own sensors** under
their legal regime:

1. `connectors/alpr` — plate + vehicle-attr events, hotlist, retention policy
2. Policy pack — warrant/case-id gates for historical pattern-of-life
3. Ontology object types — Vehicle, PlateRead, Case, Warrant, Officer, Sensor
4. Actions — `open_case`, `issue_alert`, `request_warrant_package`, `task_sensor`
5. Optional gunshot/drone object types as stubs (no hardware)

HOA/private bulk ALPR without LE authority is **out of product scope** here.

## Palantir Ontology → what else we build

| Palantir concept | ODP module |
|---|---|
| Object types / links | `platform/ontology` |
| OMS-like type registry | `ontology.Registry` |
| Object set queries | `Store.Query` / `ObjectSet` |
| Actions service | `platform/actions` |
| Security policies | `platform/policy` |
| Pipeline Builder | `apps/ingest` + connector normalize (v1); Flink later |
| AIP agents on Ontology | Export `ContextBundle` for LLMs (typed, redacted) |
| Graph / dossier UX | `apps/graph`, `apps/dossier` |
| Apollo | **not shipped** (`deploy/` absent; k8s later) |

## Safety

See [AGENTS.md](AGENTS.md). Mock default. Treat as **v0.1-scaffold**. No credentials in git. No open-cam
or untargeted biometric mass ID. Connectors fail closed without policy pass.
