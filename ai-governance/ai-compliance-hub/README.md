# ai-compliance-hub

An open **AI Compliance Evidence Hub** (AI GRC): a control library mapped
across EU AI Act, NIST AI RMF, ISO/IEC 42001 and SOC 2 (AI), plus an AI system
inventory, risk register, model/system cards, and a tamper-evident evidence
trail. Pure Python standard library (sqlite3 + http.server) — no dependencies.

## Features (MVP)

- **AI system inventory** with owners, types, and risk levels
- **Control library** with a **cross-framework mapping engine** (one control →
  many frameworks; query "which controls satisfy EU_AI_ACT?")
- **Risk register** with likelihood × impact scoring
- **Model & system card generator** (Markdown)
- **Evidence collector** with a **hash-chained audit trail** + integrity verifier
- **HTTP API** for all of the above

## Quickstart

```bash
# Seed the control library + a sample system
python3 -m compliance_hub.seed

# Run the API on :8082
python3 -m compliance_hub.run --port 8082
```

Example calls:

```bash
curl localhost:8082/controls?framework=EU_AI_ACT     # controls for a framework
curl localhost:8082/systems                          # AI system inventory
curl -X POST localhost:8082/risks -d '{"title":"prompt injection","likelihood":4,"impact":4}'
curl -X POST localhost:8082/evidence -d '{"content":"control reviewed","source":"audit"}'
curl localhost:8082/evidence/verify                  # {"valid": true}
curl localhost:8082/systems/<ID>/card                # rendered system card
```

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/systems` · POST `/systems` | AI system inventory |
| GET | `/systems/:id/card` | System card (Markdown) |
| GET | `/controls` (`?framework=`) | Control library / mapping engine |
| POST | `/controls` | Add a control with mappings |
| GET | `/risks` · POST `/risks` | Risk register |
| GET | `/evidence` · POST `/evidence` | Evidence trail |
| GET | `/evidence/verify` | Verify hash-chain integrity |
| POST | `/cards/model` | Render a model card from metadata |

## Tests

```bash
python3 -m unittest discover -s tests
```

## License

Apache-2.0
