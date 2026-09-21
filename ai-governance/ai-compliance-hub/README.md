# ai-compliance-hub

An open **AI Compliance Evidence Hub** (AI GRC): a control library mapped
across EU AI Act, NIST AI RMF, ISO/IEC 42001 and SOC 2 (AI), plus an AI system
inventory, risk register, model/system cards, and a tamper-evident evidence
trail. Pure Python standard library (sqlite3 + http.server) — no dependencies.

## Features (MVP)

- **AI system inventory** with owners, types, and risk levels
- **Control library** with a **cross-framework mapping engine** (one control →
  many frameworks; query "which controls satisfy EU_AI_ACT?")
- **Framework citation registry + validator** — EU AI Act articles and
  ISO/IEC 42001 Annex A controls are checked against a verified allow-list, so
  a mis-cited reference fails the build instead of silently poisoning an
  evidence package
- **Coverage & gap reporting** — how many controls map to each framework, and
  honestly, which controls map to none
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

curl localhost:8082/frameworks                       # registry + what it validates
curl localhost:8082/controls/coverage                # controls per framework/family
curl localhost:8082/controls/gaps                    # honest gap report
curl localhost:8082/controls/validate                # citation validation result
```

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/systems` · POST `/systems` | AI system inventory |
| GET | `/systems/:id/card` | System card (Markdown) |
| GET | `/controls` (`?framework=`) | Control library / mapping engine |
| POST | `/controls` | Add a control with mappings (rejects invalid citations, 400) |
| GET | `/controls/coverage` | Control counts per framework and family |
| GET | `/controls/gaps` (`?framework=`) | Controls with no mapping to a framework |
| GET | `/controls/validate` | Validate the shipped library's citations |
| GET | `/frameworks` | Framework registry: labels, counts, catalog |
| GET | `/risks` · POST `/risks` | Risk register |
| GET | `/evidence` · POST `/evidence` | Evidence trail |
| GET | `/evidence/verify` | Verify hash-chain integrity |
| POST | `/cards/model` | Render a model card from metadata |

## Framework citation validation

Control libraries rot: a draft article number survives a renumbering, a control
ID gets invented. In a compliance product a wrong citation is worse than none —
it produces evidence packages auditors reject.

`compliance_hub/frameworks.py` is therefore the single source of truth for which
references are legal:

| Framework | Validation | Scope registered |
|---|---|---|
| `EU_AI_ACT` | explicit allow-list + titles | 39 articles/annexes, OJ-published numbering (Reg. (EU) 2024/1689) |
| `ISO_42001` | explicit allow-list + titles | 38 Annex A controls (A.2–A.10) + 12 clauses |
| `NIST_AI_RMF` | shape + category bounds | GOVERN 1–6, MAP 1–5, MEASURE 1–4, MANAGE 1–4 |
| `SOC2_AI` | shape + family bounds | CC1–CC9, A1, PI1, C1, P1–P8 |
| `OWASP_LLM_TOP10` | explicit allow-list | LLM01–LLM10 |

Known-bad citations are registered with the reason they are wrong, so the error
message tells you the right one:

```python
>>> frameworks.validate_eu_ai_act("Article 62")
CitationError: EU_AI_ACT 'Article 62' is a known-bad citation:
  pre-OJ draft numbering; serious-incident reporting is Article 73
```

!!! warning "EU AI Act numbering"
    Serious-incident reporting is **Article 73** and post-market monitoring is
    **Article 72** in the OJ-published Regulation. Older drafts, blog posts and
    GRC exports still circulate Article 61/62. Treat the OJ numbers — the ones
    registered here — as authoritative.

See the module docstring in `compliance_hub/frameworks.py` for the **provenance**
of every registry entry (sources + the date they were checked), and note that
ISO/IEC 42001 is a paid standard — its Annex A titles here come from public
secondary enumerations, so confirm against your own copy before an audit.

Validation is **not** enforced inside `controls.add_control`, which must stay
permissive so third-party OSCAL catalogs can be imported. It is enforced (a) on
the shipped library by `tests/test_frameworks.py` and (b) at the
`POST /controls` API boundary.

### Library scope — honest

46 controls across 8 families, citing 147 distinct framework references. This is
a *working library* covering what an AI team is most often asked about, **not a
complete transcription of any framework**. Use `GET /controls/gaps` to see what
is unmapped rather than assuming coverage. Remaining gaps are tracked in
`NEXT_STEPS.md`.

The registry itself is pinned by **non-circular** anchor tests
(`RegistryAnchorTests`): validating the library against the registry alone would
pass even with a wrong registry — it did exactly that once, when `Article 75`
was mis-titled as sandboxes and a non-existent `A.3.4` was registered. The
anchors assert externally verified facts about the registry (Art 75 is market
surveillance, sandboxes are Arts 57/58, Annex A has exactly 38 controls with
per-objective counts 3+2+5+4+9+5+4+3+3, A.3 stops at A.3.3), so a stale or
invented entry fails the build.

## Tests

```bash
python3 -m unittest discover -s tests    # 64 tests
```

## License

AGPL-3.0-only
