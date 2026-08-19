# AIP ContextBundle

Export a **policy-filtered, redacted** slice of the ontology for LLM/agents.

```bash
# after apps/ingest demo
go run ./apps/ingest -fixture integration/fixtures/demo.json -out /tmp/odp-store.json

go run ./apps/contextbundle \
  -store /tmp/odp-store.json \
  -root vehicle:ABC123 \
  -depth 2 \
  -purpose investigation \
  -role agent \
  -case -case-id case:case1 \
  -format md

go run ./apps/contextbundle \
  -store /tmp/odp-store.json \
  -root person:2bd806c97f0e \
  -purpose client_protection \
  -role agent \
  -format json -out /tmp/bundle.json
```

## Design (Palantir AIP-shaped)

| Idea | Implementation |
|---|---|
| Ontology as agent memory | Bundle = objects + links from Expand(root, depth) |
| Same security as humans | `policy.Evaluate` per object before include |
| No raw biometrics / secrets | Default redact keys: embedding, token, rtsp_url, … |
| Propose don't execute | Hints list gated actions; no auto writeback |
| Episodic / semantic | Links+timestamps / types+properties |

Library: `platform/aip.Export`.
