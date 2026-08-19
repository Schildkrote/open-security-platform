# OSP webhook → ODP ontology

Point OSP emitters at this receiver:

```bash
# terminal A
go run ./apps/webhook -addr 127.0.0.1:8091 -store /tmp/odp-webhook-store.json -token devtoken

# terminal B — simulate OSP IntegrationEvent POST
go test ./platform/events -run TestHTTPWebhook -count=1   # unit
# or curl:
curl -sS -X POST http://127.0.0.1:8091/hooks/osp \
  -H "Authorization: Bearer devtoken" \
  -H "Content-Type: application/json" \
  -d @- <<'JSON'
{
  "id": "demo-1",
  "time": "2026-08-19T00:00:00Z",
  "type": "finding.created",
  "source": "offensive/username-enum",
  "action": "add_finding",
  "subject": "alice",
  "refs": {},
  "data": {"summary": "username alice on github", "severity": "low"},
  "prev_hash": "genesis",
  "hash": "optional-when-strict-chain-false"
}
JSON
```

## OSP wiring

OSP Go emitter (`platform/events.New(source, urls)`):

```go
em := events.New("offensive/username-enum", []string{
  "http://127.0.0.1:8091/hooks/osp",
})
em.Emit("finding.created", "add_finding", "alice", nil, map[string]any{
  "summary": "username alice on github",
  "severity": "low",
})
```

Python OSP `HttpEmitter` — same URL list.

## Endpoints

| Path | Method | Role |
|---|---|---|
| `/hooks/osp` | POST | IntegrationEvent JSON |
| `/healthz` | GET | liveness |

Optional `-token` requires `Authorization: Bearer …`.  
`-strict-chain` verifies hash + prev_hash (single-producer only; default off for multi-source fan-in).

Events hydrate as `Finding` objects (+ optional `Person` from `subject`) via `connectors/osp`.
