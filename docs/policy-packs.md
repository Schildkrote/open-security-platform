# Jurisdiction policy packs

JSON overlays on `platform/policy` loaded by `platform/packs`.

| Pack | File | Intent |
|---|---|---|
| US 4A ALPR | `packs/us-4a-alpr.json` | Historical plate/location queries need warrant context |
| GDPR biometric | `packs/gdpr-biometric.json` | Special-category hits; client_protection allow; research deny |
| EU AI Act RBI | `packs/eu-ai-act-rbi.json` | Patrol biometric deny; investigation needs case |

```go
p, _ := packs.Load("packs/us-4a-alpr.json")
eng := packs.NewEngine(p)
d := eng.Evaluate(policy.Request{
  Purpose: policy.PurposePatternOfLife,
  Role: policy.RoleOfficer,
  ObjectType: "PlateRead",
  Action: "query_historical",
})
// d.Outcome == require_warrant without HasWarrant
```

```bash
# load all packs
go test ./platform/packs -count=1
```

Packs are **product policy data**, not legal advice. Replace/extend with counsel-approved matrices per deployment.

## Runtime wiring (honest)

As of v0.1, packs are exercised by `platform/packs` tests and `integration/e2e_test.go`.
Production-facing paths (`connectors/alpr`, `platform/actions`, `apps/webhook`) call
`policy.Evaluate` directly. Integrating `packs.NewEngine` on those paths is required
before claiming jurisdiction-pack enforcement end-to-end.
