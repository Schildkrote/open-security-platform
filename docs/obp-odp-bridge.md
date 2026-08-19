# OBP → ODP Bridge (live)

One-way, pseudonym-only bridge: OBP match hits become ODP ontology objects.
Raw face bytes never leave OBP.

## Flow

```
biometric-train  (Gallery.identify)
   │  scripts/export_odp.py  — hash-chained ODP IntegrationEvent per hit
   ▼  POST /hooks/osp  (Bearer token optional)
ODP apps/webhook — packs.Engine on the hot path (jurisdiction-gated write)
   ▼
ontology (BiometricHit + Person(pseudo), associated_with)  → SQLite store
```

## Run it

```bash
# ODP side: webhook with SQLite + jurisdiction packs + policy context
go run ./apps/webhook -addr 127.0.0.1:8091 \
    -store /tmp/odp-store.sqlite \
    -packs packs \
    -purpose client_protection -role client_app
```

```bash
# OBP side: enrol + probe + export (offline mode prints JSON to stdout)
python3 -m train.cli --store g.json enrol --client alice --hashes "web-77"
python3 scripts/export_odp.py --store g.json --probes probes.json \
    --url http://127.0.0.1:8091/hooks/osp --token ***
```

## Contract

- Event envelope = ODP `platform/events.IntegrationEvent`;
  `hash = sha256(canonical JSON, hash zeroed)` — canonical = sorted keys,
  compact separators. Cross-language digest is pinned in
  `biometric-train/tests/test_export_odp.py` (golden value generated with a
  verbatim Go copy of ODP `events.Digest`).
- Policy: webhook ingestion is a **gated write** (`Handler.Pol` +
  `Handler.Eval`). OBP hits land as `BiometricHit`; the `gdpr-biometric`
  pack allows `client_protection` for roles `client_app|analyst|admin|agent`
  and denies `research`/`patrol_alert` for biometric objects.
- Store: `apps/webhook` auto-selects SQLite (`.sqlite`) vs JSON by
  extension; `ontology.LoadSQLite/SaveSQLite` mirror the JSON snapshot.
- Verified live 2026-08-19: 2 OBP hits → 2× HTTP 200 → 2 `BiometricHit`
  rows + 1 `Person(pseudo)` + 2 `associated_with` links in SQLite.