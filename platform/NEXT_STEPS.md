# NEXT_STEPS — platform

## Done
- ontology store, policy, audit, actions
- Jurisdiction policy packs as JSON (`packs/`) — **and now wired into the
  hot path**: `connectors/alpr` (`Ingestor.Eval`), `platform/actions`
  (`Engine.Eval`), `platform/events` webhook (`Handler.Eval` + `--packs`
  flag on `apps/webhook`). Default remains core `policy.Evaluate`
  (nil Eval); pack enforcement is opt-in per path. Pinned by
  `integration/packs_hotpath_test.go`.

## Next
- SQLite driver (durable store behind the ontology)
- OBP exporter: real OBP match hit → ODP webhook (live bus)
- Object set watch (channel subscriptions)
- Update AGENTS.md scaffold-honesty note (protected file, needs user approval)