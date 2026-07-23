# ai-redteam-platform

An open **AI Red Team Platform**: an authorized-testing control plane that
registers AI targets, runs a library of security & safety tests through a
**safe runner**, scores the results into risk-ranked findings, stores
redacted/hash-chained evidence, maps results to compliance frameworks, and
generates technical/executive/compliance reports. Pure Python standard library.

It **embeds** the sibling [`ai-redteam-evals`](../ai-redteam-evals) harness:
when that package is importable, tests can be delegated to its `EvalHarness`
(see `engine.run_via_redteam`); otherwise a vendored engine with the same
`Target` interface is used, so this repo is fully standalone.

> **Safety model** (the guardrails are the product): authorized scope only,
> target allowlists, no external calls (localhost endpoints only), rate limits,
> per-case timeouts, a kill switch, no destructive payloads, no real
> exfiltration, redacted + hashed evidence, and a tamper-evident audit log.

## Features (MVP)

- **Target registry** — AI systems under test with owner, type, tools, data
  sources, risk tier, and an **authorization gate**
- **Test library** — 12 cases mapped to **OWASP LLM Top 10**, **MITRE ATLAS**,
  and EU AI Act / NIST AI RMF / ISO 42001, each with remediation guidance
- **Safe runner** — authorization + scope check, rate limit, timeout, kill
  switch, audit; supports in-process and localhost HTTP targets
- **Scoring engine** — pass rate + severity-weighted residual risk + ranked findings
- **Evidence store** — redacted prompts/outputs, content hashes, hash-chained,
  with retention purge
- **Compliance mapping** — per-framework control coverage and failing controls
- **Reports** — technical, executive, compliance (Markdown) + JSON
- **HTTP API** for all of the above

## Quickstart

```bash
python3 examples/run_campaign.py        # offline demo (mock targets)

python3 -m ai_redteam_platform.seed     # seed sample targets
python3 -m ai_redteam_platform.run --port 8090
```

API:

```bash
curl -X POST localhost:8090/targets -d '{"name":"My App","risk_tier":"high"}'
curl -X POST localhost:8090/targets/<ID>/authorize -d '{"status":"authorized"}'
curl -X POST localhost:8090/campaigns -d '{"target_id":"<ID>","guarded":false}'
curl localhost:8090/campaigns/<CID>/report?format=executive
curl localhost:8090/compliance/<CID>
curl localhost:8090/evidence/verify
```

Test a target from the [`agent-redteam-range`](../agent-redteam-range): register
it with `"endpoint":"http://localhost:8091"` and run a campaign — the runner
calls its `/complete` endpoint (localhost only).

## Tests

```bash
python3 -m unittest discover -s tests
```

## License

Apache-2.0
