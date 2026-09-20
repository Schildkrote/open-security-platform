# purple-team

An open **Purple Team Platform**: connect red-team tests to blue-team
detections. Provides an ATT&CK technique library, **safe** (non-destructive)
test cases, a detection coverage matrix, a mock SIEM that records detection
evidence, gap analysis with tuning recommendations, an exercise timeline, and a
coverage report. Pure Python standard library.

## Features (MVP)

- **ATT&CK technique library** — 12 techniques across the kill chain, each with
  the data sources needed to detect it
- **Safe test cases** — one authorized, non-destructive test per technique
  (canary/benign actions, Atomic-Red-Team style)
- **Detection coverage matrix** — technique × detection status (detected/gap)
- **Mock SIEM** — evaluates which detection rules fire for each test (stands in
  for a real SIEM/EDR)
- **Gap analysis + recommendations** — techniques without detection, with the
  telemetry to enable and the rule to author
- **Exercise runner** — runs the tests and builds a red→blue timeline with
  detection evidence and a detection rate
- **Coverage report** — Markdown dashboard (matrix, gaps, recommendations,
  exercise results)

## Quickstart

```bash
python3 examples/run_exercise.py
```

```python
from purple_team import run_exercise, coverage_report, coverage_percent, gaps
result = run_exercise()
print(coverage_percent(), result.detection_rate, len(gaps()))
print(coverage_report(result))
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## License

AGPL-3.0-only
