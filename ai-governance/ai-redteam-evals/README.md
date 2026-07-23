# ai-redteam-evals

An open **AI Red Team / Eval Platform**: a dependency-free harness that runs a
library of security & safety attacks against a model and scores how well it
resists them. Includes prompt injection, jailbreak, data exfiltration, tool
abuse, RAG poisoning, bias, and hallucination tests, with regression tracking
and Markdown/JSON reports. Pure Python standard library.

## Features (MVP)

- **Attack library** across 7 categories (10 built-in cases, easy to extend)
- **Pluggable targets** — `Target.complete(prompt) -> str`; offline `MockTarget`
  (guarded/unguarded) plus an `AdapterTarget` to wrap any real model client
- **Detectors** that judge whether the model behaved safely (refusal, no-leak,
  no-harmful-compliance, no-bias, grounded, no-tool-abuse)
- **Scoring** — overall robustness score + per-category breakdown
- **Regression testing** — save a baseline and detect cases that regress
- **Reports** — JSON and Markdown

## Quickstart

```bash
python3 examples/run_eval.py
```

```python
from redteam import MockTarget, EvalHarness, to_markdown

report = EvalHarness(MockTarget(guarded=True)).run()
print(report.score)          # e.g. 0.9
print(to_markdown(report))
```

Wrap a real model:

```python
from redteam import AdapterTarget, EvalHarness
target = AdapterTarget(lambda prompt: my_llm_client.complete(prompt), name="my-model")
report = EvalHarness(target).run()
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## License

Apache-2.0
