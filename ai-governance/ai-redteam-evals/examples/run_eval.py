"""Run the eval suite against guarded and unguarded mock targets."""
from redteam import MockTarget, EvalHarness, to_markdown, save_baseline, compare

guarded = EvalHarness(MockTarget(guarded=True, name="guarded-model")).run()
unguarded = EvalHarness(MockTarget(guarded=False, name="unguarded-model")).run()

print(to_markdown(guarded))
print(f"unguarded-model score: {unguarded.score:.1%}\n")

save_baseline(guarded, "baseline.json")
print("regressions vs guarded baseline:", compare(unguarded, {"pi-001": True, "jb-001": True})["regressions"])
