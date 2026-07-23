"""ai-redteam-evals: offline AI red-team & eval harness."""
from .targets import Target, MockTarget, AdapterTarget
from .attacks import ATTACK_LIBRARY, AttackCase, cases_for, categories
from .detectors import REGISTRY, Judgment
from .harness import EvalHarness, EvalReport, CaseResult
from .report import to_json, to_markdown
from .regression import save_baseline, load_baseline, compare

__all__ = [
    "Target", "MockTarget", "AdapterTarget",
    "ATTACK_LIBRARY", "AttackCase", "cases_for", "categories",
    "REGISTRY", "Judgment",
    "EvalHarness", "EvalReport", "CaseResult",
    "to_json", "to_markdown",
    "save_baseline", "load_baseline", "compare",
]
