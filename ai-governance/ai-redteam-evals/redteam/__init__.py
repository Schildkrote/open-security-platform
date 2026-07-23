"""ai-redteam-evals: offline AI red-team & eval harness."""
from .attacks import ATTACK_LIBRARY, AttackCase, cases_for, categories
from .detectors import REGISTRY, Judgment
from .harness import CaseResult, EvalHarness, EvalReport
from .regression import compare, load_baseline, save_baseline
from .report import to_json, to_markdown
from .targets import AdapterTarget, MockTarget, Target

__all__ = [
    "Target", "MockTarget", "AdapterTarget",
    "ATTACK_LIBRARY", "AttackCase", "cases_for", "categories",
    "REGISTRY", "Judgment",
    "EvalHarness", "EvalReport", "CaseResult",
    "to_json", "to_markdown",
    "save_baseline", "load_baseline", "compare",
]
