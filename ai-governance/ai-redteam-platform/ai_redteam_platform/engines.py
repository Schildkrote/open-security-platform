"""External red-team engine adapters (Phase 3): NVIDIA Garak, promptfoo, and the
built-in ai-redteam-evals harness, behind a common ``EngineAdapter`` interface.

The Real adapters (Garak, promptfoo) require the respective tool to be installed;
``available()`` reports this and ``run()`` raises a clear error otherwise, so the
offline/mock model is never broken. Selecting an engine never changes the default
offline behaviour (the embedded evals harness).
"""
from __future__ import annotations

import shutil
from typing import Protocol

from .engine import CaseOutcome, Target, redteam_available, run_via_redteam


class EngineAdapter(Protocol):
    """A red-team engine that runs cases against a target and yields outcomes."""

    name: str

    def available(self) -> bool: ...
    def run(self, target: Target, cases: list) -> list[CaseOutcome]: ...


class EvalsAdapter:
    """The embedded ai-redteam-evals harness (default engine)."""

    name = "ai-redteam-evals"

    def available(self) -> bool:
        return redteam_available()

    def run(self, target: Target, cases: list) -> list[CaseOutcome]:
        return run_via_redteam(target, cases)


class GarakAdapter:
    """NVIDIA Garak LLM vulnerability scanner (Real; requires ``garak``)."""

    name = "garak"

    def available(self) -> bool:
        try:
            import garak  # noqa: F401
        except Exception:  # noqa: BLE001 - any import failure means unavailable
            return False
        return True

    def run(self, target: Target, cases: list) -> list[CaseOutcome]:
        if not self.available():
            raise RuntimeError("garak is not installed (pip install garak)")
        # A full integration configures garak probes/generators and maps their
        # results onto CaseOutcome; that mapping is wired at deploy time.
        raise NotImplementedError("garak probe mapping is configured at deploy time")


class PromptfooAdapter:
    """promptfoo red-teaming CLI (Real; requires the ``promptfoo`` binary)."""

    name = "promptfoo"

    def available(self) -> bool:
        return shutil.which("promptfoo") is not None

    def run(self, target: Target, cases: list) -> list[CaseOutcome]:
        if not self.available():
            raise RuntimeError("promptfoo is not installed (npm i -g promptfoo)")
        raise NotImplementedError("promptfoo run is configured at deploy time")


ENGINES: dict[str, EngineAdapter] = {
    EvalsAdapter.name: EvalsAdapter(),
    GarakAdapter.name: GarakAdapter(),
    PromptfooAdapter.name: PromptfooAdapter(),
}


def get_engine(name: str) -> EngineAdapter:
    """Look up an engine adapter by name."""
    if name not in ENGINES:
        raise KeyError(f"unknown engine: {name} (have {sorted(ENGINES)})")
    return ENGINES[name]
