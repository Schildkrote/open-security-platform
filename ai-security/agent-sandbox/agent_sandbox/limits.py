"""Resource limits applied to sandboxed child processes (best-effort)."""
from __future__ import annotations

import resource
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class Limits:
    cpu_seconds: int = 5            # RLIMIT_CPU
    memory_bytes: int = 256 * 2**20  # RLIMIT_AS (address space)
    file_size_bytes: int = 10 * 2**20  # RLIMIT_FSIZE
    nproc: int = 32                 # RLIMIT_NPROC


def make_preexec(limits: Limits) -> Optional[Callable[[], None]]:
    """Return a preexec_fn that applies rlimits in the child. Limits that the
    platform refuses are skipped rather than failing the run."""
    def _apply() -> None:
        specs = [
            (resource.RLIMIT_CPU, limits.cpu_seconds),
            (resource.RLIMIT_FSIZE, limits.file_size_bytes),
            (resource.RLIMIT_NPROC, limits.nproc),
        ]
        if hasattr(resource, "RLIMIT_AS"):
            specs.append((resource.RLIMIT_AS, limits.memory_bytes))
        for res, value in specs:
            try:
                resource.setrlimit(res, (value, value))
            except (ValueError, OSError):
                pass  # not enforceable on this platform; documented limitation

    return _apply
