"""The sandbox orchestrator: confined, limited, recorded command execution."""
from __future__ import annotations

import os
import shlex
import subprocess
import time
from typing import Callable, Optional

from . import filesystem as fs
from .limits import Limits, make_preexec
from .policy import CommandPolicy, EgressPolicy
from .recorder import SessionRecord

# A scrubbed environment for sandboxed children.
_BASE_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
}


class Sandbox:
    def __init__(
        self,
        command_policy: Optional[CommandPolicy] = None,
        egress_policy: Optional[EgressPolicy] = None,
        limits: Optional[Limits] = None,
        network: bool = False,
        base: Optional[str] = None,
    ) -> None:
        self.command_policy = command_policy or CommandPolicy()
        self.egress_policy = egress_policy or EgressPolicy()
        self.limits = limits or Limits()
        self.network = network
        self.base = base
        self.jail: Optional[str] = None
        self._snap: Optional[str] = None
        self._tools: dict[str, Callable[[list[str]], str]] = {}

    # -- lifecycle -------------------------------------------------------
    def __enter__(self) -> "Sandbox":
        self.jail = fs.create_jail(self.base)
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        if self.jail:
            fs.cleanup(self.jail)
            self.jail = None

    # -- tools -----------------------------------------------------------
    def register_tool(self, name: str, builder: Callable[[list[str]], str]) -> None:
        """Register a named tool that maps arguments to a shell command."""
        self._tools[name] = builder

    def run_tool(self, name: str, args: list[str], timeout: float = 5.0) -> SessionRecord:
        if name not in self._tools:
            rec = SessionRecord(command=f"tool:{name}", cwd=self._cwd(), allowed=False, reason="unknown tool")
            return rec
        return self.run(self._tools[name](args), timeout=timeout)

    # -- execution -------------------------------------------------------
    def run(self, command: str, timeout: float = 5.0) -> SessionRecord:
        assert self.jail, "sandbox not started (use 'with Sandbox() as s:')"
        rec = SessionRecord(command=command, cwd=fs.workspace(self.jail))

        ok, reason = self.command_policy.validate(command)
        if not ok:
            rec.allowed, rec.reason = False, reason
            return rec
        ok, reason = self.egress_policy.validate_command(command)
        if not ok:
            rec.allowed, rec.reason = False, reason
            return rec

        self._snap = fs.snapshot(self.jail)
        before = fs.list_files(fs.workspace(self.jail))

        env = dict(_BASE_ENV)
        env["HOME"] = self.jail
        if not self.network:
            # Best-effort network blackhole (real isolation needs netns/eBPF).
            env.update({"http_proxy": "http://127.0.0.1:1", "https_proxy": "http://127.0.0.1:1"})

        start = time.monotonic()
        try:
            proc = subprocess.run(
                shlex.split(command),
                cwd=fs.workspace(self.jail),
                env=env,
                preexec_fn=make_preexec(self.limits),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            rec.exit_code = proc.returncode
            rec.stdout = proc.stdout
            rec.stderr = proc.stderr
        except subprocess.TimeoutExpired as e:
            rec.timed_out = True
            rec.stdout = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            rec.stderr = "timeout"
        finally:
            rec.duration_s = round(time.monotonic() - start, 4)

        after = fs.list_files(fs.workspace(self.jail))
        rec.files_changed = fs.diff_files(before, after)
        return rec

    def rollback(self) -> None:
        if self.jail and self._snap:
            fs.rollback(self.jail, self._snap)

    def _cwd(self) -> str:
        return fs.workspace(self.jail) if self.jail else os.getcwd()
