# agent-sandbox

An open **Agent Runtime Sandbox**: run agent shell/tool actions in a confined
workspace with command policy, network-egress allowlisting, resource limits,
session recording, and snapshot/rollback. Pure Python standard library.

> **Threat-model note:** this MVP uses process-level confinement (separate cwd,
> scrubbed env, rlimits, policy checks). It is *not* a hard security boundary.
> Production isolation requires OS sandboxing (gVisor, Firecracker, namespaces,
> seccomp, eBPF) — see `NEXT_STEPS.md`.

## Features (MVP)

- **Sandboxed filesystem**: each session gets an isolated jail/workspace;
  writes are confined and tracked; **snapshot + rollback**
- **Command policy**: executable allowlist + denylist of dangerous patterns
  (`rm -rf /`, `mkfs`, fork bombs, `dd of=/dev/...`, etc.)
- **Network egress controls**: domain allowlist for any URL a command references
  (+ best-effort proxy blackhole when network is disabled)
- **Resource limits**: CPU time, address space, file size, process count (rlimits)
- **Session recording**: command, exit code, stdout/stderr, duration, timeout,
  files changed — serializable to JSON
- **Tool registry**: register named tools that map args → commands

## Quickstart

```bash
python3 examples/demo.py
```

```python
from agent_sandbox import Sandbox, EgressPolicy

with Sandbox(egress_policy=EgressPolicy(allowed_domains={"pypi.org"})) as s:
    rec = s.run("echo hello")
    print(rec.stdout, rec.files_changed)
    s.rollback()  # undo any filesystem changes
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## License

AGPL-3.0-only
