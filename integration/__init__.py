"""open-security-platform integration control plane (Phase 2).

Stdlib-only Python package that makes the components talk to each other: it
drives each component's existing public HTTP API, bridges their data models,
executes privileged actions through open-pam-jit inside agent-sandbox, and
records the whole flow on a common hash-chained integration-event schema.

See README.md in this directory and .context/IMPLEMENTATION_PLAN.md (Phase 2).
"""

__all__ = ["clients", "events", "flow", "servers"]
