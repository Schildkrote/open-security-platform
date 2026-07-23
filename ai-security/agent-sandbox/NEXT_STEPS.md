# Next Steps — agent-sandbox

The MVP provides process-level confinement and policy. To make it a hard
security boundary:

## Real isolation
- Run actions in **gVisor** or **Firecracker microVMs** for kernel-level isolation.
- Use **Linux namespaces** (mount/pid/net/user) + **seccomp-bpf** syscalls filtering.
- **eBPF** enforcement for file/network access (pair with an open runtime-security tool).

## Network
- True **egress firewall** via a network namespace + enforced proxy, replacing
  the best-effort env-var blackhole.
- Per-tool domain/IP allowlists with TLS inspection.

## Filesystem & state
- **OverlayFS / copy-on-write** rootfs instead of full copies for cheap snapshots.
- Signed, reproducible base images for the sandbox rootfs.
- Volume mounts with read-only/secret-injection semantics.

## Governance & integration
- Require an **`agent-identity` token** to authorize each action; scope tools by token.
- **Human approval** for high-risk actions before execution.
- Stream **session recordings** to `open-soar` / SIEM for audit and replay.
- **Browser/computer-use sandboxing** for web agents (headless browser in a VM).

## Platform
- gRPC/HTTP API, container image, orchestration (K8s), autoscaling workers.
- Per-tenant quotas, billing, and telemetry.
