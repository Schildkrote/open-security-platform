#!/usr/bin/env python3
"""Offline validation for live/docker-compose.yml (no Docker required).

Checks:
  1. The file parses as YAML (safe_load).
  2. EVERY published port is bound to 127.0.0.1 (never 0.0.0.0 / bare port).
  3. Every long-running service (no "setup" profile) has a healthcheck.
  4. Every stateful service keeps data in a named volume.
  5. Every image reference is pinned to a specific tag (no :latest / no tag).

Run: python3 live/scripts/validate_compose.py  (or `make verify-compose` in live/)
Exit code 0 = all checks pass.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NoReturn

import yaml

COMPOSE = Path(__file__).resolve().parent.parent / "docker-compose.yml"

# Services exempt from the healthcheck requirement:
#   - one-shot containers that run to completion (dependents gate on
#     `service_completed_successfully` instead);
#   - DefectDojo's celery worker/beat, which upstream's own compose file runs
#     without healthchecks (liveness is implicit; the proofs gate on the
#     nginx/uwsgi health instead).
HEALTHCHECK_EXEMPT = {
    "wazuh-certs-generator",
    "defectdojo-initializer",
    "defectdojo-celeryworker",
    "defectdojo-celerybeat",
}


def fail(msg: str) -> NoReturn:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    doc = yaml.safe_load(COMPOSE.read_text())
    if not isinstance(doc, dict) or "services" not in doc:
        fail("compose file has no 'services' mapping")

    services: dict[str, dict] = doc["services"]
    named_volumes: set[str] = set(doc.get("volumes", {}))

    port_re = re.compile(
        r"^(?:(?P<host_ip>[^:/]+):)?(?P<host_port>[\d\-]+):(?P<ctr_port>[\d\-]+)(?:/(?P<proto>\w+))?$"
    )
    checks = 0

    for name, svc in services.items():
        image = svc.get("image", "")
        if not image:
            fail(f"{name}: no image")
        if ":" not in image or image.endswith(":latest"):
            fail(f"{name}: image {image!r} is not pinned to a specific tag")
        checks += 1

        # (2) loopback-only published ports
        for p in svc.get("ports", []):
            spec = str(p)
            m = port_re.match(spec)
            if not m:
                fail(f"{name}: unparsable port spec {spec!r}")
            host_ip = m.group("host_ip")
            if host_ip != "127.0.0.1":
                fail(f"{name}: port {spec!r} is NOT bound to 127.0.0.1 (host ip {host_ip!r})")
            checks += 1

        # (3) healthcheck on long-running services (exemptions documented above)
        profiles = svc.get("profiles", [])
        if "setup" not in profiles and name not in HEALTHCHECK_EXEMPT and "healthcheck" not in svc:
            fail(f"{name}: missing healthcheck")
        checks += 1

        # (4) stateful services use named volumes (any volume at all must be named)
        for v in svc.get("volumes", []):
            spec = str(v)
            if spec.startswith("/") or spec.startswith("./"):
                continue  # bind mounts of repo config are fine
            source = spec.split(":", 1)[0]
            if source not in named_volumes:
                fail(f"{name}: volume {spec!r} is not a declared named volume")
            checks += 1

    # The four ROADMAP services + ollama must exist.
    for required in ("keycloak", "wazuh", "defectdojo", "openbao", "ollama"):
        if required not in services:
            fail(f"required service {required!r} missing")
        checks += 1

    # Each of the four ROADMAP services (+ ollama) must keep state in at least
    # one named volume.
    for required in ("keycloak", "wazuh", "defectdojo", "openbao", "ollama"):
        svc_volumes = [str(v) for v in services[required].get("volumes", [])]
        has_named = any(
            v.split(":", 1)[0] in named_volumes
            and not v.startswith(("/", "./"))
            for v in svc_volumes
        )
        if not has_named:
            fail(f"required service {required!r} has no named volume")
        checks += 1

    # Every ${VAR} the compose file interpolates must be documented in
    # .env.example (and will exist in a generated .env).
    env_example = (COMPOSE.parent / ".env.example").read_text()
    example_keys = {
        line.split("=", 1)[0].strip()
        for line in env_example.splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }
    raw = COMPOSE.read_text()
    for var in sorted(set(re.findall(r"\$\{([A-Z0-9_]+)\}", raw))):
        if var not in example_keys:
            fail(f"compose interpolates ${{{var}}} but .env.example has no such key")
        checks += 1

    print(f"PASS: {COMPOSE.name} validated ({checks} checks; YAML ok, loopback-only ports, "
          f"pinned tags, healthchecks, named volumes, env vars documented)")


if __name__ == "__main__":
    main()
