"""Command and network-egress policy for the sandbox."""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Commands that must never run, regardless of allowlist.
DANGEROUS_PATTERNS = [
    re.compile(r"\brm\s+(-[a-zA-Z]*\s+)*/(\s|$)"),      # rm -rf /
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bdd\s+.*of=/dev/"),
    re.compile(r":\(\)\s*\{.*\}\s*;"),                    # fork bomb
    re.compile(r"\b(shutdown|reboot|halt|poweroff)\b"),
    re.compile(r">\s*/dev/sd[a-z]"),
    re.compile(r"\bchmod\s+-R\s+777\s+/(\s|$)"),
]

URL_RE = re.compile(r"https?://[^\s'\"<>]+")


@dataclass
class CommandPolicy:
    """Allowlist of executables plus a denylist of dangerous patterns."""

    allowed_executables: set[str] = field(
        default_factory=lambda: {"echo", "cat", "ls", "pwd", "python3", "python", "grep", "wc", "sh"}
    )
    allow_shell: bool = False

    def validate(self, command: str) -> tuple[bool, str]:
        for pat in DANGEROUS_PATTERNS:
            if pat.search(command):
                return False, f"blocked dangerous pattern: {pat.pattern}"
        try:
            argv = shlex.split(command)
        except ValueError as e:
            return False, f"unparseable command: {e}"
        if not argv:
            return False, "empty command"
        exe = argv[0].split("/")[-1]
        if exe not in self.allowed_executables:
            return False, f"executable not allowed: {exe}"
        return True, "ok"


@dataclass
class EgressPolicy:
    """Domain allowlist for any URLs referenced by a command/tool."""

    allowed_domains: set[str] = field(default_factory=set)
    deny_by_default: bool = True

    def check_url(self, url: str) -> bool:
        host = urlparse(url).hostname or ""
        if host in self.allowed_domains:
            return True
        if any(host.endswith("." + d) for d in self.allowed_domains):
            return True
        return not self.deny_by_default

    def validate_command(self, command: str) -> tuple[bool, str]:
        for url in URL_RE.findall(command):
            if not self.check_url(url):
                return False, f"egress to {url} not allowed"
        return True, "ok"
