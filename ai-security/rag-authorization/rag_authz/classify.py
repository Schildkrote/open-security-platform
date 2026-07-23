"""Automatic data classification of document text into a sensitivity level."""
from __future__ import annotations

import re

from .acl import Sensitivity

_PATTERNS: list[tuple[Sensitivity, str, re.Pattern]] = [
    (Sensitivity.RESTRICTED, "private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (Sensitivity.RESTRICTED, "api_secret", re.compile(r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})")),
    (Sensitivity.CONFIDENTIAL, "ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    (Sensitivity.CONFIDENTIAL, "credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    (Sensitivity.CONFIDENTIAL, "confidential_keyword", re.compile(r"\b(confidential|restricted|secret)\b", re.I)),
    (Sensitivity.INTERNAL, "email", re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")),
]


def classify(text: str) -> tuple[Sensitivity, list[str]]:
    """Return the highest sensitivity indicated by the text and the reasons."""
    level = Sensitivity.PUBLIC
    reasons: list[str] = []
    for sens, name, pattern in _PATTERNS:
        if pattern.search(text):
            reasons.append(name)
            if sens > level:
                level = sens
    return level, reasons
