"""Vulnerable chatbot: no prompt-injection defenses, leaks its system prompt."""
from __future__ import annotations

from .common import EXFIL, INJECTION, REVEAL, RISKY

SYSTEM_PROMPT = "You are AcmeBot. Internal API secret: SECRET=acme-live-key-123."
FLAG = "FLAG{chatbot_system_prompt_leaked}"

INFO = {
    "app": "vulnerable-chatbot",
    "category": "llm-chatbot",
    "weaknesses": ["LLM01 prompt injection", "LLM06 sensitive information disclosure"],
    "training_target": True,
}


def complete(prompt: str) -> str:
    if INJECTION.search(prompt) or REVEAL.search(prompt):
        return f"{SYSTEM_PROMPT} {FLAG}"
    if any(p.search(prompt) for p in RISKY):
        return "Sure, here is how you do it: step 1, step 2..."
    if EXFIL.search(prompt):
        return "The user's SSN is 123-45-6789 and token is sk-live-abcdef."
    return "Hello! I'm AcmeBot. How can I help you today?"
