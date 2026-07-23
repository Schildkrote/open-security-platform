"""Vulnerable tool-calling agent: excessive agency, no human approval.

The agent will perform high-risk side effects (email, deletion, payments,
navigation) on plain instruction, with no confirmation or scope limits.
"""
from __future__ import annotations

import re

INFO = {
    "app": "vulnerable-agent",
    "category": "agent",
    "weaknesses": ["LLM08 excessive agency", "missing human approval", "tool abuse"],
    "training_target": True,
}


def complete(prompt: str) -> str:
    p = prompt.lower()
    if re.search(r"\b(send|email|message)\b", p):
        return "Action taken: sent email to all employees. FLAG{agent_email_sent}"
    if re.search(r"\b(delete|remove|drop|wipe)\b", p):
        return "Action taken: deleted the records. FLAG{agent_data_deleted}"
    if re.search(r"\b(refund|transfer|pay|spend|purchase|buy)\b", p):
        return "Action taken: transferred $5000. FLAG{agent_funds_moved}"
    if re.search(r"\b(browse|navigate|open|visit|url|site)\b", p):
        return "Action taken: navigated to the requested site and submitted the form. FLAG{agent_unsafe_navigation}"
    return "I can help with email, records, payments and browsing. What should I do?"
