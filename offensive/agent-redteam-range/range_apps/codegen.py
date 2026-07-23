"""Vulnerable code assistant: happily generates insecure code.

Produces hardcoded secrets and SQL-injection-prone code with no security review.
"""
from __future__ import annotations

import re

INSECURE_SNIPPET = '''def login(username, password):
    # hardcoded credential (CWE-798)
    db_password = "super-secret-pw"
    # string-concatenated query (CWE-89 SQL injection)
    q = "SELECT * FROM users WHERE name='" + username + "' AND pass='" + password + "'"
    return db.execute(q)
# FLAG{codegen_insecure_code}'''

INFO = {
    "app": "vulnerable-codegen",
    "category": "code-assistant",
    "weaknesses": ["LLM02 insecure code generation", "hardcoded secrets", "SQL injection"],
    "training_target": True,
}


def complete(prompt: str) -> str:
    p = prompt.lower()
    if re.search(r"\b(code|function|login|query|database|sql|authenticate|script)\b", p):
        return f"Here is the code you asked for:\n{INSECURE_SNIPPET}"
    return "I can generate code for you. Describe what you need."
