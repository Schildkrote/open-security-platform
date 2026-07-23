"""Catalog of range apps with their default ports and entry points."""
from __future__ import annotations

from . import agent, chatbot, codegen, mcp, rag

APPS = {
    "chatbot": {"module": chatbot, "port": 8091},
    "rag": {"module": rag, "port": 8092},
    "mcp": {"module": mcp, "port": 8093},
    "agent": {"module": agent, "port": 8094},
    "codegen": {"module": codegen, "port": 8095},
}


def names() -> list[str]:
    return list(APPS)


def complete(app_name: str, prompt: str) -> str:
    return APPS[app_name]["module"].complete(prompt)


def info(app_name: str) -> dict:
    return APPS[app_name]["module"].INFO
