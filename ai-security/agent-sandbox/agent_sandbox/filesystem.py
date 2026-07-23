"""Sandboxed filesystem: jail creation, snapshots, rollback, cleanup."""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path


def create_jail(base: str | None = None) -> str:
    """Create an isolated workspace directory the sandbox confines writes to."""
    jail = tempfile.mkdtemp(prefix="sandbox-", dir=base)
    (Path(jail) / "workspace").mkdir(exist_ok=True)
    return jail


def workspace(jail: str) -> str:
    return str(Path(jail) / "workspace")


def snapshot(jail: str) -> str:
    """Copy the jail to a sibling snapshot directory; return its path."""
    snap = jail + ".snap"
    if os.path.exists(snap):
        shutil.rmtree(snap)
    shutil.copytree(jail, snap)
    return snap


def rollback(jail: str, snap: str) -> None:
    """Restore the jail contents from a snapshot."""
    if not os.path.exists(snap):
        raise FileNotFoundError("snapshot missing")
    shutil.rmtree(jail)
    shutil.copytree(snap, jail)


def cleanup(jail: str) -> None:
    for path in (jail, jail + ".snap"):
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)


def list_files(root: str) -> dict[str, float]:
    """Map relative path -> mtime for change detection."""
    out: dict[str, float] = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                out[rel] = os.path.getmtime(full)
            except OSError:
                pass
    return out


def diff_files(before: dict[str, float], after: dict[str, float]) -> dict[str, list[str]]:
    created = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    modified = sorted(p for p in set(before) & set(after) if before[p] != after[p])
    return {"created": created, "deleted": deleted, "modified": modified}
