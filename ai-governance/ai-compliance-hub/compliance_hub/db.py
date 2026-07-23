"""SQLite persistence layer for the AI compliance hub."""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS systems (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner TEXT,
    system_type TEXT,
    risk_level TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'inventory',
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS controls (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    family TEXT,
    description TEXT
);
CREATE TABLE IF NOT EXISTS control_mappings (
    control_id TEXT NOT NULL,
    framework TEXT NOT NULL,
    reference TEXT NOT NULL,
    PRIMARY KEY (control_id, framework, reference)
);
CREATE TABLE IF NOT EXISTS risks (
    id TEXT PRIMARY KEY,
    system_id TEXT,
    title TEXT NOT NULL,
    category TEXT,
    likelihood INTEGER NOT NULL DEFAULT 3,
    impact INTEGER NOT NULL DEFAULT 3,
    mitigation TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    control_id TEXT,
    system_id TEXT,
    source TEXT,
    content TEXT,
    collected_at TEXT NOT NULL DEFAULT (datetime('now')),
    prev_hash TEXT,
    hash TEXT
);
"""


def connect(path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def file_db(directory: str = ".") -> sqlite3.Connection:
    Path(directory).mkdir(parents=True, exist_ok=True)
    return connect(str(Path(directory) / "compliance.db"))
