"""SQLite persistence for the AI red team platform."""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    provider TEXT,
    app_type TEXT,
    owner TEXT,
    environment TEXT,
    endpoint TEXT,
    tools TEXT NOT NULL DEFAULT '[]',
    data_sources TEXT NOT NULL DEFAULT '[]',
    risk_tier TEXT NOT NULL DEFAULT 'medium',
    authorization TEXT NOT NULL DEFAULT 'unauthorized',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    score REAL,
    passed INTEGER,
    total INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    campaign_id TEXT,
    case_id TEXT,
    target_id TEXT,
    prompt_redacted TEXT,
    response_redacted TEXT,
    passed INTEGER,
    reason TEXT,
    sha256 TEXT,
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
    return connect(str(Path(directory) / "ai_redteam.db"))
