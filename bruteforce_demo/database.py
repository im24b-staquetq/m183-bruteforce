"""Nur Authentifizierung und Verwaltung greifen auf diese Datenhaltung zu."""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from argon2 import PasswordHasher
from argon2.profiles import RFC_9106_LOW_MEMORY

# Explizites RFC-Profil: 64 MiB, drei Durchläufe, vier Argon2-Threads.
PASSWORD_HASHER = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)
DEMO_ACCOUNTS = {"pin": "0007", "dictionary": "Lernwort1", "poly": "a1"}

SCHEMA = """
CREATE TABLE demo_meta (version INTEGER NOT NULL);
INSERT INTO demo_meta VALUES (1);
CREATE TABLE users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
);
CREATE TABLE policy (id INTEGER PRIMARY KEY CHECK (id = 1), config TEXT NOT NULL);
CREATE TABLE login_state (
    username TEXT NOT NULL REFERENCES users(username),
    variant TEXT NOT NULL CHECK (variant IN ('insecure', 'protected')),
    failures INTEGER NOT NULL DEFAULT 0,
    next_allowed_at REAL NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0,
    alarmed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (username, variant)
);
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY,
    timestamp REAL NOT NULL,
    event_type TEXT NOT NULL,
    username TEXT NOT NULL,
    variant TEXT NOT NULL
);
"""


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    """Öffnet nur vorhandene Dateien; jeder Aufrufer erhält eine eigene Verbindung."""
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
    finally:
        connection.close()


def initialize(path: Path) -> None:
    """Erstellt Testdaten; eine vorhandene Datei wird niemals überschrieben."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb"):
        pass
    with connect(path) as connection, connection:
        connection.executescript(SCHEMA)
        connection.executemany(
            "INSERT INTO users VALUES (?, ?)",
            [(name, PASSWORD_HASHER.hash(password)) for name, password in DEMO_ACCOUNTS.items()],
        )
        connection.execute(
            "INSERT INTO policy VALUES (1, ?)",
            (json.dumps({"delay_mode": "progressive", "lock_threshold": 5, "audit": True}),),
        )


def reset_states(path: Path, *, clear_events: bool = False) -> None:
    """Expliziter Reset: behält Konten, Hashes und Konfiguration bei."""
    with connect(path) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM login_state")
        if clear_events:
            connection.execute("DELETE FROM audit_events")


def read_events(path: Path, limit: int = 50) -> list[sqlite3.Row]:
    if not 1 <= limit <= 1000:
        raise ValueError("Ereignislimit muss zwischen 1 und 1000 liegen.")
    with connect(path) as connection:
        return connection.execute(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()[::-1]
