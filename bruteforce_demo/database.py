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
    """Öffnet eine vorhandene SQLite-Datei und schliesst die Verbindung zuverlässig.

    :param path: Pfad einer vorhandenen Demo-Datenbank.
    :yield: Eigene Verbindung mit Zugriff auf Spalten über sqlite3.Row.
    :raises sqlite3.Error: Wenn Öffnen oder Konfiguration scheitern.
    """
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
    finally:
        connection.close()


@contextmanager
def transaction(path: Path) -> Iterator[sqlite3.Connection]:
    """Verbindet Ressourcenfreigabe mit Commit bzw. Rollback beim Verlassen.

    :param path: Pfad einer vorhandenen Demo-Datenbank.
    :yield: Verbindung, auf der der Aufrufer bei Bedarf BEGIN IMMEDIATE ausführt.
    :raises sqlite3.Error: Wenn Öffnen oder Bestätigen der Transaktion scheitern.
    """
    with connect(path) as connection:
        with connection:
            yield connection


def initialize(path: Path) -> None:
    """Erstellt Schema, künstliche Konten und das Standardprofil in einer neuen Datei.

    :param path: Gewünschter Pfad der neuen Demo-Datenbank.
    :raises FileExistsError: Wenn die Datei bereits existiert; sie bleibt erhalten.
    :raises OSError: Wenn die Datei nicht angelegt werden kann.
    :raises sqlite3.Error: Wenn Schema oder Testdaten nicht gespeichert werden können.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb"):
        pass
    with transaction(path) as connection:
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
    """Setzt ausdrücklich Fehlversuchszustände zurück; behält Konten und Profil.

    :param path: Vorhandene Demo-Datenbank.
    :param clear_events: Löscht zusätzlich Audit-Ereignisse, wenn True.
    :raises sqlite3.Error: Wenn Öffnen oder Transaktion scheitern.
    """
    with transaction(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM login_state")
        if clear_events:
            connection.execute("DELETE FROM audit_events")


def read_events(path: Path, limit: int = 50) -> list[sqlite3.Row]:
    """Liest die letzten Audit-Ereignisse in zeitlicher Reihenfolge.

    :param path: Vorhandene Demo-Datenbank.
    :param limit: Anzahl der letzten Ereignisse zwischen 1 und 1000.
    :return: Ereigniszeilen, älteste zuerst; gegebenenfalls eine leere Liste.
    :raises ValueError: Bei ungültigem Limit.
    :raises sqlite3.Error: Wenn Öffnen oder Abfrage scheitern.
    """
    if not 1 <= limit <= 1000:
        raise ValueError("Ereignislimit muss zwischen 1 und 1000 liegen.")
    with connect(path) as connection:
        return connection.execute(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()[::-1]
