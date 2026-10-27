import json
import math
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from bruteforce_demo.database import connect
from bruteforce_demo.defenses.fixed import fixed_delay
from bruteforce_demo.defenses.progressive import progressive_delay

PROFILES = ("standard", "fixed", "progressive", "lockout", "logging", "none")


@dataclass(frozen=True)
class Policy:
    delay_mode: Literal["none", "fixed", "progressive"] = "none"
    fixed_seconds: float = 1.0
    base_seconds: float = 0.25
    cap_seconds: float = 2.0
    lock_threshold: int = 0
    lock_seconds: float = 10.0
    audit: bool = False
    alarm_threshold: int = 3

    def __post_init__(self) -> None:
        if self.delay_mode not in {"none", "fixed", "progressive"}:
            raise ValueError("Unbekannter Wartezeitmodus.")
        durations = (self.fixed_seconds, self.base_seconds, self.cap_seconds, self.lock_seconds)
        if any(not math.isfinite(value) or value <= 0 for value in durations):
            raise ValueError("Zeitwerte müssen endlich und positiv sein.")
        if self.cap_seconds < self.base_seconds:
            raise ValueError("Die Obergrenze muss mindestens der Basiswartezeit entsprechen.")
        if self.lock_threshold < 0 or self.alarm_threshold < 1:
            raise ValueError("Ungültiger Sperr- oder Alarmschwellwert.")

    def delay(self, failures: int) -> float:
        if self.delay_mode == "fixed":
            return fixed_delay(self.fixed_seconds)
        if self.delay_mode == "progressive":
            return progressive_delay(failures, self.base_seconds, self.cap_seconds)
        return 0.0


def profile(name: str, **overrides: float | int) -> Policy:
    if name not in PROFILES:
        raise ValueError("Unbekanntes Schutzprofil.")
    settings: dict[str, object] = {}
    if name in {"fixed", "progressive"}:
        settings["delay_mode"] = name
    if name == "standard":
        settings.update(delay_mode="progressive", lock_threshold=5, audit=True)
    if name == "lockout":
        settings["lock_threshold"] = 5
    if name == "logging":
        settings["audit"] = True
    settings.update(overrides)
    return Policy(**settings)


def load_policy(connection: sqlite3.Connection) -> Policy:
    row = connection.execute("SELECT config FROM policy WHERE id = 1").fetchone()
    return Policy(**json.loads(row["config"]))


def configure(path: Path, policy: Policy) -> None:
    """Explizite Verwaltung: Profil ändern und geschützte Zustände zurücksetzen."""
    with connect(path) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE policy SET config = ? WHERE id = 1", (json.dumps(asdict(policy)),)
        )
        connection.execute("DELETE FROM login_state WHERE variant = 'protected'")
