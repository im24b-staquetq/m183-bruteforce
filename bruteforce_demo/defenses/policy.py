"""Validierte Schutzprofile und ihre persistente SQLite-Konfiguration."""

import json
import math
import sqlite3
from pathlib import Path
from typing import Literal

from bruteforce_demo.database import transaction
from bruteforce_demo.defenses.fixed import fixed_delay
from bruteforce_demo.defenses.progressive import progressive_delay

PROFILES = ("standard", "fixed", "progressive", "lockout", "logging", "none")


class Policy:
    """Von aussen nur lesbare Einstellungen der Schutzmassnahmen.

    Attribute:
        delay_mode: Keine, feste oder progressive Wartezeit.
        fixed_seconds: Feste Wartezeit in Sekunden.
        base_seconds, cap_seconds: Basis und Obergrenze der progressiven Wartezeit.
        lock_threshold, lock_seconds: Fehlerschwelle und Dauer der Kontosperre.
        audit, alarm_threshold: Protokollierung und Schwellwert des lokalen Alarms.
    Methoden:
        delay: Berechnet die Wartezeit für eine Fehlerzahl.
        to_dict: Liefert Einstellungen mit den bestehenden JSON-Schlüsseln.
    """

    def __init__(
        self,
        *,
        delay_mode: Literal["none", "fixed", "progressive"] = "none",
        fixed_seconds: float = 1.0,
        base_seconds: float = 0.25,
        cap_seconds: float = 2.0,
        lock_threshold: int = 0,
        lock_seconds: float = 10.0,
        audit: bool = False,
        alarm_threshold: int = 3,
    ) -> None:
        """Prüft und speichert die Schutzkonfiguration.

        :param delay_mode: 'none', 'fixed' oder 'progressive'.
        :param fixed_seconds: Positive feste Wartezeit in Sekunden.
        :param base_seconds: Positive Anfangswartezeit bei progressivem Schutz.
        :param cap_seconds: Wartezeitobergrenze, mindestens so gross wie die Basis.
        :param lock_threshold: Fehlerschwelle; 0 deaktiviert die Sperre.
        :param lock_seconds: Positive Sperrdauer in Sekunden.
        :param audit: Aktiviert Audit-Ereignisse und lokale Alarmierung.
        :param alarm_threshold: Positive Fehlerschwelle für einen Alarm.
        :raises ValueError: Bei unbekanntem Modus oder ungültigen Zeit-/Schwellwerten.
        """
        if delay_mode not in {"none", "fixed", "progressive"}:
            raise ValueError("Unbekannter Wartezeitmodus.")
        durations = (fixed_seconds, base_seconds, cap_seconds, lock_seconds)
        if any(not math.isfinite(value) or value <= 0 for value in durations):
            raise ValueError("Zeitwerte müssen endlich und positiv sein.")
        if cap_seconds < base_seconds:
            raise ValueError("Die Obergrenze muss mindestens der Basiswartezeit entsprechen.")
        if lock_threshold < 0 or alarm_threshold < 1:
            raise ValueError("Ungültiger Sperr- oder Alarmschwellwert.")
        self._delay_mode = delay_mode
        self._fixed_seconds = fixed_seconds
        self._base_seconds = base_seconds
        self._cap_seconds = cap_seconds
        self._lock_threshold = lock_threshold
        self._lock_seconds = lock_seconds
        self._audit = audit
        self._alarm_threshold = alarm_threshold

    def delay(self, failures: int) -> float:
        """Berechnet die Wartezeit nach einer fehlgeschlagenen Passwortprüfung.

        :param failures: Anzahl aufeinanderfolgender falscher Passwortprüfungen.
        :return: Wartezeit in Sekunden, 0 bei deaktivierter Wartezeit.
        """
        if self.delay_mode == "fixed":
            return fixed_delay(self.fixed_seconds)
        if self.delay_mode == "progressive":
            return progressive_delay(failures, self.base_seconds, self.cap_seconds)
        return 0.0

    def to_dict(self) -> dict[str, str | float | int | bool]:
        """Liefert das bisherige Speicherformat für SQLite und die Statusanzeige.

        :return: Schutzkonfiguration mit öffentlichen Parameternamen als Schlüsseln.
        """
        return {
            "delay_mode": self.delay_mode,
            "fixed_seconds": self.fixed_seconds,
            "base_seconds": self.base_seconds,
            "cap_seconds": self.cap_seconds,
            "lock_threshold": self.lock_threshold,
            "lock_seconds": self.lock_seconds,
            "audit": self.audit,
            "alarm_threshold": self.alarm_threshold,
        }

    @property
    def delay_mode(self) -> str:
        """Gewählter Wartezeitmodus."""
        return self._delay_mode

    @property
    def fixed_seconds(self) -> float:
        """Feste Wartezeit in Sekunden."""
        return self._fixed_seconds

    @property
    def base_seconds(self) -> float:
        """Anfangswert der progressiven Wartezeit in Sekunden."""
        return self._base_seconds

    @property
    def cap_seconds(self) -> float:
        """Obergrenze der progressiven Wartezeit in Sekunden."""
        return self._cap_seconds

    @property
    def lock_threshold(self) -> int:
        """Fehlerschwelle der Sperre; 0 deaktiviert die Sperre."""
        return self._lock_threshold

    @property
    def lock_seconds(self) -> float:
        """Dauer einer Kontosperre in Sekunden."""
        return self._lock_seconds

    @property
    def audit(self) -> bool:
        """Ob Audit-Ereignisse und lokale Alarme aktiv sind."""
        return self._audit

    @property
    def alarm_threshold(self) -> int:
        """Fehlerschwelle für einen lokalen Alarm."""
        return self._alarm_threshold


def profile(name: str, **overrides: float | int) -> Policy:
    """Erstellt ein Schutzprofil mit optional überschriebenen Parametern.

    :param name: Einer der Profilnamen aus PROFILES.
    :param overrides: Geänderte Zeitwerte oder Schwellwerte für Policy.
    :return: Validierte Schutzkonfiguration.
    :raises ValueError: Bei unbekanntem Profil oder ungültigen Einstellungen.
    :raises TypeError: Bei unbekannten Parametern in overrides.
    """
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
    """Liest das gespeicherte Schutzprofil innerhalb der aktuellen Transaktion.

    :param connection: Geöffnete Verbindung mit Row-Zeilenformat.
    :return: Validierte Schutzkonfiguration.
    :raises sqlite3.Error: Wenn die Datenbankabfrage scheitert.
    :raises ValueError: Wenn JSON oder die gespeicherten Einstellungen ungültig sind.
    """
    row = connection.execute("SELECT config FROM policy WHERE id = 1").fetchone()
    return Policy(**json.loads(row["config"]))


def configure(path: Path, policy: Policy) -> None:
    """Speichert ein Profil und setzt geschützte Zustände atomar zurück.

    :param path: Vorhandene Demo-Datenbank.
    :param policy: Validierte Schutzkonfiguration.
    :raises sqlite3.Error: Wenn Öffnen oder Transaktion scheitern.
    """
    with transaction(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE policy SET config = ? WHERE id = 1", (json.dumps(policy.to_dict()),)
        )
        connection.execute("DELETE FROM login_state WHERE variant = 'protected'")
