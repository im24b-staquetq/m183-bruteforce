"""Temporäre Datenbanken und kontrollierbare Zeit für Tests ohne echte Wartepausen."""

import shutil
from pathlib import Path

import pytest

from bruteforce_demo.database import initialize


class FakeClock:
    """Kontrollierbare Zeitquelle ohne Änderungen an der echten Systemuhr.

    Attribute:
        now: Aktueller Testzeitpunkt in Sekunden, von aussen nur lesbar.
    Methoden:
        advance: Verändert den Testzeitpunkt um eine angegebene Zeitspanne.
        __call__: Liefert den Zeitpunkt als injizierbare Zeitquelle.
    """

    def __init__(self, now: float = 1_000.0) -> None:
        """Speichert den Anfangszeitpunkt.

        :param now: Anfangszeitpunkt in Sekunden.
        """
        self._now = now

    def __call__(self) -> float:
        """Liefert den aktuellen Testzeitpunkt in Sekunden."""
        return self.now

    def advance(self, seconds: float) -> None:
        """Verändert die Testzeit ohne echtes Warten.

        :param seconds: Zeitspanne in Sekunden, die auf den Zeitpunkt addiert wird.
        """
        self._now += seconds

    @property
    def now(self) -> float:
        """Aktueller Testzeitpunkt in Sekunden."""
        return self._now


@pytest.fixture(scope="session")
def template_db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Erstellt einmalig die mit echten Argon2id-Hashes bestückte Testvorlage.

    :param tmp_path_factory: pytest-Verwaltung für temporäre Verzeichnisse.
    :return: Pfad der für einzelne Tests zu kopierenden Datenbank.
    """
    path = tmp_path_factory.mktemp("template") / "demo.db"
    initialize(path)
    return path


@pytest.fixture
def db(tmp_path: Path, template_db: Path) -> Path:
    """Stellt jedem Test eine unabhängige Kopie der Testdatenbank bereit.

    :param tmp_path: Temporäres Verzeichnis dieses Tests.
    :param template_db: Vorbereitete Datenbank mit künstlichen Testkonten.
    :return: Pfad der unabhängigen Datenbankkopie.
    """
    path = tmp_path / "demo.db"
    shutil.copyfile(template_db, path)
    return path


@pytest.fixture
def clock() -> FakeClock:
    """Liefert pro Test eine neue, kontrollierbare Zeitquelle."""
    return FakeClock()
