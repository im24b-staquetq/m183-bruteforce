"""Tests für CLI-Befehle, Live-Ausgabe und den Zustand über Programmneustarts hinweg."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from bruteforce_demo.cli import main
from bruteforce_demo.defenses.policy import configure, profile


def test_cli_demo_and_missing_database(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Prüft Initialisierung, Fehlermeldungen, Angriff, Sperrprofil und Verwaltungsbefehle.

    :param tmp_path: Leeres temporäres Verzeichnis für die neu zu erstellende Datenbank.
    :param capsys: Erfasst Zusammenfassungen und Fehlermeldungen der CLI.
    """
    path = tmp_path / "demo.db"
    args = ["--db", str(path)]
    assert main([*args, "attack", "mono"]) == 2
    assert not path.exists()
    assert main([*args, "init"]) == 0
    assert main([*args, "init"]) == 2
    assert main([*args, "attack", "mono", "--variant", "insecure"]) == 0
    assert "DEMO-ERGEBNIS" in capsys.readouterr().out
    assert main([*args, "configure", "--profile", "lockout"]) == 0
    assert main([*args, "attack", "mono", "--max-calls", "10"]) == 0
    assert "Passwortprüfungen: 5" in capsys.readouterr().out
    assert main([*args, "status"]) == 0
    assert main([*args, "events"]) == 0
    assert main([*args, "reset", "--clear-events"]) == 0


@pytest.mark.parametrize("kind,username", [("dictionary", "dictionary"), ("poly", "poly")])
def test_cli_other_attacks(
    db: Path, kind: str, username: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Prüft einen tatsächlichen Testpasswortfund über die Dictionary- oder Poly-CLI.

    :param db: Unabhängige temporäre Demo-Datenbank.
    :param kind: Parametrisierte Angriffsart.
    :param username: Dazu passendes künstliches Testkonto.
    :param capsys: Erfasst das ausdrücklich gekennzeichnete Demo-Ergebnis.
    """
    assert (
        main(["--db", str(db), "attack", kind, "--username", username, "--variant", "insecure"])
        == 0
    )
    assert "DEMO-ERGEBNIS" in capsys.readouterr().out


def test_wait_state_survives_program_restart(db: Path) -> None:
    """Prüft die gespeicherte Wartezeit durch einen zweiten, eigenständigen Python-Prozess.

    :param db: Von beiden Programmstarts verwendete temporäre Demo-Datenbank.
    """
    configure(db, profile("fixed", fixed_seconds=3600))
    args = ["--db", str(db), "attack", "mono", "--max-calls", "1"]
    assert main(args) == 0
    result = subprocess.run(
        [sys.executable, "-m", "bruteforce_demo", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        env={**os.environ, "PYTHONUTF8": "1"},
        timeout=15,
    )
    assert result.returncode == 0
    assert "Passwortprüfungen: 0" in result.stdout
    assert "Blockierte Versuche: 1" in result.stdout


@pytest.mark.parametrize(
    "kind,username",
    [("mono", "pin"), ("dictionary", "dictionary"), ("poly", "poly"), ("parallel", "pin")],
)
def test_live_display_for_all_attacks(
    db: Path, kind: str, username: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Prüft Live-Tabellenkopf, Erfolgszeile und Zusammenfassung für alle vier Angriffsarten.

    :param db: Unabhängige temporäre Demo-Datenbank.
    :param kind: Parametrisierte Angriffsart einschliesslich echter Workerprozesse.
    :param username: Dazu passendes künstliches Testkonto.
    :param capsys: Erfasst die im Elternprozess erzeugte Terminalausgabe.
    """
    assert (
        main(
            [
                "--db",
                str(db),
                "attack",
                kind,
                "--username",
                username,
                "--variant",
                "insecure",
                "--live",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert f"DEMO-LIVE | Konto: {username}" in output
    assert "Testkandidat" in output and "GEFUNDEN" in output
    assert "DEMO-ERGEBNIS" in output


def test_live_display_shows_lock_and_remaining_wait(
    db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Prüft die sichtbare Sperrmeldung mit Restwartezeit und unveränderten Prüfungszählern.

    :param db: Unabhängige temporäre Demo-Datenbank.
    :param capsys: Erfasst Live-Zeilen und abschliessende Zusammenfassung.
    """
    configure(db, profile("lockout", lock_seconds=3600))
    assert main(["--db", str(db), "attack", "mono", "--max-calls", "8", "--live"]) == 0
    output = capsys.readouterr().out
    assert "gesperrt (" in output
    assert "Passwortprüfungen: 5" in output and "Blockierte Versuche: 3" in output
    assert "GEFUNDEN" not in output


def test_live_display_is_opt_in(db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Prüft, dass ohne --live keine Kandidatentabelle oder einzelnen Testkandidaten erscheinen.

    :param db: Unabhängige temporäre Demo-Datenbank.
    :param capsys: Erfasst die Ausgabe eines Angriffs ohne Live-Option.
    """
    assert main(["--db", str(db), "attack", "mono", "--max-calls", "1"]) == 0
    output = capsys.readouterr().out
    assert "DEMO-LIVE" not in output and "'0000'" not in output
