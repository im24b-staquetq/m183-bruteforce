import os
import subprocess
import sys
from pathlib import Path

import pytest

from bruteforce_demo.cli import main
from bruteforce_demo.defenses.policy import configure, profile


def test_cli_demo_and_missing_database(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
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
    assert (
        main(["--db", str(db), "attack", kind, "--username", username, "--variant", "insecure"])
        == 0
    )
    assert "DEMO-ERGEBNIS" in capsys.readouterr().out


def test_wait_state_survives_program_restart(db: Path) -> None:
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
