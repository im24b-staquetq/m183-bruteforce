"""Tests für Kandidaten, Angriffsgrenzen, Fortschrittsanzeigen und Windows-Worker."""

import signal
from collections.abc import Callable, Iterator
from itertools import islice
from pathlib import Path

import pytest
from conftest import FakeClock

from bruteforce_demo.attacks import parallel as parallel_module
from bruteforce_demo.attacks.common import AttackSummary, Limits, print_summary, run_attack
from bruteforce_demo.attacks.dictionary import dictionary_candidates, read_words
from bruteforce_demo.attacks.mono import numeric_candidates
from bruteforce_demo.attacks.parallel import run_parallel, split_ranges
from bruteforce_demo.attacks.poly import make_charset, poly_candidates
from bruteforce_demo.database import connect
from bruteforce_demo.defenses.policy import configure, profile
from bruteforce_demo.models import LoginResult


def test_numeric_leading_zeroes_order_and_lengths() -> None:
    """Prüft führende Nullen sowie den Übergang zwischen ein- und zweistelligen Kandidaten."""
    assert list(islice(numeric_candidates(4, 4), 8)) == [f"{value:04d}" for value in range(8)]
    candidates = list(numeric_candidates(1, 2))
    assert candidates[:10] == list("0123456789")
    assert candidates[10:13] == ["00", "01", "02"]
    assert candidates[-1] == "99" and len(candidates) == 110


def test_dictionary_order_variants_and_duplicates() -> None:
    """Prüft die feste Variantenreihenfolge und die Deduplizierung über mehrere Wörter."""
    assert list(dictionary_candidates(["test", "test", "TEST", ""])) == [
        "test",
        "test1",
        "test2",
        "TEST",
        "TEST1",
        "TEST2",
        "Test",
        "Test1",
        "Test2",
    ]
    candidates = list(dictionary_candidates(read_words()))
    assert candidates.index("Lernwort1") == 7
    assert len(candidates) == len(set(candidates))


def test_poly_lazy_order_and_lengths() -> None:
    """Prüft Lazy-Iteration, Zeichenreihenfolge und den Beginn eines längeren Suchraums."""
    candidates = poly_candidates("a1", 1, 2)
    assert iter(candidates) is candidates
    assert list(candidates) == ["a", "1", "aa", "a1", "1a", "11"]
    assert list(islice(poly_candidates("a1", 10, 10), 2)) == ["a" * 10, "a" * 9 + "1"]
    assert make_charset("aab", "001", "!!?") == "ab01!?"


@pytest.mark.parametrize(
    "generator",
    [
        lambda: numeric_candidates(0, 2),
        lambda: numeric_candidates(3, 2),
        lambda: numeric_candidates(1, 11),
        lambda: poly_candidates("", 1, 1),
        lambda: poly_candidates("aa", 1, 1),
        lambda: poly_candidates("ab", 2, 1),
    ],
)
def test_invalid_candidate_settings(generator: Callable[[], Iterator[str]]) -> None:
    """Erwartet ValueError beim ersten Zugriff auf einen ungültig konfigurierten Generator.

    :param generator: Parametrisierte Fabrik für numerische oder gemischte Kandidaten.
    """
    with pytest.raises(ValueError):
        next(generator())


@pytest.mark.parametrize("workers", [1, 2, 3, 7, 16])
@pytest.mark.parametrize("start,stop", [(0, 1), (0, 10), (7, 38)])
def test_parallel_partition_complete_disjoint_balanced(start: int, stop: int, workers: int) -> None:
    """Prüft eine lückenlose Aufteilung ohne Duplikate und mit ausgeglichenen Bereichsgrössen.

    :param start: Inklusive Untergrenze des Testbereichs.
    :param stop: Exklusive Obergrenze des Testbereichs.
    :param workers: Parametrisierte gewünschte Workerzahl.
    """
    ranges = split_ranges(start, stop, workers)
    values = [value for low, high in ranges for value in range(low, high)]
    assert values == list(range(start, stop))
    assert len(values) == len(set(values))
    sizes = [high - low for low, high in ranges]
    assert max(sizes) - min(sizes) <= 1


def test_call_limit_and_blocked_accounting() -> None:
    """Prüft das Aufruflimit bei ausschliesslich blockierten Versuchen ohne Hashprüfung."""
    submitted = []

    def attempt(candidate: str) -> LoginResult:
        """Merkt den übergebenen Kandidaten und simuliert eine aktive Kontosperre.

        :param candidate: Vom Runner übergebener künstlicher Testkandidat.
        :return: Blockiertes Login-Ergebnis ohne ausgeführte Passwortprüfung.
        """
        submitted.append(candidate)
        return LoginResult("locked", False, 5)

    summary = run_attack(numeric_candidates(), attempt, "mono", "protected", Limits(3, 10))
    assert submitted == ["0000", "0001", "0002"]
    assert (summary.calls, summary.checked, summary.blocked) == (3, 0, 3)
    assert summary.outcome == "Aufruflimit erreicht"


def test_time_limit_without_real_sleep(clock: FakeClock) -> None:
    """Prüft das Zeitlimit mit einer kontrolliert fortschreitenden Uhr ohne echte Pausen.

    :param clock: Pro Test bereitgestellte, kontrollierbare Zeitquelle.
    """

    def attempt(candidate: str) -> LoginResult:
        """Simuliert eine falsche Prüfung mit einer Dauer von 0,6 Testsekunden.

        :param candidate: Für diese Zeitsimulation unerheblicher Passwortkandidat.
        :return: Fehlgeschlagenes Ergebnis mit ausgeführter Passwortprüfung.
        """
        clock.advance(0.6)
        return LoginResult("invalid", True)

    summary = run_attack(numeric_candidates(), attempt, "mono", "insecure", Limits(50, 1), clock)
    assert summary.calls == 2
    assert summary.elapsed == pytest.approx(1.2)
    assert summary.outcome == "Zeitlimit erreicht"


def test_success_stops_and_only_summary_shows_demo_password(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Prüft den sofortigen Erfolgsabbruch und die Kennzeichnung des ausgegebenen Testpassworts.

    :param capsys: pytest-Erfassung der Terminalausgaben.
    """
    summary = run_attack(
        ["test"], lambda _: LoginResult("success", True), "dictionary", "insecure", Limits()
    )
    assert summary.calls == 1 and summary.found_password == "test"
    print_summary(summary)
    assert "DEMO-ERGEBNIS" in capsys.readouterr().out


def test_ctrl_c_returns_summary() -> None:
    """Prüft, dass ein unterbrochener Kandidatenstrom eine geordnete Zusammenfassung liefert."""

    def interrupted():
        """Erzeugt einen Kandidaten und simuliert danach Ctrl+C.

        :yield: Ein künstlicher Testkandidat für einen abgeschlossenen Aufruf.
        :raises KeyboardInterrupt: Beim nächsten Zugriff auf den Generator.
        """
        yield "first"
        raise KeyboardInterrupt

    summary = run_attack(
        interrupted(), lambda _: LoginResult("invalid", True), "mono", "insecure", Limits()
    )
    assert summary.calls == 1
    assert summary.outcome == "Mit Ctrl+C abgebrochen"


@pytest.mark.parametrize("calls,seconds", [(0, 1), (1, 0), (1, float("nan")), (1, float("inf"))])
def test_invalid_limits(calls: int, seconds: float) -> None:
    """Erwartet ValueError für nicht positive oder nicht endliche Angriffsgrenzen.

    :param calls: Parametrisiertes Aufruflimit.
    :param seconds: Parametrisiertes Zeitlimit in Sekunden.
    """
    with pytest.raises(ValueError):
        Limits(calls, seconds)


@pytest.mark.parametrize("live", [False, True])
def test_spawn_workers_share_lock_and_global_call_limit(db: Path, live: bool) -> None:
    """Prüft gemeinsame Sperren und globale Zähler mit echten spawn-Workern.

    :param db: Unabhängige temporäre Demo-Datenbank.
    :param live: Aktiviert zusätzlich die Prüfung aller Fortschrittsmeldungen.
    """
    configure(db, profile("lockout", lock_seconds=3600))
    updates = []

    def capture(candidate: str, result: LoginResult, progress: AttackSummary) -> None:
        """Speichert eine Momentaufnahme der im Elternprozess zusammengezählten Versuche.

        :param candidate: Gerade gemeldeter künstlicher Testkandidat.
        :param result: Login-Ergebnis; hier werden nur die aggregierten Zähler ausgewertet.
        :param progress: Gesamtzähler einschliesslich des aktuellen Versuchs.
        """
        updates.append((candidate, progress.calls, progress.checked, progress.blocked))

    summary = run_parallel(
        db,
        "pin",
        "protected",
        Limits(12, 15),
        start=100,
        stop=140,
        workers=3,
        on_attempt=capture if live else None,
    )
    assert (summary.calls, summary.checked, summary.blocked) == (12, 5, 7)
    assert summary.outcome == "Aufruflimit erreicht"
    if live:
        assert len(updates) == len({row[0] for row in updates}) == 12
        assert [row[1] for row in updates] == list(range(1, 13))
        assert updates[-1][1:] == (12, 5, 7)
    else:
        assert not updates
    with connect(db) as connection:
        failures = connection.execute("SELECT failures FROM login_state").fetchone()[0]
    assert failures == 5


def test_spawn_workers_find_password_and_stop(db: Path) -> None:
    """Prüft einen tatsächlichen Testpasswortfund und das Beenden der übrigen Worker.

    :param db: Unabhängige temporäre Demo-Datenbank.
    """
    summary = run_parallel(db, "pin", "insecure", Limits(30, 15), workers=2)
    assert summary.found_password == "0007"
    assert 8 <= summary.calls <= 16
    assert summary.checked == summary.calls and summary.blocked == 0


def test_parallel_time_limit_includes_startup(db: Path) -> None:
    """Prüft, dass ein bereits beim Workerstart abgelaufenes Limit keine Logins mehr zulässt.

    :param db: Unabhängige temporäre Demo-Datenbank.
    """
    summary = run_parallel(db, "pin", "insecure", Limits(10, 0.000001))
    assert summary.calls == 0
    assert summary.outcome == "Zeitlimit erreicht"


def test_parallel_ctrl_c_collects_results_and_restores_signal(
    db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prüft SIGINT-Abbruch, Ergebnissammlung und Wiederherstellung des Signalhandlers.

    :param db: Unabhängige temporäre Demo-Datenbank.
    :param monkeypatch: Ersetzt vorübergehend das Warten auf Pipe-Ergebnisse.
    """
    original_wait = parallel_module.wait
    previous_handler = signal.getsignal(signal.SIGINT)
    sent = False

    def interrupt_once(connections: list, timeout: float) -> list:
        """Löst einmal SIGINT aus und wartet anschliessend regulär auf Pipe-Ergebnisse.

        :param connections: Pipe-Verbindungen der gestarteten Worker.
        :param timeout: Maximale Wartezeit dieses Polling-Schritts in Sekunden.
        :return: Verbindungen mit lesbaren Ergebnissen.
        """
        nonlocal sent
        if not sent:
            sent = True
            signal.raise_signal(signal.SIGINT)
        return original_wait(connections, timeout)

    monkeypatch.setattr(parallel_module, "wait", interrupt_once)
    summary = run_parallel(db, "pin", "insecure", Limits(100, 15), start=100, stop=500)
    assert summary.outcome == "Mit Ctrl+C abgebrochen"
    assert summary.calls == summary.checked
    assert signal.getsignal(signal.SIGINT) is previous_handler


def test_live_updates_distinguish_checks_and_blocked_calls() -> None:
    """Prüft die Fortschrittszähler bei einer Folge aus Fehler, Blockierung und Erfolg."""
    results = iter(
        [
            LoginResult("invalid", True),
            LoginResult("waiting", False, 1.5),
            LoginResult("success", True),
        ]
    )
    updates = []

    def capture(candidate: str, result: LoginResult, summary: AttackSummary) -> None:
        """Speichert Kandidat, Status und Zähler für den späteren Reihenfolgevergleich.

        :param candidate: Gerade bearbeiteter künstlicher Testkandidat.
        :param result: Ergebnis des zugehörigen Login-Aufrufs.
        :param summary: Aktuelle Angriffsstatistik einschliesslich dieses Aufrufs.
        """
        updates.append((candidate, result.status, summary.calls, summary.checked, summary.blocked))

    summary = run_attack(
        ["0000", "0001", "0007", "0008"],
        lambda _: next(results),
        "mono",
        "protected",
        Limits(),
        on_attempt=capture,
    )
    assert updates == [
        ("0000", "invalid", 1, 1, 0),
        ("0001", "waiting", 2, 1, 1),
        ("0007", "success", 3, 2, 1),
    ]
    assert summary.found_password == "0007"
