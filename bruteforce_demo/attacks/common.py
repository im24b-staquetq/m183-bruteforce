"""Gemeinsamer Angriffsablauf mit Limits und getrennten Versuchszählern."""

import math
import time
from collections.abc import Callable, Iterable

from bruteforce_demo.models import LoginResult


class Limits:
    """Obergrenzen für einen Angriff mit nur lesbaren Properties.

    Attribute:
        max_calls: Maximale Zahl der Login-Aufrufe über alle Worker.
        max_seconds: Maximale Laufzeit in Sekunden, ohne Abbruch laufender Prüfungen.
    """

    def __init__(self, max_calls: int = 30, max_seconds: float = 10.0) -> None:
        """Prüft und speichert die Grenzen.

        :param max_calls: Positive Obergrenze für Login-Aufrufe.
        :param max_seconds: Endliche, positive Laufzeit in Sekunden.
        :raises ValueError: Wenn eine Grenze ungültig ist.
        """
        if max_calls < 1 or not math.isfinite(max_seconds) or max_seconds <= 0:
            raise ValueError("Versuchslimit und Zeitlimit müssen positiv sein.")
        self._max_calls = max_calls
        self._max_seconds = max_seconds

    @property
    def max_calls(self) -> int:
        """Maximale Zahl der Login-Aufrufe."""
        return self._max_calls

    @property
    def max_seconds(self) -> float:
        """Maximale Laufzeit in Sekunden."""
        return self._max_seconds


class AttackSummary:
    """Sammelt abgeschlossene Login-Aufrufe und das Demo-Ergebnis.

    Attribute:
        kind, variant: Angriffsart und Zielvariante.
        calls, checked, blocked: Aufrufe, Passwortprüfungen und blockierte Aufrufe.
        elapsed: Gemessene Laufzeit in Sekunden.
        outcome: Lesbare Begründung für das Ende des Angriffs.
        found_password: Gefundenes künstliches Testpasswort oder None.
    Methoden:
        record: Übernimmt ein einzelnes Login-Ergebnis.
        merge: Addiert die abgeschlossene Zusammenfassung eines Workers.
    """

    def __init__(self, kind: str, variant: str) -> None:
        """Startet eine leere Statistik für Angriffsart und Zielvariante.

        :param kind: Bezeichnung des Angriffs.
        :param variant: Gewählte Login-Variante.
        """
        self._kind = kind
        self._variant = variant
        self._calls = 0
        self._checked = 0
        self._blocked = 0
        self._elapsed = 0.0
        self._outcome = "Suchraum ausgeschöpft"
        self._found_password: str | None = None

    def record(self, result: LoginResult) -> None:
        """Zählt einen abgeschlossenen Aufruf anhand seines Ergebnisses.

        :param result: Ergebnis der gemeinsamen Login-Schnittstelle.
        """
        self._calls += 1
        self._checked += int(result.password_checked)
        self._blocked += int(result.blocked)

    def merge(self, other: "AttackSummary") -> None:
        """Übernimmt Zähler und einen möglichen Fund eines beendeten Workers.

        :param other: Noch nicht übernommene Zusammenfassung eines Workers.
        """
        self._calls += other.calls
        self._checked += other.checked
        self._blocked += other.blocked
        if other.found_password is not None:
            self._found_password = other.found_password

    @property
    def kind(self) -> str:
        """Bezeichnung des Angriffs."""
        return self._kind

    @property
    def variant(self) -> str:
        """Zielvariante des Logins."""
        return self._variant

    @property
    def calls(self) -> int:
        """Zahl abgeschlossener Login-Aufrufe."""
        return self._calls

    @property
    def checked(self) -> int:
        """Zahl tatsächlich ausgeführter Passwortprüfungen."""
        return self._checked

    @property
    def blocked(self) -> int:
        """Zahl durch Schutzmassnahmen blockierter Aufrufe."""
        return self._blocked

    @property
    def elapsed(self) -> float:
        """Gemessene Laufzeit in Sekunden."""
        return self._elapsed

    @elapsed.setter
    def elapsed(self, seconds: float) -> None:
        """Speichert die gemessene Laufzeit in Sekunden."""
        self._elapsed = seconds

    @property
    def outcome(self) -> str:
        """Begründung für das Ende des Angriffs."""
        return self._outcome

    @outcome.setter
    def outcome(self, message: str) -> None:
        """Speichert die Begründung für das Ende des Angriffs."""
        self._outcome = message

    @property
    def found_password(self) -> str | None:
        """Gefundenes künstliches Testpasswort oder None."""
        return self._found_password

    @found_password.setter
    def found_password(self, password: str | None) -> None:
        """Speichert den Fund ausschliesslich für das gekennzeichnete Demo-Ergebnis."""
        self._found_password = password


ProgressCallback = Callable[[str, LoginResult, AttackSummary], None]


def run_attack(
    candidates: Iterable[str],
    attempt: Callable[[str], LoginResult],
    kind: str,
    variant: str,
    limits: Limits,
    clock: Callable[[], float] = time.monotonic,
    *,
    on_attempt: ProgressCallback | None = None,
) -> AttackSummary:
    """Übergibt Kandidaten an den Login, bis Erfolg, Limit oder Abbruch eintritt.

    :param candidates: Lazy erzeugte künstliche Testpasswörter.
    :param attempt: Login-Funktion für einen Kandidaten.
    :param kind: Angriffsart für die Zusammenfassung.
    :param variant: Gewählte Login-Variante.
    :param limits: Aufruf- und Zeitlimit.
    :param clock: Monotone Zeitquelle; in Tests kontrollierbar.
    :param on_attempt: Optionale Ausgabe nach jedem abgeschlossenen Aufruf.
    :return: Statistik und Abbruchgrund. Ctrl+C wird als Abbruchgrund zurückgegeben.
    :raises OSError: Wenn eine Ein- oder Ausgabe scheitert.
    Fehler des übergebenen Logins und Ausgabe-Callbacks werden unverändert weitergegeben.
    """
    summary = AttackSummary(kind, variant)
    started = clock()
    iterator = iter(candidates)
    try:
        while True:
            if summary.calls >= limits.max_calls:
                summary.outcome = "Aufruflimit erreicht"
                break
            if clock() - started >= limits.max_seconds:
                summary.outcome = "Zeitlimit erreicht"
                break
            try:
                candidate = next(iterator)
            except StopIteration:
                break
            if clock() - started >= limits.max_seconds:
                summary.outcome = "Zeitlimit erreicht"
                break
            result = attempt(candidate)
            summary.record(result)
            if on_attempt is not None:
                on_attempt(candidate, result, summary)
            if result.status == "success":
                summary.found_password = candidate
                summary.outcome = "Testpasswort gefunden"
                break
    except KeyboardInterrupt:
        summary.outcome = "Mit Ctrl+C abgebrochen"
    finally:
        summary.elapsed = clock() - started
    return summary


def print_summary(summary: AttackSummary) -> None:
    """Gibt Statistik und einen möglichen Fund als gekennzeichnetes Demo-Ergebnis aus.

    :param summary: Abgeschlossene Angriffsstatistik.
    """
    print(f"Angriffsart: {summary.kind} | Zielvariante: {summary.variant}")
    print(f"Login-Aufrufe: {summary.calls} | Passwortprüfungen: {summary.checked}")
    print(f"Blockierte Versuche: {summary.blocked} | Laufzeit: {summary.elapsed:.3f} s")
    print(f"Ergebnis: {summary.outcome}")
    if summary.found_password is not None:
        print(f"DEMO-ERGEBNIS – künstliches Testpasswort: {summary.found_password!r}")
