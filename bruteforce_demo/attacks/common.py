import math
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from bruteforce_demo.models import LoginResult


@dataclass(frozen=True)
class Limits:
    max_calls: int = 30
    max_seconds: float = 10.0

    def __post_init__(self) -> None:
        if self.max_calls < 1 or not math.isfinite(self.max_seconds) or self.max_seconds <= 0:
            raise ValueError("Versuchslimit und Zeitlimit müssen positiv sein.")


@dataclass
class AttackSummary:
    kind: str
    variant: str
    calls: int = 0
    checked: int = 0
    blocked: int = 0
    elapsed: float = 0.0
    outcome: str = "Suchraum ausgeschöpft"
    found_password: str | None = None

    def record(self, result: LoginResult) -> None:
        self.calls += 1
        self.checked += int(result.password_checked)
        self.blocked += int(result.blocked)


def run_attack(
    candidates: Iterable[str],
    attempt: Callable[[str], LoginResult],
    kind: str,
    variant: str,
    limits: Limits,
    clock: Callable[[], float] = time.monotonic,
) -> AttackSummary:
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
    print(f"Angriffsart: {summary.kind} | Zielvariante: {summary.variant}")
    print(f"Login-Aufrufe: {summary.calls} | Passwortprüfungen: {summary.checked}")
    print(f"Blockierte Versuche: {summary.blocked} | Laufzeit: {summary.elapsed:.3f} s")
    print(f"Ergebnis: {summary.outcome}")
    if summary.found_password is not None:
        print(f"DEMO-ERGEBNIS – künstliches Testpasswort: {summary.found_password!r}")
