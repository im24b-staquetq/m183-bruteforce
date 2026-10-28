"""Disjunkte Zahlenintervalle; Windows-kompatibler spawn-Kontext."""

import multiprocessing as mp
import signal
import time
from multiprocessing.connection import Connection, wait
from multiprocessing.sharedctypes import Synchronized
from multiprocessing.synchronize import Event
from pathlib import Path

from bruteforce_demo.attacks.common import AttackSummary, Limits, ProgressCallback
from bruteforce_demo.auth import login
from bruteforce_demo.models import Variant


def split_ranges(start: int, stop: int, workers: int) -> list[tuple[int, int]]:
    """Teilt [start, stop) lückenlos in disjunkte, möglichst gleich grosse Intervalle.

    :param start: Inklusive Untergrenze, mindestens 0.
    :param stop: Exklusive Obergrenze, grösser als start.
    :param workers: Gewünschte Workerzahl zwischen 1 und 16.
    :return: Intervallpaare; bei wenig Kandidaten werden weniger Worker verwendet.
    :raises ValueError: Bei ungültigem Bereich oder ungültiger Workerzahl.
    """
    if start < 0 or stop <= start or not 1 <= workers <= 16:
        raise ValueError("Ungültiger Suchraum oder Workerzahl (1–16).")
    count = min(workers, stop - start)
    size, remainder = divmod(stop - start, count)
    ranges = []
    cursor = start
    for index in range(count):
        end = cursor + size + int(index < remainder)
        ranges.append((cursor, end))
        cursor = end
    return ranges


def _worker(
    path: Path,
    username: str,
    variant: Variant,
    interval: tuple[int, int],
    length: int,
    limits: Limits,
    deadline: float,
    stop_event: Event,
    reserved: Synchronized,
    sender: Connection,
    report_progress: bool,
) -> None:
    """Prüft seinen Zahlenbereich über den Login und meldet das Ergebnis an den Elternprozess.

    :param path: Gemeinsame Demo-Datenbank.
    :param username: Künstliches Zielkonto.
    :param variant: Login-Variante.
    :param interval: Eigenes halboffenes Zahlenintervall.
    :param length: Feste Länge der Kandidaten einschliesslich führender Nullen.
    :param limits: Gemeinsame Laufgrenzen.
    :param deadline: Absoluter Endzeitpunkt der monotonen Uhr.
    :param stop_event: Gemeinsames Signal für Erfolg oder Abbruch.
    :param reserved: Mit Lock geschützter gemeinsamer Aufrufzähler.
    :param sender: Pipe zum Elternprozess, die hier geschlossen wird.
    :param report_progress: Sendet zusätzlich jedes abgeschlossene Versuchsergebnis.
    :raises OSError: Bei fehlgeschlagener Pipe-Kommunikation.
    :raises sqlite3.Error: Wenn die Login-Datenhaltung scheitert.
    """
    # Ctrl+C behandelt der Elternprozess; Worker beenden ihre aktuelle Transaktion.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    summary = AttackSummary("parallel", variant)
    try:
        for number in range(*interval):
            with reserved.get_lock():
                if stop_event.is_set() or time.monotonic() >= deadline:
                    break
                if reserved.value >= limits.max_calls:
                    break
                reserved.value += 1
            candidate = f"{number:0{length}d}"
            result = login(path, username, candidate, variant)
            summary.record(result)
            if result.status == "success":
                summary.found_password = candidate
                stop_event.set()
            if report_progress:
                sender.send((candidate, result))
            if summary.found_password is not None:
                break
    finally:
        sender.send(summary)
        sender.close()


def run_parallel(
    path: Path,
    username: str,
    variant: Variant,
    limits: Limits,
    *,
    length: int = 4,
    start: int = 0,
    stop: int = 16,
    workers: int = 2,
    on_attempt: ProgressCallback | None = None,
) -> AttackSummary:
    """Startet Windows-kompatible Worker und sammelt ihre Ergebnisse im Elternprozess.

    :param path: Gemeinsame Demo-Datenbank.
    :param username: Künstliches Zielkonto.
    :param variant: Login-Variante.
    :param limits: Globales Aufruflimit und Zeitlimit einschliesslich Workerstart.
    :param length: Feste numerische Kandidatenlänge von 1 bis 10.
    :param start: Inklusive Untergrenze des Suchraums.
    :param stop: Exklusive Obergrenze des Suchraums.
    :param workers: Anzahl der Worker, höchstens 16.
    :param on_attempt: Optionale Ausgabe der Versuchsergebnisse im Elternprozess.
    :return: Zusammengeführte Statistik; SIGINT führt zu einem geordneten Abbruch.
    :raises ValueError: Bei ungültigen Suchraumparametern oder Aufruf ausserhalb des Hauptthreads.
    :raises RuntimeError: Wenn ein Worker ohne gültiges Ergebnis oder mit Fehler endet.
    :raises OSError: Wenn Prozessstart oder Pipe-Kommunikation scheitern.
    """
    if not 1 <= length <= 10 or stop > 10**length:
        raise ValueError("Länge muss 1–10 sein; Bereich muss in diese Länge passen.")
    ranges = split_ranges(start, stop, workers)
    context = mp.get_context("spawn")
    stop_event = context.Event()
    reserved = context.Value("q", 0)
    summary = AttackSummary("parallel", variant)
    progress = AttackSummary("parallel", variant)
    started = time.monotonic()
    deadline = started + limits.max_seconds
    processes: list[mp.Process] = []
    receivers: list[Connection] = []
    interrupted = False

    def handle_interrupt(_signum: int, _frame: object) -> None:
        """Setzt das Stop-Event; Signalnummer und Stackframe werden nicht benötigt.

        :param _signum: Von Python übergebene Signalnummer.
        :param _frame: Von Python übergebener Stackframe.
        """
        nonlocal interrupted
        interrupted = True
        stop_event.set()

    previous_handler = signal.signal(signal.SIGINT, handle_interrupt)
    try:
        for interval in ranges:
            if stop_event.is_set():
                break
            receiver, sender = context.Pipe(duplex=False)
            process = context.Process(
                target=_worker,
                args=(
                    path,
                    username,
                    variant,
                    interval,
                    length,
                    limits,
                    deadline,
                    stop_event,
                    reserved,
                    sender,
                    on_attempt is not None,
                ),
            )
            process.start()
            sender.close()
            processes.append(process)
            receivers.append(receiver)
        pending = list(receivers)
        while pending:
            try:
                ready = wait(pending, timeout=0.1)
            except KeyboardInterrupt:
                interrupted = True
                stop_event.set()
                continue
            for receiver in ready:
                try:
                    message = receiver.recv()
                except EOFError as error:
                    raise RuntimeError("Ein Worker endete ohne Ergebnis.") from error
                if not isinstance(message, AttackSummary):
                    candidate, result = message
                    progress.record(result)
                    if on_attempt is not None:
                        on_attempt(candidate, result, progress)
                    continue
                summary.merge(message)
                pending.remove(receiver)
    finally:
        stop_event.set()
        for process in processes:
            process.join(timeout=15)
            if process.is_alive():
                process.terminate()
                process.join()
        for receiver in receivers:
            receiver.close()
        signal.signal(signal.SIGINT, previous_handler)
    if any(process.exitcode != 0 for process in processes):
        raise RuntimeError("Mindestens ein Worker wurde nicht sauber beendet.")
    summary.elapsed = time.monotonic() - started
    if summary.found_password is not None:
        summary.outcome = "Testpasswort gefunden"
    elif interrupted:
        summary.outcome = "Mit Ctrl+C abgebrochen"
    elif summary.calls >= limits.max_calls:
        summary.outcome = "Aufruflimit erreicht"
    elif time.monotonic() >= deadline:
        summary.outcome = "Zeitlimit erreicht"
    return summary
