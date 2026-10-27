"""Disjunkte Zahlenintervalle; Windows-kompatibler spawn-Kontext."""

import multiprocessing as mp
import signal
import time
from multiprocessing.connection import Connection, wait
from multiprocessing.sharedctypes import Synchronized
from multiprocessing.synchronize import Event
from pathlib import Path

from bruteforce_demo.attacks.common import AttackSummary, Limits
from bruteforce_demo.auth import login
from bruteforce_demo.models import Variant


def split_ranges(start: int, stop: int, workers: int) -> list[tuple[int, int]]:
    """Halboffene Intervalle [start, stop), Grössen unterscheiden sich höchstens um eins."""
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
) -> None:
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
) -> AttackSummary:
    if not 1 <= length <= 10 or stop > 10**length:
        raise ValueError("Länge muss 1–10 sein; Bereich muss in diese Länge passen.")
    ranges = split_ranges(start, stop, workers)
    context = mp.get_context("spawn")
    stop_event = context.Event()
    reserved = context.Value("q", 0)
    summary = AttackSummary("parallel", variant)
    started = time.monotonic()
    deadline = started + limits.max_seconds
    processes: list[mp.Process] = []
    receivers: list[Connection] = []
    interrupted = False

    def handle_interrupt(signum: int, frame: object) -> None:
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
                    part = receiver.recv()
                except EOFError as error:
                    raise RuntimeError("Ein Worker endete ohne Ergebnis.") from error
                summary.calls += part.calls
                summary.checked += part.checked
                summary.blocked += part.blocked
                if part.found_password is not None:
                    summary.found_password = part.found_password
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
