import argparse
import getpass
import sqlite3
import sys
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

from argon2.exceptions import VerificationError

from bruteforce_demo.attacks.common import Limits, print_summary, run_attack
from bruteforce_demo.attacks.dictionary import dictionary_candidates, read_words
from bruteforce_demo.attacks.mono import numeric_candidates
from bruteforce_demo.attacks.parallel import run_parallel
from bruteforce_demo.attacks.poly import make_charset, poly_candidates
from bruteforce_demo.auth import login
from bruteforce_demo.database import connect, initialize, read_events, reset_states
from bruteforce_demo.defenses.policy import PROFILES, configure, load_policy, profile


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Lokale Brute-Force-Demo mit künstlichen Testkonten"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("runtime/demo.db"),
        help="SQLite-Datei (Standard: runtime/demo.db)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Neue Testdatenbank erstellen; überschreibt keine Datei")
    setup = sub.add_parser(
        "configure", help="Schutzprofil setzen; geschützte Zustände zurücksetzen"
    )
    setup.add_argument("--profile", choices=PROFILES, default="standard")
    setup.add_argument("--fixed-seconds", type=float)
    setup.add_argument("--base-seconds", type=float)
    setup.add_argument("--cap-seconds", type=float)
    setup.add_argument("--lock-threshold", type=int)
    setup.add_argument("--lock-seconds", type=float)
    setup.add_argument("--alarm-threshold", type=int)
    sub.add_parser("status", help="Gespeichertes Schutzprofil und Kontozustände anzeigen")
    reset = sub.add_parser("reset", help="Explizit Zustände zurücksetzen; behält Konten und Profil")
    reset.add_argument(
        "--clear-events", action="store_true", help="Zusätzlich Audit-Ereignisse löschen"
    )
    events = sub.add_parser("events", help="Persistente Audit- und Alarmereignisse anzeigen")
    events.add_argument("--limit", type=int, default=50)
    manual = sub.add_parser("login", help="Manuell anmelden; Passwort verdeckt abfragen")
    manual.add_argument("username", choices=("pin", "dictionary", "poly"))
    manual.add_argument("--variant", choices=("insecure", "protected"), default="protected")
    attack = sub.add_parser("attack", help="Kontrollierten lokalen Angriff starten")
    attack.add_argument("kind", choices=("mono", "dictionary", "poly", "parallel"))
    attack.add_argument("--username", choices=("pin", "dictionary", "poly"), default="pin")
    attack.add_argument("--variant", choices=("insecure", "protected"), default="protected")
    attack.add_argument("--max-calls", type=int, default=30)
    attack.add_argument("--max-seconds", type=float, default=10)
    attack.add_argument("--min-length", type=int)
    attack.add_argument("--max-length", type=int)
    attack.add_argument(
        "--letters", default="ab", help="Poly-Buchstaben in gewünschter Reihenfolge"
    )
    attack.add_argument("--digits", default="01", help="Poly-Ziffern")
    attack.add_argument("--symbols", default="", help="Optionale Poly-Sonderzeichen, z.B. '!?'")
    attack.add_argument(
        "--wordlist", type=Path, help="Nur eigene künstliche Testwortlisten verwenden"
    )
    attack.add_argument("--length", type=int, default=4, help="Feste Länge für Parallel-Angriff")
    attack.add_argument("--start", type=int, default=0, help="Parallel: inklusive Untergrenze")
    attack.add_argument("--stop", type=int, default=16, help="Parallel: exklusive Obergrenze")
    attack.add_argument("--workers", type=int, default=2)
    return parser


def execute_attack(args: argparse.Namespace) -> None:
    limits = Limits(args.max_calls, args.max_seconds)
    if args.kind == "parallel":
        summary = run_parallel(
            args.db,
            args.username,
            args.variant,
            limits,
            length=args.length,
            start=args.start,
            stop=args.stop,
            workers=args.workers,
        )
    else:
        if args.kind == "mono":
            candidates = numeric_candidates(
                4 if args.min_length is None else args.min_length,
                4 if args.max_length is None else args.max_length,
            )
        elif args.kind == "dictionary":
            candidates = dictionary_candidates(read_words(args.wordlist))
        else:
            candidates = poly_candidates(
                make_charset(args.letters, args.digits, args.symbols),
                2 if args.min_length is None else args.min_length,
                2 if args.max_length is None else args.max_length,
            )
        summary = run_attack(
            candidates,
            partial(login, args.db, args.username, variant=args.variant),
            args.kind,
            args.variant,
            limits,
        )
    print_summary(summary)


def dispatch(args: argparse.Namespace) -> None:
    if args.command == "init":
        initialize(args.db)
        print("Künstliche Testkonten angelegt: pin, dictionary, poly. Schutzprofil: standard.")
    elif args.command == "configure":
        names = (
            "fixed_seconds",
            "base_seconds",
            "cap_seconds",
            "lock_threshold",
            "lock_seconds",
            "alarm_threshold",
        )
        overrides = {name: getattr(args, name) for name in names if getattr(args, name) is not None}
        configure(args.db, profile(args.profile, **overrides))
        print(f"Profil {args.profile!r} gespeichert; geschützte Kontozustände zurückgesetzt.")
    elif args.command == "reset":
        reset_states(args.db, clear_events=args.clear_events)
        print("Demo-Zustände zurückgesetzt. Konten, Hashes und Schutzprofil beibehalten.")
    elif args.command == "status":
        with connect(args.db) as connection:
            print(f"Geschütztes Profil: {load_policy(connection)}")
            rows = connection.execute("SELECT * FROM login_state ORDER BY username, variant")
            for row in rows:
                print(dict(row))
        print("Zeitpunkte sind Unix-Zeit; 0 bedeutet: keine Wartezeit/Sperre gesetzt.")
    elif args.command == "events":
        events = read_events(args.db, args.limit)
        if not events:
            print("Keine Audit-Ereignisse vorhanden.")
        for event in events:
            timestamp = datetime.fromtimestamp(event["timestamp"], tz=UTC).isoformat()
            print(
                f"{timestamp} | {event['event_type']} | {event['variant']} | "
                f"Konto: {event['username']!r}"
            )
    elif args.command == "login":
        result = login(args.db, args.username, getpass.getpass("Testpasswort: "), args.variant)
        messages = {
            "success": "Anmeldung erfolgreich",
            "invalid": "Anmeldedaten ungültig",
            "waiting": "Wartezeit aktiv",
            "locked": "Konto vorübergehend gesperrt",
        }
        checked = "ja" if result.password_checked else "nein"
        print(f"{messages[result.status]}. Passwort geprüft: {checked}.")
        if result.blocked:
            print(f"Frühestens in {result.retry_after:.3f} Sekunden erneut versuchen.")
    else:
        execute_attack(args)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        dispatch(args)
        return 0
    except KeyboardInterrupt:
        print("Mit Ctrl+C abgebrochen.", file=sys.stderr)
        return 130
    except (OSError, sqlite3.Error, ValueError, RuntimeError, VerificationError) as error:
        print(
            f"Fehler: {error}. Datenbank zuerst mit 'init' erstellen; vorhandene Dateien bleiben "
            "erhalten.",
            file=sys.stderr,
        )
        return 2
