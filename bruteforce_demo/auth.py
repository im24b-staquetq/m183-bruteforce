"""Gemeinsame Login-Schnittstelle für manuelle Anmeldung und Angriffe."""

import time
from collections.abc import Callable
from pathlib import Path

from argon2.exceptions import VerifyMismatchError

from bruteforce_demo.database import PASSWORD_HASHER, connect
from bruteforce_demo.defenses.audit import announce_alarm, record_event
from bruteforce_demo.defenses.lockout import should_lock
from bruteforce_demo.defenses.policy import Policy, load_policy
from bruteforce_demo.models import LoginResult, Variant


def login(
    path: Path,
    username: str,
    password: str,
    variant: Variant = "protected",
    *,
    clock: Callable[[], float] = time.time,
) -> LoginResult:
    """Atomare Zustandsprüfung, Hashprüfung und Aktualisierung pro Aufruf.

    Der Zeitgeber ist für Tests injizierbar. Angriffs-CLI und Worker verwenden
    ausschliesslich die echte Zeit und die gespeicherte Konfiguration.
    """
    if variant not in {"insecure", "protected"}:
        raise ValueError("Unbekannte Login-Variante.")
    alarm = False
    with connect(path) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        policy = load_policy(connection) if variant == "protected" else Policy(audit=True)
        now = clock()
        row = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            if policy.audit:
                record_event(connection, now, "LOGIN_FAILED", username, variant)
            return LoginResult("invalid", False)
        connection.execute(
            "INSERT OR IGNORE INTO login_state (username, variant) VALUES (?, ?)",
            (username, variant),
        )
        state = connection.execute(
            "SELECT * FROM login_state WHERE username = ? AND variant = ?", (username, variant)
        ).fetchone()
        failures = state["failures"]
        next_allowed = state["next_allowed_at"]
        locked_until = state["locked_until"]
        alarmed = state["alarmed"]
        if locked_until > now:
            return LoginResult("locked", False, locked_until - now)
        if locked_until > 0:
            failures, next_allowed, locked_until, alarmed = 0, 0.0, 0.0, 0
        if next_allowed > now:
            return LoginResult("waiting", False, next_allowed - now)
        try:
            PASSWORD_HASHER.verify(row["password_hash"], password)
        except VerifyMismatchError:
            result = LoginResult("invalid", True)
        else:
            result = LoginResult("success", True)
        # Die Wartezeit beginnt nach der teuren Hashprüfung.
        now = clock()
        if result.status == "success":
            failures, next_allowed, locked_until, alarmed = 0, 0.0, 0.0, 0
            if policy.audit:
                record_event(connection, now, "LOGIN_SUCCESS", username, variant)
        else:
            failures += 1
            next_allowed = now + policy.delay(failures)
            if policy.audit:
                record_event(connection, now, "LOGIN_FAILED", username, variant)
                if failures >= policy.alarm_threshold and not alarmed:
                    alarmed, alarm = 1, True
                    record_event(connection, now, "ALARM", username, variant)
            if should_lock(failures, policy.lock_threshold):
                locked_until = now + policy.lock_seconds
                if policy.audit:
                    record_event(connection, now, "ACCOUNT_LOCKED", username, variant)
        connection.execute(
            """UPDATE login_state
               SET failures = ?, next_allowed_at = ?, locked_until = ?, alarmed = ?
               WHERE username = ? AND variant = ?""",
            (failures, next_allowed, locked_until, alarmed, username, variant),
        )
    if alarm:
        announce_alarm()
    return result
