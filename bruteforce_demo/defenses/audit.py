"""logging-Handler mit derselben SQLite-Transaktion wie der Login-Zustand."""

import logging
import sqlite3
import sys


class DatabaseAuditHandler(logging.Handler):
    def __init__(self, connection: sqlite3.Connection) -> None:
        super().__init__()
        self.connection = connection

    def emit(self, record: logging.LogRecord) -> None:
        self.connection.execute(
            "INSERT INTO audit_events (timestamp, event_type, username, variant) "
            "VALUES (?, ?, ?, ?)",
            (record.event_time, record.getMessage(), record.username, record.variant),
        )


def record_event(
    connection: sqlite3.Connection, timestamp: float, event: str, username: str, variant: str
) -> None:
    logger = logging.Logger("bruteforce.audit", level=logging.INFO)
    handler = DatabaseAuditHandler(connection)
    logger.addHandler(handler)
    try:
        logger.log(
            logging.WARNING if event == "ALARM" else logging.INFO,
            event,
            extra={"event_time": timestamp, "username": username, "variant": variant},
        )
    finally:
        logger.removeHandler(handler)
        handler.close()


def announce_alarm() -> None:
    print(
        "LOKALER ALARM: Mehrere fehlgeschlagene Passwortprüfungen; siehe Audit-Ereignisse.",
        file=sys.stderr,
    )
