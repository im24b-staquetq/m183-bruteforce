"""logging-Handler mit derselben SQLite-Transaktion wie der Login-Zustand."""

import logging
import sqlite3
import sys


class DatabaseAuditHandler(logging.Handler):
    """Schreibt LogRecords über die bereits laufende Login-Transaktion.

    Attribute:
        connection: Nur lesbarer Zugriff auf die vorhandene SQLite-Verbindung.
    Methoden:
        emit: Speichert Ereignistyp, Zeitpunkt, Konto und Variante ohne Passwort.
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        """Verwendet die Verbindung des aufrufenden Logins.

        :param connection: Geöffnete SQLite-Verbindung; wird hier nicht geschlossen.
        """
        super().__init__()
        self._connection = connection

    def emit(self, record: logging.LogRecord) -> None:
        """Speichert genau ein strukturiertes Audit-Ereignis.

        :param record: LogRecord mit event_time, username und variant.
        :raises sqlite3.Error: Wenn das Einfügen scheitert; der Login wird zurückgerollt.
        """
        self.connection.execute(
            "INSERT INTO audit_events (timestamp, event_type, username, variant) "
            "VALUES (?, ?, ?, ?)",
            (record.event_time, record.getMessage(), record.username, record.variant),
        )

    @property
    def connection(self) -> sqlite3.Connection:
        """SQLite-Verbindung der zugehörigen Login-Transaktion."""
        return self._connection


def record_event(
    connection: sqlite3.Connection, timestamp: float, event: str, username: str, variant: str
) -> None:
    """Protokolliert ein Sicherheitsereignis über den SQLite-Logging-Handler.

    :param connection: Verbindung der laufenden Login-Transaktion.
    :param timestamp: Unix-Zeitpunkt des Ereignisses.
    :param event: Ereignistyp; enthält keine Passwörter oder Hashes.
    :param username: Betroffenes künstliches Testkonto.
    :param variant: Gewählte Login-Variante.
    :raises sqlite3.Error: Wenn das Speichern des Ereignisses scheitert.
    """
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
    """Gibt nach dem Commit eine lokale Alarmmeldung ohne Zugangsdaten auf stderr aus."""
    print(
        "LOKALER ALARM: Mehrere fehlgeschlagene Passwortprüfungen; siehe Audit-Ereignisse.",
        file=sys.stderr,
    )
