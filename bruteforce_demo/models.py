"""Gemeinsame Ergebnistypen der Login-Schnittstelle."""

from typing import Literal

Variant = Literal["insecure", "protected"]
LoginStatus = Literal["success", "invalid", "waiting", "locked"]


class LoginResult:
    """Ergebnis eines Login-Aufrufs mit nur lesbaren Properties.

    Attribute:
        status: Ergebniscode der Anmeldung.
        password_checked: Ob Argon2 tatsächlich ausgeführt wurde.
        retry_after: Verbleibende Wartezeit in Sekunden.
        blocked: Ob Wartezeit oder Kontosperre den Aufruf abgewiesen haben.
    """

    def __init__(
        self, status: LoginStatus, password_checked: bool, retry_after: float = 0.0
    ) -> None:
        """Speichert den Ergebniscode, die Prüfmarkierung und die Restwartezeit.

        :param status: Ergebniscode der Anmeldung.
        :param password_checked: True, wenn eine Passwortprüfung stattgefunden hat.
        :param retry_after: Wartezeit in Sekunden bis zum nächsten erlaubten Versuch.
        """
        self._status = status
        self._password_checked = password_checked
        self._retry_after = retry_after

    @property
    def status(self) -> LoginStatus:
        """Ergebniscode der Anmeldung."""
        return self._status

    @property
    def password_checked(self) -> bool:
        """Ob das Passwort tatsächlich geprüft wurde."""
        return self._password_checked

    @property
    def retry_after(self) -> float:
        """Verbleibende Wartezeit in Sekunden."""
        return self._retry_after

    @property
    def blocked(self) -> bool:
        """Ob eine aktive Wartezeit oder Kontosperre den Aufruf blockiert hat."""
        return self.status in {"waiting", "locked"}
