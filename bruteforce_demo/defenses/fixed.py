"""Konstante Wartezeit nach einer falschen Passwortprüfung."""


def fixed_delay(seconds: float) -> float:
    """Liefert die feste Wartezeit aus dem bereits validierten Profil.

    :param seconds: Konfigurierte positive Wartezeit in Sekunden.
    :return: Unveränderte Wartezeit in Sekunden.
    """
    return seconds
