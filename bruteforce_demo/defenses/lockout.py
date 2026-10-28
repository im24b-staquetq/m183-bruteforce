"""Entscheidung über eine temporäre Kontosperre nach falschen Prüfungen."""


def should_lock(failures: int, threshold: int) -> bool:
    """Prüft, ob die aktivierte Fehlerschwelle erreicht ist.

    :param failures: Anzahl aufeinanderfolgender falscher Passwortprüfungen.
    :param threshold: Sperrschwelle; 0 deaktiviert die Sperre.
    :return: True, wenn eine Sperre ausgelöst werden soll.
    """
    return 0 < threshold <= failures
