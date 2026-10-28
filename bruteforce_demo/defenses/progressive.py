"""Begrenzte exponentielle Wartezeit nach wiederholten Fehlversuchen."""

import math


def progressive_delay(failures: int, base: float, cap: float) -> float:
    """Berechnet min(cap, base * 2**(failures-1)) ohne riesige Zwischenzahlen.

    :param failures: Anzahl falscher Prüfungen; bei Werten unter 1 ist das Ergebnis 0.
    :param base: Vom Profil validierte positive Anfangswartezeit in Sekunden.
    :param cap: Vom Profil validierte positive Obergrenze, mindestens base.
    :return: Wartezeit in Sekunden, höchstens cap.
    """
    if failures < 1:
        return 0.0
    exponent = failures - 1
    if base >= cap or exponent >= math.log2(cap) - math.log2(base):
        return cap
    return min(cap, math.ldexp(base, exponent))
