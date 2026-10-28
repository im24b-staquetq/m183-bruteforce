"""Kleine gemischte Zeichensätze und speichersparende Kandidatenerzeugung."""

import string
from collections.abc import Iterator
from itertools import product


def make_charset(letters: str = "ab", digits: str = "01", symbols: str = "") -> str:
    """Verbindet Zeichenklassen und entfernt Duplikate ohne Sortierung.

    :param letters: ASCII-Buchstaben in gewünschter Reihenfolge.
    :param digits: Ziffern von 0 bis 9.
    :param symbols: Optionale ASCII-Sonderzeichen.
    :return: Eindeutiger, nicht leerer Zeichensatz.
    :raises ValueError: Bei unzulässigen Zeichen oder leerem Zeichensatz.
    """
    if any(character not in string.ascii_letters for character in letters):
        raise ValueError("--letters erlaubt nur ASCII-Buchstaben.")
    if any(character not in string.digits for character in digits):
        raise ValueError("--digits erlaubt nur Ziffern von 0 bis 9.")
    if any(character not in string.punctuation for character in symbols):
        raise ValueError("--symbols erlaubt nur ASCII-Sonderzeichen.")
    charset = "".join(dict.fromkeys(letters + digits + symbols))
    if not charset:
        raise ValueError("Der Zeichensatz darf nicht leer sein.")
    return charset


def poly_candidates(charset: str, min_length: int = 2, max_length: int = 2) -> Iterator[str]:
    """Erzeugt alle Kandidaten lazy, zuerst nach Länge und dann nach Zeichenreihenfolge.

    :param charset: Nicht leerer Zeichensatz ohne doppelte Zeichen.
    :param min_length: Kürzeste Kandidatenlänge, mindestens 1.
    :param max_length: Längste Kandidatenlänge, höchstens 10.
    :yield: Jeweils ein künstlicher Testkandidat.
    :raises ValueError: Beim Iterieren, falls Zeichensatz oder Längen ungültig sind.
    """
    if not charset or len(charset) != len(set(charset)):
        raise ValueError("Der Zeichensatz muss eindeutig und nicht leer sein.")
    if not 1 <= min_length <= max_length <= 10:
        raise ValueError("Längen müssen 1 <= Minimum <= Maximum <= 10 erfüllen.")
    for length in range(min_length, max_length + 1):
        for characters in product(charset, repeat=length):
            yield "".join(characters)
