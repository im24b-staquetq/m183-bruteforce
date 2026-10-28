"""Kleine künstliche Wortlisten und deterministische Passwortvarianten."""

from collections.abc import Iterable, Iterator
from importlib.resources import files
from pathlib import Path


def read_words(path: Path | None = None) -> list[str]:
    """Liest eine UTF-8-Testwortliste ohne Leerzeilen und Kommentarzeilen.

    :param path: Eigene künstliche Testwortliste; None verwendet die mitgelieferte Datei.
    :return: Wörter in Dateireihenfolge, zunächst noch mit möglichen Duplikaten.
    :raises OSError: Wenn die Wortliste nicht gelesen werden kann.
    :raises UnicodeError: Wenn die Datei kein gültiges UTF-8 enthält.
    """
    text = (
        path.read_text(encoding="utf-8")
        if path is not None
        else files("bruteforce_demo").joinpath("data/words.txt").read_text(encoding="utf-8")
    )
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def dictionary_candidates(words: Iterable[str]) -> Iterator[str]:
    """Variiert Grossschreibung und hängt '', '1' oder '2' an, ohne doppelte Kandidaten.

    :param words: Künstliche Ausgangswörter in gewünschter Reihenfolge.
    :yield: Eindeutige Testkandidaten in deterministischer Reihenfolge.
    """
    seen: set[str] = set()
    for word in words:
        if not word:
            continue
        for form in (word, word.lower(), word.upper(), word.capitalize()):
            for suffix in ("", "1", "2"):
                candidate = form + suffix
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate
