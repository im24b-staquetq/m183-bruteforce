from collections.abc import Iterable, Iterator
from importlib.resources import files
from pathlib import Path


def read_words(path: Path | None = None) -> list[str]:
    text = (
        path.read_text(encoding="utf-8")
        if path is not None
        else files("bruteforce_demo").joinpath("data/words.txt").read_text(encoding="utf-8")
    )
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def dictionary_candidates(words: Iterable[str]) -> Iterator[str]:
    """Pro Wort: Original, klein, gross, erster Buchstabe gross; jeweils '', '1', '2'."""
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
