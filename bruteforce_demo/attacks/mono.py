from collections.abc import Iterator
from itertools import product


def numeric_candidates(min_length: int = 4, max_length: int = 4) -> Iterator[str]:
    if not 1 <= min_length <= max_length <= 10:
        raise ValueError("Längen müssen 1 <= Minimum <= Maximum <= 10 erfüllen.")
    for length in range(min_length, max_length + 1):
        for digits in product("0123456789", repeat=length):
            yield "".join(digits)
