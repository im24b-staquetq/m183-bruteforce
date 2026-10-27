import math


def progressive_delay(failures: int, base: float, cap: float) -> float:
    """min(cap, base * 2**(failures-1)), ohne riesige Zwischenzahlen."""
    if failures < 1:
        return 0.0
    exponent = failures - 1
    if base >= cap or exponent >= math.log2(cap) - math.log2(base):
        return cap
    return min(cap, math.ldexp(base, exponent))
