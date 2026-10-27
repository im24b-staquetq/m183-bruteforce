def should_lock(failures: int, threshold: int) -> bool:
    return threshold > 0 and failures >= threshold
