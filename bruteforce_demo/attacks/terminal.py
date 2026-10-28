"""Optionale Demo-Anzeige: nur künstliche Testkandidaten, keine Audit-Logs."""

from bruteforce_demo.attacks.common import AttackSummary, ProgressCallback
from bruteforce_demo.models import LoginResult


def terminal_progress(username: str, kind: str, variant: str) -> ProgressCallback:
    print(f"DEMO-LIVE | Konto: {username} | Angriff: {kind} | Variante: {variant}")
    print(f"{'Testkandidat':<18} {'Status':<24} {'Aufrufe':>7} {'Geprüft':>8} {'Blockiert':>9}")

    def show_attempt(candidate: str, result: LoginResult, summary: AttackSummary) -> None:
        statuses = {
            "success": "GEFUNDEN",
            "invalid": "falsch",
            "waiting": "Wartezeit",
            "locked": "gesperrt",
        }
        status = statuses[result.status]
        if result.blocked:
            status += f" ({result.retry_after:.2f} s)"
        # repr verhindert, dass Steuerzeichen aus einer Testwortliste das Terminal verändern.
        label = repr(candidate)
        if len(label) > 18:
            label = label[:15] + "..."
        print(
            f"{label:<18} {status:<24} {summary.calls:>7} "
            f"{summary.checked:>8} {summary.blocked:>9}",
            flush=True,
        )

    return show_attempt
