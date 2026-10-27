from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
from conftest import FakeClock

from bruteforce_demo.auth import login
from bruteforce_demo.database import PASSWORD_HASHER, connect, initialize, read_events, reset_states
from bruteforce_demo.defenses.policy import Policy, configure, profile


def state(db: Path, variant: str = "protected") -> dict:
    with connect(db) as connection:
        return dict(
            connection.execute(
                "SELECT * FROM login_state WHERE username = ? AND variant = ?", ("pin", variant)
            ).fetchone()
        )


def test_correct_and_wrong_password(db: Path, clock: FakeClock) -> None:
    assert login(db, "pin", "0007", clock=clock).status == "success"
    result = login(db, "pin", "wrong", clock=clock)
    assert result.status == "invalid"
    assert result.password_checked


@pytest.mark.parametrize("username", ["missing", "' OR 1=1 --"])
def test_unknown_user_and_parameterized_sql(db: Path, username: str) -> None:
    result = login(db, username, "0007")
    assert result.status == "invalid"
    assert not result.password_checked
    assert not result.blocked


def test_insecure_has_no_limit_even_with_protected_lock(db: Path, clock: FakeClock) -> None:
    configure(db, profile("lockout"))
    for _ in range(5):
        login(db, "pin", "wrong", clock=clock)
    assert login(db, "pin", "0007", clock=clock).status == "locked"
    for _ in range(8):
        result = login(db, "pin", "wrong", "insecure", clock=clock)
        assert result.password_checked and not result.blocked
    assert login(db, "pin", "0007", "insecure", clock=clock).status == "success"
    assert login(db, "pin", "0007", clock=clock).status == "locked"


def test_argon2id_parameters_and_individual_salts(db: Path) -> None:
    with connect(db) as connection:
        hashes = [row[0] for row in connection.execute("SELECT password_hash FROM users")]
    assert all(value.startswith("$argon2id$v=19$m=65536,t=3,p=4$") for value in hashes)
    assert len({value.split("$")[4] for value in hashes}) == 3
    assert PASSWORD_HASHER.hash("same") != PASSWORD_HASHER.hash("same")


def test_initialization_preserves_existing_file(db: Path) -> None:
    before = db.read_bytes()
    with pytest.raises(FileExistsError):
        initialize(db)
    assert db.read_bytes() == before


def test_fixed_delay_persists_between_connections(db: Path, clock: FakeClock) -> None:
    configure(db, profile("fixed", fixed_seconds=2))
    assert login(db, "pin", "wrong", clock=clock).password_checked
    clock.advance(0.5)
    result = login(db, "pin", "0007", clock=clock)
    assert result.status == "waiting" and not result.password_checked
    assert result.retry_after == pytest.approx(1.5)
    assert state(db)["failures"] == 1
    clock.advance(1.5)
    assert login(db, "pin", "0007", clock=clock).status == "success"


def test_progressive_delay_and_cap(db: Path, clock: FakeClock) -> None:
    configure(db, profile("progressive", base_seconds=1, cap_seconds=3))
    for expected_delay in (1, 2, 3, 3):
        assert login(db, "pin", "wrong", clock=clock).password_checked
        result = login(db, "pin", "wrong", clock=clock)
        assert result.status == "waiting"
        assert result.retry_after == expected_delay
        clock.advance(expected_delay)


def test_lock_threshold_expiry_and_no_extra_hash_check(db: Path, clock: FakeClock) -> None:
    configure(db, profile("lockout", lock_seconds=10))
    for _ in range(5):
        assert login(db, "pin", "wrong", clock=clock).password_checked
    with patch("bruteforce_demo.auth.PASSWORD_HASHER", wraps=PASSWORD_HASHER) as hasher:
        for _ in range(10):
            result = login(db, "pin", "0007", clock=clock)
            assert result.status == "locked"
            assert result.retry_after == 10
            assert not result.password_checked
        hasher.verify.assert_not_called()
    assert state(db)["failures"] == 5
    clock.advance(10)
    assert login(db, "pin", "wrong", clock=clock).password_checked
    assert state(db)["failures"] == 1
    assert state(db)["locked_until"] == 0


def test_success_resets_all_failure_state(db: Path, clock: FakeClock) -> None:
    configure(db, profile("standard", base_seconds=1, cap_seconds=2, lock_threshold=4))
    for _ in range(3):
        login(db, "pin", "wrong", clock=clock)
        clock.advance(2)
    assert state(db)["alarmed"] == 1
    assert login(db, "pin", "0007", clock=clock).status == "success"
    after = state(db)
    assert all(
        after[key] == 0 for key in ("failures", "next_allowed_at", "locked_until", "alarmed")
    )


def test_expired_lock_allows_correct_password(db: Path, clock: FakeClock) -> None:
    configure(db, profile("lockout", lock_threshold=1, lock_seconds=2))
    login(db, "pin", "wrong", clock=clock)
    clock.advance(2)
    assert login(db, "pin", "0007", clock=clock).status == "success"


def test_concurrent_connections_cannot_overrun_lock(db: Path, clock: FakeClock) -> None:
    configure(db, profile("lockout", lock_threshold=3, lock_seconds=3600))
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: login(db, "pin", "wrong", clock=clock), range(12)))
    assert sum(result.password_checked for result in results) == 3
    assert sum(result.blocked for result in results) == 9
    assert state(db)["failures"] == 3


def test_audit_alarm_no_secrets_or_flood(
    db: Path, clock: FakeClock, capsys: pytest.CaptureFixture[str]
) -> None:
    configure(db, Policy(lock_threshold=5, audit=True, alarm_threshold=3))
    secret = "NEVER-LOG-THIS-PASSWORD"
    for _ in range(15):
        login(db, "pin", secret, clock=clock)
    events = [dict(event) for event in read_events(db)]
    kinds = [event["event_type"] for event in events]
    assert kinds.count("LOGIN_FAILED") == 5
    assert kinds.count("ALARM") == 1
    assert kinds.count("ACCOUNT_LOCKED") == 1
    output = capsys.readouterr().err
    assert output.count("LOKALER ALARM") == 1
    assert secret not in str(events) + output
    assert "argon2" not in str(events) + output
    assert all(event["timestamp"] == clock.now for event in events)
    assert all(event["username"] == "pin" for event in events)


def test_reset_is_explicit_and_keeps_accounts_and_policy(db: Path, clock: FakeClock) -> None:
    configure(db, Policy(lock_threshold=1, audit=True))
    login(db, "pin", "wrong", clock=clock)
    reset_states(db)
    assert read_events(db)
    assert login(db, "pin", "0007", clock=clock).status == "success"
    reset_states(db, clear_events=True)
    assert not read_events(db)


def test_logging_alone_does_not_prevent_attempts(db: Path, clock: FakeClock) -> None:
    configure(db, profile("logging"))
    for _ in range(8):
        result = login(db, "pin", "wrong", clock=clock)
        assert result.password_checked and not result.blocked
    kinds = [event["event_type"] for event in read_events(db)]
    assert kinds.count("LOGIN_FAILED") == 8
    assert kinds.count("ALARM") == 1


def test_alarm_rearms_after_lock_expiry(db: Path, clock: FakeClock) -> None:
    configure(db, Policy(lock_threshold=3, lock_seconds=1, audit=True))
    for _ in range(3):
        login(db, "pin", "wrong", clock=clock)
    clock.advance(1)
    for _ in range(3):
        login(db, "pin", "wrong", clock=clock)
    kinds = [event["event_type"] for event in read_events(db)]
    assert kinds.count("ALARM") == 2
    assert kinds.count("ACCOUNT_LOCKED") == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        {"base_seconds": 0},
        {"cap_seconds": -1},
        {"lock_seconds": float("nan")},
        {"fixed_seconds": float("inf")},
        {"lock_threshold": -1},
        {"alarm_threshold": 0},
        {"base_seconds": 4, "cap_seconds": 2},
    ],
)
def test_invalid_policy(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        Policy(**kwargs)
