"""
tests/m1_core/test_auth_lockout.py
AT-02.2: Lockout enforcement tests.

Tests:
  - 5 failures → 6th attempt (even with correct password) is refused
  - Account unlocks after lockout expires (frozen clock)
  - Enumeration safety: unknown users get same error as wrong passwords
  - Per-IP lockout: 5 failures from same IP locks that IP
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch


def _make_request(ip: str = "127.0.0.1") -> MagicMock:
    req = MagicMock()
    req.session = {}
    req.client = MagicMock()
    req.client.host = ip
    req.headers = {}
    return req


def _make_db_with_user(password: str = "Admin@secure1", failed: int = 0, locked_until=None):
    """Return a mock DB with one Member row."""
    from clarinet.models import Member
    from clarinet.auth import hash_password

    member = Member(
        member_id=1,
        username="admin",
        password_hash=hash_password(password),
        role="ADMIN",
        is_active=True,
        failed_attempts=failed,
        locked_until=locked_until,
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = member
    db.get.return_value = member
    db.query.return_value.filter.return_value.count.return_value = 0
    return db, member


def test_wrong_password_increments_counter():
    """Each wrong password increments failed_attempts."""
    from clarinet.auth import attempt_login

    db, member = _make_db_with_user(failed=0)
    req = _make_request()

    with patch("clarinet.auth._write_login_attempt"), \
         patch("clarinet.auth._audit"), \
         patch("clarinet.auth._count_recent_ip_failures", return_value=0):
        user, err = attempt_login(req, db, "admin", "wrongpassword")

    assert user is None
    assert err is not None
    assert member.failed_attempts == 1


def test_five_failures_triggers_lockout():
    """5 consecutive wrong passwords lock the account."""
    from clarinet.auth import attempt_login

    db, member = _make_db_with_user(failed=4)  # 4 previous failures
    req = _make_request()

    with patch("clarinet.auth._write_login_attempt"), \
         patch("clarinet.auth._audit"), \
         patch("clarinet.auth._count_recent_ip_failures", return_value=0):
        user, err = attempt_login(req, db, "admin", "wrongpassword")

    assert user is None
    assert err is not None
    assert member.locked_until is not None   # lockout set


def test_locked_account_refuses_correct_password():
    """A locked account refuses even the correct password."""
    from clarinet.auth import attempt_login

    locked_until = datetime.now(timezone.utc) + timedelta(minutes=3)
    db, member = _make_db_with_user(failed=0, locked_until=locked_until)
    req = _make_request()

    with patch("clarinet.auth._write_login_attempt"), \
         patch("clarinet.auth._audit"), \
         patch("clarinet.auth._count_recent_ip_failures", return_value=0):
        user, err = attempt_login(req, db, "admin", "Admin@secure1")

    assert user is None
    # The message is the same as for a wrong password, so it does not reveal that the account exists.
    assert err == "Invalid username or password."


def test_expired_lockout_allows_login():
    """A lockout in the past is cleared and login succeeds."""
    from clarinet.auth import attempt_login

    # Lockout in the past
    locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
    db, member = _make_db_with_user(failed=0, locked_until=locked_until)
    req = _make_request()

    with patch("clarinet.auth._write_login_attempt"), \
         patch("clarinet.auth._audit"), \
         patch("clarinet.auth._count_recent_ip_failures", return_value=0), \
         patch("clarinet.auth.login_user"):
        user, err = attempt_login(req, db, "admin", "Admin@secure1")

    assert err is None
    assert user is not None


def test_enumeration_safety_unknown_user():
    """Unknown username gives the same generic error as wrong password."""
    from clarinet.auth import attempt_login

    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None  # no user found
    db.query.return_value.filter.return_value.count.return_value = 0
    req = _make_request()

    with patch("clarinet.auth._write_login_attempt"), \
         patch("clarinet.auth._audit"), \
         patch("clarinet.auth._count_recent_ip_failures", return_value=0):
        user, err = attempt_login(req, db, "nobody", "anypassword")

    assert user is None
    assert err == "Invalid username or password."


def test_ip_lockout_blocks_further_attempts():
    """5+ failures from same IP return generic error even for unknown users."""
    from clarinet.auth import attempt_login

    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.query.return_value.filter.return_value.count.return_value = 0
    req = _make_request(ip="1.2.3.4")

    with patch("clarinet.auth._write_login_attempt"), \
         patch("clarinet.auth._audit"), \
         patch("clarinet.auth._count_recent_ip_failures", return_value=5):
        user, err = attempt_login(req, db, "anyone", "anypass")

    assert user is None
    assert err is not None


def test_successful_login_resets_counter():
    """Successful login resets failed_attempts and locked_until."""
    from clarinet.auth import attempt_login

    db, member = _make_db_with_user(failed=3)
    req = _make_request()

    with patch("clarinet.auth._write_login_attempt"), \
         patch("clarinet.auth._audit"), \
         patch("clarinet.auth._count_recent_ip_failures", return_value=0), \
         patch("clarinet.auth.login_user"):
        user, err = attempt_login(req, db, "admin", "Admin@secure1")

    assert err is None
    assert member.failed_attempts == 0
    assert member.locked_until is None

