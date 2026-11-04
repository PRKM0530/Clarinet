"""
clarinet/core_svc/recovery.py
Reset a forgotten password with a recovery code.

A member gets a code when they create their account, and can make a new one on
their account page. The code is shown once and only a hash is kept. Entering the
username and the code on the "Forgot your password?" page sets a new password
and issues a fresh code. Nobody else, including an administrator, can reset a
member's password.

The code is 16 characters from an alphabet without look-alike letters (80 bits),
so guessing is hopeless, and attempts are limited as well.
Administrators are not covered: they recover with the command line on the machine.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"        # no I, O, 0 or 1
CODE_LENGTH = 16
MAX_PER_USERNAME_PER_HOUR = 5
MAX_PER_IP_PER_HOUR = 20

WRONG = "That username and recovery code do not match."
TOO_MANY = "Too many attempts. Please try again in an hour."

_dummy_hash: str | None = None


def new_code() -> str:
    """A fresh code written as XXXX-XXXX-XXXX-XXXX."""
    raw = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
    return "-".join(raw[i:i + 4] for i in range(0, CODE_LENGTH, 4))


def normalise(text: str | None) -> str:
    """What was typed, without spaces, dashes or case, so 'abcd efgh...' matches 'ABCD-EFGH-...'."""
    return "".join(ch for ch in (text or "").upper() if ch.isalnum())


def has_code(db: Session, member_id: int) -> bool:
    from clarinet.models.recovery import RecoveryCode
    return db.get(RecoveryCode, member_id) is not None


def issue(db: Session, member) -> str:
    """Make a new code for `member`, replacing any earlier one. Returns it; this is the only time it can be read."""
    from clarinet.auth import hash_password
    from clarinet.models.recovery import RecoveryCode

    code = new_code()
    digest = hash_password(normalise(code))
    row = db.get(RecoveryCode, member.member_id)
    if row is None:
        db.add(RecoveryCode(member_id=member.member_id, code_hash=digest))
    else:
        row.code_hash = digest
        row.created_at = datetime.utcnow()
    db.commit()
    return code


def _dummy() -> str:
    global _dummy_hash
    if _dummy_hash is None:
        from clarinet.auth import hash_password
        _dummy_hash = hash_password("dummy-recovery-code")
    return _dummy_hash


def reset_password(db: Session, ip: str, username: str, code: str, new_password: str, confirm: str):
    """
    Try to reset a password. Returns (member, new_code, None) on success, or
    (None, None, (message, http_status)) on failure. Every wrong answer for the
    username or the code looks the same, and takes the same time.
    """
    from clarinet.auth import end_sessions, hash_password, verify_password
    from clarinet.models import Member
    from clarinet.models.recovery import RecoveryAttempt, RecoveryCode

    username = (username or "").strip()
    since = datetime.utcnow() - timedelta(hours=1)
    by_name = db.query(func.count(RecoveryAttempt.attempt_id)).filter(
        RecoveryAttempt.username == username.lower(), RecoveryAttempt.attempted_at >= since).scalar() or 0
    by_ip = db.query(func.count(RecoveryAttempt.attempt_id)).filter(
        RecoveryAttempt.ip_address == ip, RecoveryAttempt.attempted_at >= since).scalar() or 0
    if by_name >= MAX_PER_USERNAME_PER_HOUR or by_ip >= MAX_PER_IP_PER_HOUR:
        return None, None, (TOO_MANY, 429)
    db.add(RecoveryAttempt(ip_address=ip, username=username.lower()))
    db.commit()

    if len(new_password) < 8:
        return None, None, ("The new password must be at least 8 characters.", 422)
    if new_password != confirm:
        return None, None, ("The two passwords do not match.", 422)

    member = db.query(Member).filter(func.lower(Member.username) == username.lower()).first() if username else None
    row = db.get(RecoveryCode, member.member_id) if member is not None else None
    eligible = member is not None and row is not None and member.is_active and member.role == "MEMBER"
    matches = verify_password(normalise(code), row.code_hash if eligible else _dummy())
    if not (eligible and matches):
        return None, None, (WRONG, 422)

    member.password_hash = hash_password(new_password)
    db.commit()
    end_sessions(db, member.member_id)               # whoever else was signed in is signed out
    fresh = issue(db, member)
    from clarinet.auth import audit
    audit(db, member.member_id, "PASSWORD_RESET_WITH_RECOVERY_CODE", "Member", member.member_id, {"ip": ip})
    return member, fresh, None
