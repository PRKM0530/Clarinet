"""
clarinet/auth.py
Session helpers for HttpOnly signed-cookie sessions.

Policy:
  - Session expires after 30 minutes of idle (ACC-01)
  - Login lockout: 5 failures → locked 5 min (ACC-02)
  - Per-IP lockout: 5 failures from same IP in 5 min → lock (ACC-02b)
  - Every login attempt is written to LoginAttempt table
  - bcrypt for password hashing (NFR-14)
  - Generic error messages prevent username enumeration (ACC-03)
  - Session fixation fix: session cleared before login (ACC-04)

M1 OWNS THIS FILE — do not edit in other branches.
"""

import time
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from clarinet.config import settings
from clarinet.models import AuditLog, Member

# bcrypt context — lazy import via passlib
from passlib.context import CryptContext

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Lockout constants
_MAX_ATTEMPTS = 5
_LOCKOUT_MINUTES = 5
_IP_WINDOW_SECONDS = 300  # 5 minutes


def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


# ─── Session read/write ────────────────────────────────────────────────────────

def get_session_user(request: Request, db: Session) -> "Member | None":
    """
    Return the authenticated Member from the signed session cookie,
    or None if the session is missing, expired, or the user no longer exists.
    Updates last_activity on every call so the idle clock resets.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return None

    # Idle timeout check
    last_activity = request.session.get("last_activity", 0)
    idle_limit = settings.SESSION_IDLE_MINUTES * 60
    if time.time() - last_activity > idle_limit:
        request.session.clear()
        return None

    user = db.get(Member, user_id)
    if user is None or not user.is_active:
        request.session.clear()
        return None

    # Bump the idle clock
    request.session["last_activity"] = time.time()
    return user


def login_user(request: Request, user: "Member") -> None:
    """Stamp the session after a successful login (session fixation fix: clear first)."""
    request.session.clear()
    request.session["user_id"] = user.member_id
    request.session["username"] = user.username
    request.session["role"] = user.role
    request.session["last_activity"] = time.time()


def logout_user(request: Request) -> None:
    request.session.clear()


# ─── Login attempt logic ───────────────────────────────────────────────────────

def _get_client_ip(request: Request) -> str:
    """Extract real client IP, honouring X-Forwarded-For if set."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _count_recent_ip_failures(db: Session, ip: str, window_s: int = _IP_WINDOW_SECONDS) -> int:
    """Count failed login attempts from `ip` in the last `window_s` seconds."""
    try:
        from clarinet.models.reports import LoginAttempt
        cutoff = datetime.utcnow() - timedelta(seconds=window_s)
        return (
            db.query(LoginAttempt)
            .filter(
                LoginAttempt.ip_address == ip,
                LoginAttempt.success == False,
                LoginAttempt.attempted_at >= cutoff,
            )
            .count()
        )
    except Exception:
        return 0


def _write_login_attempt(
    db: Session,
    ip: str,
    username: str,
    success: bool,
    member_id: int | None = None,
) -> None:
    """Record a login attempt (best-effort; never raises)."""
    try:
        from clarinet.models.reports import LoginAttempt
        db.add(LoginAttempt(
            ip_address=ip,
            username=username,
            member_id=member_id,
            success=success,
            attempted_at=datetime.utcnow(),
        ))
    except Exception:
        pass  # table may not exist yet in early migrations


def attempt_login(
    request: Request,
    db: Session,
    username: str,
    password: str,
) -> "tuple[Member | None, str | None]":
    """
    Try to authenticate a user.

    Returns (user, None) on success, or (None, error_message) on failure.
    Enforces per-user AND per-IP lockout after 5 failures.
    All error messages are generic to prevent username enumeration.
    """
    ip = _get_client_ip(request)
    generic_error = "Invalid username or password."
    locked_error_template = (
        "This account is temporarily locked. Try again in {mins} minute(s)."
    )

    # ── Per-IP lockout check (even before DB lookup) ──────────────────────────
    if _count_recent_ip_failures(db, ip) >= _MAX_ATTEMPTS:
        _write_login_attempt(db, ip, username, False)
        _audit(db, None, "LOGIN_BLOCKED", detail={"username": username, "reason": "ip_lockout", "ip": ip})
        db.commit()
        return None, generic_error  # don't reveal IP lockout to attacker

    # ── Look up user ──────────────────────────────────────────────────────────
    user = db.query(Member).filter(Member.username == username).first()

    if user is None:
        _write_login_attempt(db, ip, username, False)
        _audit(db, None, "LOGIN_FAIL", detail={"username": username, "reason": "unknown_user"})
        db.commit()
        return None, generic_error

    if not user.is_active:
        _write_login_attempt(db, ip, username, False, user.member_id)
        _audit(db, user.member_id, "LOGIN_FAIL", detail={"reason": "account_inactive"})
        db.commit()
        # Generic: don't reveal "account disabled" to attackers
        return None, generic_error

    # ── Per-user lockout check ────────────────────────────────────────────────
    now_utc = datetime.now(timezone.utc)
    if user.locked_until is not None:
        locked_until = user.locked_until
        # Make timezone-aware for comparison
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if now_utc < locked_until:
            remaining_s = (locked_until - now_utc).total_seconds()
            remaining_min = max(1, int(remaining_s // 60) + 1)
            _write_login_attempt(db, ip, username, False, user.member_id)
            _audit(db, user.member_id, "LOGIN_BLOCKED", detail={"reason": "user_lockout"})
            db.commit()
            return None, locked_error_template.format(mins=remaining_min)
        else:
            # Lockout expired — clear it
            user.locked_until = None
            user.failed_attempts = 0

    # ── Password check ────────────────────────────────────────────────────────
    if not verify_password(password, user.password_hash):
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= _MAX_ATTEMPTS:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=_LOCKOUT_MINUTES)
            user.failed_attempts = 0
            _write_login_attempt(db, ip, username, False, user.member_id)
            _audit(db, user.member_id, "LOGIN_FAIL", detail={"reason": "wrong_password_lockout"})
            db.commit()
            return None, generic_error
        else:
            _write_login_attempt(db, ip, username, False, user.member_id)
            _audit(db, user.member_id, "LOGIN_FAIL", detail={"reason": "wrong_password", "attempts": user.failed_attempts})
            db.commit()
            return None, generic_error

    # ── Success ───────────────────────────────────────────────────────────────
    user.failed_attempts = 0
    user.locked_until = None
    _write_login_attempt(db, ip, username, True, user.member_id)
    _audit(db, user.member_id, "LOGIN_OK", detail={"ip": ip})
    db.commit()
    login_user(request, user)
    return user, None


# ─── Redirect helpers ──────────────────────────────────────────────────────────

def require_login(request: Request, db: Session) -> "Member | RedirectResponse":
    """
    Return the current Member or a RedirectResponse to /login.
    Usage:
        result = require_login(request, db)
        if isinstance(result, RedirectResponse):
            return result
        user: Member = result
    """
    user = get_session_user(request, db)
    if user is None:
        return RedirectResponse(url="/login?reason=session", status_code=302)
    return user


def require_admin(request: Request, db: Session) -> "Member | RedirectResponse":
    """Same as require_login but also enforces the ADMIN role."""
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    if not result.is_admin:
        return RedirectResponse(url="/dashboard?error=forbidden", status_code=302)
    return result


# ─── Audit helper ─────────────────────────────────────────────────────────────

def _audit(
    db: Session,
    actor_id: "int | None",
    action: str,
    target_type: "str | None" = None,
    target_id: "str | None" = None,
    detail: "dict | None" = None,
) -> None:
    import json
    log = AuditLog(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        detail_json=json.dumps(detail or {}),
    )
    db.add(log)
    # Caller is responsible for db.commit()


def audit(
    db: Session,
    actor_id: "int | None",
    action: str,
    target_type: "str | None" = None,
    target_id=None,
    detail: "dict | None" = None,
    commit: bool = True,
) -> None:
    """Public version — commits by default."""
    _audit(db, actor_id, action, target_type, target_id, detail)
    if commit:
        db.commit()
