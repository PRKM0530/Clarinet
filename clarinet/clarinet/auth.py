"""
clarinet/auth.py
Session helpers for HttpOnly signed-cookie sessions.

Policy:
  - Session expires after 30 minutes of idle (ACC-01)
  - Every login failure is written to AuditLog (ACC-09)
  - bcrypt for password hashing (NFR-14)
  - No login attempt limit — unlimited retries allowed
"""

import time
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import RedirectResponse
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from clarinet.config import settings
from clarinet.models import AuditLog, Member

# bcrypt context
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


# Session read/write

def get_session_user(request: Request, db: Session) -> Member | None:
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


def login_user(request: Request, user: Member) -> None:
    """Stamp the session after a successful login."""
    request.session.clear()
    request.session["user_id"] = user.member_id
    request.session["username"] = user.username
    request.session["role"] = user.role
    request.session["last_activity"] = time.time()


def logout_user(request: Request) -> None:
    request.session.clear()


# Login attempt logic

def attempt_login(
    request: Request,
    db: Session,
    username: str,
    password: str,
) -> tuple[Member | None, str | None]:
    """
    Try to authenticate a user.

    Returns (user, None) on success, or (None, error_message) on failure.
    No lockout or attempt limits — any number of tries is allowed.
    """
    user = db.query(Member).filter(Member.username == username).first()

    # Unknown user — don't reveal whether username exists
    if user is None:
        _audit(db, None, "LOGIN_FAIL", detail={"username": username, "reason": "unknown_user"})
        db.commit()
        return None, "Invalid username or password."

    # Account not active
    if not user.is_active:
        _audit(db, user.member_id, "LOGIN_FAIL", detail={"reason": "account_inactive"})
        db.commit()
        return None, "Your account has been disabled. Contact the administrator."

    # Password check — no attempt limit
    if not verify_password(password, user.password_hash):
        _audit(db, user.member_id, "LOGIN_FAIL", detail={"reason": "wrong_password"})
        db.commit()
        return None, "Invalid username or password."

    # Success
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()
    _audit(db, user.member_id, "LOGIN_OK")
    db.commit()
    login_user(request, user)
    return user, None


# Redirect helpers

def require_login(request: Request, db: Session) -> Member | RedirectResponse:
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


def require_admin(request: Request, db: Session) -> Member | RedirectResponse:
    """Same as require_login but also enforces the ADMIN role."""
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    if not result.is_admin:
        return RedirectResponse(url="/dashboard?error=forbidden", status_code=302)
    return result


# Audit helper

def _audit(
    db: Session,
    actor_id: int | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict | None = None,
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
    actor_id: int | None,
    action: str,
    target_type: str | None = None,
    target_id=None,
    detail: dict | None = None,
    commit: bool = True,
) -> None:
    """Public version — commits by default."""
    _audit(db, actor_id, action, target_type, target_id, detail)
    if commit:
        db.commit()
