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

# Passwords are hashed with the bcrypt library directly. passlib's bcrypt layer is not thread-safe: with
# several requests hashing at once (the web server runs routes in a thread pool) about 1 hash in 70 came out
# invalid and the account could never log in. The stored format ($2b$12$...) is the same, so existing hashes work.
import threading

import bcrypt

_BCRYPT_ROUNDS = 12
# While testing, passlib/bcrypt occasionally returned a wrong answer when several threads hashed or checked
# passwords at the same time: an invalid hash (about 1 in 70) or a false "wrong password" that passed on an
# immediate retry. The cause was not found and it did not always reproduce, so the code defends against both:
# bcrypt calls run one at a time (a login takes ~0.25 s, so this is cheap), a new hash is checked before it is
# returned, and a failed check is repeated once before the password is rejected.
_bcrypt_lock = threading.Lock()

# Lockout limits come from the ALERT_LOCKOUT_* settings (read at the moment of use)
def _max_attempts() -> int:
    return max(1, int(settings.ALERT_LOCKOUT_ATTEMPTS))


def _lockout_minutes() -> int:
    return max(1, int(settings.ALERT_LOCKOUT_MINUTES))


def _password_bytes(plain: str) -> bytes:
    return plain.encode("utf-8")[:72]            # bcrypt only uses the first 72 bytes


def hash_password(plain: str) -> str:
    """A bcrypt hash that is guaranteed to verify: an invalid result is thrown away and made again."""
    secret = _password_bytes(plain)
    for _ in range(5):
        with _bcrypt_lock:
            hashed = bcrypt.hashpw(secret, bcrypt.gensalt(_BCRYPT_ROUNDS))
            if bcrypt.checkpw(secret, hashed):
                return hashed.decode("ascii")
    raise RuntimeError("could not create a valid password hash")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        secret, stored = _password_bytes(plain), hashed.encode("ascii")
        for _ in range(2):                         # a wrong answer is checked once more before it is believed
            with _bcrypt_lock:
                if bcrypt.checkpw(secret, stored):
                    return True
        return False
    except (ValueError, TypeError, UnicodeEncodeError):               # not a valid bcrypt hash
        return False


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
        request.state.session_timed_out = True
        return None

    # The login must still be recorded on the server: logout and password resets delete it.
    from clarinet.models.sessions import ActiveSession
    sid = request.session.get("sid")
    record = db.get(ActiveSession, sid) if sid else None
    if record is None or record.member_id != user_id:
        request.session.clear()
        return None

    user = db.get(Member, user_id)
    if user is None or not user.is_active:
        request.session.clear()
        return None

    # Bump the idle clock, except for the page's own background status poll: an open tab must not keep an
    # abandoned session alive forever.
    if request.headers.get("X-Clarinet-Poll") != "1":
        request.session["last_activity"] = time.time()
    return user


def login_user(request: Request, user: "Member", db: "Session | None" = None) -> None:
    """Stamp the session after a successful login (session fixation fix: clear first) and record it server-side."""
    import secrets
    from clarinet.models.sessions import ActiveSession
    request.session.clear()
    sid = secrets.token_urlsafe(24)
    own = db is None
    if own:
        from clarinet.database import SessionLocal
        db = SessionLocal()
    try:
        db.add(ActiveSession(sid=sid, member_id=user.member_id))
        db.commit()
    finally:
        if own:
            db.close()
    request.session["sid"] = sid
    request.session["user_id"] = user.member_id
    request.session["username"] = user.username
    request.session["role"] = user.role
    request.session["last_activity"] = time.time()


def logout_user(request: Request, db: "Session | None" = None) -> None:
    """End the session on the server (so a copied cookie stops working) and clear the browser's cookie."""
    sid = request.session.get("sid")
    if sid:
        from clarinet.models.sessions import ActiveSession
        own = db is None
        if own:
            from clarinet.database import SessionLocal
            db = SessionLocal()
        try:
            db.query(ActiveSession).filter(ActiveSession.sid == sid).delete()
            db.commit()
        finally:
            if own:
                db.close()
    request.session.clear()


def end_other_sessions(db: "Session", member_id: int, keep_sid: "str | None") -> None:
    """Sign a member out everywhere except the session they are using now."""
    from clarinet.models.sessions import ActiveSession
    q = db.query(ActiveSession).filter(ActiveSession.member_id == member_id)
    if keep_sid:
        q = q.filter(ActiveSession.sid != keep_sid)
    q.delete(synchronize_session=False)
    db.commit()


def end_sessions(db: "Session", member_id: int) -> None:
    """Log a member out everywhere (disabled account, password reset)."""
    from clarinet.models.sessions import ActiveSession
    db.query(ActiveSession).filter(ActiveSession.member_id == member_id).delete()
    db.commit()


# ─── Login attempt logic ───────────────────────────────────────────────────────

def client_ip(request: Request) -> str:
    """
    The address the request really came from. X-Forwarded-For is only believed when the connection itself
    comes from a trusted proxy (settings.TRUSTED_PROXIES); otherwise anyone could pick their own address
    and dodge the per-address lockout. The right-most address that is not a trusted proxy is used.
    """
    peer = request.client.host if request.client else "unknown"
    trusted = {p.strip() for p in settings.TRUSTED_PROXIES.split(",") if p.strip()}
    if peer in trusted:
        chain = [a.strip() for a in request.headers.get("X-Forwarded-For", "").split(",") if a.strip()]
        for address in reversed(chain):
            if address not in trusted:
                return address
    return peer


_get_client_ip = client_ip


def _count_recent_ip_failures(db: Session, ip: str, window_s: int | None = None) -> int:
    """Count failed login attempts from `ip` in the last `window_s` seconds."""
    try:
        from clarinet.models.reports import LoginAttempt
        window_s = window_s if window_s is not None else _lockout_minutes() * 60
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
    # One message for every failure (wrong password, unknown user, disabled or locked account), so the
    # login page never tells an attacker which usernames exist.
    generic_error = "Invalid username or password."
    locked_error_template = generic_error

    # ── Per-IP lockout check (even before DB lookup) ──────────────────────────
    if _count_recent_ip_failures(db, ip) >= _max_attempts():
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
        if user.failed_attempts >= _max_attempts():
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=_lockout_minutes())
            user.failed_attempts = 0
            _write_login_attempt(db, ip, username, False, user.member_id)
            _audit(db, user.member_id, "LOGIN_FAIL", detail={"reason": "wrong_password_lockout"})
            db.commit()
            try:
                from clarinet.core_svc.alerts import raise_alert
                raise_alert(db, "WARNING", "LOCKOUT", f"{username} was locked out",
                            f"Several wrong passwords for '{username}' from {ip}. The account is locked for "
                            f"{_lockout_minutes()} minutes. If this was not them, someone may be guessing.",
                            dedupe_key=username, cooldown_s=_lockout_minutes() * 60)
            except Exception:
                pass
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
    login_user(request, user, db)
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
        reason = "timeout" if getattr(request.state, "session_timed_out", False) else "session"
        return RedirectResponse(url=f"/login?reason={reason}", status_code=302)
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
