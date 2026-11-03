"""
clarinet/routers/signup.py
Anyone on the network can create a normal member account and sign in at once. Asking for administrator access
is allowed too, but it only takes effect when an existing administrator approves it (Settings page and an alert).
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.app_settings import get_setting
from clarinet.auth import audit, client_ip, get_session_user, hash_password, login_user
from clarinet.core_svc.accounts import ask_for_admin
from clarinet.database import get_db
from clarinet.models import Member, Settings as AppSettings
from clarinet.models.accounts import SignupAttempt

router = APIRouter(tags=["signup"])

MAX_ATTEMPTS_PER_HOUR = 10


def signup_enabled(db: Session) -> bool:
    return (get_setting(db, "signup_enabled", "true") or "true").lower() != "false"


def _page(request, db, error="", username="", want_admin=False, status=200):
    return templates.TemplateResponse("auth/signup.html", {
        "request": request, "error": error, "username_val": username, "want_admin": want_admin,
        "enabled": signup_enabled(db)}, status_code=status)


@router.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request, db: Session = Depends(get_db)):
    if get_session_user(request, db):
        return RedirectResponse(url="/dashboard", status_code=302)
    setup = db.get(AppSettings, "setup_complete")
    if setup is None or setup.value != "true":
        return RedirectResponse(url="/setup", status_code=302)
    return _page(request, db)


@router.post("/signup", response_class=HTMLResponse)
def signup(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    password_confirm: str = Form(""),
    want_admin: str = Form(""),
    db: Session = Depends(get_db),
):
    setup = db.get(AppSettings, "setup_complete")
    if setup is None or setup.value != "true":
        return RedirectResponse(url="/setup", status_code=302)
    username = username.strip()
    asked = want_admin == "yes"
    if not signup_enabled(db):
        return _page(request, db, "Sign-up is turned off on this network. Ask an administrator for an account.", username, asked, 403)

    ip = client_ip(request)
    recent = db.query(func.count(SignupAttempt.attempt_id)).filter(
        SignupAttempt.ip_address == ip, SignupAttempt.attempted_at >= datetime.utcnow() - timedelta(hours=1)).scalar() or 0
    if recent >= MAX_ATTEMPTS_PER_HOUR:
        return _page(request, db, "Too many attempts from this address. Please try again in an hour.", username, asked, 429)
    db.add(SignupAttempt(ip_address=ip, attempted_at=datetime.utcnow()))
    db.commit()

    problem = None
    if len(username) < 3:
        problem = "Choose a username of at least 3 characters."
    elif len(password) < 8:
        problem = "The password must be at least 8 characters."
    elif password != password_confirm:
        problem = "The two passwords do not match."
    elif db.query(Member).filter(func.lower(Member.username) == username.lower()).first():
        problem = "That username is taken. Please choose another."
    if problem:
        return _page(request, db, problem, username, asked, 422)

    member = Member(username=username, password_hash=hash_password(password), role="MEMBER", is_active=True)
    db.add(member)
    db.commit()
    audit(db, member.member_id, "SIGNUP", "Member", member.member_id, {"ip": ip, "asked_for_admin": asked})
    if asked:
        ask_for_admin(db, member)
    login_user(request, member, db)
    return RedirectResponse(url="/dashboard?info=" + ("welcome_admin_asked" if asked else "welcome"), status_code=302)
