"""
clarinet/routers/auth_routes.py
Login, logout pages and POST handlers.
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import attempt_login, logout_user, get_session_user
from clarinet.database import get_db
from clarinet.models import Settings as AppSettings

router = APIRouter(tags=["auth"])


def _setup_done(db: Session) -> bool:
    row = db.get(AppSettings, "setup_complete")
    return row is not None and row.value == "true"


# GET /login

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    # If already logged in, redirect to dashboard
    if get_session_user(request, db):
        return RedirectResponse(url="/dashboard", status_code=302)

    # If setup not done yet, send to wizard
    if not _setup_done(db):
        return RedirectResponse(url="/setup", status_code=302)

    reason = request.query_params.get("reason", "")
    error = request.query_params.get("error", "")
    flash_msg = ""
    if reason == "session":
        flash_msg = "Your session expired. Please log in again."
    elif reason == "timeout":
        flash_msg = "You were logged out after 30 minutes of inactivity."

    from clarinet.routers.signup import signup_enabled
    return templates.TemplateResponse(
        "auth/login.html",
        {"request": request, "flash": flash_msg, "error": error, "signup_enabled": signup_enabled(db)},
    )


# POST /login

@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user, error = attempt_login(request, db, username, password)
    if error:
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "error": error, "flash": "", "username_val": username},
            status_code=401,
        )

    # Role-based redirect
    if user.is_admin:
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/dashboard", status_code=302)


# GET /logout

@router.get("/logout")
def logout(request: Request):
    logout_user(request)
    return RedirectResponse(url="/login", status_code=302)


# GET / (root redirect)

@router.get("/")
def root(request: Request, db: Session = Depends(get_db)):
    if not _setup_done(db):
        return RedirectResponse(url="/setup", status_code=302)
    if get_session_user(request, db):
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)
