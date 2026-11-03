"""
clarinet/routers/recovery.py
GET/POST /forgot  a member who forgot their password sets a new one with their recovery code.
No account is needed and no administrator is involved (see core_svc/recovery.py).
"""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import client_ip, get_session_user
from clarinet.core_svc import recovery
from clarinet.database import get_db
from clarinet.models import Settings as AppSettings

router = APIRouter(tags=["recovery"])


def _setup_done(db: Session) -> bool:
    row = db.get(AppSettings, "setup_complete")
    return row is not None and row.value == "true"


def _form(request, error="", username="", status=200):
    return templates.TemplateResponse("auth/forgot.html", {
        "request": request, "error": error, "username_val": username}, status_code=status)


@router.get("/forgot", response_class=HTMLResponse)
def forgot_page(request: Request, db: Session = Depends(get_db)):
    if get_session_user(request, db):
        return RedirectResponse(url="/account", status_code=302)
    if not _setup_done(db):
        return RedirectResponse(url="/setup", status_code=302)
    return _form(request)


@router.post("/forgot", response_class=HTMLResponse)
def forgot_submit(
    request: Request,
    username: str = Form(""),
    recovery_code: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    db: Session = Depends(get_db),
):
    if not _setup_done(db):
        return RedirectResponse(url="/setup", status_code=302)
    member, fresh, problem = recovery.reset_password(
        db, client_ip(request), username, recovery_code, new_password, confirm_password)
    if problem:
        message, status = problem
        return _form(request, message, username.strip(), status)
    return templates.TemplateResponse("auth/recovery_code.html", {
        "request": request,
        "title": "Your password was changed",
        "intro": "You can sign in with the new password. Your old recovery code no longer works. This is the new one.",
        "code": fresh,
        "continue_url": "/login",
        "continue_label": "Go to sign in",
    })
