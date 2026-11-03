"""
clarinet/routers/account.py
Every signed-in person (member or admin) can see their own account and change their own password.
"""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import audit, end_other_sessions, hash_password, require_login, verify_password
from clarinet.database import get_db

router = APIRouter(prefix="/account", tags=["account"])


@router.get("", response_class=HTMLResponse)
def account_page(request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    return templates.TemplateResponse("account/index.html", {
        "request": request,
        "user": result,
        "page": "account",
        "info": request.query_params.get("info", ""),
        "error": request.query_params.get("error", ""),
    })


@router.post("/password")
def change_password(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    db: Session = Depends(get_db),
):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    def back(code: str, kind: str = "error"):
        return RedirectResponse(url=f"/account?{kind}={code}", status_code=302)

    if not verify_password(current_password, user.password_hash):
        return back("password_wrong")
    if new_password != confirm_password:
        return back("password_mismatch")
    if len(new_password) < 8:
        return back("password_short")
    if new_password == current_password:
        return back("password_same")

    user.password_hash = hash_password(new_password)
    user.failed_attempts = 0
    user.locked_until = None
    audit(db, user.member_id, "CHANGE_PASSWORD", "Member", user.member_id)
    end_other_sessions(db, user.member_id, request.session.get("sid"))     # other devices must sign in again
    return back("password_changed", "info")
