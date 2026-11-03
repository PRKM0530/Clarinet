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
    from clarinet.models.accounts import AdminRequest
    admin_request = db.get(AdminRequest, result.member_id)
    from clarinet.core_svc import recovery
    return templates.TemplateResponse("account/index.html", {
        "has_recovery_code": recovery.has_code(db, result.member_id),
        "request": request,
        "user": result,
        "page": "account",
        "admin_status": admin_request.status if admin_request else None,
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


@router.post("/admin-request")
def ask_for_admin_access(request: Request, db: Session = Depends(get_db)):
    """A member asks to become an administrator; an existing administrator decides."""
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    from clarinet.core_svc.accounts import ask_for_admin
    asked = ask_for_admin(db, result)
    if asked:
        audit(db, result.member_id, "ADMIN_REQUEST", "Member", result.member_id)
    return RedirectResponse(url="/account?info=" + ("admin_asked" if asked else "admin_already"), status_code=302)


@router.post("/recovery-code", response_class=HTMLResponse)
def new_recovery_code(
    request: Request,
    current_password: str = Form(""),
    db: Session = Depends(get_db),
):
    """Make a new recovery code (members only). The old one stops working. Needs the current password."""
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result
    if user.is_admin:
        return RedirectResponse(url="/account?error=admin_no_recovery", status_code=302)
    if not verify_password(current_password, user.password_hash):
        return RedirectResponse(url="/account?error=password_wrong", status_code=302)

    from clarinet.core_svc import recovery
    code = recovery.issue(db, user)
    audit(db, user.member_id, "NEW_RECOVERY_CODE", "Member", user.member_id)
    return templates.TemplateResponse("auth/recovery_code.html", {
        "request": request,
        "title": "Your new recovery code",
        "intro": "Your earlier code no longer works. Keep this one instead.",
        "code": code,
        "continue_url": "/account",
        "continue_label": "Back to my account",
    })


@router.post("/sign-out-others")
def sign_out_other_devices(request: Request, db: Session = Depends(get_db)):
    """End every sign-in of this account except the one being used now."""
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    end_other_sessions(db, result.member_id, request.session.get("sid"))
    audit(db, result.member_id, "SIGN_OUT_OTHERS", "Member", result.member_id)
    return RedirectResponse(url="/security?info=signed_out_others", status_code=302)
