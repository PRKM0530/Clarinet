"""
clarinet/routers/settings_routes.py — system settings (admin only).
Rewrites the form-parsing to use explicit Form() params instead of
manually calling request.form() (which is an awaitable in Starlette).
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from typing import Optional

from clarinet import templates
from clarinet.auth import require_admin, audit, hash_password
from clarinet.database import get_db
from clarinet.models import Member, Settings as AppSettings

router = APIRouter(prefix="/settings", tags=["settings"])


def _get_all_settings(db: Session) -> dict[str, str]:
    rows = db.query(AppSettings).all()
    return {r.key: r.value for r in rows}


def _set(db: Session, key: str, value: str) -> None:
    row = db.get(AppSettings, key)
    if row:
        row.value = value
    else:
        db.add(AppSettings(key=key, value=value))


# GET /settings

@router.get("", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    cfg = _get_all_settings(db)
    members = db.query(Member).order_by(Member.created_at).all()

    return templates.TemplateResponse("settings/index.html", {
        "request": request,
        "user": user,
        "page": "settings",
        "cfg": cfg,
        "members": members,
        "info":  request.query_params.get("info", ""),
        "error": request.query_params.get("error", ""),
    })


# POST /settings/update — explicit Form() params

@router.post("/update")
def update_settings(
    request: Request,
    network_mode: Optional[str]   = Form(None),
    network_interface: Optional[str] = Form(None),
    plan_download_mbps: Optional[str] = Form(None),
    plan_upload_mbps: Optional[str]   = Form(None),
    billing_day: Optional[str]        = Form(None),
    speed_test_interval_hours: Optional[str] = Form(None),
    slowdown_latency_multiplier: Optional[str] = Form(None),
    slowdown_speed_threshold: Optional[str]    = Form(None),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    params = {
        "network_mode": network_mode,
        "network_interface": network_interface,
        "plan_download_mbps": plan_download_mbps,
        "plan_upload_mbps": plan_upload_mbps,
        "billing_day": billing_day,
        "speed_test_interval_hours": speed_test_interval_hours,
        "slowdown_latency_multiplier": slowdown_latency_multiplier,
        "slowdown_speed_threshold": slowdown_speed_threshold,
    }

    changed = []
    for key, val in params.items():
        if val is not None:
            row = db.get(AppSettings, key)
            old = row.value if row else None
            if old != val:
                _set(db, key, val)
                changed.append(key)

    if changed:
        audit(db, user.member_id, "UPDATE_SETTINGS", detail={"changed": changed})

    return RedirectResponse(url="/settings?info=saved", status_code=302)


# POST /settings/members/create

@router.post("/members/create")
def create_member(
    request: Request,
    username: str  = Form(...),
    password: str  = Form(...),
    role: str      = Form("MEMBER"),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    if db.query(Member).filter(Member.username == username).first():
        return RedirectResponse(url="/settings?error=username_taken", status_code=302)

    if len(password) < 8:
        return RedirectResponse(url="/settings?error=password_too_short", status_code=302)

    new_member = Member(
        username=username.strip(),
        password_hash=hash_password(password),
        role=role if role in ("ADMIN", "MEMBER") else "MEMBER",
        is_active=True,
    )
    db.add(new_member)
    db.flush()
    audit(db, user.member_id, "CREATE_MEMBER", "Member", new_member.member_id,
          {"username": username, "role": role})
    return RedirectResponse(url="/settings?info=member_created", status_code=302)


# POST /settings/members/{member_id}/toggle

@router.post("/members/{member_id}/toggle")
def toggle_member(member_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    if member_id == user.member_id:
        return RedirectResponse(url="/settings?error=cannot_disable_self", status_code=302)

    member = db.get(Member, member_id)
    if member:
        member.is_active = not member.is_active
        audit(db, user.member_id, "TOGGLE_MEMBER", "Member", member_id,
              {"active": member.is_active})
        db.commit()
    return RedirectResponse(url="/settings", status_code=302)


# POST /settings/members/{member_id}/reset-password

@router.post("/members/{member_id}/reset-password")
def reset_password(
    member_id: int,
    request: Request,
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    if len(new_password) < 8:
        return RedirectResponse(url="/settings?error=password_too_short", status_code=302)

    member = db.get(Member, member_id)
    if member:
        member.password_hash = hash_password(new_password)
        member.failed_attempts = 0
        member.locked_until = None
        audit(db, user.member_id, "RESET_PASSWORD", "Member", member_id)
        db.commit()
    return RedirectResponse(url="/settings?info=password_reset", status_code=302)
