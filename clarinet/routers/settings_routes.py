"""
clarinet/routers/settings_routes.py — system settings (admin only).
Rewrites the form-parsing to use explicit Form() params instead of
manually calling request.form() (which is an awaitable in Starlette).
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
import ipaddress
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


def _number(text, low, high, whole=False):
    """The parsed number if `text` is a finite number in [low, high], otherwise None."""
    try:
        value = int(text) if whole else float(text)
    except (TypeError, ValueError):
        return None
    if value != value or not (low <= value <= high):      # NaN or out of range
        return None
    return value


def _validate_settings(params: dict) -> str | None:
    """Return an error code for the first invalid value, or None. Blank values are skipped."""
    checks = [
        ("network_mode", lambda v: v.upper() in ("FULL", "MONITOR", "PUBLIC"), "bad_mode"),
        ("plan_download_mbps", lambda v: _number(v, 0.1, 100_000) is not None, "bad_plan_speed"),
        ("plan_upload_mbps", lambda v: _number(v, 0.1, 100_000) is not None, "bad_plan_speed"),
        ("billing_day", lambda v: _number(v, 1, 28, whole=True) is not None, "bad_billing_day"),
        ("speed_test_interval_hours", lambda v: _number(v, 1, 168, whole=True) is not None, "bad_interval"),
        ("slowdown_latency_multiplier", lambda v: _number(v, 1.0, 20.0) is not None, "bad_multiplier"),
        ("slowdown_speed_threshold", lambda v: _number(v, 0.05, 1.0) is not None, "bad_threshold_ratio"),
    ]
    for key, ok, code in checks:
        value = params.get(key)
        if value is not None and value.strip() != "" and not ok(value.strip()):
            return code
    return None


# POST /settings/update — explicit Form() params

@router.post("/update")
def update_settings(
    request: Request,
    network_mode: Optional[str]   = Form(None),
    network_interface: Optional[str] = Form(None),
    plan_download_mbps: Optional[str] = Form(None),
    plan_upload_mbps: Optional[str]   = Form(None),
    billing_day: Optional[str]        = Form(None),
    monthly_limit_gb: Optional[str]   = Form(None),
    speed_report_threshold_pct: Optional[str] = Form(None),
    speed_test_interval_hours: Optional[str] = Form(None),
    slowdown_latency_multiplier: Optional[str] = Form(None),
    slowdown_speed_threshold: Optional[str]    = Form(None),
    router_ip: Optional[str] = Form(None),
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

    # Router address used as the "router" ping target. Blank clears it; anything else must be a real IP.
    if router_ip is not None:
        router_ip = router_ip.strip()
        if router_ip:
            try:
                ipaddress.ip_address(router_ip)
            except ValueError:
                return RedirectResponse(url="/settings?error=bad_router_ip", status_code=302)
        params["router_ip"] = router_ip

    # Reject nonsense before it is stored: a bad value here would later break pages that read it.
    error = _validate_settings(params)
    if error:
        return RedirectResponse(url=f"/settings?error={error}", status_code=302)
    for key in [k for k, v in params.items() if v is not None and v.strip() == "" and k != "router_ip"]:
        params[key] = None                       # an empty box means "leave unchanged"

    # Monthly data limit: blank means no limit; otherwise GB -> bytes under "limit.bytes".
    if monthly_limit_gb is not None:
        text = monthly_limit_gb.strip()
        if text == "":
            params["limit.bytes"] = ""
        else:
            try:
                gb = float(text)
            except ValueError:
                gb = -1
            if not (0 < gb <= 1_000_000):
                return RedirectResponse(url="/settings?error=bad_limit", status_code=302)
            params["limit.bytes"] = str(int(gb * 1_073_741_824))

    # A speed test under this share of the plan counts as "below plan" in the speed report
    if speed_report_threshold_pct is not None and speed_report_threshold_pct.strip() != "":
        text = speed_report_threshold_pct.strip()
        if not text.isdigit() or not (10 <= int(text) <= 100):
            return RedirectResponse(url="/settings?error=bad_threshold", status_code=302)
        params["speed_report_threshold_pct"] = text

    if params.get("network_mode"):
        params["network_mode"] = params["network_mode"].strip().upper()
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


# POST /settings/purge: delete all stored network data (SYS-5)

@router.post("/purge")
def purge_everything(
    request: Request,
    confirm: str = Form(""),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    if confirm.strip() != "DELETE":
        return RedirectResponse(url="/settings?error=confirm_delete", status_code=302)

    from clarinet.core_svc.purge import purge_all_data
    counts = purge_all_data(db)
    audit(db, user.member_id, "PURGE_ALL_DATA", detail={"rows": sum(counts.values())})
    return RedirectResponse(url="/settings?info=data_deleted", status_code=302)


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

    username = username.strip()
    if len(username) < 3:
        return RedirectResponse(url="/settings?error=bad_username", status_code=302)

    if db.query(Member).filter(Member.username == username).first():
        return RedirectResponse(url="/settings?error=username_taken", status_code=302)

    if len(password) < 8:
        return RedirectResponse(url="/settings?error=password_too_short", status_code=302)

    new_member = Member(
        username=username,
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
        if not member.is_active:
            from clarinet.auth import end_sessions
            end_sessions(db, member_id)
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
        from clarinet.auth import end_sessions
        end_sessions(db, member_id)
    return RedirectResponse(url="/settings?info=password_reset", status_code=302)
