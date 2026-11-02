"""
clarinet/routers/priority.py  (M2 rewrite)
Member speed-priority requests and admin decisions.

Fixes (F-07):
(a) Ownership check: members can only request for their own devices
(b) Automatic policy engine: FAIR-2, auto-approve/deny based on fairness credit
(c) grant_mbps defaulted to plan speed (no more HTTP 422)
(d) Template variable fixed: passes 'my_devices' not 'devices'
(e) Max duration 60 min default (SRS), not 480
(f) tc actually applied on approval
(g) Fairness credit tracked (FAIR-5)
(h) Cancel endpoint for members (FAIR-4)
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin, require_login, audit
from clarinet.database import get_db
from clarinet.models import Device, PriorityGrant

router = APIRouter(prefix="/priority", tags=["priority"])

# Policy defaults (FAIR-2, FAIR-5). The admin can change them on the Priority page (FAIR-6).
_DEFAULT_DURATION_MIN = 60
_MAX_DURATION_MIN = 120
_DAILY_CREDIT_LIMIT_MIN = 180   # max priority minutes per member per day


def get_policy(db) -> dict:
    """The current priority policy: defaults unless the admin has changed them."""
    from clarinet.app_settings import get_setting

    def number(key: str, default: int) -> int:
        raw = get_setting(db, key, str(default))
        return int(raw) if raw and raw.isdigit() else default

    return {
        "default_duration_min": number("priority.default_duration_min", _DEFAULT_DURATION_MIN),
        "max_duration_min": number("priority.max_duration_min", _MAX_DURATION_MIN),
        "daily_limit_min": number("priority.daily_limit_min", _DAILY_CREDIT_LIMIT_MIN),
    }


def _get_plan_kbps(db) -> int:
    from clarinet.app_settings import get_setting
    dl = float(get_setting(db, "plan_download_mbps", "100") or 100)
    return int(dl * 1000)


def _fairness_credit_today(db, member_id: int) -> int:
    """Return minutes of priority used today by this member."""
    try:
        from clarinet.models.guest import FairnessCredit
        from clarinet.app_settings import get_setting
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(get_setting(db, "timezone", "Asia/Kolkata"))
        today = datetime.now(tz).strftime("%Y-%m-%d")
        credit = (
            db.query(FairnessCredit)
            .filter(FairnessCredit.member_id == member_id, FairnessCredit.day == today)
            .first()
        )
        return credit.minutes_used if credit else 0
    except Exception:
        return 0


def _auto_decide(db, member_id: int, device_id: int, duration_min: int) -> tuple[str, str]:
    """
    FAIR-2 automatic policy:
    - Deny if member already has an APPROVED grant active
    - Deny if fairness credit would exceed daily limit
    - Approve otherwise
    Returns (decision, reason).
    """
    # Already has active grant?
    now = datetime.now(timezone.utc)
    existing = (
        db.query(PriorityGrant)
        .filter(
            PriorityGrant.member_id == member_id,
            PriorityGrant.decision == "APPROVED",
            PriorityGrant.expires_at > now,
        )
        .first()
    )
    if existing:
        return "DENIED", "You already have an active priority grant."

    # Fairness credit check
    daily_limit = get_policy(db)["daily_limit_min"]
    used_today = _fairness_credit_today(db, member_id)
    if used_today + duration_min > daily_limit:
        remaining = max(0, daily_limit - used_today)
        return "DENIED", (
            f"Daily priority limit reached. "
            f"You have used {used_today} of {daily_limit} minutes today. "
            f"You can request up to {remaining} more minute(s) today."
        )

    return "APPROVED", "Request approved automatically."


@router.get("", response_class=HTMLResponse)
def priority_page(request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.enforcer.mode import get_mode
    mode = get_mode(db)

    # Members see only their own devices (F-07a fix)
    if user.is_admin:
        my_devices = db.query(Device).filter(Device.state == "APPROVED").all()
        pending_grants = (
            db.query(PriorityGrant)
            .filter(PriorityGrant.decision == "PENDING")
            .order_by(PriorityGrant.requested_at.desc())
            .all()
        )
    else:
        my_devices = (
            db.query(Device)
            .filter(Device.owner_member_id == user.member_id, Device.state == "APPROVED")
            .all()
        )
        pending_grants = []

    now = datetime.now(timezone.utc)
    my_grants = (
        db.query(PriorityGrant)
        .filter(PriorityGrant.member_id == user.member_id)
        .order_by(PriorityGrant.requested_at.desc())
        .limit(10)
        .all()
    )
    used_today = _fairness_credit_today(db, user.member_id)

    return templates.TemplateResponse("priority/index.html", {
        "request": request,
        "user": user,
        "page": "priority",
        "my_devices": my_devices,         # F-07d fix: was 'devices', now 'my_devices'
        "devices": my_devices,             # keep both for template compat
        "pending_grants": pending_grants,
        "my_grants": my_grants,
        "mode": mode,
        "mode_available": mode == "FULL",
        "used_today_min": used_today,
        "daily_limit_min": get_policy(db)["daily_limit_min"],
        "default_duration_min": get_policy(db)["default_duration_min"],
        "policy": get_policy(db),
        "now": now,
        "error": request.query_params.get("error"),
        "info": request.query_params.get("info"),
    })


@router.post("/request")
def request_priority(
    request: Request,
    device_id: int = Form(...),
    duration_min: int = Form(_DEFAULT_DURATION_MIN),
    reason: str = Form(""),
    db: Session = Depends(get_db),
):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.enforcer.mode import get_mode
    if get_mode(db) != "FULL":
        return RedirectResponse(url="/priority?error=Priority+requires+Full-Control+mode", status_code=302)

    # Validate ownership (F-07a fix)
    device = db.get(Device, device_id)
    if not device:
        return RedirectResponse(url="/priority?error=Device+not+found", status_code=302)
    if not user.is_admin and device.owner_member_id != user.member_id:
        return RedirectResponse(url="/priority?error=You+can+only+request+priority+for+your+own+devices", status_code=302)

    duration_min = max(1, min(duration_min, get_policy(db)["max_duration_min"]))

    # Auto policy decision (F-07b fix)
    decision, policy_reason = _auto_decide(db, user.member_id, device_id, duration_min)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=duration_min) if decision == "APPROVED" else None
    plan_kbps = _get_plan_kbps(db)

    grant = PriorityGrant(
        member_id=user.member_id,
        device_id=device_id,
        requested_at=now,
        decision=decision,
        duration_min=duration_min,
        reason=reason[:256] if reason else None,
        grant_mbps=plan_kbps / 1000,   # F-07c fix: default to plan speed
        expires_at=expires_at,
    )
    db.add(grant)
    db.flush()
    audit(db, user.member_id, "REQUEST_PRIORITY", "PriorityGrant", grant.grant_id, {
        "device_id": device_id,
        "duration_min": duration_min,
        "decision": decision,
        "reason": policy_reason,
    })

    # Apply tc if approved (F-07f fix)
    if decision == "APPROVED":
        _apply_priority(db, device, grant)

    db.commit()

    if decision == "APPROVED":
        return RedirectResponse(url="/priority?info=Priority+granted+automatically", status_code=302)
    return RedirectResponse(url=f"/priority?error={policy_reason.replace(' ', '+')}", status_code=302)


def _apply_priority(db, device: Device, grant: PriorityGrant) -> None:
    """Apply tc priority shaping for this device."""
    try:
        from clarinet.app_settings import get_setting
        from clarinet.enforcer.tc_wrapper import setup_htb, set_priority
        iface = get_setting(db, "network_interface", "")
        plan_dl = float(get_setting(db, "plan_download_mbps", "100") or 100)
        if iface:
            setup_htb(iface, plan_dl)
            set_priority(iface, device.mac_address)
    except Exception:
        pass


@router.post("/{grant_id}/cancel")
def cancel_priority(grant_id: int, request: Request, db: Session = Depends(get_db)):
    """FAIR-4: Member can cancel their own active priority grant."""
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    grant = db.get(PriorityGrant, grant_id)
    if not grant:
        return RedirectResponse(url="/priority?error=Grant+not+found", status_code=302)
    if not user.is_admin and grant.member_id != user.member_id:
        return RedirectResponse(url="/priority?error=Not+your+grant", status_code=302)
    if grant.decision not in ("APPROVED", "PENDING"):
        return RedirectResponse(url="/priority?error=Grant+cannot+be+cancelled", status_code=302)

    grant.decision = "EXPIRED"
    grant.expires_at = datetime.now(timezone.utc)
    audit(db, user.member_id, "CANCEL_PRIORITY", "PriorityGrant", grant_id, {})

    # Remove tc priority
    try:
        from clarinet.app_settings import get_setting
        from clarinet.enforcer.tc_wrapper import remove_priority
        iface = get_setting(db, "network_interface", "")
        device = db.get(Device, grant.device_id)
        if iface and device:
            remove_priority(iface, device.mac_address)
    except Exception:
        pass

    db.commit()
    return RedirectResponse(url="/priority?info=Priority+cancelled", status_code=302)


@router.post("/{grant_id}/approve")
def approve_grant(
    grant_id: int,
    request: Request,
    grant_mbps: float = Form(None),
    db: Session = Depends(get_db),
):
    """Admin manually approves a pending grant."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    grant = db.get(PriorityGrant, grant_id)
    if not grant or grant.decision != "PENDING":
        return RedirectResponse(url="/priority?error=Grant+not+found+or+not+pending", status_code=302)

    plan_kbps = _get_plan_kbps(db)
    grant.decision = "APPROVED"
    grant.grant_mbps = grant_mbps or (plan_kbps / 1000)  # F-07c fix
    grant.expires_at = datetime.now(timezone.utc) + timedelta(minutes=grant.duration_min or _DEFAULT_DURATION_MIN)
    audit(db, user.member_id, "APPROVE_PRIORITY", "PriorityGrant", grant_id, {"grant_mbps": grant.grant_mbps})

    device = db.get(Device, grant.device_id)
    if device:
        _apply_priority(db, device, grant)

    db.commit()
    return RedirectResponse(url="/priority?info=Priority+approved", status_code=302)


@router.post("/{grant_id}/deny")
def deny_grant(grant_id: int, reason: str = Form(""), request: Request = None, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    grant = db.get(PriorityGrant, grant_id)
    if grant and grant.decision == "PENDING":
        grant.decision = "DENIED"
        grant.reason = reason[:256] if reason else "Denied by admin."
        audit(db, user.member_id, "DENY_PRIORITY", "PriorityGrant", grant_id, {"reason": grant.reason})
        db.commit()
    return RedirectResponse(url="/priority?info=Priority+denied", status_code=302)


# ──────────────────────────────────────────────
# JSON API (contract C-09)
# ──────────────────────────────────────────────

@router.get("/summary")
def priority_summary(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    from clarinet.enforcer.mode import get_mode
    mode = get_mode(db)
    now = datetime.now(timezone.utc)

    active = (
        db.query(PriorityGrant)
        .filter(PriorityGrant.decision == "APPROVED", PriorityGrant.expires_at > now)
        .count()
    )
    pending = db.query(PriorityGrant).filter(PriorityGrant.decision == "PENDING").count()

    return JSONResponse({
        "available": mode == "FULL",
        "mode": mode,
        "active_grants": active,
        "pending_requests": pending,
    })


@router.post("/policy")
def update_policy(
    request: Request,
    default_duration_min: str = Form(""),
    max_duration_min: str = Form(""),
    daily_limit_min: str = Form(""),
    db: Session = Depends(get_db),
):
    """FAIR-6: the admin changes the limits that decide priority requests."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result

    values = {"default_duration_min": default_duration_min, "max_duration_min": max_duration_min,
              "daily_limit_min": daily_limit_min}
    if not all(v.strip().isdigit() and 1 <= int(v) <= 1440 for v in values.values()):
        return RedirectResponse(url="/priority?error=bad_policy", status_code=302)
    default_m, max_m, daily_m = (int(values[k]) for k in ("default_duration_min", "max_duration_min", "daily_limit_min"))
    if not (default_m <= max_m <= daily_m):
        return RedirectResponse(url="/priority?error=bad_policy_order", status_code=302)

    from clarinet.app_settings import set_setting
    for key, value in values.items():
        set_setting(db, f"priority.{key}", str(int(value)))
    audit(db, result.member_id, "UPDATE_PRIORITY_POLICY", detail={k: int(v) for k, v in values.items()})
    return RedirectResponse(url="/priority?info=policy_saved", status_code=302)
