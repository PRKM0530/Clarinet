"""
clarinet/routers/rules.py  (M2 enhancement)
Time-based block/rate-limit rules.

Added/Fixed (M2):
- /api/rules/summary and /api/rules/device/{id} JSON (contract C-09)
- Toggle properly lifts nft block when rule is deactivated
- Time-limited exceptions (RuleException has expires_at)
- RATE_LIMIT supported in UI
- Mode gating: rules unavailable in PUBLIC mode; MONITOR shows note
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin, audit
from clarinet.database import get_db
from clarinet.models import Device, TimeRule, RuleException

router = APIRouter(prefix="/rules", tags=["rules"])

DAYS_OF_WEEK = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


@router.get("", response_class=HTMLResponse)
def rules_page(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.enforcer.mode import get_mode
    mode = get_mode(db)

    rules = (
        db.query(TimeRule)
        .join(Device, TimeRule.device_id == Device.device_id)
        .order_by(TimeRule.created_at.desc())
        .all()
    )
    devices = (
        db.query(Device)
        .filter(Device.state.in_(["APPROVED", "BLOCKED"]))
        .order_by(Device.label)
        .all()
    )

    return templates.TemplateResponse("rules/index.html", {
        "request": request,
        "user": user,
        "page": "rules",
        "rules": rules,
        "devices": devices,
        "days": DAYS_OF_WEEK,
        "mode": mode,
        "mode_available": mode != "PUBLIC",
        "error": request.query_params.get("error"),
        "info": request.query_params.get("info"),
    })


@router.post("/create")
def create_rule(
    request: Request,
    device_id: int = Form(...),
    days: list[str] = Form([]),
    start_time: str = Form(...),
    end_time: str = Form(...),
    action: str = Form(...),
    rate_kbps: str = Form(""),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    # Rules only act in Full Control mode, so creating one elsewhere would silently do nothing
    from clarinet.app_settings import get_setting
    from clarinet.core_svc.mode import can_enforce, parse_mode
    if not can_enforce(parse_mode(get_setting(db, "network_mode"))):
        return RedirectResponse(url="/rules?error=Time+rules+need+Full+Control+mode", status_code=302)

    # Validate action
    if action not in ("BLOCK", "RATE_LIMIT"):
        return RedirectResponse(url="/rules?error=Invalid+action", status_code=302)
    if not [d for d in days if d in DAYS_OF_WEEK]:
        return RedirectResponse(url="/rules?error=Tick+at+least+one+day", status_code=302)
    try:
        rate_kbps = int(float(rate_kbps)) if rate_kbps.strip() else None      # a browser sends a blank box as ""
    except ValueError:
        return RedirectResponse(url="/rules?error=The+speed+must+be+a+number", status_code=302)
    if action == "RATE_LIMIT" and not rate_kbps:
        return RedirectResponse(url="/rules?error=Rate+limit+requires+a+speed+value", status_code=302)

    # Validate device exists
    device = db.get(Device, device_id)
    if not device:
        return RedirectResponse(url="/rules?error=Device+not+found", status_code=302)

    valid_days = [d for d in days if d in DAYS_OF_WEEK]
    rule = TimeRule(
        device_id=device_id,
        days_json=json.dumps(valid_days),
        start_time=start_time,
        end_time=end_time,
        action=action,
        rate_kbps=rate_kbps if action == "RATE_LIMIT" else None,
        created_by=user.member_id,
        active=True,
    )
    db.add(rule)
    db.flush()
    audit(db, user.member_id, "CREATE_RULE", "TimeRule", rule.rule_id, {
        "device_id": device_id,
        "action": action,
        "days": valid_days,
        "start_time": start_time,
        "end_time": end_time,
    })
    db.commit()
    return RedirectResponse(url="/rules?info=Rule+created", status_code=302)


@router.post("/{rule_id}/toggle")
def toggle_rule(rule_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    rule = db.get(TimeRule, rule_id)
    if not rule:
        return RedirectResponse(url="/rules?error=Rule+not+found", status_code=302)

    rule.active = not rule.active
    audit(db, user.member_id, "TOGGLE_RULE", "TimeRule", rule_id,
          {"active": rule.active})
    db.commit()

    # If deactivating, lift any block this rule imposed
    if not rule.active and rule.action == "BLOCK":
        device = db.get(Device, rule.device_id)
        if device and device.state == "APPROVED":
            try:
                from clarinet.enforcer.nft_wrapper import unblock_device
                unblock_device(device.mac_address)
            except Exception:
                pass

    return RedirectResponse(url="/rules?info=Rule+updated", status_code=302)


@router.post("/{rule_id}/delete")
def delete_rule(rule_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    rule = db.get(TimeRule, rule_id)
    if rule:
        device_id = rule.device_id
        action = rule.action
        was_active = rule.active
        audit(db, user.member_id, "DELETE_RULE", "TimeRule", rule_id, {"action": action})
        db.delete(rule)
        db.commit()

        # Lift block if the rule was active and blocking (F-06e fix)
        if was_active and action == "BLOCK":
            device = db.get(Device, device_id)
            if device and device.state == "APPROVED":
                try:
                    from clarinet.enforcer.nft_wrapper import unblock_device
                    unblock_device(device.mac_address)
                except Exception:
                    pass

    return RedirectResponse(url="/rules?info=Rule+deleted", status_code=302)


@router.post("/{rule_id}/exception")
def grant_exception(
    rule_id: int,
    request: Request,
    duration_hours: int = Form(1),
    db: Session = Depends(get_db),
):
    """
    Grant a temporary exception for this rule (lifts block for N hours).
    Duration is validated: 1 hour minimum, 24 hours maximum (SRS ACC-3).
    """
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    rule = db.get(TimeRule, rule_id)
    if not rule:
        return RedirectResponse(url="/rules?error=Rule+not+found", status_code=302)

    duration_hours = max(1, min(duration_hours, 24))
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=duration_hours)

    exception = RuleException(
        rule_id=rule_id,
        device_id=rule.device_id,
        granted_by=user.member_id,
        granted_at=now,
        expires_at=expires,
    )
    db.add(exception)
    audit(db, user.member_id, "GRANT_EXCEPTION", "RuleException", rule_id, {
        "device_id": rule.device_id,
        "duration_hours": duration_hours,
    })
    db.commit()

    # Lift the block immediately
    try:
        from clarinet.enforcer.nft_wrapper import unblock_device
        device = db.get(Device, rule.device_id)
        if device:
            unblock_device(device.mac_address)
    except Exception:
        pass

    return RedirectResponse(url="/rules?info=Exception+granted", status_code=302)


# ──────────────────────────────────────────────
# JSON API (contract C-09)
# ──────────────────────────────────────────────

@router.get("/summary")
def rules_summary(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    from clarinet.enforcer.mode import get_mode
    mode = get_mode(db)

    active_rules = db.query(TimeRule).filter(TimeRule.active == True).count()
    total_rules = db.query(TimeRule).count()
    now = datetime.now(timezone.utc)
    active_exceptions = (
        db.query(RuleException)
        .filter(RuleException.expires_at > now)
        .count()
    )

    return JSONResponse({
        "available": mode != "PUBLIC",
        "mode": mode,
        "active_rules": active_rules,
        "total_rules": total_rules,
        "active_exceptions": active_exceptions,
    })


@router.get("/device/{device_id}")
def rules_for_device(device_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    rules = (
        db.query(TimeRule)
        .filter(TimeRule.device_id == device_id)
        .all()
    )
    now = datetime.now(timezone.utc)
    return JSONResponse({
        "device_id": device_id,
        "rules": [
            {
                "rule_id": r.rule_id,
                "days": json.loads(r.days_json or "[]"),
                "start_time": r.start_time,
                "end_time": r.end_time,
                "action": r.action,
                "rate_kbps": r.rate_kbps,
                "active": r.active,
            }
            for r in rules
        ],
    })
