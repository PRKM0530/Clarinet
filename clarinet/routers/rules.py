"""clarinet/routers/rules.py — time-based block/rate-limit rules (admin only)."""

import json
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin, audit
from clarinet.database import get_db
from clarinet.models import Device, TimeRule, RuleException
from datetime import datetime, timedelta, timezone

router = APIRouter(prefix="/rules", tags=["rules"])

DAYS_OF_WEEK = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


@router.get("", response_class=HTMLResponse)
def rules_page(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    rules = (
        db.query(TimeRule)
        .join(Device, TimeRule.device_id == Device.device_id)
        .order_by(TimeRule.created_at.desc())
        .all()
    )
    devices = db.query(Device).filter(Device.state == "APPROVED").order_by(Device.label).all()

    return templates.TemplateResponse("rules/index.html", {
        "request": request,
        "user": user,
        "page": "rules",
        "rules": rules,
        "devices": devices,
        "days": DAYS_OF_WEEK,
    })


@router.post("/create")
def create_rule(
    request: Request,
    device_id: int = Form(...),
    days: list[str] = Form(...),
    start_time: str = Form(...),
    end_time: str = Form(...),
    action: str = Form(...),
    rate_kbps: int | None = Form(None),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    rule = TimeRule(
        device_id=device_id,
        days_json=json.dumps([d for d in days if d in DAYS_OF_WEEK]),
        start_time=start_time,
        end_time=end_time,
        action=action,
        rate_kbps=rate_kbps if action == "RATE_LIMIT" else None,
        created_by=user.member_id,
        active=True,
    )
    db.add(rule)
    db.flush()
    audit(db, user.member_id, "CREATE_RULE", "TimeRule", rule.rule_id,
          {"device_id": device_id, "action": action})
    return RedirectResponse(url="/rules", status_code=302)


@router.post("/{rule_id}/toggle")
def toggle_rule(rule_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    rule = db.get(TimeRule, rule_id)
    if rule:
        rule.active = not rule.active
        audit(db, user.member_id, "TOGGLE_RULE", "TimeRule", rule_id, {"active": rule.active})
        db.commit()
    return RedirectResponse(url="/rules", status_code=302)


@router.post("/{rule_id}/delete")
def delete_rule(rule_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    rule = db.get(TimeRule, rule_id)
    if rule:
        db.delete(rule)
        audit(db, user.member_id, "DELETE_RULE", "TimeRule", rule_id)
    return RedirectResponse(url="/rules", status_code=302)


@router.post("/{rule_id}/exception")
def grant_exception(rule_id: int, request: Request, db: Session = Depends(get_db)):
    """Grant a one-hour override for a blocked device (ACC-3)."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    rule = db.get(TimeRule, rule_id)
    if rule:
        exc = RuleException(
            rule_id=rule_id,
            device_id=rule.device_id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            granted_by=user.member_id,
        )
        db.add(exc)
        audit(db, user.member_id, "GRANT_EXCEPTION", "TimeRule", rule_id,
              {"device_id": rule.device_id, "hours": 1})
        db.commit()
    return RedirectResponse(url="/rules", status_code=302)
