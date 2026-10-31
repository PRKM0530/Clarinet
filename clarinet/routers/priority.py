"""clarinet/routers/priority.py — bandwidth priority requests (admin + member)."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_login, require_admin, audit
from clarinet.database import get_db
from clarinet.models import Device, PriorityGrant

router = APIRouter(prefix="/priority", tags=["priority"])


@router.get("", response_class=HTMLResponse)
def priority_page(request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    if user.is_admin:
        grants = db.query(PriorityGrant).order_by(PriorityGrant.requested_at.desc()).limit(100).all()
        devices = db.query(Device).filter(Device.state == "APPROVED").all()
    else:
        grants = (
            db.query(PriorityGrant)
            .filter(PriorityGrant.member_id == user.member_id)
            .order_by(PriorityGrant.requested_at.desc())
            .limit(50)
            .all()
        )
        devices = (
            db.query(Device)
            .filter(Device.owner_member_id == user.member_id, Device.state == "APPROVED")
            .all()
        )

    return templates.TemplateResponse("priority/index.html", {
        "request": request,
        "user": user,
        "page": "priority",
        "grants": grants,
        "devices": devices,
    })


@router.post("/request")
def request_priority(
    request: Request,
    device_id: int = Form(...),
    duration_min: int = Form(60),
    reason: str = Form(""),
    db: Session = Depends(get_db),
):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    grant = PriorityGrant(
        member_id=user.member_id,
        device_id=device_id,
        duration_min=min(duration_min, 480),   # cap at 8 hours
        reason=reason[:500],
        decision="PENDING",
    )
    db.add(grant)
    db.flush()
    audit(db, user.member_id, "REQUEST_PRIORITY", "PriorityGrant", grant.grant_id,
          {"device_id": device_id, "duration_min": duration_min})
    return RedirectResponse(url="/priority", status_code=302)


@router.post("/{grant_id}/approve")
def approve_priority(
    grant_id: int,
    request: Request,
    grant_mbps: float = Form(...),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    grant = db.get(PriorityGrant, grant_id)
    if grant and grant.decision == "PENDING":
        grant.decision = "APPROVED"
        grant.grant_mbps = grant_mbps
        grant.expires_at = datetime.now(timezone.utc) + timedelta(minutes=grant.duration_min or 60)
        audit(db, user.member_id, "APPROVE_PRIORITY", "PriorityGrant", grant_id,
              {"grant_mbps": grant_mbps})
        db.commit()
    return RedirectResponse(url="/priority", status_code=302)


@router.post("/{grant_id}/deny")
def deny_priority(grant_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    grant = db.get(PriorityGrant, grant_id)
    if grant and grant.decision == "PENDING":
        grant.decision = "DENIED"
        audit(db, user.member_id, "DENY_PRIORITY", "PriorityGrant", grant_id)
        db.commit()
    return RedirectResponse(url="/priority", status_code=302)
