"""
clarinet/routers/devices.py
Device management — list, approve, block, label, assign owner.
Admin only (except GET /api/devices/mine for members).
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_login, require_admin, audit
from clarinet.database import get_db
from clarinet.models import Device, Member, DeviceHistory, Alert
from datetime import datetime, timezone

router = APIRouter(prefix="/devices", tags=["devices"])


# GET /devices

@router.get("", response_class=HTMLResponse)
def device_list(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    devices = db.query(Device).order_by(Device.last_seen.desc()).all()
    members = db.query(Member).filter(Member.is_active == True).all()

    new_count = sum(1 for d in devices if d.state == "NEW")
    return templates.TemplateResponse("devices/index.html", {
        "request": request,
        "user": user,
        "page": "devices",
        "devices": devices,
        "members": members,
        "new_count": new_count,
    })


# POST /devices/{device_id}/approve

@router.post("/{device_id}/approve")
def approve_device(
    device_id: int,
    request: Request,
    owner_id: int | None = Form(None),
    label: str | None = Form(None),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    device = db.get(Device, device_id)
    if device is None:
        return RedirectResponse(url="/devices?error=not_found", status_code=302)

    device.state = "APPROVED"
    if owner_id:
        device.owner_member_id = owner_id
    if label:
        device.label = label.strip()[:128]

    audit(db, user.member_id, "APPROVE_DEVICE", "Device", device_id,
          {"mac": device.mac_address, "label": device.label})
    return RedirectResponse(url="/devices", status_code=302)


# POST /devices/{device_id}/block

@router.post("/{device_id}/block")
def block_device(
    device_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    device = db.get(Device, device_id)
    if device is None:
        return RedirectResponse(url="/devices?error=not_found", status_code=302)

    device.state = "BLOCKED"
    audit(db, user.member_id, "BLOCK_DEVICE", "Device", device_id,
          {"mac": device.mac_address})
    return RedirectResponse(url="/devices", status_code=302)


# POST /devices/{device_id}/label

@router.post("/{device_id}/label")
def relabel_device(
    device_id: int,
    request: Request,
    label: str = Form(...),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    device = db.get(Device, device_id)
    if device:
        device.label = label.strip()[:128]
        audit(db, user.member_id, "LABEL_DEVICE", "Device", device_id, {"label": label})
        db.commit()
    return RedirectResponse(url="/devices", status_code=302)


# GET /devices/{device_id} (device detail)

@router.get("/{device_id}", response_class=HTMLResponse)
def device_detail(device_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    device = db.get(Device, device_id)
    if device is None:
        return RedirectResponse(url="/devices?error=not_found", status_code=302)

    history = (
        db.query(DeviceHistory)
        .filter(DeviceHistory.device_id == device_id)
        .order_by(DeviceHistory.timestamp.desc())
        .limit(50)
        .all()
    )
    alerts = (
        db.query(Alert)
        .filter(Alert.device_id == device_id)
        .order_by(Alert.raised_at.desc())
        .limit(20)
        .all()
    )
    members = db.query(Member).filter(Member.is_active == True).all()

    return templates.TemplateResponse("devices/detail.html", {
        "request": request,
        "user": user,
        "page": "devices",
        "device": device,
        "history": history,
        "alerts": alerts,
        "members": members,
    })
