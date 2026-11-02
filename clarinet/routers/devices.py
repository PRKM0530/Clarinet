"""
clarinet/routers/devices.py
Device management routes for M1.

Routes:
  GET  /devices              — device list (search, filter, sort)
  GET  /devices/{id}         — device detail
  POST /devices/{id}/rename  — set device label
  POST /devices/{id}/approve — approve a NEW device
  POST /devices/{id}/block   — block a device (FULL mode only)
  POST /devices/{id}/unblock — unblock a device
  POST /devices/{id}/delete  — delete device (admin only)
  GET  /export/devices.csv   — CSV export
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy.orm import Session
from typing import Optional

from clarinet import templates
from clarinet.auth import require_admin, require_login, audit
from clarinet.database import get_db

router = APIRouter(tags=["devices"])


@router.get("/devices", response_class=HTMLResponse)
def devices_list(request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.models import Device
    from clarinet.core_svc.permissions import member_device_ids

    search = request.query_params.get("q", "").strip()
    state_filter = request.query_params.get("state", "")
    allowed_ids = member_device_ids(db, user)

    q = db.query(Device).filter(Device.device_id.in_(allowed_ids))
    if state_filter:
        q = q.filter(Device.state == state_filter.upper())
    if search:
        like = f"%{search}%"
        q = q.filter(
            (Device.mac_address.ilike(like)) |
            (Device.label.ilike(like)) |
            (Device.hostname.ilike(like)) |
            (Device.ip_address.ilike(like)) |
            (Device.vendor.ilike(like))
        )

    devices = q.order_by(Device.last_seen.desc()).all()

    return templates.TemplateResponse("devices/index.html", {
        "request": request,
        "user": user,
        "page": "devices",
        "devices": devices,
        "search": search,
        "state_filter": state_filter,
        "info": request.query_params.get("info", ""),
        "error": request.query_params.get("error", ""),
    })


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(device_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.core_svc.permissions import can_view_device
    from clarinet.models import Device, DeviceHistory

    if not can_view_device(db, user, device_id):
        return RedirectResponse(url="/devices?error=forbidden", status_code=302)

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

    # Fetch M2 rules (graceful failure per C-08)
    m2_rules = None
    try:
        import httpx
        resp = httpx.get(f"http://localhost:8000/api/rules/device/{device_id}", timeout=1.0)
        if resp.status_code == 200:
            m2_rules = resp.json()
    except Exception:
        pass

    return templates.TemplateResponse("devices/detail.html", {
        "request": request,
        "user": user,
        "page": "devices",
        "device": device,
        "history": history,
        "m2_rules": m2_rules,
        "info": request.query_params.get("info", ""),
        "error": request.query_params.get("error", ""),
    })


@router.post("/devices/{device_id}/rename")
def rename_device(
    device_id: int,
    request: Request,
    label: str = Form(...),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.models import Device
    from clarinet.models.devices_ext import DeviceAlias, DeviceEvent

    device = db.get(Device, device_id)
    if device is None:
        return RedirectResponse(url="/devices?error=not_found", status_code=302)

    old_label = device.label
    device.label = label.strip()[:128]

    db.add(DeviceAlias(device_id=device_id, label=device.label, set_by=user.member_id))
    db.add(DeviceEvent(
        device_id=device_id,
        event_type="RENAME",
        old_value=old_label,
        new_value=device.label,
        actor_id=user.member_id,
    ))
    audit(db, user.member_id, "RENAME_DEVICE", "Device", device_id, {"label": device.label})

    return RedirectResponse(url=f"/devices/{device_id}?info=renamed", status_code=302)


@router.post("/devices/{device_id}/approve")
def approve_device(device_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.models import Device
    from clarinet.models.devices_ext import DeviceEvent

    device = db.get(Device, device_id)
    if device is None:
        return RedirectResponse(url="/devices?error=not_found", status_code=302)

    old_state = device.state
    device.state = "APPROVED"
    db.add(DeviceEvent(
        device_id=device_id, event_type="STATE_CHANGE",
        old_value=old_state, new_value="APPROVED", actor_id=user.member_id,
    ))
    audit(db, user.member_id, "APPROVE_DEVICE", "Device", device_id)
    return RedirectResponse(url=f"/devices/{device_id}?info=approved", status_code=302)


@router.post("/devices/{device_id}/block")
def block_device(device_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.app_settings import get_setting
    from clarinet.core_svc.mode import parse_mode, can_enforce

    mode = parse_mode(get_setting(db, "network_mode"))
    if not can_enforce(mode):
        return RedirectResponse(url=f"/devices/{device_id}?error=monitor_mode_only", status_code=302)

    from clarinet.models import Device
    from clarinet.models.devices_ext import DeviceEvent

    device = db.get(Device, device_id)
    if device is None:
        return RedirectResponse(url="/devices?error=not_found", status_code=302)

    old_state = device.state
    device.state = "BLOCKED"
    db.add(DeviceEvent(
        device_id=device_id, event_type="BLOCK",
        old_value=old_state, new_value="BLOCKED", actor_id=user.member_id,
    ))
    audit(db, user.member_id, "BLOCK_DEVICE", "Device", device_id)

    # Notify M2 (C-08: lazy import)
    try:
        from clarinet.enforcer.enforcer import request_reconcile
        request_reconcile()
    except Exception:
        pass

    return RedirectResponse(url=f"/devices/{device_id}?info=blocked", status_code=302)


@router.post("/devices/{device_id}/unblock")
def unblock_device(device_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.models import Device
    from clarinet.models.devices_ext import DeviceEvent

    device = db.get(Device, device_id)
    if device is None:
        return RedirectResponse(url="/devices?error=not_found", status_code=302)

    old_state = device.state
    device.state = "APPROVED"
    db.add(DeviceEvent(
        device_id=device_id, event_type="UNBLOCK",
        old_value=old_state, new_value="APPROVED", actor_id=user.member_id,
    ))
    audit(db, user.member_id, "UNBLOCK_DEVICE", "Device", device_id)

    try:
        from clarinet.enforcer.enforcer import request_reconcile
        request_reconcile()
    except Exception:
        pass

    return RedirectResponse(url=f"/devices/{device_id}?info=unblocked", status_code=302)


@router.post("/devices/{device_id}/delete")
def delete_device(device_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.core_svc.purge import purge_device
    audit(db, user.member_id, "DELETE_DEVICE", "Device", device_id)
    purge_device(db, device_id)
    return RedirectResponse(url="/devices?info=deleted", status_code=302)


@router.get("/export/devices.csv")
def export_devices_csv(request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.models import Device
    from clarinet.core_svc.permissions import member_device_ids
    from clarinet.core_svc.exporter import devices_to_csv

    allowed_ids = member_device_ids(db, user)
    devices = db.query(Device).filter(Device.device_id.in_(allowed_ids)).all()
    csv_data = devices_to_csv(devices)

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="devices.csv"'},
    )
