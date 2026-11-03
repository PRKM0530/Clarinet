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

    from clarinet.models import Member
    from clarinet.models.merging import MergedMac
    members = (
        db.query(Member).filter(Member.is_active == True).order_by(Member.username).all()  # noqa: E712
        if user.is_admin else []
    )
    others = (
        db.query(Device).filter(Device.device_id != device_id).order_by(Device.last_seen.desc()).all()
        if user.is_admin else []
    )
    aliases = db.query(MergedMac).filter(MergedMac.primary_device_id == device_id).all() if user.is_admin else []

    return templates.TemplateResponse("devices/detail.html", {
        "request": request,
        "user": user,
        "page": "devices",
        "device": device,
        "history": history,
        "members": members,
        "others": others,
        "aliases": aliases,
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
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.models import Device
    from clarinet.models.devices_ext import DeviceAlias, DeviceEvent

    device = db.get(Device, device_id)
    if device is None:
        return RedirectResponse(url="/devices?error=not_found", status_code=302)
    if not user.is_admin and device.owner_member_id != user.member_id:      # a member may label their own devices
        return RedirectResponse(url="/devices?error=forbidden", status_code=302)

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


def _parse_owner(db, raw: str | None):
    """
    Turn the owner form value into a member id.
    Returns (member_id_or_None, ok). Empty means "no owner"; an unknown or
    disabled member is rejected so a device never ends up owned by nobody real.
    """
    from clarinet.models import Member
    if raw is None or raw.strip() == "":
        return None, True
    if not raw.strip().isdigit():
        return None, False
    member = db.get(Member, int(raw))
    if member is None or not member.is_active:
        return None, False
    return member.member_id, True


@router.post("/devices/{device_id}/approve")
def approve_device(
    device_id: int,
    request: Request,
    label: str | None = Form(None),
    owner_id: str | None = Form(None),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.models import Device
    from clarinet.models.devices_ext import DeviceEvent

    device = db.get(Device, device_id)
    if device is None:
        return RedirectResponse(url="/devices?error=not_found", status_code=302)

    new_owner, ok = _parse_owner(db, owner_id)
    if not ok:
        return RedirectResponse(url="/devices?error=bad_owner", status_code=302)

    old_state = device.state
    device.state = "APPROVED"
    if label and label.strip():
        device.label = label.strip()[:128]
    # Approving without choosing an owner keeps whatever owner was already set.
    if owner_id is not None and owner_id.strip() != "":
        device.owner_member_id = new_owner
    db.add(DeviceEvent(
        device_id=device_id, event_type="STATE_CHANGE",
        old_value=old_state, new_value="APPROVED", actor_id=user.member_id,
    ))
    audit(db, user.member_id, "APPROVE_DEVICE", "Device", device_id,
          {"label": device.label, "owner_id": device.owner_member_id})
    return RedirectResponse(url=f"/devices/{device_id}?info=approved", status_code=302)


@router.post("/devices/{device_id}/owner")
def set_device_owner(
    device_id: int,
    request: Request,
    owner_id: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """Assign a device to a member, or clear the owner (empty value)."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.models import Device
    from clarinet.models.devices_ext import DeviceEvent

    device = db.get(Device, device_id)
    if device is None:
        return RedirectResponse(url="/devices?error=not_found", status_code=302)

    new_owner, ok = _parse_owner(db, owner_id)
    if not ok:
        return RedirectResponse(url=f"/devices/{device_id}?error=bad_owner", status_code=302)

    old_owner = device.owner_member_id
    device.owner_member_id = new_owner
    db.add(DeviceEvent(
        device_id=device_id, event_type="OWNER_CHANGE",
        old_value=str(old_owner) if old_owner else None,
        new_value=str(new_owner) if new_owner else None,
        actor_id=user.member_id,
    ))
    audit(db, user.member_id, "SET_DEVICE_OWNER", "Device", device_id,
          {"old_owner_id": old_owner, "new_owner_id": new_owner})
    return RedirectResponse(url=f"/devices/{device_id}?info=owner_set", status_code=302)


@router.post("/devices/{device_id}/merge")
def merge_device(
    device_id: int,
    request: Request,
    other_id: str = Form(""),
    db: Session = Depends(get_db),
):
    """Fold another entry into this device (DEV-5)."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.core_svc.device_merge import MergeError, merge_devices
    if not other_id.strip().isdigit():
        return RedirectResponse(url=f"/devices/{device_id}?error=bad_merge", status_code=302)
    try:
        merge_devices(db, device_id, int(other_id), actor_id=user.member_id)
    except MergeError:
        return RedirectResponse(url=f"/devices/{device_id}?error=bad_merge", status_code=302)
    audit(db, user.member_id, "MERGE_DEVICES", "Device", device_id, {"merged_id": int(other_id)})
    return RedirectResponse(url=f"/devices/{device_id}?info=merged", status_code=302)


@router.post("/devices/{device_id}/split")
def split_device(
    device_id: int,
    request: Request,
    mac: str = Form(""),
    db: Session = Depends(get_db),
):
    """Make a merged address its own device again (DEV-5)."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.core_svc.device_merge import MergeError, split_address
    from clarinet.models.merging import MergedMac
    alias = db.get(MergedMac, mac.strip().upper())
    if alias is None or alias.primary_device_id != device_id:
        return RedirectResponse(url=f"/devices/{device_id}?error=bad_merge", status_code=302)
    try:
        new_id = split_address(db, alias.mac_address, actor_id=user.member_id)
    except MergeError:
        return RedirectResponse(url=f"/devices/{device_id}?error=bad_merge", status_code=302)
    audit(db, user.member_id, "SPLIT_DEVICE", "Device", device_id, {"mac": alias.mac_address, "new_id": new_id})
    return RedirectResponse(url=f"/devices/{new_id}?info=split", status_code=302)


def _apply_enforcement(db) -> None:
    """Make the network match the new device state right away (not up to 15 s later). Never breaks the page."""
    try:
        from clarinet.enforcer.reconcile import apply_now
        apply_now(db)
    except Exception:
        pass


@router.post("/devices/{device_id}/guest")
def mark_device_guest(device_id: int, request: Request, db: Session = Depends(get_db)):
    """Treat this device as a guest: internet only, no access to the rest of the network."""
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
    device.state = "GUEST"
    db.add(DeviceEvent(
        device_id=device_id, event_type="STATE_CHANGE",
        old_value=old_state, new_value="GUEST", actor_id=user.member_id,
    ))
    audit(db, user.member_id, "MARK_GUEST_DEVICE", "Device", device_id)
    _apply_enforcement(db)
    return RedirectResponse(url=f"/devices/{device_id}?info=marked_guest", status_code=302)


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
    _apply_enforcement(db)

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

    _apply_enforcement(db)

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
    _apply_enforcement(db)
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
