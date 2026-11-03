"""
clarinet/routers/api.py
JSON REST API — live data for charts, status polling, and future mobile clients.

All endpoints require a valid session cookie (same auth as HTML pages).
Prefix: /api/v1
"""

from datetime import date, timedelta, datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from clarinet.auth import require_login, require_admin
from clarinet.database import get_db
from clarinet.models import (
    Alert, Device, SlowdownEvent, SpeedTestResult,
    UsageRecord, PingRecord,
)

router = APIRouter(prefix="/api/v1", tags=["api"])


def _auth(request: Request, db: Session):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return None, result
    return result, None


def _admin(request: Request, db: Session):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return None, result
    return result, None


# GET /api/v1/status

@router.get("/status")
def api_status(request: Request, db: Session = Depends(get_db)):
    """Overall network health snapshot — used by the dashboard header."""
    user, err = _auth(request, db)
    if err:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    total_devices  = db.query(func.count(Device.device_id)).scalar() or 0
    from clarinet.core_svc.presence import online_cutoff
    online_devices = db.query(func.count(Device.device_id)).filter(
        Device.last_seen >= online_cutoff(), Device.state != "BLOCKED").scalar() or 0
    new_devices    = db.query(func.count(Device.device_id)).filter(Device.state == "NEW").scalar() or 0
    open_alerts    = db.query(func.count(Alert.alert_id)).filter(Alert.status == "OPEN").scalar() or 0
    critical_alerts = db.query(func.count(Alert.alert_id)).filter(
        Alert.status == "OPEN", Alert.level == "CRITICAL"
    ).scalar() or 0

    active_slowdown = db.query(SlowdownEvent).filter(SlowdownEvent.ended_at == None).first()

    today = date.today().isoformat()
    today_bytes = db.query(
        func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out)
    ).filter(UsageRecord.date == today).scalar() or 0

    from clarinet.core_svc.speed_filters import valid_only
    latest_speed = valid_only(db.query(SpeedTestResult)).order_by(SpeedTestResult.tested_at.desc()).first()

    return {
        "total_devices": total_devices,
        "online_devices": online_devices,
        "new_devices": new_devices,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "today_traffic_mb": round(today_bytes / 1_048_576, 1),
        "slowdown_active": active_slowdown is not None,
        "slowdown_cause": (
            active_slowdown.causes[0].get("cause") if active_slowdown and active_slowdown.causes else None
        ),
        "latest_speed": {
            "download_mbps": round(latest_speed.download_mbps, 1),
            "upload_mbps": round(latest_speed.upload_mbps, 1),
            "latency_ms": round(latest_speed.latency_ms, 0),
            "tested_at": latest_speed.tested_at.isoformat(),
        } if latest_speed else None,
    }


# GET /api/v1/devices

@router.get("/devices")
def api_devices(request: Request, db: Session = Depends(get_db)):
    """List all devices (admin) or own devices (member)."""
    user, err = _auth(request, db)
    if err:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    if user.is_admin:
        devices = db.query(Device).order_by(Device.last_seen.desc()).all()
    else:
        devices = db.query(Device).filter(Device.owner_member_id == user.member_id).all()

    return [
        {
            "device_id": d.device_id,
            "mac_address": d.mac_address,
            "ip_address": d.ip_address,
            "hostname": d.hostname,
            "label": d.label,
            "vendor": d.vendor,
            "state": d.state,
            "is_random_mac": d.is_random_mac,
            "first_seen": d.first_seen.isoformat() if d.first_seen else None,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        }
        for d in devices
    ]


# GET /api/v1/alerts

@router.get("/alerts")
def api_alerts(
    request: Request,
    limit: int = 20,
    status: str = "OPEN",
    db: Session = Depends(get_db),
):
    """Recent alerts — filterable by status (OPEN / RESOLVED / ALL)."""
    user, err = _auth(request, db)
    if err:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    from clarinet.core_svc.permissions import visible_alerts
    q = visible_alerts(db, user)
    if status != "ALL":
        q = q.filter(Alert.status == status)
    alerts = q.order_by(Alert.raised_at.desc()).limit(max(1, min(limit, 200))).all()

    return [
        {
            "alert_id": a.alert_id,
            "level": a.level,
            "type": a.type,
            "title": a.title,
            "message": a.message,
            "status": a.status,
            "device_id": a.device_id,
            "raised_at": a.raised_at.isoformat(),
        }
        for a in alerts
    ]


# GET /api/v1/latency

@router.get("/latency")
def api_latency(
    request: Request,
    hours: int = 24,
    db: Session = Depends(get_db),
):
    """Latency time-series for the last N hours (for live charts)."""
    user, err = _auth(request, db)
    if err:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    hours = min(max(hours, 1), 24 * 365)           # a huge value would overflow the date arithmetic
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    try:
        records = (
            db.query(PingRecord)
            .filter(PingRecord.measured_at >= since)
            .order_by(PingRecord.measured_at.asc())
            .limit(500)
            .all()
        )
        return [
            {
                "measured_at": r.measured_at.isoformat(),
                "target": r.target,
                "avg_ms": r.avg_ms,
                "packet_loss": r.packet_loss,
            }
            for r in records
        ]
    except Exception:
        # PingRecord table might not exist in all deployments
        return []


# GET /api/v1/usage/today

@router.get("/usage/today")
def api_usage_today(request: Request, db: Session = Depends(get_db)):
    """Per-device usage totals for today."""
    user, err = _auth(request, db)
    if err:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    today = date.today().isoformat()
    q = (
        db.query(
            Device.device_id,
            Device.label,
            Device.hostname,
            Device.mac_address,
            Device.state,
            func.sum(UsageRecord.bytes_in).label("bytes_in"),
            func.sum(UsageRecord.bytes_out).label("bytes_out"),
        )
        .join(UsageRecord, Device.device_id == UsageRecord.device_id)
        .filter(UsageRecord.date == today)
        .group_by(Device.device_id)
        .order_by(func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out).desc())
    )
    if not user.is_admin:
        q = q.filter(Device.owner_member_id == user.member_id)

    rows = q.all()
    return [
        {
            "device_id": r.device_id,
            "name": r.label or r.hostname or r.mac_address,
            "state": r.state,
            "bytes_in": r.bytes_in or 0,
            "bytes_out": r.bytes_out or 0,
            "total_mb": round(((r.bytes_in or 0) + (r.bytes_out or 0)) / 1_048_576, 2),
        }
        for r in rows
    ]


# GET /api/v1/speed

@router.get("/speed")
def api_speed(
    request: Request,
    limit: int = 30,
    db: Session = Depends(get_db),
):
    """Speed test history (latest N results)."""
    user, err = _admin(request, db)
    if err:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    from clarinet.core_svc.speed_filters import valid_only
    results = (
        valid_only(db.query(SpeedTestResult))
        .order_by(SpeedTestResult.tested_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "result_id": r.result_id,
            "download_mbps": round(r.download_mbps, 2),
            "upload_mbps": round(r.upload_mbps, 2),
            "latency_ms": round(r.latency_ms, 1),
            "server_host": r.server_host,
            "below_plan": r.below_plan,
            "tested_at": r.tested_at.isoformat(),
        }
        for r in results
    ]


# GET /api/v1/slowdowns

@router.get("/slowdowns")
def api_slowdowns(
    request: Request,
    limit: int = 10,
    db: Session = Depends(get_db),
):
    """Recent slowdown events with causes."""
    user, err = _admin(request, db)
    if err:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    events = (
        db.query(SlowdownEvent)
        .order_by(SlowdownEvent.started_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "event_id": e.event_id,
            "started_at": e.started_at.isoformat(),
            "ended_at": e.ended_at.isoformat() if e.ended_at else None,
            "active": e.ended_at is None,
            "causes": e.causes,
        }
        for e in events
    ]
