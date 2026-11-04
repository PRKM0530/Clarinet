"""
clarinet/routers/api.py
JSON REST API — live data for charts, status polling, and future mobile clients.

All endpoints require a valid session cookie (same auth as HTML pages).
Prefix: /api/v1
"""

from datetime import timedelta, datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from clarinet.auth import require_login, require_admin
from clarinet.core_svc.speed_filters import known_latency
from clarinet.database import get_db
from clarinet.models import (
    Alert, Device, SlowdownEvent, SpeedTestResult,
    PingRecord,
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

    # A member sees only their own devices, their own devices' alerts and their own traffic
    from clarinet.core_svc.permissions import member_device_ids, visible_alerts
    from clarinet.core_svc.presence import online_cutoff
    own_ids = None if user.is_admin else member_device_ids(db, user)

    def devices():
        q = db.query(func.count(Device.device_id))
        return q if own_ids is None else q.filter(Device.device_id.in_(own_ids))

    total_devices = devices().scalar() or 0
    online_devices = devices().filter(Device.last_seen >= online_cutoff(), Device.state != "BLOCKED").scalar() or 0
    new_devices = devices().filter(Device.state == "NEW").scalar() or 0
    alerts = visible_alerts(db, user).filter(Alert.status == "OPEN")
    open_alerts = alerts.count()
    critical_alerts = alerts.filter(Alert.level == "CRITICAL").count()

    active_slowdown = db.query(SlowdownEvent).filter(SlowdownEvent.ended_at == None).first()

    from clarinet.core_svc.localtime import local_today
    from clarinet.core_svc.usage_service import bytes_between
    today = local_today().isoformat()
    today_bytes = bytes_between(db, today, today, own_ids)

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
            "latency_ms": round(known_latency(latest_speed.latency_ms), 0) if known_latency(latest_speed.latency_ms) else None,
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

    from clarinet.core_svc.localtime import local_today
    from clarinet.core_svc.usage_service import usage_range
    today = local_today().isoformat()
    usage = usage_range(db, user, today, today)          # the viewer's own today; members only see their devices
    devices = ({d.device_id: d for d in db.query(Device).filter(Device.device_id.in_(list(usage.by_device)))}
               if usage.by_device else {})
    rows = sorted(((devices[i], bi, bo) for i, (bi, bo) in usage.by_device.items() if i in devices),
                  key=lambda r: r[1] + r[2], reverse=True)
    return [
        {
            "device_id": d.device_id,
            "name": d.label or d.hostname or d.mac_address,
            "state": d.state,
            "bytes_in": bi or 0,
            "bytes_out": bo or 0,
            "total_mb": round(((bi or 0) + (bo or 0)) / 1_048_576, 2),
        }
        for d, bi, bo in rows
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
            "latency_ms": round(known_latency(r.latency_ms), 1) if known_latency(r.latency_ms) else None,
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
