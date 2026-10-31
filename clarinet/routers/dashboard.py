"""
clarinet/routers/dashboard.py
Main overview page — summary cards + live alert feed.
Accessible by both admins and members (content differs by role).
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_login
from clarinet.database import get_db
from clarinet.models import (
    Alert, Device, SlowdownEvent, SpeedTestResult, UsageRecord, Member
)
from datetime import date, timedelta

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    # Summary counts
    total_devices = db.query(func.count(Device.device_id)).scalar() or 0
    online_devices = (
        db.query(func.count(Device.device_id))
        .filter(Device.state == "APPROVED")
        .scalar() or 0
    )
    new_devices = (
        db.query(func.count(Device.device_id))
        .filter(Device.state == "NEW")
        .scalar() or 0
    )
    open_alerts = (
        db.query(func.count(Alert.alert_id))
        .filter(Alert.status == "OPEN")
        .scalar() or 0
    )
    critical_alerts = (
        db.query(func.count(Alert.alert_id))
        .filter(Alert.status == "OPEN", Alert.level == "CRITICAL")
        .scalar() or 0
    )

    # Recent alerts (last 10)
    recent_alerts = (
        db.query(Alert)
        .filter(Alert.status == "OPEN")
        .order_by(Alert.raised_at.desc())
        .limit(10)
        .all()
    )

    # Latest speed test
    latest_speed = (
        db.query(SpeedTestResult)
        .order_by(SpeedTestResult.tested_at.desc())
        .first()
    )

    # Active slowdown
    active_slowdown = (
        db.query(SlowdownEvent)
        .filter(SlowdownEvent.ended_at == None)
        .order_by(SlowdownEvent.started_at.desc())
        .first()
    )

    # Today's total traffic (bytes → MB)
    today = date.today().isoformat()
    today_traffic = db.query(
        func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out)
    ).filter(UsageRecord.date == today).scalar() or 0
    today_traffic_mb = round(today_traffic / 1_048_576, 1)

    # Top-5 devices by usage today
    top_devices = (
        db.query(
            Device.label,
            Device.hostname,
            Device.mac_address,
            Device.state,
            func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out).label("total")
        )
        .join(UsageRecord, Device.device_id == UsageRecord.device_id)
        .filter(UsageRecord.date == today)
        .group_by(Device.device_id)
        .order_by(func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out).desc())
        .limit(5)
        .all()
    )

    # For members: only show their own data
    if not user.is_admin:
        new_devices = None  # members don't see new-device alerts

    return templates.TemplateResponse("dashboard/overview.html", {
        "request": request,
        "user": user,
        "page": "dashboard",
        # stats
        "total_devices": total_devices,
        "online_devices": online_devices,
        "new_devices": new_devices,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "today_traffic_mb": today_traffic_mb,
        # data
        "recent_alerts": recent_alerts,
        "latest_speed": latest_speed,
        "active_slowdown": active_slowdown,
        "top_devices": top_devices,
        # flash messages
        "error": request.query_params.get("error", ""),
    })
