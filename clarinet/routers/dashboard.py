"""
clarinet/routers/dashboard.py
Main overview page — summary cards + live alert feed.
Accessible by both admins and members. Admins see the whole network; members
only see their own devices and the alerts about them.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_login
from clarinet.core_svc.permissions import member_device_ids, visible_alerts
from clarinet.database import get_db
from clarinet.models import (
    Alert, Device, PingRecord, SlowdownEvent, SpeedTestResult, UsageRecord, Member
)
from datetime import date, datetime, timedelta, timezone

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    # Admins see everything; members only their own devices and alerts about them.
    # Network-wide alerts (security, router, Wi-Fi) have no device and stay admin-only.
    own_ids = None if user.is_admin else member_device_ids(db, user)

    def scope_devices(query):
        return query if own_ids is None else query.filter(Device.device_id.in_(own_ids))

    # Summary counts
    total_devices = scope_devices(db.query(func.count(Device.device_id))).scalar() or 0
    online_devices = (
        scope_devices(db.query(func.count(Device.device_id)))
        .filter(Device.state == "APPROVED")
        .scalar() or 0
    )
    new_devices = (
        scope_devices(db.query(func.count(Device.device_id)))
        .filter(Device.state == "NEW")
        .scalar() or 0
    )
    open_alerts = visible_alerts(db, user).filter(Alert.status == "OPEN").count()
    critical_alerts = (
        visible_alerts(db, user)
        .filter(Alert.status == "OPEN", Alert.level == "CRITICAL")
        .count()
    )

    # Recent alerts (last 10)
    recent_alerts = (
        visible_alerts(db, user)
        .filter(Alert.status == "OPEN")
        .order_by(Alert.raised_at.desc())
        .limit(10)
        .all()
    )

    # Latest speed test (a network-wide measurement, fine for everyone)
    latest_speed = (
        db.query(SpeedTestResult)
        .order_by(SpeedTestResult.tested_at.desc())
        .first()
    )

    # Average internet latency over the last hour (reachable pings to the internet, not the router)
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    avg_latency = (
        db.query(func.avg(PingRecord.avg_ms))
        .filter(PingRecord.measured_at >= since, PingRecord.reachable == True, PingRecord.target != "router")  # noqa: E712
        .scalar()
    )

    # Active slowdown (network-wide, fine for everyone)
    active_slowdown = (
        db.query(SlowdownEvent)
        .filter(SlowdownEvent.ended_at == None)
        .order_by(SlowdownEvent.started_at.desc())
        .first()
    )

    # Today's total traffic (bytes → MB)
    today = date.today().isoformat()
    traffic_q = db.query(func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out)).filter(UsageRecord.date == today)
    if own_ids is not None:
        traffic_q = traffic_q.filter(UsageRecord.device_id.in_(own_ids))
    today_traffic_mb = round((traffic_q.scalar() or 0) / 1_048_576, 1)

    # Top-5 devices by usage today
    top_devices_q = (
        db.query(
            Device.label,
            Device.hostname,
            Device.mac_address,
            Device.state,
            func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out).label("total")
        )
        .join(UsageRecord, Device.device_id == UsageRecord.device_id)
        .filter(UsageRecord.date == today)
    )
    top_devices = (
        scope_devices(top_devices_q)
        .group_by(Device.device_id)
        .order_by(func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out).desc())
        .limit(5)
        .all()
    )

    # Monthly data limit progress (the whole connection's usage, so admins only)
    limit = None
    if user.is_admin:
        from clarinet.core_svc.limit_service import get_limit_summary
        summary = get_limit_summary(db)
        if summary.bytes_limit:
            limit = summary

    # Members don't review unapproved devices
    if not user.is_admin:
        new_devices = None

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
        "limit": limit,
        "avg_latency": avg_latency,
        "active_slowdown": active_slowdown,
        "top_devices": top_devices,
        # flash messages
        "error": request.query_params.get("error", ""),
    })
