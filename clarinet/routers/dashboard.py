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


def scope_devices_history(query, own_ids):
    """Limit a history query to a member's own devices (None = administrator, no limit)."""
    from clarinet.models import Device
    return query if own_ids is None else query.filter(Device.device_id.in_(own_ids))


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
    from clarinet.core_svc.presence import online_cutoff
    online_devices = (
        scope_devices(db.query(func.count(Device.device_id)))
        .filter(Device.last_seen >= online_cutoff(), Device.state != "BLOCKED")
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
    from clarinet.core_svc.speed_filters import valid_only
    latest_speed = (
        valid_only(db.query(SpeedTestResult))
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

    # Network health badge (network-wide, fine for everyone)
    health = "Healthy"
    if active_slowdown is not None:
        causes = active_slowdown.causes
        health = "Critical slowdown" if causes and causes[0].get("cause") == "INTERNET_OUTAGE" else "Degraded"

    # Latency of the router and the two public targets over the last three hours
    now_utc = datetime.now(timezone.utc)
    latency: dict[str, list] = {}
    for r in (db.query(PingRecord).filter(PingRecord.measured_at >= now_utc - timedelta(hours=3), PingRecord.avg_ms.isnot(None))
              .order_by(PingRecord.measured_at.asc()).all()):
        at = r.measured_at if r.measured_at.tzinfo else r.measured_at.replace(tzinfo=timezone.utc)
        latency.setdefault(r.target, []).append({"x": round(-(now_utc - at).total_seconds() / 60, 1), "y": r.avg_ms})
    has_router_ping = "router" in latency

    # Usage bars: share of the busiest device
    top_max = max([(d.total or 0) for d in top_devices], default=0)

    # Recent joins and leaves (a member only sees their own devices)
    from clarinet.models import DeviceHistory
    hist_q = (db.query(DeviceHistory, Device).join(Device, Device.device_id == DeviceHistory.device_id))
    activity = scope_devices_history(hist_q, own_ids).order_by(DeviceHistory.timestamp.desc()).limit(12).all()

    from clarinet.models import UsageRecord as _U
    no_usage_data = (db.query(func.count(_U.record_id)).scalar() or 0) == 0

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
        "top_max": top_max,
        "health": health,
        "latency": latency,
        "has_router_ping": has_router_ping,
        "activity": activity,
        "no_usage_data": no_usage_data,
        # flash messages
        "error": request.query_params.get("error", ""),
        "info": request.query_params.get("info", ""),
    })
