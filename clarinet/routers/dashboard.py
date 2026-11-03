"""
clarinet/routers/dashboard.py
Main overview page — summary cards + live alert feed.
Accessible by both admins and members. Admins see the whole network; members
only see their own devices and the alerts about them.
"""

from clarinet.core_svc.localtime import local_today
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_login
from clarinet.core_svc.permissions import member_device_ids, visible_alerts
from clarinet.database import get_db
from clarinet.models import (
    Alert, Device
)

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
    from clarinet.core_svc.presence import ONLINE_WINDOW_SECONDS, online_cutoff
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

    # Speed belongs to a device: what this person's devices measured, and which visible devices are slow
    from clarinet.core_svc import device_speed
    cards = [device_speed.summary(db, dev) for dev in device_speed.devices_for(db, user)]
    mine = [c for c in cards if c.latest and c.device.owner_member_id == user.member_id] or [c for c in cards if c.latest]
    my_speed = max(mine, key=lambda c: c.latest.tested_at, default=None)
    slow_devices = [c for c in cards if c.status in ("slower", "much_slower")]

    # Today's total traffic (bytes → MB)
    from clarinet.core_svc.usage_service import bytes_between
    today = local_today().isoformat()
    today_traffic_mb = round(bytes_between(db, today, today, own_ids) / 1_048_576, 1)

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

    health = "Healthy" if not slow_devices else ("Much slower" if any(c.status == "much_slower" for c in slow_devices) else "Some devices slower")

    from clarinet.models import UsageRecord as _U
    no_usage_data = (db.query(func.count(_U.record_id)).scalar() or 0) == 0

    return templates.TemplateResponse("dashboard/overview.html", {
        "request": request,
        "user": user,
        "page": "dashboard",
        # stats
        "total_devices": total_devices,
        "online_devices": online_devices,
        "online_minutes": ONLINE_WINDOW_SECONDS // 60,
        "new_devices": new_devices,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "today_traffic_mb": today_traffic_mb,
        # data
        "recent_alerts": recent_alerts,
        "my_speed": my_speed,
        "slow_devices": slow_devices,
        "limit": limit,
        "health": health,
        "no_usage_data": no_usage_data,
        # flash messages
        "error": request.query_params.get("error", ""),
        "info": request.query_params.get("info", ""),
    })
