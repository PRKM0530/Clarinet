"""
clarinet/routers/status.py
System status routes for M1. (C-06 contract)

Routes:
  GET /status              — full status page (admin)
  GET /api/status/topbar   — C-06: {mode, mode_word, network, network_word, open_alerts, recent}
  GET /api/status/health   — health check (200 OK)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin, require_login
from clarinet.database import get_db

router = APIRouter(tags=["status"])


@router.get("/api/status/health")
def health_check():
    """Simple health check — returns 200 if the app is running."""
    return {"status": "ok"}


@router.get("/api/status/topbar")
def topbar_api(request: Request, db: Session = Depends(get_db)):
    """
    C-06: Topbar data for all authenticated users.
    Returns: {mode, mode_word, network, network_word, open_alerts, recent}
    """
    from clarinet.auth import get_session_user
    user = get_session_user(request, db)
    if user is None:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)

    from clarinet.app_settings import get_setting
    from clarinet.core_svc.mode import parse_mode, mode_word, network_word
    from clarinet.core_svc.permissions import visible_alerts

    raw_mode = get_setting(db, "network_mode") or "MONITOR"
    mode = parse_mode(raw_mode)

    from clarinet.models import Alert
    open_alerts = (
        visible_alerts(db, user)
        .filter(Alert.status == "OPEN")
        .count()
    )

    recent_alerts = (
        visible_alerts(db, user)
        .filter(Alert.status == "OPEN")
        .order_by(Alert.raised_at.desc())
        .limit(5)
        .all()
    )

    return {
        "mode": mode.value,
        "mode_word": mode_word(mode),
        "network": "private" if mode.value != "PUBLIC" else "public",
        "network_word": network_word(mode),
        "open_alerts": open_alerts,
        "recent": [
            {
                "alert_id": a.alert_id,
                "level": a.level,
                "type": a.type,
                "title": a.title,
                "raised_at": a.raised_at.isoformat() if a.raised_at else None,
            }
            for a in recent_alerts
        ],
    }


@router.get("/status", response_class=HTMLResponse)
def status_page(request: Request, db: Session = Depends(get_db)):
    """Full system status page — admin only."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.app_settings import get_setting
    from clarinet.core_svc.mode import parse_mode, mode_word, network_word, can_enforce
    from clarinet.core_svc.limit_service import get_limit_summary
    from clarinet.models import Alert, Device

    raw_mode = get_setting(db, "network_mode") or "MONITOR"
    mode = parse_mode(raw_mode)

    total_devices = db.query(Device).count()
    online_devices = db.query(Device).filter(Device.state == "APPROVED").count()
    new_devices = db.query(Device).filter(Device.state == "NEW").count()
    open_alerts = db.query(Alert).filter(Alert.status == "OPEN").count()

    try:
        limit = get_limit_summary(db)
    except Exception:
        limit = None

    return templates.TemplateResponse("status/index.html", {
        "request": request,
        "user": user,
        "page": "status",
        "mode": mode.value,
        "mode_word": mode_word(mode),
        "network_word": network_word(mode),
        "can_enforce": can_enforce(mode),
        "total_devices": total_devices,
        "online_devices": online_devices,
        "new_devices": new_devices,
        "open_alerts": open_alerts,
        "limit": limit,
        "iface": get_setting(db, "network_interface") or "—",
        "router_ip": get_setting(db, "router_ip") or "—",
    })

