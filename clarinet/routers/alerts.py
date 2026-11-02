"""
clarinet/routers/alerts.py
Alert management routes for M1.

Routes:
  GET  /alerts                  — alert list with filters/pagination
  POST /alerts/{id}/ack         — acknowledge an alert
  POST /alerts/{id}/resolve     — resolve an alert
  GET  /api/devices/summary     — C-07: device counts summary
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin, require_login
from clarinet.database import get_db

router = APIRouter(tags=["alerts"])


@router.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    # Filters
    level_filter = request.query_params.get("level", "")
    status_filter = request.query_params.get("status", "OPEN")
    page = max(1, int(request.query_params.get("page", "1")))
    per_page = 20

    from clarinet.core_svc.permissions import visible_alerts
    from clarinet.models import Alert
    q = visible_alerts(db, user)
    if level_filter:
        q = q.filter(Alert.level == level_filter.upper())
    if status_filter:
        q = q.filter(Alert.status == status_filter.upper())

    total = q.count()
    alerts = (
        q.order_by(Alert.raised_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return templates.TemplateResponse("alerts/index.html", {
        "request": request,
        "user": user,
        "page": "alerts",
        "alerts": alerts,
        "total": total,
        "cur_page": page,
        "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
        "level_filter": level_filter,
        "status_filter": status_filter,
        "info": request.query_params.get("info", ""),
        "error": request.query_params.get("error", ""),
    })


@router.post("/alerts/{alert_id}/ack")
def ack_alert_route(alert_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.core_svc.alerts import ack_alert
    from clarinet.auth import audit
    from clarinet.core_svc.permissions import visible_alerts
    from clarinet.models import Alert
    if visible_alerts(db, user).filter(Alert.alert_id == alert_id).first() is None:
        return RedirectResponse(url="/alerts?info=not_found", status_code=302)
    ok = ack_alert(db, alert_id, user.member_id)
    if ok:
        audit(db, user.member_id, "ACK_ALERT", "Alert", alert_id)
    return RedirectResponse(
        url=f"/alerts?info={'acked' if ok else 'not_found'}",
        status_code=302,
    )


@router.post("/alerts/{alert_id}/resolve")
def resolve_alert_route(alert_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.core_svc.alerts import resolve_alert_by_id
    from clarinet.auth import audit
    ok = resolve_alert_by_id(db, alert_id)
    if ok:
        audit(db, user.member_id, "RESOLVE_ALERT", "Alert", alert_id)
    return RedirectResponse(
        url=f"/alerts?info={'resolved' if ok else 'not_found'}",
        status_code=302,
    )


@router.get("/api/devices/summary")
def api_devices_summary(request: Request, db: Session = Depends(get_db)):
    """
    C-07: Device counts summary.
    Returns total, approved, new, blocked, guest counts.
    """
    from clarinet.auth import get_session_user
    user = get_session_user(request, db)
    if user is None:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)

    from clarinet.core_svc.permissions import member_device_ids
    from clarinet.models import Device
    from sqlalchemy import func

    query = db.query(Device.state, func.count(Device.device_id))
    if not user.is_admin:
        query = query.filter(Device.device_id.in_(member_device_ids(db, user)))
    rows = query.group_by(Device.state).all()
    counts = {state: count for state, count in rows}
    total = sum(counts.values())

    return {
        "total": total,
        "approved": counts.get("APPROVED", 0),
        "new": counts.get("NEW", 0),
        "blocked": counts.get("BLOCKED", 0),
        "guest": counts.get("GUEST", 0),
    }
