"""clarinet/routers/alerts.py"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin, audit
from clarinet.database import get_db
from clarinet.models import Alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_class=HTMLResponse)
def alert_list(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    alerts = (
        db.query(Alert)
        .order_by(Alert.raised_at.desc())
        .limit(200)
        .all()
    )
    open_count = sum(1 for a in alerts if a.status == "OPEN")
    critical_count = sum(1 for a in alerts if a.level == "CRITICAL" and a.status == "OPEN")

    return templates.TemplateResponse("alerts/index.html", {
        "request": request,
        "user": user,
        "page": "alerts",
        "alerts": alerts,
        "open_count": open_count,
        "critical_count": critical_count,
    })


@router.post("/{alert_id}/ack")
def ack_alert(alert_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    alert = db.get(Alert, alert_id)
    if alert:
        alert.status = "ACK"
        audit(db, user.member_id, "ACK_ALERT", "Alert", alert_id)
    return RedirectResponse(url="/alerts", status_code=302)


@router.post("/{alert_id}/resolve")
def resolve_alert(alert_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    alert = db.get(Alert, alert_id)
    if alert:
        alert.status = "RESOLVED"
        audit(db, user.member_id, "RESOLVE_ALERT", "Alert", alert_id)
    return RedirectResponse(url="/alerts", status_code=302)
