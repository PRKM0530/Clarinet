"""clarinet/routers/security.py — ARP alerts, router audit, rogue device view."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin
from clarinet.database import get_db
from clarinet.models import Alert, AuditLog, Device

router = APIRouter(prefix="/security", tags=["security"])


@router.get("", response_class=HTMLResponse)
def security_page(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    # Security-relevant alerts: ARP spoofing, unknown devices, random MACs
    sec_alerts = (
        db.query(Alert)
        .filter(Alert.type.in_(["ARP_SPOOF", "NEW_DEVICE", "RANDOM_MAC", "PORT_SCAN"]))
        .order_by(Alert.raised_at.desc())
        .limit(100)
        .all()
    )

    # Devices with random MACs (privacy concern / hard to track)
    random_mac_devices = (
        db.query(Device)
        .filter(Device.is_random_mac == True)
        .order_by(Device.last_seen.desc())
        .all()
    )

    # Recent audit log (last 50 entries)
    audit_logs = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .limit(50)
        .all()
    )

    return templates.TemplateResponse("security/index.html", {
        "request": request,
        "user": user,
        "page": "security",
        "sec_alerts": sec_alerts,
        "random_mac_devices": random_mac_devices,
        "audit_logs": audit_logs,
    })
