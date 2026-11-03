"""clarinet/routers/security.py — security alerts, router audit, access points, known networks."""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import audit, require_admin
from clarinet.database import get_db
from clarinet.models import Alert, AuditLog, Device
from clarinet.models.security import (
    KnownNetwork, RouterAuditFinding, SeenAccessPoint, TrustedAccessPoint,
)

router = APIRouter(prefix="/security", tags=["security"])

SECURITY_ALERT_TYPES = [
    "ARP_SPOOF", "NEW_DEVICE", "RANDOM_MAC", "PORT_SCAN",
    "FAKE_AP", "UNFAMILIAR_NETWORK", "ROUTER_AUDIT",
]


def _back(message: str | None = None) -> RedirectResponse:
    suffix = f"?msg={message}" if message else ""
    return RedirectResponse(url=f"/security{suffix}", status_code=303)


def _member_security(request: Request, db: Session, user):
    """What a member may see: their own devices, the alerts about them, and their own sign-ins and sessions."""
    from clarinet.core_svc import recovery
    from clarinet.core_svc.permissions import member_device_ids, visible_alerts
    from clarinet.models.reports import LoginAttempt
    from clarinet.models.sessions import ActiveSession

    ids = member_device_ids(db, user)
    devices = db.query(Device).filter(Device.device_id.in_(ids)).order_by(Device.last_seen.desc()).all() if ids else []
    open_by_device = {}
    for alert in visible_alerts(db, user).filter(Alert.status == "OPEN").all():
        open_by_device[alert.device_id] = open_by_device.get(alert.device_id, 0) + 1

    sessions = db.query(ActiveSession).filter(ActiveSession.member_id == user.member_id).order_by(ActiveSession.created_at.desc()).all()
    current_sid = request.session.get("sid")
    sign_ins = (
        db.query(LoginAttempt).filter(LoginAttempt.member_id == user.member_id)
        .order_by(LoginAttempt.attempted_at.desc()).limit(10).all()
    )
    return templates.TemplateResponse("security/member.html", {
        "request": request,
        "user": user,
        "page": "security",
        "devices": devices,
        "open_by_device": open_by_device,
        "alerts": visible_alerts(db, user).order_by(Alert.raised_at.desc()).limit(10).all(),
        "sessions": sessions,
        "current_sid": current_sid,
        "sign_ins": sign_ins,
        "failed_recently": sum(1 for s in sign_ins if not s.success),
        "has_recovery_code": recovery.has_code(db, user.member_id),
        "info": request.query_params.get("info", ""),
        "error": request.query_params.get("error", ""),
    })


@router.get("", response_class=HTMLResponse)
def security_page(request: Request, db: Session = Depends(get_db)):
    from clarinet.auth import require_login
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result
    if not user.is_admin:
        return _member_security(request, db, user)

    sec_alerts = (
        db.query(Alert)
        .filter(Alert.type.in_(SECURITY_ALERT_TYPES))
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

    audit_logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(50).all()

    # Latest router audit run
    latest = db.query(RouterAuditFinding).order_by(RouterAuditFinding.found_at.desc()).first()
    router_findings = []
    if latest is not None:
        router_findings = (
            db.query(RouterAuditFinding)
            .filter(RouterAuditFinding.run_id == latest.run_id)
            .all()
        )
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "OK": 3}
        router_findings.sort(key=lambda f: order.get(f.severity, 9))

    access_points = (
        db.query(SeenAccessPoint)
        .order_by(SeenAccessPoint.verdict.desc(), SeenAccessPoint.last_seen.desc())
        .limit(60)
        .all()
    )
    trusted_aps = db.query(TrustedAccessPoint).order_by(TrustedAccessPoint.ssid).all()
    trusted_bssids = {t.bssid for t in trusted_aps}
    networks = db.query(KnownNetwork).order_by(KnownNetwork.last_seen.desc()).all()

    return templates.TemplateResponse("security/index.html", {
        "request": request,
        "user": user,
        "page": "security",
        "msg": request.query_params.get("msg"),
        "sec_alerts": sec_alerts,
        "random_mac_devices": random_mac_devices,
        "audit_logs": audit_logs,
        "router_findings": router_findings,
        "router_audit_time": latest.found_at if latest else None,
        "router_gateway": latest.gateway_ip if latest else None,
        "access_points": access_points,
        "trusted_aps": trusted_aps,
        "trusted_bssids": trusted_bssids,
        "networks": networks,
    })


# Router audit

@router.post("/router-audit/run")
def run_router_audit(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result

    from clarinet.collector.router_audit import run_audit
    outcome = run_audit(db)
    audit(db, result.member_id, "ROUTER_AUDIT_RUN", "Router", outcome.get("gateway_ip"),
          detail={"findings": outcome.get("findings", 0), "high": outcome.get("high", 0)})
    return _back("audit_failed" if not outcome["ok"] else "audit_done")


# Wi-Fi access points

@router.post("/wifi/scan")
def scan_wifi(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result

    from clarinet.collector.wifi_scan import scan_and_evaluate
    summary = scan_and_evaluate(db)
    audit(db, result.member_id, "WIFI_SCAN", "WiFi", None, detail=summary)
    return _back("scan_done")


@router.post("/access-points/trust")
def trust_access_point(
    request: Request,
    bssid: list[str] = Form([]),
    label: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """Trust only the access points the admin ticked, one by one."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    if not bssid:
        return _back("ap_none")

    for raw in bssid:
        bssid_value = raw.strip().upper()
        seen = db.get(SeenAccessPoint, bssid_value)
        already = db.query(TrustedAccessPoint).filter(TrustedAccessPoint.bssid == bssid_value).first()
        if seen is None or already is not None:
            continue
        db.add(TrustedAccessPoint(ssid=seen.ssid, bssid=bssid_value, label=(label or None)))
        seen.verdict, seen.reason = "OK", None
        db.commit()
        audit(db, result.member_id, "TRUST_AP", "AccessPoint", bssid_value, detail={"ssid": seen.ssid})
    return _back("ap_trusted")


@router.post("/access-points/{ap_id}/untrust")
def untrust_access_point(ap_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result

    ap = db.get(TrustedAccessPoint, ap_id)
    if ap is not None:
        db.delete(ap)
        db.commit()
        audit(db, result.member_id, "UNTRUST_AP", "AccessPoint", ap.bssid, detail={"ssid": ap.ssid})
    return _back("ap_removed")


# Known networks

@router.post("/networks/{network_id}/trust")
def trust_network(network_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result

    net = db.get(KnownNetwork, network_id)
    if net is not None:
        net.trusted = True
        db.commit()
        audit(db, result.member_id, "TRUST_NETWORK", "Network", net.gateway_mac)
    return _back("network_trusted")


@router.post("/networks/{network_id}/forget")
def forget_network(network_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result

    net = db.get(KnownNetwork, network_id)
    if net is not None:
        db.delete(net)
        db.commit()
        audit(db, result.member_id, "FORGET_NETWORK", "Network", net.gateway_mac)
    return _back("network_removed")


# JSON summary (used by the dashboard)

@router.get("/summary")
def security_summary(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return JSONResponse({"error": "forbidden"}, status_code=403)

    counts = dict(
        db.query(Alert.type, func.count(Alert.alert_id))
        .filter(Alert.type.in_(SECURITY_ALERT_TYPES), Alert.status == "OPEN")
        .group_by(Alert.type)
        .all()
    )
    return {
        "open_alerts": counts,
        "open_total": sum(counts.values()),
        "suspect_access_points": db.query(SeenAccessPoint).filter(SeenAccessPoint.verdict == "SUSPECT").count(),
        "untrusted_networks": db.query(KnownNetwork).filter(KnownNetwork.trusted == False).count(),  # noqa: E712
    }
