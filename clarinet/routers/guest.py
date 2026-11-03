"""
clarinet/routers/guest.py  (M2 rewrite)
Guest portal and voucher management.

Fixes (F-04):
- redeem() activates the voucher (status ACTIVE)
- Records guest MAC from request headers / forwarded IP
- Opens nft guest access via enforcer
- Creates Device(state=GUEST) row for the guest device
- Voucher cannot be redeemed again once ACTIVE/EXPIRED/REVOKED
- Brute-force limit: max 10 attempts per IP per 10 minutes
- Voucher duration can be as short as 30 minutes (Form min removed)
"""
from __future__ import annotations

import secrets
import string
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin, audit
from clarinet.database import get_db
from clarinet.models import Voucher

router = APIRouter(tags=["guest"])

# Brute-force config
_MAX_ATTEMPTS = 10
_ATTEMPT_WINDOW_MINUTES = 10


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _client_ip(request: Request) -> str:
    from clarinet.auth import client_ip
    return client_ip(request)             # X-Forwarded-For is only believed from a trusted proxy


def _is_rate_limited(ip: str, db: Session) -> bool:
    """Return True if this IP has too many failed attempts recently."""
    from clarinet.models.guest import RedeemAttempt
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=_ATTEMPT_WINDOW_MINUTES)
    count = (
        db.query(RedeemAttempt)
        .filter(
            RedeemAttempt.ip == ip,
            RedeemAttempt.success == False,
            RedeemAttempt.attempted_at > cutoff,
        )
        .count()
    )
    return count >= _MAX_ATTEMPTS


def _log_attempt(ip: str, code: str, success: bool, db: Session) -> None:
    from clarinet.models.guest import RedeemAttempt
    db.add(RedeemAttempt(ip=ip, code_tried=code[:32], success=success))


def _redeem_problem(mac: str | None, voucher: Voucher, db: Session) -> str | None:
    """Why this device cannot use a voucher right now, or None. A refused redeem does not use the voucher up."""
    if mac is None:
        return "We could not identify your device yet. Make sure you are connected to this network's Wi-Fi (not mobile data or a VPN), wait about 15 seconds so the network can see you, and try again. Your voucher has not been used."
    from clarinet.models import Device
    from clarinet.models.guest import EnforcementStatus
    device = db.query(Device).filter(Device.mac_address == mac).first()
    if device is not None and device.state in ("APPROVED", "BLOCKED"):
        return ("This device already has access to the network and does not need a voucher."
                if device.state == "APPROVED" else "This device has been blocked by the administrator.")
    active = db.query(EnforcementStatus).filter(EnforcementStatus.mac == mac).first()
    if active is not None and active.voucher_id != voucher.voucher_id:
        return "This device already has an active voucher. Wait until it ends before using another."
    return None


def _get_mac_for_request(request: Request) -> str | None:
    """
    Best-effort: extract the guest device MAC from the request.
    In a real deployment behind dnsmasq/DHCP, the IP→MAC map comes from ARP.
    Here we use the forwarded IP and try to look up in the device table.
    """
    ip = _client_ip(request)
    try:
        from clarinet.database import SessionLocal
        from clarinet.models import Device
        with SessionLocal() as db:
            dev = db.query(Device).filter(Device.ip_address == ip).first()
            if dev:
                return dev.mac_address
    except Exception:
        pass
    return None


def _activate_voucher(voucher: Voucher, mac: str | None, db: Session) -> None:
    """
    Set voucher ACTIVE, create Device(GUEST), open nft access,
    create EnforcementStatus row.
    """
    now = datetime.utcnow()  # naive UTC — matches SQLite storage
    voucher.status = "ACTIVE"

    # Create / update Device row for this guest
    if mac:
        from clarinet.models import Device
        device = db.query(Device).filter(Device.mac_address == mac).first()
        if not device:
            device = Device(
                mac_address=mac,
                state="GUEST",
                first_seen=now,
                last_seen=now,
                label=f"Guest ({voucher.code})",
            )
            db.add(device)
        elif device.state not in ("BLOCKED",):
            device.state = "GUEST"
        db.flush()

        # EnforcementStatus
        from clarinet.models.guest import EnforcementStatus
        existing = db.query(EnforcementStatus).filter(EnforcementStatus.mac == mac).first()
        if not existing:
            db.add(EnforcementStatus(
                mac=mac,
                voucher_id=voucher.voucher_id,
                granted_at=now,
                expires_at=voucher.expires_at,
                data_cap_mb=voucher.data_cap_mb,
                speed_cap_mbps=voucher.speed_cap_mbps,
            ))


def _open_voucher_access(voucher: Voucher, mac: str | None, db: Session) -> None:
    """
    Open the network for a voucher holder. Called AFTER the database change is saved: the reconcile job removes
    access rules for anyone the database does not (yet) list as a guest, so changing the network first could
    have the new rule deleted a moment later.
    """
    if not mac:
        return
    # Open nft guest access
    try:
        from clarinet.app_settings import get_setting as _gs
        from clarinet.enforcer.nft_wrapper import open_guest_access
        open_guest_access(mac, interface=_gs(db, "network_interface", ""))
    except Exception:
        pass

    # Apply speed cap if configured
    if voucher.speed_cap_mbps:
        try:
            from clarinet.database import SessionLocal as SL
            from clarinet.app_settings import get_setting
            from clarinet.enforcer.tc_wrapper import set_rate_limit
            with SL() as _db:
                iface = get_setting(_db, "guest.interface",
                                    get_setting(_db, "network_interface", ""))
            if iface:
                set_rate_limit(iface, mac, int(voucher.speed_cap_mbps * 1000))
        except Exception:
            pass


# ──────────────────────────────────────────────
# Public portal (no auth)
# ──────────────────────────────────────────────

@router.get("/guest", response_class=HTMLResponse)
def guest_portal(request: Request):
    return templates.TemplateResponse("guest/portal.html", {"request": request})


@router.post("/guest/redeem", response_class=HTMLResponse)
def redeem_voucher(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db),
):
    ip = _client_ip(request)
    code = code.strip().upper()

    # Brute-force protection
    if _is_rate_limited(ip, db):
        return templates.TemplateResponse("guest/portal.html", {
            "request": request,
            "error": "Too many attempts. Please wait 10 minutes before trying again.",
        })

    voucher = db.query(Voucher).filter(Voucher.code == code).first()
    now = datetime.utcnow()  # naive UTC — matches SQLite storage

    if voucher is None:
        _log_attempt(ip, code, False, db)
        db.commit()
        return templates.TemplateResponse("guest/portal.html", {
            "request": request,
            "error": "Invalid voucher code. Please check and try again.",
        })

    if voucher.status == "EXPIRED" or (voucher.expires_at and voucher.expires_at < now):
        voucher.status = "EXPIRED"
        _log_attempt(ip, code, False, db)
        db.commit()
        return templates.TemplateResponse("guest/portal.html", {
            "request": request,
            "error": "This voucher has expired.",
        })

    if voucher.status != "UNUSED":
        _log_attempt(ip, code, False, db)
        db.commit()
        return templates.TemplateResponse("guest/portal.html", {
            "request": request,
            "error": f"This voucher has already been used.",
        })

    # The voucher is only used up when it can actually open access for this device.
    mac = _get_mac_for_request(request)
    problem = _redeem_problem(mac, voucher, db)
    if problem:
        db.commit()
        return templates.TemplateResponse("guest/portal.html", {"request": request, "error": problem})

    _activate_voucher(voucher, mac, db)
    _log_attempt(ip, code, True, db)
    db.commit()
    _open_voucher_access(voucher, mac, db)

    return templates.TemplateResponse("guest/success.html", {
        "request": request,
        "voucher": voucher,
        "expires_at": voucher.expires_at,
    })


# ──────────────────────────────────────────────
# Admin: voucher management
# ──────────────────────────────────────────────

@router.get("/vouchers", response_class=HTMLResponse)
def voucher_list(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    vouchers = db.query(Voucher).order_by(Voucher.created_at.desc()).all()
    return templates.TemplateResponse("guest/vouchers.html", {
        "request": request,
        "user": user,
        "page": "guest",
        "vouchers": vouchers,
        "info": request.query_params.get("info", ""),
        "error": request.query_params.get("error", ""),
    })


@router.post("/vouchers/create")
def create_voucher(
    request: Request,
    expires_hours: str = Form(""),      # what the page sends (1 h, 4 h, 24 h ...)
    expires_minutes: str = Form(""),    # older callers: minutes
    data_cap_mb: str = Form(""),        # a browser sends an empty box as ""
    speed_cap_mbps: str = Form(""),
    label: str | None = Form(None),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    try:
        if expires_minutes.strip():
            minutes = float(expires_minutes)
        elif expires_hours.strip():
            minutes = float(expires_hours) * 60
        else:
            minutes = 1440                                    # default 24 hours
        data_cap = int(float(data_cap_mb)) if data_cap_mb.strip() else None
        speed_cap = float(speed_cap_mbps) if speed_cap_mbps.strip() else None
    except ValueError:
        return RedirectResponse(url="/vouchers?error=bad_voucher", status_code=302)
    if minutes != minutes or (data_cap is not None and data_cap <= 0) or (speed_cap is not None and speed_cap <= 0):
        return RedirectResponse(url="/vouchers?error=bad_voucher", status_code=302)
    # Validate: minimum 30 minutes (SRS AT-13.1), maximum 30 days
    expires_minutes = int(max(30, min(minutes, 43200)))

    # Generate readable 8-char code (no ambiguous characters)
    alphabet = (string.ascii_uppercase.replace("O", "").replace("I", "")
                + string.digits.replace("0", ""))
    code = "".join(secrets.choice(alphabet) for _ in range(8))

    voucher = Voucher(
        code=code,
        created_by=user.member_id,
        expires_at=datetime.utcnow() + timedelta(minutes=expires_minutes),  # naive UTC
        data_cap_mb=data_cap,
        speed_cap_mbps=speed_cap,
        status="UNUSED",
    )
    db.add(voucher)
    db.flush()
    audit(db, user.member_id, "CREATE_VOUCHER", "Voucher", voucher.voucher_id, {
        "code": code,
        "expires_minutes": expires_minutes,
        "data_cap_mb": data_cap_mb,
        "speed_cap_mbps": speed_cap_mbps,
    })
    db.commit()
    return RedirectResponse(url="/vouchers?info=Voucher+created", status_code=302)


@router.post("/vouchers/{voucher_id}/revoke")
def revoke_voucher(voucher_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    voucher = db.get(Voucher, voucher_id)
    if voucher and voucher.status in ("UNUSED", "ACTIVE"):
        previous = voucher.status
        if previous == "ACTIVE":
            _close_active_voucher(voucher, db)
        voucher.status = "REVOKED"
        audit(db, user.member_id, "REVOKE_VOUCHER", "Voucher", voucher_id,
              {"previous_status": previous})
        db.commit()
    return RedirectResponse(url="/vouchers?info=Voucher+revoked", status_code=302)


def _drop_speed_cap(mac: str, db: Session) -> None:
    try:
        from clarinet.app_settings import get_setting
        from clarinet.enforcer.tc_wrapper import remove_rate_limit
        iface = get_setting(db, "guest.interface", get_setting(db, "network_interface", ""))
        if iface:
            remove_rate_limit(iface, mac)
    except Exception:
        pass


def _close_active_voucher(voucher: Voucher, db: Session) -> None:
    """Helper: close nft access and remove enforcement for an active voucher."""
    try:
        from clarinet.models.guest import EnforcementStatus
        from clarinet.enforcer.nft_wrapper import close_guest_access
        from clarinet.models import Device

        records = (
            db.query(EnforcementStatus)
            .filter(EnforcementStatus.voucher_id == voucher.voucher_id)
            .all()
        )
        for record in records:
            close_guest_access(record.mac)
            _drop_speed_cap(record.mac, db)
            device = db.query(Device).filter(Device.mac_address == record.mac).first()
            if device and device.state == "GUEST":
                db.delete(device)
            db.delete(record)
    except Exception:
        pass


# ──────────────────────────────────────────────
# JSON summary (contract C-09)
# ──────────────────────────────────────────────

@router.get("/api/guest/summary")
def guest_summary(request: Request, db: Session = Depends(get_db)):
    from clarinet.auth import require_admin as _ra
    result = _ra(request, db)
    if isinstance(result, RedirectResponse):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if not isinstance(result, object) or not hasattr(result, "is_admin"):
        return JSONResponse({"error": "Forbidden"}, status_code=403)

    now = datetime.utcnow()  # naive UTC — matches SQLite storage
    active = db.query(Voucher).filter(Voucher.status == "ACTIVE").count()
    unused = db.query(Voucher).filter(Voucher.status == "UNUSED", Voucher.expires_at > now).count()
    total = db.query(Voucher).count()

    return JSONResponse({
        "active_sessions": active,
        "unused_vouchers": unused,
        "total_vouchers": total,
        "available": True,
    })
