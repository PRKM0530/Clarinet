"""
clarinet/routers/setup_routes.py
First-run setup wizard (admin only, shown before any login).

Steps:
  1. Welcome + network mode selection
  2. Create admin account (username + password)
  3. ISP plan details (download/upload speed, billing day)
  4. Done → redirect to login
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import hash_password, audit
from clarinet.database import get_db
from clarinet.models import Member, Settings as AppSettings

router = APIRouter(prefix="/setup", tags=["setup"])


def _setup_done(db: Session) -> bool:
    row = db.get(AppSettings, "setup_complete")
    return row is not None and row.value == "true"


def _set(db: Session, key: str, value: str) -> None:
    row = db.get(AppSettings, key)
    if row:
        row.value = value
    else:
        db.add(AppSettings(key=key, value=value))


def _wizard_extras() -> dict:
    """What the wizard needs: the time zones, and the time zone this computer is in.
    The network connection and the router are found automatically, so they are not asked for."""
    from clarinet.core_svc.localtime import common_zones, machine_zone
    return {"zones": common_zones(), "machine_zone": machine_zone()}


# GET /setup

@router.get("", response_class=HTMLResponse)
def wizard_page(request: Request, db: Session = Depends(get_db)):
    if _setup_done(db):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("setup/wizard.html", {
        "request": request,
        "step": 1,
        "error": None,
        **_wizard_extras(),
    })


# POST /setup/admin

@router.post("/admin", response_class=HTMLResponse)
def wizard_create_admin(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    network_mode: str = Form("MONITOR"),
    hold_new_devices: list[str] = Form([]),
    plan_download: float = Form(100.0),
    plan_upload: float = Form(20.0),
    billing_day: int = Form(1),
    monthly_limit_gb: str = Form(""),
    network_interface: str = Form(""),
    router_ip: str = Form(""),
    timezone: str = Form(""),
    consent: str = Form(""),
    db: Session = Depends(get_db),
):
    if _setup_done(db):
        return RedirectResponse(url="/login", status_code=302)

    errors = []

    # Validation
    if len(username) < 3:
        errors.append("Username must be at least 3 characters.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if password != password_confirm:
        errors.append("Passwords do not match.")
    if network_mode not in ("FULL", "MONITOR"):
        errors.append("Invalid network mode.")
    if not (1 <= billing_day <= 28):
        errors.append("Billing day must be between 1 and 28.")
    if not (0 < plan_download <= 100_000) or not (0 < plan_upload <= 100_000):      # also rejects NaN
        errors.append("Plan speeds must be numbers above zero.")

    # NFR-21: the administrator confirms they are allowed to monitor this network
    if consent != "yes":
        errors.append("Please confirm that you are allowed to monitor this network.")

    from clarinet.core_svc import netinfo
    from clarinet.core_svc.localtime import machine_zone, valid_zone
    import ipaddress
    network_interface, router_ip, timezone = network_interface.strip(), router_ip.strip(), timezone.strip() or machine_zone()
    if network_interface and not netinfo.interface_name_ok(network_interface):
        errors.append("That network interface name is not valid.")
    if router_ip:
        try:
            ipaddress.ip_address(router_ip)
        except ValueError:
            errors.append("The router address must be an IP address such as 192.168.1.1, or left empty.")
    if not valid_zone(timezone):
        timezone = machine_zone()          # found automatically; the browser normally supplies the real one

    limit_bytes = ""
    if monthly_limit_gb.strip():
        try:
            gb = float(monthly_limit_gb)
        except ValueError:
            gb = -1
        if not (0 < gb <= 1_000_000):
            errors.append("Monthly data limit must be a positive number of GB, or empty for no limit.")
        else:
            limit_bytes = str(int(gb * 1_073_741_824))

    # Check username isn't taken
    existing = db.query(Member).filter(Member.username == username).first()
    if existing:
        errors.append(f"Username '{username}' is already taken.")

    if errors:
        return templates.TemplateResponse("setup/wizard.html", {
            "request": request,
            "step": 1,
            "error": " ".join(errors),
            **_wizard_extras(),
            "form": {
                "username": username,
                "network_interface": network_interface,
                "router_ip": router_ip,
                "timezone": timezone,
                "network_mode": network_mode,
                "plan_download": plan_download,
                "plan_upload": plan_upload,
                "billing_day": billing_day,
            }
        }, status_code=422)

    # Create admin member
    admin = Member(
        username=username,
        password_hash=hash_password(password),
        role="ADMIN",
        is_active=True,
    )
    db.add(admin)
    db.flush()  # get member_id

    # Persist settings
    _set(db, "network_mode", network_mode)
    _set(db, "hold_new_devices", "true" if "true" in hold_new_devices and network_mode == "FULL" else "false")
    _set(db, "plan_download_mbps", str(plan_download))
    _set(db, "plan_upload_mbps", str(plan_upload))
    _set(db, "billing_day", str(billing_day))
    if network_interface:
        _set(db, "network_interface", network_interface)
    _set(db, "router_ip", router_ip)
    _set(db, "timezone", timezone)
    if limit_bytes:
        _set(db, "limit.bytes", limit_bytes)
    _set(db, "setup_complete", "true")
    db.commit()

    audit(db, admin.member_id, "SETUP_COMPLETE", detail={
        "network_mode": network_mode,
        "plan_download_mbps": plan_download,
    })

    return templates.TemplateResponse("setup/done.html", {
        "request": request,
        "username": username,
    })
