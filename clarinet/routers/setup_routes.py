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


# GET /setup

@router.get("", response_class=HTMLResponse)
def wizard_page(request: Request, db: Session = Depends(get_db)):
    if _setup_done(db):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("setup/wizard.html", {
        "request": request,
        "step": 1,
        "error": None,
    })


# POST /setup/admin

@router.post("/admin", response_class=HTMLResponse)
def wizard_create_admin(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    network_mode: str = Form("MONITOR"),
    plan_download: float = Form(100.0),
    plan_upload: float = Form(20.0),
    billing_day: int = Form(1),
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
    if network_mode not in ("FULL", "MONITOR", "PUBLIC"):
        errors.append("Invalid network mode.")
    if not (1 <= billing_day <= 28):
        errors.append("Billing day must be between 1 and 28.")

    # Check username isn't taken
    existing = db.query(Member).filter(Member.username == username).first()
    if existing:
        errors.append(f"Username '{username}' is already taken.")

    if errors:
        return templates.TemplateResponse("setup/wizard.html", {
            "request": request,
            "step": 1,
            "error": " ".join(errors),
            "form": {
                "username": username,
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
    _set(db, "plan_download_mbps", str(plan_download))
    _set(db, "plan_upload_mbps", str(plan_upload))
    _set(db, "billing_day", str(billing_day))
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
