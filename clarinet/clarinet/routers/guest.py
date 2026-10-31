"""clarinet/routers/guest.py — guest portal and voucher management."""

import secrets
import string
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin, audit
from clarinet.database import get_db
from clarinet.models import Voucher

router = APIRouter(tags=["guest"])

# /guest  (public portal — no auth required)

@router.get("/guest", response_class=HTMLResponse)
def guest_portal(request: Request):
    return templates.TemplateResponse("guest/portal.html", {"request": request})


@router.post("/guest/redeem", response_class=HTMLResponse)
def redeem_voucher(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db),
):
    code = code.strip().upper()
    voucher = db.query(Voucher).filter(Voucher.code == code).first()
    now = datetime.now(timezone.utc)

    if voucher is None:
        return templates.TemplateResponse("guest/portal.html", {
            "request": request,
            "error": "Invalid voucher code.",
        })
    if voucher.status != "UNUSED":
        return templates.TemplateResponse("guest/portal.html", {
            "request": request,
            "error": f"Voucher is already {voucher.status.lower()}.",
        })
    if voucher.expires_at < now:
        voucher.status = "EXPIRED"
        db.commit()
        return templates.TemplateResponse("guest/portal.html", {
            "request": request,
            "error": "This voucher has expired.",
        })

    return templates.TemplateResponse("guest/success.html", {
        "request": request,
        "voucher": voucher,
    })


# /vouchers (admin management)

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
    })


@router.post("/vouchers/create")
def create_voucher(
    request: Request,
    expires_hours: int = Form(24),
    data_cap_mb: int | None = Form(None),
    speed_cap_mbps: float | None = Form(None),
    db: Session = Depends(get_db),
):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    # Generate a readable 8-character code (no ambiguous chars)
    alphabet = string.ascii_uppercase.replace("O", "").replace("I", "") + string.digits.replace("0", "")
    code = "".join(secrets.choice(alphabet) for _ in range(8))

    voucher = Voucher(
        code=code,
        created_by=user.member_id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=expires_hours),
        data_cap_mb=data_cap_mb,
        speed_cap_mbps=speed_cap_mbps,
        status="UNUSED",
    )
    db.add(voucher)
    db.flush()
    audit(db, user.member_id, "CREATE_VOUCHER", "Voucher", voucher.voucher_id,
          {"code": code, "expires_hours": expires_hours})
    return RedirectResponse(url="/vouchers", status_code=302)


@router.post("/vouchers/{voucher_id}/revoke")
def revoke_voucher(voucher_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    voucher = db.get(Voucher, voucher_id)
    if voucher and voucher.status in ("UNUSED", "ACTIVE"):
        voucher.status = "REVOKED"
        audit(db, user.member_id, "REVOKE_VOUCHER", "Voucher", voucher_id)
        db.commit()
    return RedirectResponse(url="/vouchers", status_code=302)
