"""clarinet/routers/usage.py — per-device usage dashboard (admin + member)."""

from datetime import date, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_login
from clarinet.database import get_db
from clarinet.models import Device, UsageRecord

router = APIRouter(prefix="/usage", tags=["usage"])


@router.get("", response_class=HTMLResponse)
def usage_page(request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    # Last 7 days of daily totals per device
    since = (date.today() - timedelta(days=6)).isoformat()

    if user.is_admin:
        # Admin sees all devices
        records = (
            db.query(
                Device.device_id,
                Device.mac_address,
                Device.label,
                Device.hostname,
                UsageRecord.date,
                func.sum(UsageRecord.bytes_in).label("bytes_in"),
                func.sum(UsageRecord.bytes_out).label("bytes_out"),
            )
            .join(UsageRecord, Device.device_id == UsageRecord.device_id)
            .filter(UsageRecord.date >= since)
            .group_by(Device.device_id, UsageRecord.date)
            .order_by(UsageRecord.date, (func.sum(UsageRecord.bytes_in) + func.sum(UsageRecord.bytes_out)).desc())
            .all()
        )
    else:
        # Member sees only their own devices
        records = (
            db.query(
                Device.device_id,
                Device.mac_address,
                Device.label,
                Device.hostname,
                UsageRecord.date,
                func.sum(UsageRecord.bytes_in).label("bytes_in"),
                func.sum(UsageRecord.bytes_out).label("bytes_out"),
            )
            .join(UsageRecord, Device.device_id == UsageRecord.device_id)
            .filter(UsageRecord.date >= since, Device.owner_member_id == user.member_id)
            .group_by(Device.device_id, UsageRecord.date)
            .order_by(UsageRecord.date)
            .all()
        )

    # Build chart-friendly structure: { "mac_or_label": { "date": bytes_total } }
    chart_data: dict[str, dict[str, int]] = {}
    for r in records:
        name = r.label or r.hostname or r.mac_address
        chart_data.setdefault(name, {})[r.date] = (r.bytes_in or 0) + (r.bytes_out or 0)

    # Date labels for last 7 days
    date_labels = [(date.today() - timedelta(days=i)).isoformat() for i in range(6, -1, -1)]

    return templates.TemplateResponse("usage/index.html", {
        "request": request,
        "user": user,
        "page": "usage",
        "records": records,
        "chart_data": chart_data,
        "date_labels": date_labels,
    })
