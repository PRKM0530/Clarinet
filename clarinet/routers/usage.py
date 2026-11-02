"""
clarinet/routers/usage.py
Traffic usage routes for M1.

Routes:
  GET /usage              — usage overview (period selector)
  GET /usage/device/{id}  — per-device usage breakdown
  GET /api/usage/summary  — JSON summary for a period
  GET /api/limit/summary  — C-07: data limit summary
  GET /export/usage.csv   — CSV export
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_login
from clarinet.database import get_db

router = APIRouter(tags=["usage"])


@router.get("/usage", response_class=HTMLResponse)
def usage_page(request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    period = _clean_period(request.query_params.get("period", "week"))
    from clarinet.core_svc.usage_service import usage_for
    from clarinet.core_svc.settings_m1 import billing_day
    bday = billing_day(db)
    usage = usage_for(db, user, period, billing_day=bday)

    return templates.TemplateResponse("usage/index.html", {
        "request": request,
        "user": user,
        "page": "usage",
        "period": period,
        "usage": usage,
        "device": None,
        "device_rows": _device_rows(db, usage),
        "by_day_json": _json_safe(usage.by_day),
        "by_hour_json": _json_safe(usage.by_hour),
    })


@router.get("/usage/device/{device_id}", response_class=HTMLResponse)
def usage_device(device_id: int, request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.core_svc.permissions import can_view_device
    from clarinet.models import Device
    if not can_view_device(db, user, device_id):
        return RedirectResponse(url="/usage?error=forbidden", status_code=302)

    device = db.get(Device, device_id)
    if device is None:
        return RedirectResponse(url="/usage?error=not_found", status_code=302)

    period = _clean_period(request.query_params.get("period", "week"))
    from clarinet.core_svc.usage_service import usage_for
    from clarinet.core_svc.settings_m1 import billing_day
    bday = billing_day(db)
    usage = usage_for(db, user, period, device_id=device_id, billing_day=bday)

    return templates.TemplateResponse("usage/index.html", {
        "request": request,
        "user": user,
        "page": "usage",
        "period": period,
        "usage": usage,
        "device": device,
        "device_rows": _device_rows(db, usage),
        "by_day_json": _json_safe(usage.by_day),
        "by_hour_json": _json_safe(usage.by_hour),
    })


@router.get("/api/usage/summary")
def api_usage_summary(request: Request, db: Session = Depends(get_db)):
    from clarinet.auth import get_session_user
    user = get_session_user(request, db)
    if user is None:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)

    period = _clean_period(request.query_params.get("period", "week"))
    device_id = request.query_params.get("device_id")
    did = int(device_id) if device_id and device_id.isdigit() else None

    from clarinet.core_svc.usage_service import usage_for
    from clarinet.core_svc.settings_m1 import billing_day
    bday = billing_day(db)
    usage = usage_for(db, user, period, device_id=did, billing_day=bday)

    return {
        "period": period,
        "period_start": usage.period_start,
        "period_end": usage.period_end,
        "total_mb": usage.total_mb,
        "total_gb": usage.total_gb,
        "bytes_in": usage.bytes_in,
        "bytes_out": usage.bytes_out,
        "by_day": usage.by_day,
        "by_hour": usage.by_hour,
    }


@router.get("/api/limit/summary")
def api_limit_summary(request: Request, db: Session = Depends(get_db)):
    """
    C-07: Data limit summary for the current billing period.
    """
    from clarinet.auth import get_session_user
    user = get_session_user(request, db)
    if user is None:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)

    from clarinet.core_svc.limit_service import get_limit_summary
    try:
        s = get_limit_summary(db)
        return {
            "bytes_used": s.bytes_used,
            "bytes_limit": s.bytes_limit,
            "projected_bytes": s.projected_bytes,
            "status": s.status,
            "period_start": s.period_start,
            "period_end": s.period_end,
            "days_remaining": s.days_remaining,
            "pct_used": s.pct_used,
            "mb_used": s.mb_used,
            "gb_used": s.gb_used,
        }
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/export/usage.csv")
def export_usage_csv(request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    period = _clean_period(request.query_params.get("period", "month"))
    from clarinet.core_svc.usage_service import usage_for
    from clarinet.core_svc.settings_m1 import billing_day
    from clarinet.core_svc.exporter import rows_to_csv
    from clarinet.models import UsageRecord

    bday = billing_day(db)
    usage = usage_for(db, user, period, billing_day=bday)

    from clarinet.core_svc.permissions import member_device_ids
    allowed_ids = member_device_ids(db, user)

    records = (
        db.query(UsageRecord)
        .filter(
            UsageRecord.device_id.in_(allowed_ids),
            UsageRecord.date >= usage.period_start,
            UsageRecord.date <= usage.period_end,
        )
        .order_by(UsageRecord.date, UsageRecord.device_id, UsageRecord.hour)
        .all()
    )

    from clarinet.core_svc.exporter import usage_to_csv
    csv_data = usage_to_csv(records)

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="usage_{period}.csv"'},
    )


def _json_safe(d: dict) -> str:
    import json
    return json.dumps({str(k): v for k, v in d.items()})


def _clean_period(period: str) -> str:
    """Accept only a known period keyword or a real YYYY-MM-DD date; anything else means "week"."""
    from datetime import date
    if period in ("today", "week", "month", "billing"):
        return period
    try:
        date.fromisoformat(period)
        return period
    except ValueError:
        return "week"


def _device_rows(db, usage) -> list[dict]:
    """Per-device totals for the table, biggest first. Only devices the usage result already covers."""
    from clarinet.models import Device
    if not usage.by_device:
        return []
    devices = {d.device_id: d for d in db.query(Device).filter(Device.device_id.in_(list(usage.by_device)))}
    rows = [
        {"device": devices[i], "bytes_in": bi, "bytes_out": bo, "total": bi + bo}
        for i, (bi, bo) in usage.by_device.items() if i in devices
    ]
    return sorted(rows, key=lambda r: r["total"], reverse=True)
