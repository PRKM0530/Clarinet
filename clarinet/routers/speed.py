"""
clarinet/routers/speed.py  (M2 enhancement)
Speed-test results, ISP plan view, and API summary.

Added (M2):
- /api/speed/summary JSON (contract C-09)
- /speed/export.csv speed test CSV export
- Mode-aware display (MONITOR shows "approximate" note, PUBLIC shows unavailable)
- Manual trigger returns JSON status
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin
from clarinet.database import get_db
from clarinet.models import SpeedTestResult

router = APIRouter(prefix="/speed", tags=["speed"])


@router.get("", response_class=HTMLResponse)
def speed_page(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.app_settings import get_setting
    from clarinet.enforcer.mode import get_mode

    mode = get_mode(db)
    plan_download = float(get_setting(db, "plan_download_mbps", "0") or 0)
    plan_upload = float(get_setting(db, "plan_upload_mbps", "0") or 0)

    results = (
        db.query(SpeedTestResult)
        .order_by(SpeedTestResult.tested_at.desc())
        .limit(100)
        .all()
    )
    latest = results[0] if results else None

    chart_labels = [r.tested_at.strftime("%d %b %H:%M") for r in reversed(results[:30])]
    chart_dl = [r.download_mbps for r in reversed(results[:30])]
    chart_ul = [r.upload_mbps for r in reversed(results[:30])]
    chart_lat = [r.latency_ms for r in reversed(results[:30])]

    from clarinet.collector.speed_test import is_running
    return templates.TemplateResponse("speed/index.html", {
        "request": request,
        "user": user,
        "page": "speed",
        "results": results,
        "latest": latest,
        "plan_download": plan_download,
        "plan_upload": plan_upload,
        "chart_labels": chart_labels,
        "chart_dl": chart_dl,
        "chart_ul": chart_ul,
        "chart_lat": chart_lat,
        "mode": mode,
        "test_running": is_running(),
        "error": request.query_params.get("error"),
        "info": request.query_params.get("info"),
    })


@router.post("/run")
def trigger_speed_test(request: Request, db: Session = Depends(get_db)):
    """Manually trigger a speed test (runs in background thread)."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result

    from clarinet.enforcer.mode import get_mode
    if get_mode(db) == "PUBLIC":
        return RedirectResponse(url="/speed?error=Speed+test+unavailable+in+client+mode", status_code=302)

    from clarinet.collector.speed_test import run_speed_test_async, is_running
    if is_running():
        return RedirectResponse(url="/speed?info=Speed+test+already+running", status_code=302)

    run_speed_test_async()
    return RedirectResponse(url="/speed?info=Speed+test+started", status_code=302)


@router.get("/export.csv")
def export_speed_csv(request: Request, db: Session = Depends(get_db)):
    """Export speed test results as CSV (admin only)."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result

    from clarinet.app_settings import get_setting
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(get_setting(db, "timezone", "Asia/Kolkata"))

    results = db.query(SpeedTestResult).order_by(SpeedTestResult.tested_at.asc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Time", "Download (Mbps)", "Upload (Mbps)", "Latency (ms)", "Busy", "Below Plan", "Server"])

    for r in results:
        local_time = r.tested_at.astimezone(tz).strftime("%Y-%m-%d %H:%M")
        writer.writerow([
            local_time,
            r.download_mbps,
            r.upload_mbps,
            r.latency_ms,
            "Yes" if r.busy else "No",
            "Yes" if r.below_plan else "No",
            r.server_host or "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.read()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=speed_tests.csv"},
    )


# ──────────────────────────────────────────────
# JSON summary (contract C-09)
# ──────────────────────────────────────────────

@router.get("/summary")
def speed_summary(request: Request, db: Session = Depends(get_db)):
    """
    JSON summary for the M1 dashboard card.
    Shape: {available, last_run_at, download_mbps, upload_mbps, latency_ms,
            below_plan, plan_download, plan_upload, mode}
    """
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    from clarinet.app_settings import get_setting
    from clarinet.enforcer.mode import get_mode

    mode = get_mode(db)
    if mode == "PUBLIC":
        return JSONResponse({"available": False, "reason": "Speed test unavailable in client mode"})

    plan_dl = float(get_setting(db, "plan_download_mbps", "0") or 0)
    plan_ul = float(get_setting(db, "plan_upload_mbps", "0") or 0)

    latest = (
        db.query(SpeedTestResult)
        .order_by(SpeedTestResult.tested_at.desc())
        .first()
    )

    if latest is None:
        return JSONResponse({
            "available": True,
            "last_run_at": None,
            "download_mbps": None,
            "upload_mbps": None,
            "latency_ms": None,
            "below_plan": False,
            "plan_download": plan_dl,
            "plan_upload": plan_ul,
            "mode": mode,
        })

    return JSONResponse({
        "available": True,
        "last_run_at": latest.tested_at.isoformat().replace("+00:00", "Z"),
        "download_mbps": latest.download_mbps,
        "upload_mbps": latest.upload_mbps,
        "latency_ms": latest.latency_ms,
        "below_plan": latest.below_plan,
        "plan_download": plan_dl,
        "plan_upload": plan_ul,
        "mode": mode,
    })


@router.get("/report", response_class=HTMLResponse)
def speed_report_page(request: Request, db: Session = Depends(get_db)):
    """Printable comparison of speed tests with the plan, to show the provider (UC-08)."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result

    from clarinet.core_svc.speed_report import build_speed_report
    try:
        days = int(request.query_params.get("days", "30"))
    except ValueError:
        days = 30
    days = days if days in (7, 30, 90) else 30

    return templates.TemplateResponse("speed/report.html", {
        "request": request,
        "user": result,
        "page": "speed",
        "report": build_speed_report(db, days),
        "generated": datetime.now(timezone.utc),
    })
