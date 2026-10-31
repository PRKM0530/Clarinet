"""clarinet/routers/speed.py — speed-test results and ISP plan view (admin only)."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin
from clarinet.database import get_db
from clarinet.models import SpeedTestResult, Settings as AppSettings

router = APIRouter(prefix="/speed", tags=["speed"])


@router.get("", response_class=HTMLResponse)
def speed_page(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    results = (
        db.query(SpeedTestResult)
        .order_by(SpeedTestResult.tested_at.desc())
        .limit(100)
        .all()
    )

    plan_dl = db.get(AppSettings, "plan_download_mbps")
    plan_ul = db.get(AppSettings, "plan_upload_mbps")
    plan_download = float(plan_dl.value) if plan_dl else 100.0
    plan_upload = float(plan_ul.value) if plan_ul else 20.0

    # Latest result for the summary card
    latest = results[0] if results else None

    # Chart data: timestamps + speeds
    chart_labels = [r.tested_at.strftime("%d %b %H:%M") for r in reversed(results[:30])]
    chart_dl = [r.download_mbps for r in reversed(results[:30])]
    chart_ul = [r.upload_mbps for r in reversed(results[:30])]
    chart_lat = [r.latency_ms for r in reversed(results[:30])]

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
    })


@router.post("/run")
def trigger_speed_test(request: Request, db: Session = Depends(get_db)):
    """Manually trigger a speed test (runs in background thread)."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result

    from clarinet.collector.speed_test import run_speed_test_async
    run_speed_test_async()
    return RedirectResponse(url="/speed?info=speed_test_started", status_code=302)
