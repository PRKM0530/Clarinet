"""
clarinet/routers/slowdowns.py  (M3 enhancement)
Slowdown event history, current diagnosis, and JSON summary endpoints.

Added (M3):
- /api/slowdowns/summary JSON (contract C-09)
- /api/slowdowns/status JSON (any logged-in user, words only)
- Advanced settings card on the slowdowns page
- F-15 fix: duration uses total_seconds() // 60, not .seconds // 60
- Removes "AI-powered" claim from template context
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin, require_login
from clarinet.database import get_db
from clarinet.models import SlowdownEvent

router = APIRouter(prefix="/slowdowns", tags=["slowdowns"])


@router.get("", response_class=HTMLResponse)
def slowdowns_page(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    from clarinet.app_settings import get_setting
    from clarinet.analytics.mode import get_mode

    mode = get_mode(db)

    events = (
        db.query(SlowdownEvent)
        .order_by(SlowdownEvent.started_at.desc())
        .limit(50)
        .all()
    )
    active = next((e for e in events if e.ended_at is None), None)

    parsed_events = []
    for e in events:
        try:
            causes = json.loads(e.causes_json or "[]")
        except Exception:
            causes = []
        try:
            raw = json.loads(e.raw_metrics_json or "{}")
        except Exception:
            raw = {}

        # F-15 fix: use total_seconds() // 60 for correct multi-hour durations
        duration_min = None
        if e.ended_at:
            ended = e.ended_at if e.ended_at.tzinfo else e.ended_at.replace(tzinfo=timezone.utc)
            started = e.started_at if e.started_at.tzinfo else e.started_at.replace(tzinfo=timezone.utc)
            duration_min = int((ended - started).total_seconds() // 60)

        parsed_events.append({
            "event": e,
            "causes": causes,
            "raw": raw,
            "duration_min": duration_min,
        })

    # Advanced settings values
    latency_mult = get_setting(db, "slowdown_latency_multiplier", "2.0")
    speed_thresh = get_setting(db, "slowdown_speed_threshold", "0.50")
    perf_wifi_iface = get_setting(db, "perf.wifi_iface", "")
    sec_monitor_iface = get_setting(db, "sec.monitor_iface", "")
    wifi_iface_effective = sec_monitor_iface or perf_wifi_iface

    return templates.TemplateResponse("slowdowns/index.html", {
        "request": request,
        "user": user,
        "page": "slowdowns",
        "events": parsed_events,
        "active": active,
        "mode": mode,
        # F-15 fix: removed "AI-powered" — replaced with "Rule-based" in template context
        "diagnosis_method": "Rule-based",
        "error": request.query_params.get("error"),
        "info": request.query_params.get("info"),
        # Advanced settings
        "latency_mult": latency_mult,
        "speed_thresh": speed_thresh,
        "wifi_iface": wifi_iface_effective,
    })


@router.post("/settings")
def save_settings(
    request: Request,
    latency_multiplier: float = Form(2.0),
    speed_threshold: float = Form(0.50),
    wifi_iface: str = Form(""),
    db: Session = Depends(get_db),
):
    """Admin can tune slowdown thresholds from the Slowdowns page (shared §A.4)."""
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result

    from clarinet.app_settings import set_setting
    set_setting(db, "slowdown_latency_multiplier", str(max(1.0, min(latency_multiplier, 10.0))))
    set_setting(db, "slowdown_speed_threshold", str(max(0.1, min(speed_threshold, 1.0))))
    if wifi_iface:
        set_setting(db, "perf.wifi_iface", wifi_iface.strip())

    return RedirectResponse(url="/slowdowns?info=Settings+saved", status_code=302)


# ──────────────────────────────────────────────
# JSON API (contracts C-09, C-10)
# ──────────────────────────────────────────────

@router.get("/api/slowdowns/summary")
def slowdowns_summary(request: Request, db: Session = Depends(get_db)):
    """
    Admin-only JSON summary for M1 dashboard.
    Shape defined in analytics/summary_api.py build_summary().
    """
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    from clarinet.analytics.summary_api import build_summary
    return JSONResponse(build_summary(db))


@router.get("/api/slowdowns/status")
def slowdowns_status(request: Request, db: Session = Depends(get_db)):
    """
    Any logged-in user. Returns words-only network status.
    Used by topbar and member overview.
    """
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    from clarinet.analytics.summary_api import build_status
    return JSONResponse(build_status(db))
