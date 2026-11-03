"""
clarinet/routers/reports.py
GET /reports  daily and weekly usage summaries (USE-3), for admins and members.
"""

from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_login
from clarinet.core_svc.reports import build_report
from clarinet.database import get_db

router = APIRouter(tags=["reports"])


def _parse_day(raw: str | None, fallback: date) -> date:
    """A valid YYYY-MM-DD date that is not in the future, otherwise the fallback."""
    try:
        day = date.fromisoformat(raw) if raw else fallback
    except ValueError:
        return fallback
    today = datetime.now(timezone.utc).date()
    oldest = today - timedelta(days=3650)          # ten years back is plenty; avoids date overflow
    return max(min(day, today), oldest)


@router.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, db: Session = Depends(get_db)):
    result = require_login(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    view = "day" if request.query_params.get("view") == "day" else "week"
    today = datetime.now(timezone.utc).date()
    end_day = _parse_day(request.query_params.get("date"), today - timedelta(days=1))
    step = 1 if view == "day" else 7

    report = build_report(db, user, view, end_day)
    older = end_day - timedelta(days=step)
    newer = end_day + timedelta(days=step)

    return templates.TemplateResponse("reports/index.html", {
        "request": request,
        "user": user,
        "page": "reports",
        "view": view,
        "report": report,
        "older_url": f"/reports?view={view}&date={older.isoformat()}",
        "newer_url": f"/reports?view={view}&date={newer.isoformat()}" if newer <= today else None,
    })
