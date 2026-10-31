"""clarinet/routers/slowdowns.py — slowdown event history and current diagnosis."""

import json
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import require_admin
from clarinet.database import get_db
from clarinet.models import SlowdownEvent

router = APIRouter(prefix="/slowdowns", tags=["slowdowns"])


@router.get("", response_class=HTMLResponse)
def slowdowns_page(request: Request, db: Session = Depends(get_db)):
    result = require_admin(request, db)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    events = (
        db.query(SlowdownEvent)
        .order_by(SlowdownEvent.started_at.desc())
        .limit(50)
        .all()
    )

    # Active event (no ended_at)
    active = next((e for e in events if e.ended_at is None), None)

    # Parse JSON causes for template use
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
        parsed_events.append({"event": e, "causes": causes, "raw": raw})

    return templates.TemplateResponse("slowdowns/index.html", {
        "request": request,
        "user": user,
        "page": "slowdowns",
        "events": parsed_events,
        "active": active,
    })
