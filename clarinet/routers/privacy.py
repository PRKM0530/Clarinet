"""
clarinet/routers/privacy.py
SYS-8: a public page that says what Clarinet collects, how long it is kept, and
that nothing leaves the network. Public on purpose: the people being monitored
should be able to read it without an account.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from clarinet import templates
from clarinet.auth import get_session_user
from clarinet.core_svc.settings_m1 import (
    retention_login_attempts_days, retention_samples_hours, retention_traffic_days,
)
from clarinet.database import get_db

router = APIRouter(tags=["privacy"])


@router.get("/privacy", response_class=HTMLResponse)
def privacy_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("privacy/index.html", {
        "request": request,
        "user": get_session_user(request, db),
        "traffic_days": retention_traffic_days(db),
        "sample_hours": retention_samples_hours(db),
        "login_days": retention_login_attempts_days(db),
    })
