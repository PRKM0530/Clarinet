"""
clarinet/analytics/summary_api.py
JSON summary endpoints and Python contract for M3.

Contracts (C-09, C-10):
  /api/slowdowns/summary  — JSON for M1 dashboard card
  /api/slowdowns/status   — one-word network status (any logged-in user)
  slowdowns_between(db, start, end) -> list[dict]  — M1 daily/weekly summaries
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

log = logging.getLogger("clarinet.analytics.summary_api")


def slowdowns_between(db, start: datetime, end: datetime) -> list[dict]:
    """
    Contract C-10: return SlowdownEvents in [start, end] as plain dicts.
    Used by M1's daily/weekly summaries.
    """
    from clarinet.models import SlowdownEvent
    import json

    events = (
        db.query(SlowdownEvent)
        .filter(SlowdownEvent.started_at >= start, SlowdownEvent.started_at < end)
        .order_by(SlowdownEvent.started_at.asc())
        .all()
    )

    result = []
    for e in events:
        try:
            causes = json.loads(e.causes_json or "[]")
        except Exception:
            causes = []
        top_cause = causes[0]["cause"] if causes else "NO_CLEAR_CAUSE"

        duration_s = None
        if e.ended_at:
            ended = e.ended_at if e.ended_at.tzinfo else e.ended_at.replace(tzinfo=timezone.utc)
            started = e.started_at if e.started_at.tzinfo else e.started_at.replace(tzinfo=timezone.utc)
            duration_s = (ended - started).total_seconds()

        result.append({
            "event_id": e.event_id,
            "started_at": e.started_at.isoformat().replace("+00:00", "Z"),
            "ended_at": e.ended_at.isoformat().replace("+00:00", "Z") if e.ended_at else None,
            "duration_s": duration_s,
            "top_cause": top_cause,
            "causes": causes,
        })
    return result


def build_summary(db) -> dict:
    """Build the /api/slowdowns/summary JSON payload."""
    from clarinet.models import SlowdownEvent, Alert
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    last_7d = now - timedelta(days=7)

    # Active event
    active = db.query(SlowdownEvent).filter(SlowdownEvent.ended_at.is_(None)).first()

    # Last 7-day count
    count_7d = (
        db.query(SlowdownEvent)
        .filter(SlowdownEvent.started_at >= last_7d)
        .count()
    )

    # Last event
    last_event = (
        db.query(SlowdownEvent)
        .order_by(SlowdownEvent.started_at.desc())
        .first()
    )

    # Open slowdown/outage alerts
    open_alerts = (
        db.query(Alert)
        .filter(Alert.type.in_(["SLOWDOWN", "INTERNET_OUTAGE"]), Alert.status == "OPEN")
        .count()
    )

    status = "good"
    if active:
        import json
        try:
            causes = json.loads(active.causes_json or "[]")
            top = causes[0]["cause"] if causes else ""
        except Exception:
            top = ""
        status = "problem" if top == "INTERNET_OUTAGE" else "slow"

    return {
        "available": True,
        "status": status,
        "active_event": {
            "event_id": active.event_id,
            "started_at": active.started_at.isoformat().replace("+00:00", "Z"),
        } if active else None,
        "events_last_7d": count_7d,
        "last_event_at": (
            last_event.started_at.isoformat().replace("+00:00", "Z")
            if last_event else None
        ),
        "open_alerts": open_alerts,
        "diagnose_url": "/slowdowns",
    }


def build_status(db) -> dict:
    """Build the /api/slowdowns/status JSON (any logged-in user — words only)."""
    from clarinet.models import SlowdownEvent

    active = db.query(SlowdownEvent).filter(SlowdownEvent.ended_at.is_(None)).first()
    if not active:
        return {"network": "good", "network_word": "Looking good"}

    import json
    try:
        causes = json.loads(active.causes_json or "[]")
        top = causes[0]["cause"] if causes else "NO_CLEAR_CAUSE"
    except Exception:
        top = "NO_CLEAR_CAUSE"

    if top == "INTERNET_OUTAGE":
        return {"network": "problem", "network_word": "Internet is down"}
    return {"network": "slow", "network_word": "Network is slow"}

