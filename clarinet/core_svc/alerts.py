"""
clarinet/core_svc/alerts.py
M1 alert service — C-01 contract implementation.

Public API (C-01):
  raise_alert(db, level, type, title, message, device_id=None,
              dedupe_key=None, cooldown_s=3600) -> Alert | None

  resolve_alert(db, type, device_id=None) -> int  (count resolved)

All alert creation goes through raise_alert so that:
  - Duplicate alerts within the cooldown window are suppressed
  - WebSocket push is attempted (never raises on failure)
  - Consistent commit discipline is maintained
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from clarinet.models import Alert

if TYPE_CHECKING:
    pass

log = logging.getLogger("clarinet.core_svc.alerts")

_DEFAULT_COOLDOWN = 3600  # 1 hour


def raise_alert(
    db: Session,
    level: str,
    type: str,
    title: str,
    message: str,
    device_id: int | None = None,
    dedupe_key: str | None = None,
    cooldown_s: int = _DEFAULT_COOLDOWN,
) -> "Alert | None":
    """
    Create a new Alert, respecting deduplication.

    If an OPEN alert of the same `type` (and `device_id` if given) was raised
    within the last `cooldown_s` seconds, the new alert is suppressed and None
    is returned.

    On success: commits, broadcasts via WebSocket (best-effort), returns Alert.

    (C-01 contract)
    """
    # ── Deduplication check ────────────────────────────────────────────────────
    cutoff = datetime.utcnow() - timedelta(seconds=cooldown_s)
    q = db.query(Alert).filter(
        Alert.type == type,
        Alert.status == "OPEN",
        Alert.raised_at >= cutoff,
    )
    if device_id is not None:
        q = q.filter(Alert.device_id == device_id)
    if dedupe_key is not None:
        # Prefer dedupe by key if given — stored in title for now (simple impl)
        q = q.filter(Alert.title == title)

    if q.first() is not None:
        log.debug("Alert suppressed (cooldown): type=%s device_id=%s", type, device_id)
        return None

    # ── Create alert ──────────────────────────────────────────────────────────
    alert = Alert(
        level=level.upper(),
        type=type.upper(),
        title=title,
        message=message,
        device_id=device_id,
        status="OPEN",
        raised_at=datetime.utcnow(),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    log.info("Alert raised: [%s] %s — %s", level, type, title)

    # ── WebSocket push (best-effort) ──────────────────────────────────────────
    try:
        from clarinet.routers.ws import broadcast_alert_sync
        broadcast_alert_sync({
            "type": alert.type,
            "level": alert.level,
            "title": alert.title,
            "message": alert.message,
            "alert_id": alert.alert_id,
            "device_id": alert.device_id,
            "raised_at": alert.raised_at.isoformat(),
        })
    except Exception as exc:
        log.debug("WS broadcast failed (non-fatal): %s", exc)

    return alert


def resolve_alert(
    db: Session,
    type: str,
    device_id: int | None = None,
) -> int:
    """
    Mark all OPEN alerts of the given type (and device_id) as RESOLVED.
    Returns the count of alerts resolved.
    """
    q = db.query(Alert).filter(
        Alert.type == type,
        Alert.status == "OPEN",
    )
    if device_id is not None:
        q = q.filter(Alert.device_id == device_id)

    count = 0
    for alert in q.all():
        alert.status = "RESOLVED"
        count += 1

    if count:
        db.commit()
        log.info("Resolved %d alert(s) of type %s", count, type)

    return count


def ack_alert(db: Session, alert_id: int, actor_id: int | None = None) -> bool:
    """Acknowledge a single alert by ID. Returns True if found."""
    alert = db.get(Alert, alert_id)
    if alert is None or alert.status != "OPEN":
        return False
    alert.status = "ACK"
    db.commit()
    return True


def resolve_alert_by_id(db: Session, alert_id: int) -> bool:
    """Resolve a single alert by ID. Returns True if found."""
    alert = db.get(Alert, alert_id)
    if alert is None or alert.status == "RESOLVED":
        return False
    alert.status = "RESOLVED"
    db.commit()
    return True

