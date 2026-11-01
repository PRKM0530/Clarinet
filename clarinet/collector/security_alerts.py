"""
clarinet/collector/security_alerts.py
One place for the security checks to raise alerts.

Scans repeat every few minutes, so raise() skips an alert if an identical one
(same type and title) is already open or was raised recently.
"""

import logging
from datetime import datetime, timedelta, timezone

log = logging.getLogger("clarinet.security.alerts")

DEDUPE_MINUTES = 60


def raise_alert(
    alert_type: str,
    level: str,
    title: str,
    message: str,
    device_id: int | None = None,
    extra: dict | None = None,
    db=None,
) -> bool:
    """
    Create an Alert and push it to connected dashboards.
    Returns False when it was skipped as a duplicate.
    Pass `db` to reuse a session; otherwise a short-lived one is used.
    """
    from clarinet.database import SessionLocal
    from clarinet.models import Alert

    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        since = datetime.now(timezone.utc) - timedelta(minutes=DEDUPE_MINUTES)
        duplicate = (
            db.query(Alert)
            .filter(Alert.type == alert_type, Alert.title == title, Alert.raised_at >= since)
            .first()
        )
        if duplicate is not None:
            return False

        alert = Alert(
            level=level, type=alert_type, title=title, message=message, device_id=device_id,
        )
        db.add(alert)
        db.commit()

        try:
            from clarinet.routers.ws import broadcast_alert_sync
            broadcast_alert_sync({
                "type": alert_type, "level": level, "title": title, "message": message,
                **(extra or {}),
            })
        except Exception as e:
            log.debug("Alert broadcast skipped: %s", e)
        log.warning("%s: %s", alert_type, title)
        return True
    finally:
        if own_session:
            db.close()
