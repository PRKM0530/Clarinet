"""
clarinet/collector/security_alerts.py
How the security checks raise alerts.

A thin wrapper over core_svc.alerts.raise_alert, so security alerts follow the
same rules as every other alert (commit, WebSocket push, duplicate suppression).
Scans repeat every few minutes, so the title is used as the duplicate key: the
same alert is not raised again while one is still open within the cooldown.
"""

import logging

log = logging.getLogger("clarinet.security.alerts")

COOLDOWN_SECONDS = 3600


def raise_alert(
    alert_type: str,
    level: str,
    title: str,
    message: str,
    device_id: int | None = None,
    extra: dict | None = None,   # kept so callers can describe the alert; not stored
    db=None,
) -> bool:
    """
    Raise a security alert. Returns False when it was skipped as a duplicate.
    Pass `db` to reuse a session; otherwise a short-lived one is used.
    """
    from clarinet.core_svc.alerts import raise_alert as core_raise_alert
    from clarinet.database import SessionLocal

    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        alert = core_raise_alert(
            db, level, alert_type, title, message,
            device_id=device_id, dedupe_key=title, cooldown_s=COOLDOWN_SECONDS,
        )
        return alert is not None
    finally:
        if own_session:
            db.close()
