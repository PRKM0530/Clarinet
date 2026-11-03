"""
clarinet/core_svc/heartbeat.py
Each collector job calls beat() after a successful cycle. The watchdog job raises an alert when a
collector has been silent for more than twice its expected interval.
"""
import logging
from datetime import datetime

log = logging.getLogger("clarinet.core_svc.heartbeat")


def beat(collector: str, interval_s: int) -> None:
    """Record that `collector` just finished a cycle. Never raises."""
    try:
        from clarinet.database import SessionLocal
        from clarinet.models.traffic import CollectorHeartbeat
        with SessionLocal() as db:
            row = db.query(CollectorHeartbeat).filter(CollectorHeartbeat.collector == collector).first()
            now = datetime.utcnow()                      # the watchdog compares with utcnow()
            if row is None:
                db.add(CollectorHeartbeat(collector=collector, last_seen=now, interval_s=interval_s, ok=True))
            else:
                row.last_seen, row.interval_s, row.ok = now, interval_s, True
            db.commit()
    except Exception as exc:
        log.debug("heartbeat for %s failed: %s", collector, exc)
