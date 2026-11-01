"""
clarinet/core_svc/purge.py
Data purge / retention enforcement for M1.

Operations:
  purge_old_samples(db)        — delete TrafficSample older than retention window
  purge_old_login_attempts(db) — delete LoginAttempt older than 30 days
  purge_old_usage(db)          — delete UsageRecord older than retention_traffic_days
  purge_device(db, device_id)  — delete a device and all its data (cascades)
  purge_all_data(db)           — factory reset (keeps Members and Settings)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

log = logging.getLogger("clarinet.core_svc.purge")


def purge_old_samples(db: Session, hours: int = 24) -> int:
    """Delete TrafficSample rows older than `hours` hours."""
    try:
        from clarinet.models.traffic import TrafficSample
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        count = db.query(TrafficSample).filter(TrafficSample.sampled_at < cutoff).delete()
        db.commit()
        log.debug("Purged %d old traffic samples", count)
        return count
    except Exception as exc:
        log.warning("purge_old_samples failed: %s", exc)
        db.rollback()
        return 0


def purge_old_login_attempts(db: Session, days: int = 30) -> int:
    """Delete LoginAttempt rows older than `days` days."""
    try:
        from clarinet.models.reports import LoginAttempt
        cutoff = datetime.utcnow() - timedelta(days=days)
        count = db.query(LoginAttempt).filter(LoginAttempt.attempted_at < cutoff).delete()
        db.commit()
        log.debug("Purged %d old login attempts", count)
        return count
    except Exception as exc:
        log.warning("purge_old_login_attempts failed: %s", exc)
        db.rollback()
        return 0


def purge_old_usage(db: Session, days: int = 90) -> int:
    """Delete UsageRecord rows older than `days` days."""
    try:
        from datetime import date
        from clarinet.models import UsageRecord
        cutoff = (date.today() - timedelta(days=days)).isoformat()
        count = db.query(UsageRecord).filter(UsageRecord.date < cutoff).delete()
        db.commit()
        log.debug("Purged %d old usage records", count)
        return count
    except Exception as exc:
        log.warning("purge_old_usage failed: %s", exc)
        db.rollback()
        return 0


def purge_device(db: Session, device_id: int) -> bool:
    """
    Delete a device and all its dependent data.
    SQLAlchemy cascade handles UsageRecord, DeviceHistory, Alert etc.
    Returns True if the device existed and was deleted.
    """
    from clarinet.models import Device
    device = db.get(Device, device_id)
    if device is None:
        return False
    db.delete(device)
    db.commit()
    log.info("Deleted device_id=%d", device_id)
    return True


def purge_all_data(db: Session) -> dict[str, int]:
    """
    Factory reset: delete all network data (devices, usage, alerts, history).
    Keeps: Member accounts, Settings, AuditLog.
    Returns counts of deleted rows per table.
    """
    from clarinet.models import Alert, Device, DeviceHistory, UsageRecord

    counts: dict[str, int] = {}

    counts["usage_records"] = db.query(UsageRecord).delete()
    counts["alerts"] = db.query(Alert).delete()
    counts["device_history"] = db.query(DeviceHistory).delete()
    counts["devices"] = db.query(Device).delete()

    db.commit()
    log.warning("Factory reset executed: %s", counts)
    return counts
