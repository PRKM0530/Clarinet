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
from clarinet.core_svc.localtime import local_today

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
        from clarinet.models import UsageRecord
        cutoff = (local_today() - timedelta(days=days)).isoformat()
        count = db.query(UsageRecord).filter(UsageRecord.date < cutoff).delete()
        db.commit()
        log.debug("Purged %d old usage records", count)
        return count
    except Exception as exc:
        log.warning("purge_old_usage failed: %s", exc)
        db.rollback()
        return 0


def purge_old_domains(db: Session, days: int = 7) -> int:
    """Delete domain-level detail older than `days`. The per-activity totals stay."""
    from datetime import datetime, timedelta
    from clarinet.models.traffic import DomainObservation

    cutoff = datetime.utcnow() - timedelta(days=days)
    count = db.query(DomainObservation).filter(DomainObservation.observed_at < cutoff).delete()
    db.commit()
    return count


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


# Tables that are configuration or accountability, not collected network data.
KEEP_TABLES = {
    "member", "settings", "audit_log", "login_attempt", "setup_progress",
    "trusted_access_point", "known_network", "active_session", "admin_request",       # logins survive a data purge
}


def purge_all_data(db: Session) -> dict[str, int]:
    """
    Delete all collected network data: devices, usage, alerts, history, speed
    tests, latency, slowdowns, rules, vouchers, security observations.
    Keeps member accounts, settings, the audit log and the trusted access
    point / known network decisions.

    Works from the table metadata, children first, so tables added later are
    covered and foreign keys are never violated.
    Returns the number of rows deleted per table (only tables that had rows).
    """
    from clarinet.database import Base
    import clarinet.models  # noqa: F401  (make sure every table is registered)

    counts: dict[str, int] = {}
    for table in reversed(Base.metadata.sorted_tables):
        if table.name in KEEP_TABLES:
            continue
        deleted = db.execute(table.delete()).rowcount or 0
        if deleted:
            counts[table.name] = deleted

    db.commit()
    log.warning("All stored data deleted: %s", counts)
    return counts
