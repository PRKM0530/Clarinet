"""
clarinet/core_svc/summaries.py
Daily and weekly summary generation for M1.

Called by APScheduler daily_summary and weekly_summary jobs.
Lazily imports M3's slowdowns_between to avoid hard coupling.
"""

from __future__ import annotations
from clarinet.core_svc.localtime import local_today

import logging
from dataclasses import dataclass
from datetime import date, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

log = logging.getLogger("clarinet.core_svc.summaries")


@dataclass
class DailySummary:
    date: str
    total_bytes: int
    top_devices: list[dict]   # [{device_id, label, mac, bytes_total}]
    open_alerts: int
    new_devices: int
    slowdown_minutes: int
    period_limit_pct: float | None  # None if no limit set


@dataclass
class WeeklySummary:
    week_start: str
    week_end: str
    total_bytes: int
    daily_totals: dict[str, int]    # {"YYYY-MM-DD": bytes}
    top_devices: list[dict]
    slowdown_events: int
    avg_slowdown_minutes: float
    open_alerts: int


def _slowdown_minutes_for(db: Session, day_str: str) -> int:
    """Lazily import M3 and get total slowdown minutes for a given day."""
    try:
        from clarinet.analytics.summary_api import slowdowns_between
        start = day_str
        # "end" is next day start (exclusive)
        end = (date.fromisoformat(day_str) + timedelta(days=1)).isoformat()
        events = slowdowns_between(db, start, end)
        minutes = 0
        for ev in events:
            if ev.ended_at and ev.started_at:
                duration = (ev.ended_at - ev.started_at).total_seconds() / 60
                minutes += int(duration)
        return minutes
    except Exception as exc:
        log.debug("M3 slowdowns_between unavailable: %s", exc)
        return 0


def build_daily_summary(db: Session, target_date: date | None = None) -> DailySummary:
    """Generate a daily summary for `target_date` (default: yesterday)."""
    from clarinet.models import Alert, Device, UsageRecord

    if target_date is None:
        target_date = local_today() - timedelta(days=1)

    day_str = target_date.isoformat()

    # Total bytes
    total_bytes = (
        db.query(func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out))
        .filter(UsageRecord.date == day_str)
        .scalar()
    ) or 0

    # Top 5 devices
    top_q = (
        db.query(
            Device.device_id,
            Device.label,
            Device.mac_address,
            func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out).label("total"),
        )
        .join(UsageRecord, Device.device_id == UsageRecord.device_id)
        .filter(UsageRecord.date == day_str)
        .group_by(Device.device_id)
        .order_by(func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out).desc())
        .limit(5)
    )
    top_devices = [
        {"device_id": r.device_id, "label": r.label, "mac": r.mac_address, "bytes_total": r.total}
        for r in top_q.all()
    ]

    # Alerts
    open_alerts = (
        db.query(func.count(Alert.alert_id))
        .filter(Alert.status == "OPEN")
        .scalar()
    ) or 0

    # New devices discovered today
    new_devices = (
        db.query(func.count(Device.device_id))
        .filter(func.date(Device.first_seen) == day_str)
        .scalar()
    ) or 0

    # Slowdowns (from M3)
    slowdown_minutes = _slowdown_minutes_for(db, day_str)

    # Limit usage fraction
    try:
        from clarinet.core_svc.limit_service import get_limit_summary
        ls = get_limit_summary(db)
        limit_pct = ls.pct_used
    except Exception:
        limit_pct = None

    return DailySummary(
        date=day_str,
        total_bytes=total_bytes,
        top_devices=top_devices,
        open_alerts=open_alerts,
        new_devices=new_devices,
        slowdown_minutes=slowdown_minutes,
        period_limit_pct=limit_pct,
    )


def build_weekly_summary(db: Session, week_end: date | None = None) -> WeeklySummary:
    """Generate a 7-day rolling summary ending on `week_end` (default: yesterday)."""
    from clarinet.models import Alert, Device, SlowdownEvent, UsageRecord

    if week_end is None:
        week_end = local_today() - timedelta(days=1)

    week_start = week_end - timedelta(days=6)
    start_str = week_start.isoformat()
    end_str = week_end.isoformat()

    # Total
    total_bytes = (
        db.query(func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out))
        .filter(UsageRecord.date >= start_str, UsageRecord.date <= end_str)
        .scalar()
    ) or 0

    # Daily totals
    daily_q = (
        db.query(UsageRecord.date, func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out))
        .filter(UsageRecord.date >= start_str, UsageRecord.date <= end_str)
        .group_by(UsageRecord.date)
        .all()
    )
    daily_totals = {row[0]: row[1] for row in daily_q}

    # Top devices
    top_q = (
        db.query(
            Device.device_id,
            Device.label,
            Device.mac_address,
            func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out).label("total"),
        )
        .join(UsageRecord, Device.device_id == UsageRecord.device_id)
        .filter(UsageRecord.date >= start_str, UsageRecord.date <= end_str)
        .group_by(Device.device_id)
        .order_by(func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out).desc())
        .limit(5)
    )
    top_devices = [
        {"device_id": r.device_id, "label": r.label, "mac": r.mac_address, "bytes_total": r.total}
        for r in top_q.all()
    ]

    # Slowdown events in the week
    try:
        from clarinet.models import SlowdownEvent
        week_events = (
            db.query(SlowdownEvent)
            .filter(
                SlowdownEvent.started_at >= week_start.isoformat(),
                SlowdownEvent.started_at <= week_end.isoformat() + "T23:59:59",
            )
            .all()
        )
        slowdown_count = len(week_events)
        total_slow_min = sum(
            int((ev.ended_at - ev.started_at).total_seconds() / 60)
            for ev in week_events
            if ev.ended_at
        )
        avg_slow_min = total_slow_min / slowdown_count if slowdown_count else 0.0
    except Exception:
        slowdown_count = 0
        avg_slow_min = 0.0

    open_alerts = (
        db.query(func.count(Alert.alert_id))
        .filter(Alert.status == "OPEN")
        .scalar()
    ) or 0

    return WeeklySummary(
        week_start=start_str,
        week_end=end_str,
        total_bytes=total_bytes,
        daily_totals=daily_totals,
        top_devices=top_devices,
        slowdown_events=slowdown_count,
        avg_slowdown_minutes=avg_slow_min,
        open_alerts=open_alerts,
    )

