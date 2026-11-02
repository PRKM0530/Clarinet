"""
clarinet/core_svc/reports.py
Daily and weekly usage reports (USE-3).

A report covers one day or one week and is built for a particular viewer:
admins get the whole network, members only their own devices. Network-wide
extras (slowdowns, new devices, data limit) are for admins only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from sqlalchemy.orm import Session

from clarinet.core_svc.activity import LABELS
from clarinet.core_svc.permissions import visible_alerts
from clarinet.core_svc.usage_service import usage_range
from clarinet.models import Device, SlowdownEvent


@dataclass
class Report:
    kind: str                       # "day" | "week"
    start: str
    end: str
    total_bytes: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    previous_total: int = 0
    change_pct: float | None = None  # versus the period before; None when there was no data before
    by_day: dict[str, int] = field(default_factory=dict)
    top_devices: list[dict] = field(default_factory=list)
    activity: list[dict] = field(default_factory=list)
    peak_hour: int | None = None
    alerts: int = 0
    new_devices: int | None = None        # admins only
    slowdown_minutes: int | None = None   # admins only
    limit_pct: float | None = None        # admins only


def week_ending(day: date) -> tuple[date, date]:
    """The seven days ending on `day`."""
    return day - timedelta(days=6), day


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def build_report(db: Session, member, kind: str, end_day: date) -> Report:
    """Build the daily (kind="day") or weekly (kind="week") report ending on `end_day`."""
    start_day = end_day if kind == "day" else end_day - timedelta(days=6)
    length = (end_day - start_day).days + 1
    prev_end = start_day - timedelta(days=1)
    prev_start = prev_end - timedelta(days=length - 1)

    usage = usage_range(db, member, start_day.isoformat(), end_day.isoformat())
    previous = usage_range(db, member, prev_start.isoformat(), prev_end.isoformat())

    report = Report(
        kind=kind, start=start_day.isoformat(), end=end_day.isoformat(),
        total_bytes=usage.total_bytes, bytes_in=usage.bytes_in, bytes_out=usage.bytes_out,
        previous_total=previous.total_bytes,
    )
    if previous.total_bytes > 0:
        report.change_pct = round((usage.total_bytes - previous.total_bytes) * 100 / previous.total_bytes, 1)

    # one bar for every day of a week, including quiet ones
    report.by_day = {
        (start_day + timedelta(days=i)).isoformat(): usage.by_day.get((start_day + timedelta(days=i)).isoformat(), 0)
        for i in range(length)
    }
    if usage.by_hour:
        report.peak_hour = max(usage.by_hour, key=usage.by_hour.get)

    devices = {d.device_id: d for d in db.query(Device).filter(Device.device_id.in_(list(usage.by_device)))} if usage.by_device else {}
    ranked = sorted(usage.by_device.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True)[:5]
    report.top_devices = [
        {"device": devices[i], "bytes": b_in + b_out}
        for i, (b_in, b_out) in ranked if i in devices
    ]

    total_activity = sum(usage.by_activity.values())
    report.activity = [
        {"key": k, "label": LABELS.get(k, k.title()), "bytes": v,
         "pct": round(v * 100 / total_activity, 1) if total_activity else 0}
        for k, v in usage.by_activity.items()
    ]

    start_dt = datetime.combine(start_day, datetime.min.time(), tzinfo=timezone.utc)
    end_dt = datetime.combine(end_day + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)
    report.alerts = visible_alerts(db, member).filter(
        _alert_time() >= start_dt, _alert_time() < end_dt
    ).count()

    if member.is_admin:
        report.new_devices = db.query(Device).filter(Device.first_seen >= start_dt, Device.first_seen < end_dt).count()
        minutes = 0
        for ev in db.query(SlowdownEvent).filter(SlowdownEvent.started_at >= start_dt, SlowdownEvent.started_at < end_dt):
            if ev.ended_at:
                minutes += int((_as_utc(ev.ended_at) - _as_utc(ev.started_at)).total_seconds() // 60)
        report.slowdown_minutes = minutes
        try:
            from clarinet.core_svc.limit_service import get_limit_summary
            summary = get_limit_summary(db)
            if summary.bytes_limit and summary.pct_used is not None:
                report.limit_pct = round(summary.pct_used * 100, 1)
        except Exception:
            report.limit_pct = None
    return report


def _alert_time():
    from clarinet.models import Alert
    return Alert.raised_at
