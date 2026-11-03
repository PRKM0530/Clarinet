"""
clarinet/core_svc/usage_service.py
Single-query traffic usage aggregation for M1.

Public API:
  usage_for(db, member, period, device_id=None) -> UsageResult

  period: "today" | "week" | "month" | "billing" | "YYYY-MM-DD" (exact day)
"""

from __future__ import annotations
from clarinet.core_svc.localtime import local_today

import logging
from dataclasses import dataclass, field
from datetime import date, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from clarinet.models import UsageRecord

log = logging.getLogger("clarinet.core_svc.usage")


@dataclass
class UsageResult:
    """Aggregated usage figures for the requested period and scope."""
    bytes_in: int = 0
    bytes_out: int = 0
    # Per-device breakdown: {device_id: (bytes_in, bytes_out)}
    by_device: dict[int, tuple[int, int]] = field(default_factory=dict)
    # Per-day totals: {"YYYY-MM-DD": bytes_total}
    by_day: dict[str, int] = field(default_factory=dict)
    # Per-hour totals (0–23)
    by_hour: dict[int, int] = field(default_factory=dict)
    # Bytes per activity type: {"STREAMING": bytes_total}, biggest first
    by_activity: dict[str, int] = field(default_factory=dict)
    period_start: str = ""
    period_end: str = ""

    @property
    def total_bytes(self) -> int:
        return self.bytes_in + self.bytes_out

    @property
    def total_mb(self) -> float:
        return round(self.total_bytes / 1_048_576, 2)

    @property
    def total_gb(self) -> float:
        return round(self.total_bytes / 1_073_741_824, 3)


def local_slot(day: str, hour: int) -> tuple[str, int]:
    """A stored UTC (date, hour) bucket as the configured zone's (date, hour)."""
    from datetime import datetime, timezone
    from clarinet.core_svc.localtime import to_local
    moment = to_local(datetime.fromisoformat(day).replace(hour=hour, tzinfo=timezone.utc))
    return moment.date().isoformat(), moment.hour


def _utc_window(start_date: str, end_date: str) -> tuple[str, str]:
    """Stored dates that can hold hours of local days start..end (a zone is at most a day away from UTC)."""
    return ((date.fromisoformat(start_date) - timedelta(days=1)).isoformat(),
            (date.fromisoformat(end_date) + timedelta(days=1)).isoformat())


def bytes_between(db: Session, start_date: str, end_date: str, device_ids: list[int] | None = None) -> int:
    """Total bytes used on the local days start..end (inclusive) by the given devices (all when None)."""
    lo, hi = _utc_window(start_date, end_date)
    q = db.query(UsageRecord.date, UsageRecord.hour, func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out)).filter(
        UsageRecord.date >= lo, UsageRecord.date <= hi)
    if device_ids is not None:
        q = q.filter(UsageRecord.device_id.in_(device_ids))
    total = 0
    for day, hour, size in q.group_by(UsageRecord.date, UsageRecord.hour):
        if start_date <= local_slot(day, hour)[0] <= end_date:
            total += int(size or 0)
    return total


def bytes_by_device(db: Session, start_date: str, end_date: str) -> dict[int, int]:
    """Total bytes per device on the local days start..end (inclusive), for every device."""
    lo, hi = _utc_window(start_date, end_date)
    rows = (db.query(UsageRecord.device_id, UsageRecord.date, UsageRecord.hour,
                     func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out))
            .filter(UsageRecord.date >= lo, UsageRecord.date <= hi)
            .group_by(UsageRecord.device_id, UsageRecord.date, UsageRecord.hour))
    totals: dict[int, int] = {}
    for device_id, day, hour, size in rows:
        if start_date <= local_slot(day, hour)[0] <= end_date:
            totals[device_id] = totals.get(device_id, 0) + int(size or 0)
    return totals


def _date_range(period: str) -> tuple[str, str]:
    """Return (start_date_str, end_date_str) for the given period keyword."""
    today = local_today()
    if period == "today":
        s = today
        e = today
    elif period == "week":
        s = today - timedelta(days=6)
        e = today
    elif period == "month":
        s = today.replace(day=1)
        e = today
    elif period == "billing":
        from clarinet.core_svc.timeutil import billing_period_start
        # We need billing_day — use default 1 if not DB-accessible here
        # Callers should pass the billing_day from settings
        s = billing_period_start(1)  # overridden by usage_for()
        e = today
    elif len(period) == 10 and "-" in period:
        s = date.fromisoformat(period)
        e = s
    else:
        s = today
        e = today
    return s.isoformat(), e.isoformat()


def usage_for(
    db: Session,
    member,           # Member ORM object
    period: str,
    device_id: int | None = None,
    billing_day: int = 1,
) -> UsageResult:
    """
    Aggregate UsageRecord rows for `member` over `period`.

    - Admins get network-wide aggregation.
    - Members see only their own devices (owner_member_id == member_id).
    - If device_id given, further filter to that device.
    """
    # Resolve date range
    if period == "billing":
        from clarinet.core_svc.timeutil import billing_period_start
        start_date = billing_period_start(billing_day).isoformat()
        end_date = local_today().isoformat()
    else:
        start_date, end_date = _date_range(period)

    return usage_range(db, member, start_date, end_date, device_id=device_id)


def usage_range(
    db: Session,
    member,
    start_date: str,
    end_date: str,
    device_id: int | None = None,
) -> UsageResult:
    """
    Aggregate usage between two dates (inclusive, YYYY-MM-DD) for what `member`
    may see: everything for admins, only their own devices for members.
    """
    from clarinet.core_svc.permissions import member_device_ids

    # Allowed device scope
    allowed_ids = member_device_ids(db, member)
    if device_id is not None:
        if device_id not in allowed_ids:
            return UsageResult(period_start=start_date, period_end=end_date)
        allowed_ids = [device_id]

    if not allowed_ids:
        return UsageResult(period_start=start_date, period_end=end_date)

    # Base query: a wider window of stored (UTC) dates, then each bucket is placed on its local day
    lo, hi = _utc_window(start_date, end_date)
    q = (
        db.query(UsageRecord)
        .filter(
            UsageRecord.device_id.in_(allowed_ids),
            UsageRecord.date >= lo,
            UsageRecord.date <= hi,
        )
    )

    result = UsageResult(period_start=start_date, period_end=end_date)

    for rec in q.all():
        local_day, local_hour = local_slot(rec.date, rec.hour)
        if not (start_date <= local_day <= end_date):
            continue
        result.bytes_in += rec.bytes_in
        result.bytes_out += rec.bytes_out

        # By device
        if rec.device_id not in result.by_device:
            result.by_device[rec.device_id] = (0, 0)
        bi, bo = result.by_device[rec.device_id]
        result.by_device[rec.device_id] = (bi + rec.bytes_in, bo + rec.bytes_out)

        # By day
        day_total = result.by_day.get(local_day, 0)
        result.by_day[local_day] = day_total + rec.bytes_in + rec.bytes_out

        # By hour (the viewer's hour of the day)
        hr_total = result.by_hour.get(local_hour, 0)
        result.by_hour[local_hour] = hr_total + rec.bytes_in + rec.bytes_out

    result.by_activity = _activity_totals(db, allowed_ids, start_date, end_date)
    return result


def _activity_totals(db: Session, device_ids: list[int], start_date: str, end_date: str) -> dict[str, int]:
    """Bytes per activity type for the given devices and dates, biggest first."""
    from clarinet.models.traffic import UsageActivity

    lo, hi = _utc_window(start_date, end_date)
    rows = (
        db.query(UsageActivity.date, UsageActivity.hour, UsageActivity.category,
                 func.sum(UsageActivity.bytes_in + UsageActivity.bytes_out))
        .filter(
            UsageActivity.device_id.in_(device_ids),
            UsageActivity.date >= lo,
            UsageActivity.date <= hi,
        )
        .group_by(UsageActivity.date, UsageActivity.hour, UsageActivity.category)
        .all()
    )
    totals: dict[str, int] = {}
    for day, hour, category, total in rows:
        if total and start_date <= local_slot(day, hour)[0] <= end_date:
            totals[category] = totals.get(category, 0) + int(total)
    return dict(sorted(totals.items(), key=lambda kv: kv[1], reverse=True))
