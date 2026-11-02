"""
clarinet/core_svc/usage_service.py
Single-query traffic usage aggregation for M1.

Public API:
  usage_for(db, member, period, device_id=None) -> UsageResult

  period: "today" | "week" | "month" | "billing" | "YYYY-MM-DD" (exact day)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from clarinet.models import Device, UsageRecord

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


def _date_range(period: str) -> tuple[str, str]:
    """Return (start_date_str, end_date_str) for the given period keyword."""
    today = date.today()
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
        end_date = date.today().isoformat()
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

    # Base query
    q = (
        db.query(UsageRecord)
        .filter(
            UsageRecord.device_id.in_(allowed_ids),
            UsageRecord.date >= start_date,
            UsageRecord.date <= end_date,
        )
    )

    result = UsageResult(period_start=start_date, period_end=end_date)

    for rec in q.all():
        result.bytes_in += rec.bytes_in
        result.bytes_out += rec.bytes_out

        # By device
        if rec.device_id not in result.by_device:
            result.by_device[rec.device_id] = (0, 0)
        bi, bo = result.by_device[rec.device_id]
        result.by_device[rec.device_id] = (bi + rec.bytes_in, bo + rec.bytes_out)

        # By day
        day_total = result.by_day.get(rec.date, 0)
        result.by_day[rec.date] = day_total + rec.bytes_in + rec.bytes_out

        # By hour
        hr_total = result.by_hour.get(rec.hour, 0)
        result.by_hour[rec.hour] = hr_total + rec.bytes_in + rec.bytes_out

    result.by_activity = _activity_totals(db, allowed_ids, start_date, end_date)
    return result


def _activity_totals(db: Session, device_ids: list[int], start_date: str, end_date: str) -> dict[str, int]:
    """Bytes per activity type for the given devices and dates, biggest first."""
    from clarinet.models.traffic import UsageActivity

    rows = (
        db.query(UsageActivity.category, func.sum(UsageActivity.bytes_in + UsageActivity.bytes_out))
        .filter(
            UsageActivity.device_id.in_(device_ids),
            UsageActivity.date >= start_date,
            UsageActivity.date <= end_date,
        )
        .group_by(UsageActivity.category)
        .all()
    )
    totals = {category: int(total or 0) for category, total in rows if total}
    return dict(sorted(totals.items(), key=lambda kv: kv[1], reverse=True))

