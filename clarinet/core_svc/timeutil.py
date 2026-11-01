"""
clarinet/core_svc/timeutil.py
Time and timezone helpers for M1.

The app stores settings in IST (Asia/Kolkata, UTC+5:30) by convention but
all DB datetimes are UTC. This module provides the bridge.
"""

from __future__ import annotations

import zoneinfo
from datetime import date, datetime, timedelta, timezone

_IST = zoneinfo.ZoneInfo("Asia/Kolkata")
_UTC = timezone.utc


def now_utc() -> datetime:
    """Current time as timezone-aware UTC datetime."""
    return datetime.now(_UTC)


def now_ist() -> datetime:
    """Current time as timezone-aware IST datetime."""
    return datetime.now(_IST)


def utc_to_ist(dt: datetime) -> datetime:
    """Convert a UTC datetime to IST."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_UTC)
    return dt.astimezone(_IST)


def ist_to_utc(dt: datetime) -> datetime:
    """Convert an IST datetime to UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_IST)
    return dt.astimezone(_UTC)


def billing_period_start(billing_day: int, ref: date | None = None) -> date:
    """
    Return the start date of the current billing period.
    billing_day: 1-28 (day-of-month the cycle resets).
    ref: reference date (default: today).
    """
    if ref is None:
        ref = date.today()

    if ref.day >= billing_day:
        # We're in the period that started this month
        return ref.replace(day=billing_day)
    else:
        # We haven't hit billing_day yet — period started last month
        if ref.month == 1:
            prev_month = ref.replace(year=ref.year - 1, month=12, day=billing_day)
        else:
            try:
                prev_month = ref.replace(month=ref.month - 1, day=billing_day)
            except ValueError:
                # billing_day > last day of prev month (e.g. 31 in Feb)
                prev_month = ref.replace(month=ref.month - 1, day=1)
        return prev_month


def billing_period_end(billing_day: int, ref: date | None = None) -> date:
    """Return the day before the *next* billing period start."""
    start = billing_period_start(billing_day, ref)
    if start.month == 12:
        next_start = start.replace(year=start.year + 1, month=1, day=billing_day)
    else:
        try:
            next_start = start.replace(month=start.month + 1, day=billing_day)
        except ValueError:
            next_start = start.replace(month=start.month + 1, day=1)
    return next_start - timedelta(days=1)


def days_remaining_in_period(billing_day: int, ref: date | None = None) -> int:
    """Days remaining until the billing period ends (inclusive of end day)."""
    if ref is None:
        ref = date.today()
    end = billing_period_end(billing_day, ref)
    return max(0, (end - ref).days + 1)


def period_fraction_elapsed(billing_day: int, ref: date | None = None) -> float:
    """Fraction (0.0–1.0) of the current billing period that has elapsed."""
    if ref is None:
        ref = date.today()
    start = billing_period_start(billing_day, ref)
    end = billing_period_end(billing_day, ref)
    total_days = (end - start).days + 1
    elapsed = (ref - start).days + 1
    return min(1.0, elapsed / total_days) if total_days > 0 else 0.0
