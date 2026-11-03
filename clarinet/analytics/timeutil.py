"""
clarinet/analytics/timeutil.py
Timezone helpers for M3 (intentionally duplicated for branch independence).
"""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo


def local_now(tz_name: str = "") -> datetime:
    from clarinet.core_svc.localtime import machine_zone
    try:
        tz = ZoneInfo(tz_name or machine_zone())
    except Exception:
        tz = ZoneInfo("UTC")
    return datetime.now(tz)


def get_tz(db) -> ZoneInfo:
    try:
        from clarinet.app_settings import get_setting
        from clarinet.core_svc.localtime import machine_zone
        return ZoneInfo(get_setting(db, "timezone", "") or machine_zone())
    except Exception:
        return ZoneInfo("UTC")


def ensure_utc(dt: datetime | None) -> datetime | None:
    """Normalise a naive or aware datetime to UTC-aware."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

