"""
clarinet/core_svc/localtime.py
One place that knows which time zone the people using Clarinet live in.

Everything is STORED in UTC; this module turns it into local time for pages, and tells the scheduled jobs and
time rules which zone "22:00" means. The zone is a setting (asked in the setup wizard); until it is set the
machine's own zone is used.
"""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, available_timezones

_lock = threading.Lock()
_cache: dict = {"at": 0.0, "name": None}
_TTL = 30


def machine_zone() -> str:
    """The zone this computer is set to (for example 'Asia/Kolkata'), or 'UTC' if it cannot be told."""
    try:
        with open("/etc/timezone") as f:
            name = f.read().strip()
            if name in available_timezones():
                return name
    except OSError:
        pass
    try:
        target = os.path.realpath("/etc/localtime")
        if "zoneinfo/" in target:
            name = target.split("zoneinfo/", 1)[1]
            if name in available_timezones():
                return name
    except OSError:
        pass
    return "UTC"


def valid_zone(name: str | None) -> bool:
    return bool(name) and name in available_timezones()


def zone_name() -> str:
    """The configured zone name (cached for a few seconds so a page does not query for every timestamp)."""
    with _lock:
        if _cache["name"] is None or time.time() - _cache["at"] > _TTL:
            name = None
            try:
                from clarinet.app_settings import get_setting
                from clarinet.database import SessionLocal
                with SessionLocal() as db:
                    name = get_setting(db, "timezone", "")
            except Exception:
                pass
            _cache["name"] = name if valid_zone(name) else machine_zone()
            _cache["at"] = time.time()
        return _cache["name"]


def configured_zone(db) -> str:
    """The zone name from the settings in `db` (the machine's zone when none is set or the value is not a zone)."""
    from clarinet.app_settings import get_setting
    name = get_setting(db, "timezone", "")
    return name if valid_zone(name) else machine_zone()


def reset_cache() -> None:
    with _lock:
        _cache["name"], _cache["at"] = None, 0.0


def tz() -> ZoneInfo:
    return ZoneInfo(zone_name())


def to_local(value: datetime | None) -> datetime | None:
    """A stored time (naive values are UTC) in the configured zone."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(tz())


def local_filter(value, fmt: str = "%d %b %H:%M") -> str:
    """Jinja filter: {{ alert.raised_at|local('%H:%M') }}"""
    local = to_local(value)
    return local.strftime(fmt) if local is not None else ""


def common_zones() -> list[str]:
    return sorted(available_timezones())
