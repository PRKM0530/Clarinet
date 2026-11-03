"""
clarinet/core_svc/system_status.py
What "System status" shows: how the Clarinet program and the computer it runs on are doing.

It is about the system, not about any one device (device speed and slowdowns are per device).
Everything here uses only the standard library, so it works on any computer; a value that
needs Linux is None elsewhere and the page says so.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session


@dataclass
class Collector:
    name: str
    last_seen: datetime | None
    lag_seconds: int | None
    state: str                      # ok | stale


@dataclass
class Status:
    uptime_seconds: int
    python: str
    system: str
    load: tuple[float, float, float] | None
    memory_used_pct: int | None
    memory_total_bytes: int | None
    disk_free_bytes: int | None
    disk_total_bytes: int | None
    database_bytes: int | None
    gateway: dict | None
    internet: dict | None
    collectors: list[Collector] = field(default_factory=list)
    can_control: bool = False
    problem: str | None = None


def human_duration(seconds: int) -> str:
    days, rest = divmod(max(0, int(seconds)), 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days} d {hours} h"
    if hours:
        return f"{hours} h {minutes} min"
    return f"{minutes} min" if minutes else "under a minute"


def _windows_memory():
    """(used percent, total bytes) from the Windows memory status call."""
    import ctypes

    class MemoryStatus(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong), ("total", ctypes.c_ulonglong),
                    ("avail", ctypes.c_ulonglong), ("total_page", ctypes.c_ulonglong), ("avail_page", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong), ("avail_virtual", ctypes.c_ulonglong),
                    ("avail_extended", ctypes.c_ulonglong)]
    status = MemoryStatus()
    status.length = ctypes.sizeof(MemoryStatus)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return None, None
    return int(status.load), int(status.total)


def _memory():
    """(used percent, total bytes): /proc/meminfo on Linux, the memory status call on Windows, else (None, None)."""
    if platform.system() == "Windows":
        try:
            return _windows_memory()
        except Exception:
            return None, None
    try:
        values = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            values[key] = int(rest.split()[0]) * 1024
        total, available = values["MemTotal"], values["MemAvailable"]
        return round((total - available) * 100 / total), total
    except (OSError, KeyError, ValueError, ZeroDivisionError):
        return None, None


def _database_file() -> Path | None:
    try:
        from clarinet.database import engine
        name = engine.url.database
        return Path(name) if name and name != ":memory:" else None
    except Exception:
        return None


def _latest_ping(db: Session, target: str) -> dict | None:
    from clarinet.models import PingRecord
    row = db.query(PingRecord).filter(PingRecord.target == target).order_by(PingRecord.measured_at.desc()).first()
    if row is None:
        return None
    return {"reachable": bool(row.reachable), "avg_ms": row.avg_ms, "loss": row.packet_loss, "at": row.measured_at}


def snapshot(db: Session) -> Status:
    import clarinet
    from clarinet.core_svc import netinfo
    from clarinet.core_svc.enforcement_status import problem
    from clarinet.models.traffic import CollectorHeartbeat

    used, total = _memory()
    db_file = _database_file()
    folder = db_file.parent if db_file is not None and db_file.parent.exists() else Path.cwd()
    try:
        usage = shutil.disk_usage(folder)
        disk_free, disk_total = usage.free, usage.total
    except OSError:
        disk_free = disk_total = None
    try:
        load = tuple(round(x, 2) for x in os.getloadavg())
    except (AttributeError, OSError):
        load = None

    now = datetime.utcnow()
    collectors = []
    for hb in db.query(CollectorHeartbeat).order_by(CollectorHeartbeat.collector).all():
        lag = int((now - hb.last_seen).total_seconds())
        collectors.append(Collector(hb.collector, hb.last_seen, lag, "ok" if lag <= hb.interval_s * 2 else "stale"))

    return Status(
        uptime_seconds=int(time.time() - getattr(clarinet, "STARTED_AT", time.time())),
        python=sys.version.split()[0],
        system=f"{platform.system()} {platform.release()}".strip(),
        load=load,
        memory_used_pct=used,
        memory_total_bytes=total,
        disk_free_bytes=disk_free,
        disk_total_bytes=disk_total,
        database_bytes=db_file.stat().st_size if db_file is not None and db_file.exists() else None,
        gateway=_latest_ping(db, "router"),
        internet=_latest_ping(db, "google_dns") or _latest_ping(db, "cloudflare"),
        collectors=collectors,
        can_control=netinfo.can_control_cached(),
        problem=problem(),
    )
