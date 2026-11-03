"""
clarinet/core_svc/device_speed.py
Per-device speed results and the "slowdown" of each device.

The test runs in the device's own browser against Clarinet (see static/js/device_speed.js),
so it measures that device's link: its Wi-Fi or cable, to the Clarinet computer. It is
stored per device and never mixed with the internet speed measured at the gateway.

Slowdown is how far a device's latest download is below its own recent typical
download (the median of its earlier results), so a phone on weak Wi-Fi is judged
against itself and not against a laptop on a cable.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from clarinet.models import Device
from clarinet.models.devspeed import DeviceSpeedResult

MIN_SECONDS_BETWEEN_TESTS = 20
BASELINE_WINDOW = 10          # earlier results the typical speed is taken from
BASELINE_MINIMUM = 3          # how many earlier results are needed before a slowdown is judged
SLOWER_AT_PCT = 25
MUCH_SLOWER_AT_PCT = 50
MAX_MBPS = 100_000
MAX_LATENCY_MS = 60_000


class Refused(Exception):
    """A result that was not stored; the message is safe to show."""


@dataclass
class DeviceSpeed:
    device: Device
    latest: DeviceSpeedResult | None = None
    tests: int = 0
    baseline_mbps: float | None = None
    baseline_latency_ms: float | None = None
    slowdown_pct: int | None = None
    latency_change_pct: int | None = None
    status: str = "none"                 # none | learning | ok | slower | much_slower
    history: list[DeviceSpeedResult] = field(default_factory=list)


def _number(value, high):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number and 0 <= number <= high else None      # also rejects NaN


def record(db: Session, device: Device, member_id: int | None, download, upload, latency, jitter=None) -> DeviceSpeedResult:
    down, up = _number(download, MAX_MBPS), _number(upload, MAX_MBPS)
    lat, jit = _number(latency, MAX_LATENCY_MS), _number(jitter, MAX_LATENCY_MS) if jitter is not None else None
    if down is None or up is None or lat is None or (jitter is not None and jit is None):
        raise Refused("The measurement was not valid.")
    if down <= 0:
        raise Refused("The test did not measure any download speed.")

    last = (
        db.query(DeviceSpeedResult).filter(DeviceSpeedResult.device_id == device.device_id)
        .order_by(DeviceSpeedResult.tested_at.desc()).first()
    )
    if last is not None:
        tested = last.tested_at if last.tested_at.tzinfo else last.tested_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - tested < timedelta(seconds=MIN_SECONDS_BETWEEN_TESTS):
            raise Refused("This device was tested a moment ago. Please wait a little before testing again.")

    row = DeviceSpeedResult(device_id=device.device_id, download_mbps=round(down, 2), upload_mbps=round(up, 2),
                            latency_ms=round(lat, 1), jitter_ms=None if jit is None else round(jit, 1), run_by=member_id)
    db.add(row)
    db.commit()
    return row


def summary(db: Session, device: Device, history: int = 6) -> DeviceSpeed:
    rows = (
        db.query(DeviceSpeedResult).filter(DeviceSpeedResult.device_id == device.device_id)
        .order_by(DeviceSpeedResult.tested_at.desc()).limit(BASELINE_WINDOW + 1).all()
    )
    result = DeviceSpeed(device=device, tests=db.query(DeviceSpeedResult).filter(
        DeviceSpeedResult.device_id == device.device_id).count(), history=rows[:history])
    if not rows:
        return result
    result.latest = rows[0]
    earlier = rows[1:]
    if len(earlier) < BASELINE_MINIMUM:
        result.status = "learning"
        return result

    result.baseline_mbps = round(statistics.median(r.download_mbps for r in earlier), 2)
    result.baseline_latency_ms = round(statistics.median(r.latency_ms for r in earlier), 1)
    if result.baseline_mbps > 0:
        result.slowdown_pct = max(0, round((1 - rows[0].download_mbps / result.baseline_mbps) * 100))
    if result.baseline_latency_ms > 0:
        result.latency_change_pct = round((rows[0].latency_ms / result.baseline_latency_ms - 1) * 100)
    pct = result.slowdown_pct or 0
    result.status = "much_slower" if pct >= MUCH_SLOWER_AT_PCT else "slower" if pct >= SLOWER_AT_PCT else "ok"
    return result


def devices_for(db: Session, member) -> list[Device]:
    """The devices this person may see: all for an administrator, their own for a member."""
    query = db.query(Device).filter(Device.state != "BLOCKED") if member.is_admin else \
        db.query(Device).filter(Device.owner_member_id == member.member_id)
    return query.order_by(Device.last_seen.desc()).all()
