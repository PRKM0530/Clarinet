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
DEFAULT_TEST_MINUTES = 60      # how often each device tests itself while Clarinet is open on it
BASELINE_WINDOW = 10          # earlier results the typical speed is taken from
BASELINE_MINIMUM = 3          # how many earlier results are needed before a slowdown is judged
SLOWER_AT_PCT = 25
MUCH_SLOWER_AT_PCT = 50
CONFIRM_WITHIN = timedelta(hours=6)    # at least this long; it grows with the test interval (see confirm_window)
MIN_DROP_MBPS = 2.0                    # a change smaller than this is noise, however large it looks in percent
DELAY_TIMES = 3.0                      # a delay this many times the usual ...
DELAY_EXTRA_MS = 100.0                 # ... and at least this much longer is a slowdown too (calls and games suffer)
MAX_MBPS = 100_000
MAX_LATENCY_MS = 60_000


def test_interval_minutes(db: Session) -> int:
    """How often a device tests itself automatically: 15 minutes to a day, 60 by default."""
    from clarinet.app_settings import get_setting
    try:
        minutes = int(float(get_setting(db, "device_test_interval_minutes", str(DEFAULT_TEST_MINUTES))))
    except (TypeError, ValueError):
        minutes = DEFAULT_TEST_MINUTES
    return max(15, min(1440, minutes))


def confirm_window(db: Session) -> timedelta:
    """Two low tests confirm a slowdown only if they are this close together: room for a test to be missed."""
    return max(CONFIRM_WITHIN, timedelta(minutes=test_interval_minutes(db) * 2.5))


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
    status: str = "none"                 # none | learning | ok | possible | slower | much_slower
    reason: str = ""                     # for slower / much_slower: "speed" or "delay"
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


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def summary(db: Session, device: Device, history: int = 6) -> DeviceSpeed:
    """
    Is this device slow? Judged against the device's own earlier results, and never on one reading alone:
    Wi-Fi speed jumps around, so a low result is only "possible" until the test before it, within a few hours,
    is low as well. A change smaller than MIN_DROP_MBPS is ignored. A long delay counts as a slowdown too.
    """
    rows = (
        db.query(DeviceSpeedResult).filter(DeviceSpeedResult.device_id == device.device_id)
        .order_by(DeviceSpeedResult.tested_at.desc()).limit(BASELINE_WINDOW + 2).all()
    )
    result = DeviceSpeed(device=device, tests=db.query(DeviceSpeedResult).filter(
        DeviceSpeedResult.device_id == device.device_id).count(), history=rows[:history])
    if not rows:
        return result
    result.latest = rows[0]

    recent = rows[:1]
    if len(rows) > 1 and _aware(rows[0].tested_at) - _aware(rows[1].tested_at) <= confirm_window(db):
        recent = rows[:2]                                   # a confirming pair
    earlier = rows[len(recent):]
    if len(earlier) < BASELINE_MINIMUM:
        result.status = "learning"
        return result

    result.baseline_mbps = round(statistics.median(r.download_mbps for r in earlier), 2)
    result.baseline_latency_ms = round(statistics.median(r.latency_ms for r in earlier), 1)

    def drop(r) -> int:
        """How far below the usual this result is, in percent; 0 when the change is only noise."""
        if result.baseline_mbps <= 0 or result.baseline_mbps - r.download_mbps < MIN_DROP_MBPS:
            return 0
        return max(0, round((1 - r.download_mbps / result.baseline_mbps) * 100))

    def delayed(r) -> bool:
        base = result.baseline_latency_ms
        return base > 0 and r.latency_ms > max(DELAY_TIMES * base, base + DELAY_EXTRA_MS)

    drops = [drop(r) for r in recent]
    if result.baseline_latency_ms > 0:
        result.latency_change_pct = round((rows[0].latency_ms / result.baseline_latency_ms - 1) * 100)

    slow = [d >= SLOWER_AT_PCT for d in drops]
    late = [delayed(r) for r in recent]
    confirmed_speed = len(recent) == 2 and all(slow)
    confirmed_delay = len(recent) == 2 and all(late)
    result.slowdown_pct = min(drops) if len(recent) == 2 and confirmed_speed else drops[0]
    if confirmed_speed or confirmed_delay:
        result.status = "much_slower" if result.slowdown_pct >= MUCH_SLOWER_AT_PCT else "slower"
        result.reason = "speed" if confirmed_speed else "delay"
    elif slow[0] or late[0]:
        result.status = "possible"                           # the latest reading is low but nothing confirms it yet
    else:
        result.status = "ok"
    return result


def may_measure(member, device: Device) -> bool:
    """Speed and slowdown describe one device in its own corner of the network, so they belong to its owner.
    Nobody else, an administrator included, measures it or reads its results."""
    return device.owner_member_id == member.member_id


def devices_for(db: Session, member) -> list[Device]:
    """The devices whose speed this person sees: the ones assigned to them. A member's environment (distance to
    the router, walls, their own Wi-Fi) is not the administrator's, and a speed test can only be taken on the
    device itself, so nobody gets a list of devices they are not using. A shared device (a TV) can be assigned
    to someone on the Devices page."""
    query = db.query(Device).filter(Device.owner_member_id == member.member_id)
    return query.order_by(Device.last_seen.desc()).all()
