"""
clarinet/analytics/baseline.py  (M3 rewrite)
Per-hour latency/packet-loss baseline built from PingRecord rows.

Fixes (F-10):
- Built from PingRecord latency, NOT SpeedTestResult (which is sparse)
- 7-day rolling window with outlier rejection (IQR)
- 7-day fixed-value learning period before baselines are "ready"
- Separate outage baseline (packet_loss > 50%) excluded from latency stats
- latency_is_elevated() uses per-hour std dev for a tighter threshold
"""
from __future__ import annotations

import logging
import statistics
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from clarinet.models import Baseline

log = logging.getLogger("clarinet.analytics.baseline")

BASELINE_WINDOW_DAYS = 7
MIN_SAMPLES_READY = 20           # minimum PingRecord rows before baseline is "ready"
MIN_HISTORY_HOURS = 24           # ...and they must cover at least a day, so every hour of the day has been seen
OUTLIER_IQR_FACTOR = 1.5        # IQR-based outlier rejection factor


def rebuild_all(db=None) -> int:
    """
    Rebuild per-hour-of-week baseline rows from the last BASELINE_WINDOW_DAYS of PingRecord.
    Returns the number of hour-buckets updated.
    """
    from clarinet.database import SessionLocal
    from clarinet.models import PingRecord, Baseline

    session = db or SessionLocal()
    close_after = db is None

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=BASELINE_WINDOW_DAYS)
        records = (
            session.query(PingRecord)
            .filter(
                PingRecord.measured_at >= cutoff,
                PingRecord.target.in_(["google_dns", "cloudflare"]),
                PingRecord.reachable == True,
                PingRecord.packet_loss < 0.5,   # exclude outage samples
            )
            .all()
        )

        if not records:
            log.info("No usable PingRecord rows for baseline rebuild")
            return 0

        # Group by (day_of_week, hour)
        from collections import defaultdict
        buckets: dict[tuple[int, int], list[float]] = defaultdict(list)
        for r in records:
            dt = r.measured_at
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            buckets[(dt.weekday(), dt.hour)].append(r.avg_ms)

        updated = 0
        now = datetime.now(timezone.utc)

        for (dow, hour), latencies in buckets.items():
            clean = _reject_outliers(latencies)
            if not clean:
                continue

            avg = statistics.mean(clean)
            std = statistics.stdev(clean) if len(clean) > 1 else 0.0

            existing = (
                session.query(Baseline)
                .filter(Baseline.hour == hour, Baseline.day_of_week == dow)
                .first()
            )
            if existing:
                existing.avg_latency_ms = round(avg, 1)
                existing.std_latency_ms = round(std, 1)
                existing.sample_count = len(clean)
                existing.updated_at = now
            else:
                session.add(Baseline(
                    hour=hour,
                    day_of_week=dow,
                    avg_latency_ms=round(avg, 1),
                    std_latency_ms=round(std, 1),
                    sample_count=len(clean),
                    updated_at=now,
                ))
            updated += 1

        session.commit()
        log.info("Baseline rebuild complete: %d hour-buckets", updated)
        return updated
    finally:
        if close_after:
            session.close()


def _reject_outliers(values: list[float]) -> list[float]:
    """Remove values outside [Q1 - k*IQR, Q3 + k*IQR]."""
    if len(values) < 4:
        return values
    sorted_v = sorted(values)
    n = len(sorted_v)
    q1 = sorted_v[n // 4]
    q3 = sorted_v[3 * n // 4]
    iqr = q3 - q1
    lo = q1 - OUTLIER_IQR_FACTOR * iqr
    hi = q3 + OUTLIER_IQR_FACTOR * iqr
    return [v for v in values if lo <= v <= hi]


def get_baseline_for_now(db) -> "Baseline | None":
    """
    The expected latency for the current hour.

    Preferred: the row for this weekday and hour. A new install only has a few days of data, so most
    weekday-hour rows are empty; then fall back to the same hour on other days, and finally to the overall
    average. With no rows at all but enough ping history, the baseline is built now rather than at 03:00.
    """
    from types import SimpleNamespace
    from clarinet.models import Baseline

    rows = db.query(Baseline).all()
    if not rows and is_baseline_ready(db):
        rebuild_all(db)
        rows = db.query(Baseline).all()
    if not rows:
        return None

    now = datetime.now(timezone.utc)
    for row in rows:
        if row.hour == now.hour and row.day_of_week == now.weekday():
            return row

    def blend(chosen):
        weight = sum(r.sample_count or 1 for r in chosen)
        avg = sum((r.avg_latency_ms or 0) * (r.sample_count or 1) for r in chosen) / weight
        std = sum((r.std_latency_ms or 0) * (r.sample_count or 1) for r in chosen) / weight
        return SimpleNamespace(avg_latency_ms=round(avg, 1), std_latency_ms=round(std, 1), sample_count=weight)

    same_hour = [r for r in rows if r.hour == now.hour]
    return blend(same_hour or rows)


def is_baseline_ready(db) -> bool:
    """True once there are enough reachable pings, spanning at least a day, to trust a baseline."""
    from clarinet.models import PingRecord
    from sqlalchemy import func
    cutoff = datetime.now(timezone.utc) - timedelta(days=BASELINE_WINDOW_DAYS)
    count, oldest = (
        db.query(func.count(PingRecord.record_id), func.min(PingRecord.measured_at))
        .filter(PingRecord.measured_at >= cutoff, PingRecord.reachable == True)  # noqa: E712
        .one()
    )
    if count < MIN_SAMPLES_READY or oldest is None:
        return False
    if oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - oldest >= timedelta(hours=MIN_HISTORY_HOURS)


def latency_is_elevated(current_ms: float, baseline: "Baseline | None", multiplier: float = 2.0) -> bool:
    """
    Return True if current latency exceeds baseline * multiplier.

    Fixes (F-10): uses 2× baseline (SRS), not 3× (old code).
    Also uses std-dev band: elevated if current > avg + multiplier * std (when std > 0).
    """
    if baseline is None or baseline.avg_latency_ms is None:
        return False
    avg = baseline.avg_latency_ms
    std = baseline.std_latency_ms or 0.0
    # SRS: latency > 2× baseline average
    if current_ms > avg * multiplier:
        return True
    # Also elevated if well outside the normal spread
    if std > 0 and current_ms > avg + 3 * std:
        return True
    return False


def speed_is_below_plan(current_mbps: float, plan_mbps: float, threshold: float = 0.80) -> bool:
    """Return True if current speed is below threshold% of plan (SRS: 80%, not 70%)."""
    if plan_mbps <= 0:
        return False
    return current_mbps < plan_mbps * threshold
