"""
clarinet/analytics/early_warning.py
Early-warning detector (UC-17): rising latency trend before threshold is hit.

Detects: latency trending upward over the last N samples,
even if individual samples haven't crossed the alert threshold.
"""
from __future__ import annotations

import logging
import statistics
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

log = logging.getLogger("clarinet.analytics.early_warning")

# Look at the last N minutes of ping records
TREND_WINDOW_MINUTES = 10
TREND_MIN_SAMPLES = 4
# Warn if the slope of latency over TREND_WINDOW_MINUTES is > this ms/min
SLOPE_WARN_THRESHOLD = 5.0
# Warn if latest latency is above X% of the alert threshold
PRE_THRESHOLD_FRACTION = 0.70


def check_early_warning(db) -> dict | None:
    """
    Return a warning dict if latency is trending upward, else None.

    Dict shape: {level: "WARNING", type: "EARLY_SLOWDOWN_WARNING",
                 title: str, message: str}
    """
    from clarinet.models import PingRecord
    from clarinet.analytics.baseline import get_baseline_for_now

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=TREND_WINDOW_MINUTES)
    records = (
        db.query(PingRecord)
        .filter(
            PingRecord.measured_at >= cutoff,
            PingRecord.target.in_(["google_dns", "cloudflare"]),
            PingRecord.reachable == True,
        )
        .order_by(PingRecord.measured_at.asc())
        .all()
    )

    if len(records) < TREND_MIN_SAMPLES:
        return None

    latencies = [r.avg_ms for r in records if r.avg_ms is not None]
    if len(latencies) < TREND_MIN_SAMPLES:
        return None

    baseline = get_baseline_for_now(db)
    if baseline is None or baseline.avg_latency_ms is None:
        return None

    # Simple linear trend: compare first half vs second half
    mid = len(latencies) // 2
    first_half_avg = statistics.mean(latencies[:mid])
    second_half_avg = statistics.mean(latencies[mid:])

    slope_per_min = (second_half_avg - first_half_avg) / (TREND_WINDOW_MINUTES / 2)
    latest = latencies[-1]
    threshold = baseline.avg_latency_ms * 2.0   # alert threshold

    is_rising = slope_per_min >= SLOPE_WARN_THRESHOLD
    near_threshold = latest > threshold * PRE_THRESHOLD_FRACTION

    if is_rising and near_threshold:
        return {
            "level": "WARNING",
            "type": "EARLY_SLOWDOWN_WARNING",
            "title": "Your internet speed may be slowing down soon",
            "message": (
                f"Network latency has been rising over the last {TREND_WINDOW_MINUTES} minutes "
                f"(currently {latest:.0f} ms, normal is {baseline.avg_latency_ms:.0f} ms). "
                f"This may indicate a slowdown is on the way."
            ),
        }
    return None


def run_early_warning_check() -> None:
    """Called by the scheduler. Raises an alert if an early warning is detected."""
    try:
        from clarinet.database import SessionLocal
        from clarinet.models import Alert

        with SessionLocal() as db:
            warning = check_early_warning(db)
            if warning is None:
                return

            # Don't re-raise if one is already open
            existing = (
                db.query(Alert)
                .filter(Alert.type == "EARLY_SLOWDOWN_WARNING", Alert.status == "OPEN")
                .first()
            )
            if existing:
                return

            try:
                from clarinet.core_svc.alerts import raise_alert
                raise_alert(db, warning["level"], warning["type"],
                            warning["title"], warning["message"], cooldown_s=1800)
            except ImportError:
                db.add(Alert(
                    level=warning["level"],
                    type=warning["type"],
                    title=warning["title"],
                    message=warning["message"],
                ))
                db.commit()
            log.info("Early warning raised")
    except Exception as exc:
        log.error("early_warning check failed: %s", exc)

