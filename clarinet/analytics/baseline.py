"""
clarinet/analytics/baseline.py
Build and query per-hour traffic normal ranges (PERF-2).

The baseline is a rolling average of the last 28 days of:
  - Download / upload speed test results grouped by hour + day-of-week
  - Latency measurements grouped by hour + day-of-week

Used by diagnosis.py to decide whether current metrics are "abnormal".
"""

import logging
from datetime import datetime, timezone

import numpy as np
import pandas as pd

log = logging.getLogger("clarinet.analytics.baseline")


def rebuild_all() -> None:
    """
    Recompute the Baseline table from the last 28 days of SpeedTestResult
    and latency measurements (once pinger stores them — Phase 4).
    Called nightly at 03:00 UTC by APScheduler.
    """
    from clarinet.database import SessionLocal
    from clarinet.models import Baseline, SpeedTestResult

    log.info("Rebuilding baselines")
    with SessionLocal() as db:
        results = db.query(SpeedTestResult).all()
        if not results:
            log.info("No speed test data yet — skipping baseline rebuild")
            return

        # Build a DataFrame
        rows = [
            {
                "tested_at": r.tested_at,
                "download_mbps": r.download_mbps,
                "upload_mbps": r.upload_mbps,
                "latency_ms": r.latency_ms,
                "hour": r.tested_at.hour,
                "dow": r.tested_at.weekday(),   # 0=Mon … 6=Sun
            }
            for r in results
        ]
        df = pd.DataFrame(rows)

        # Group by hour + day-of-week
        grouped = df.groupby(["dow", "hour"]).agg(
            avg_download=("download_mbps", "mean"),
            avg_upload=("upload_mbps", "mean"),
            avg_latency=("latency_ms", "mean"),
            std_latency=("latency_ms", "std"),
            count=("download_mbps", "count"),
        ).reset_index()

        now = datetime.now(timezone.utc)
        for _, row in grouped.iterrows():
            existing = (
                db.query(Baseline)
                .filter(
                    Baseline.hour == int(row["hour"]),
                    Baseline.day_of_week == int(row["dow"]),
                )
                .first()
            )
            if existing:
                existing.avg_download_mbps = round(row["avg_download"], 2)
                existing.avg_upload_mbps = round(row["avg_upload"], 2)
                existing.avg_latency_ms = round(row["avg_latency"], 1)
                existing.std_latency_ms = round(row["std_latency"] or 0, 1)
                existing.sample_count = int(row["count"])
                existing.updated_at = now
            else:
                db.add(Baseline(
                    hour=int(row["hour"]),
                    day_of_week=int(row["dow"]),
                    avg_download_mbps=round(row["avg_download"], 2),
                    avg_upload_mbps=round(row["avg_upload"], 2),
                    avg_latency_ms=round(row["avg_latency"], 1),
                    std_latency_ms=round(row["std_latency"] or 0, 1),
                    sample_count=int(row["count"]),
                    updated_at=now,
                ))

        db.commit()
        log.info("Baseline rebuild complete: %d hour-buckets", len(grouped))


def get_baseline_for_now(db) -> "Baseline | None":
    """Return the baseline row for the current hour and day-of-week."""
    from clarinet.models import Baseline
    now = datetime.now(timezone.utc)
    return (
        db.query(Baseline)
        .filter(Baseline.hour == now.hour, Baseline.day_of_week == now.weekday())
        .first()
    )


def latency_is_elevated(current_ms: float, baseline: "Baseline", multiplier: float = 3.0) -> bool:
    """Return True if current latency exceeds baseline * multiplier."""
    if baseline is None or baseline.avg_latency_ms is None:
        return False
    return current_ms > baseline.avg_latency_ms * multiplier


def speed_is_below_plan(current_mbps: float, plan_mbps: float, threshold: float = 0.70) -> bool:
    return current_mbps < plan_mbps * threshold
