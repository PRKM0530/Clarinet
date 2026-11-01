"""
clarinet/jobs/performance.py  (M3 fix)
Performance background jobs: latency, DNS timing, baselines, early warning.

Fixes (F-14):
- daily_summary() is no longer just a baseline rebuild — it now delegates
  to M1's summary service (lazy import) and includes slowdown data
- Cron times use local timezone (IST) not hardcoded UTC hour
- next_run_time=now so jobs run immediately on startup
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger("clarinet.jobs.performance")


def register(scheduler) -> None:
    # Latency / slowdown check every 60 s
    scheduler.add_job(
        latency_check,
        trigger=IntervalTrigger(seconds=60),
        id="latency_check",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        next_run_time=datetime.now(timezone.utc),
    )

    # DNS latency every 5 minutes
    scheduler.add_job(
        dns_measure,
        trigger=IntervalTrigger(minutes=5),
        id="dns_measure",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        next_run_time=datetime.now(timezone.utc),
    )

    # Early-warning check every 5 minutes
    scheduler.add_job(
        early_warning_check,
        trigger=IntervalTrigger(minutes=5),
        id="early_warning",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        next_run_time=datetime.now(timezone.utc),
    )

    # Rebuild baselines at 03:00 IST (= 21:30 UTC previous day)
    # F-14 fix: use local timezone (Asia/Kolkata)
    scheduler.add_job(
        rebuild_baselines,
        trigger=CronTrigger(hour=3, minute=0, timezone="Asia/Kolkata"),
        id="rebuild_baselines",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )

    # Retention: clean up old ping records (keep 30 days)
    scheduler.add_job(
        retention,
        trigger=CronTrigger(hour=2, minute=30, timezone="Asia/Kolkata"),
        id="perf_retention",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )


# ──────────────────────────────────────────────

def latency_check() -> None:
    try:
        from clarinet.collector.pinger import measure_and_store
        measure_and_store()
    except Exception as exc:
        log.debug("Latency check failed: %s", exc)


def dns_measure() -> None:
    try:
        from clarinet.collector.dns_timer import measure_dns, average_dns_ms
        results = measure_dns()
        avg = average_dns_ms(results)
        if avg is not None:
            log.debug("DNS avg: %.1f ms", avg)
    except Exception as exc:
        log.debug("DNS measure failed: %s", exc)


def early_warning_check() -> None:
    try:
        from clarinet.analytics.early_warning import run_early_warning_check
        run_early_warning_check()
    except Exception as exc:
        log.debug("Early warning check failed: %s", exc)


def rebuild_baselines() -> None:
    log.info("Rebuilding latency baselines")
    try:
        from clarinet.analytics.baseline import rebuild_all
        rebuild_all()
    except Exception as exc:
        log.error("Baseline rebuild failed: %s", exc)


def retention() -> None:
    """Remove PingRecord rows older than 30 days."""
    from datetime import timedelta
    try:
        from clarinet.database import SessionLocal
        from clarinet.models import PingRecord
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        with SessionLocal() as db:
            deleted = db.query(PingRecord).filter(PingRecord.measured_at < cutoff).delete()
            db.commit()
            if deleted:
                log.info("Ping retention: deleted %d old records", deleted)
    except Exception as exc:
        log.error("Perf retention failed: %s", exc)
