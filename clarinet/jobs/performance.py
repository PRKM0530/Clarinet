"""Performance jobs: latency, DNS timing and baselines."""

import logging

from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger("clarinet.jobs.performance")


def register(scheduler) -> None:
    # Latency / slowdown check
    scheduler.add_job(
        latency_check,
        trigger=IntervalTrigger(seconds=60),
        id="latency_check",
        replace_existing=True,
    )

    # DNS latency check every 5 minutes
    scheduler.add_job(
        dns_measure,
        trigger=IntervalTrigger(minutes=5),
        id="dns_measure",
        replace_existing=True,
    )

    # Rebuild baselines at 03:00 UTC
    scheduler.add_job(
        rebuild_baselines,
        trigger=CronTrigger(hour=3, minute=0),
        id="rebuild_baselines",
        replace_existing=True,
    )

    # Daily tasks at 00:05 UTC
    scheduler.add_job(
        daily_summary,
        trigger=CronTrigger(hour=0, minute=5),
        id="daily_summary",
        replace_existing=True,
    )


def latency_check() -> None:
    try:
        from clarinet.collector.pinger import measure_and_store
        measure_and_store()
    except Exception as e:
        log.debug("Latency check failed: %s", e)


def dns_measure() -> None:
    """Measure DNS resolution time; feeds SLOW_DNS diagnosis."""
    try:
        from clarinet.collector.dns_timer import measure_dns, average_dns_ms
        results = measure_dns()
        avg = average_dns_ms(results)
        if avg is not None:
            log.debug("DNS avg: %.1f ms", avg)
    except Exception as e:
        log.debug("DNS measure failed: %s", e)


def rebuild_baselines() -> None:
    log.info("Rebuilding baselines")
    try:
        from clarinet.analytics.baseline import rebuild_all
        rebuild_all()
    except Exception as e:
        log.error("Baseline rebuild failed: %s", e)


def daily_summary() -> None:
    log.info("Running daily tasks (baseline rebuild + summary)")
    rebuild_baselines()
