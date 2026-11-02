"""Activity jobs: watch DNS lookups and sort each device's usage into activity types."""

import logging

from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger("clarinet.jobs.activity")


def register(scheduler) -> None:
    # Start the DNS observer once (Linux with Scapy and root; skipped elsewhere)
    scheduler.add_job(
        start_dns_observer,
        id="dns_observer_start",
        replace_existing=True,
    )

    # Write the counted lookups to the database every minute
    scheduler.add_job(
        flush_dns,
        trigger=IntervalTrigger(seconds=60),
        id="dns_flush",
        replace_existing=True,
    )

    # Re-sort the last two days of usage into activity types
    scheduler.add_job(
        classify_usage,
        trigger=IntervalTrigger(minutes=15),
        id="classify_usage",
        replace_existing=True,
    )


def start_dns_observer() -> None:
    try:
        from clarinet.app_settings import get_setting
        from clarinet.collector.dns_observer import start_sniffer
        from clarinet.database import SessionLocal
        with SessionLocal() as db:
            iface = get_setting(db, "network_interface") or None
        if iface:
            start_sniffer(iface)
    except Exception as e:
        log.debug("DNS observer not started: %s", e)


def flush_dns() -> None:
    try:
        from clarinet.collector.dns_observer import flush
        from clarinet.database import SessionLocal
        with SessionLocal() as db:
            flush(db)
    except Exception as e:
        log.debug("DNS flush failed: %s", e)


def classify_usage() -> None:
    try:
        from clarinet.core_svc.activity import classify_recent
        from clarinet.database import SessionLocal
        with SessionLocal() as db:
            classify_recent(db, hours=48)
    except Exception as e:
        log.warning("Activity classification failed: %s", e)
