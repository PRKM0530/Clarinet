"""Security jobs: Wi-Fi scans, network checks, router audit, port-scan sniffer."""

import logging

from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger("clarinet.jobs.security")


def register(scheduler) -> None:
    # Fake access point scan every 5 minutes
    scheduler.add_job(
        wifi_scan,
        trigger=IntervalTrigger(minutes=5),
        id="wifi_scan",
        replace_existing=True,
    )

    # Unfamiliar network check every 2 minutes
    scheduler.add_job(
        network_check,
        trigger=IntervalTrigger(minutes=2),
        id="network_check",
        replace_existing=True,
    )

    # Router audit once a day (and on demand from the Security page)
    scheduler.add_job(
        router_audit,
        trigger=IntervalTrigger(hours=24),
        id="router_audit",
        replace_existing=True,
        next_run_time=None,   # not on startup, it probes the router
    )

    # Port-scan sniffer: started once, runs in its own thread
    scheduler.add_job(
        start_port_scan_sniffer,
        id="port_scan_sniffer",
        replace_existing=True,
    )


def wifi_scan() -> None:
    try:
        from clarinet.collector.wifi_scan import scan_and_evaluate
        from clarinet.database import SessionLocal
        with SessionLocal() as db:
            scan_and_evaluate(db)
    except Exception as e:
        log.debug("Wi-Fi scan skipped: %s", e)


def network_check() -> None:
    try:
        from clarinet.collector.network_check import check_and_evaluate
        from clarinet.database import SessionLocal
        with SessionLocal() as db:
            check_and_evaluate(db)
    except Exception as e:
        log.debug("Network check skipped: %s", e)


def router_audit() -> None:
    try:
        from clarinet.collector.router_audit import run_audit
        from clarinet.database import SessionLocal
        with SessionLocal() as db:
            run_audit(db)
    except Exception as e:
        log.error("Router audit failed: %s", e)


def start_port_scan_sniffer() -> None:
    try:
        from clarinet.app_settings import get_setting
        from clarinet.collector.port_scan import start_sniffer
        from clarinet.database import SessionLocal
        with SessionLocal() as db:
            iface = get_setting(db, "network_interface") or None
        if iface:
            start_sniffer(iface)
    except Exception as e:
        log.debug("Port-scan sniffer not started: %s", e)
