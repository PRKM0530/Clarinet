"""Core jobs: device discovery and traffic accounting."""

import logging

from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger("clarinet.jobs.core")


def register(scheduler) -> None:
    # Device discovery via ARP
    scheduler.add_job(
        arp_scan,
        trigger=IntervalTrigger(seconds=30),
        id="arp_scan",
        replace_existing=True,
    )

    # Poll nftables counters -> UsageRecord every 60 s
    scheduler.add_job(
        poll_traffic,
        trigger=IntervalTrigger(seconds=60),
        id="poll_traffic",
        replace_existing=True,
    )


def arp_scan() -> None:
    """ARP scan: discovers devices and creates NEW entries + WebSocket alerts."""
    try:
        from clarinet.app_settings import get_setting
        from clarinet.database import SessionLocal
        with SessionLocal() as db:
            iface = get_setting(db, "network_interface") or None

        if not iface:
            log.debug("ARP scan skipped: no network_interface configured")
            return

        from clarinet.collector.arp_scanner import run_scan_loop
        run_scan_loop(iface)
    except Exception as e:
        log.debug("ARP scan failed (Linux only?): %s", e)


def poll_traffic() -> None:
    """Poll nftables byte counters and write them to UsageRecord."""
    try:
        from clarinet.app_settings import get_setting
        from clarinet.database import SessionLocal
        with SessionLocal() as db:
            iface = get_setting(db, "network_interface") or None
        if not iface:
            return
        from clarinet.collector.traffic_counter import poll_nft_counters
        poll_nft_counters(iface)
    except Exception as e:
        log.debug("Traffic poll skipped (Linux only?): %s", e)
