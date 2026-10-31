"""
clarinet/scheduler.py  (Phase 2 — adds ARP scan + pinger loops)

APScheduler background jobs:
  Every 30 s  → ARP scan (device discovery)
  Every 60 s  → ICMP latency + slowdown check
  Every 6 h   → Speed test (configurable interval)
  Every 1 h   → Expire vouchers
  At 03:00    → Rebuild baselines
  Every 60 s  → Enforce time rules (block/unblock via nftables)
  At 00:05    → Daily usage summary
"""

import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger("clarinet.scheduler")

_scheduler: BackgroundScheduler | None = None


def start_scheduler() -> None:
    global _scheduler
    _scheduler = BackgroundScheduler(timezone="UTC", daemon=True)

    # Device discovery via ARP (Phase 2)
    _scheduler.add_job(
        _arp_scan,
        trigger=IntervalTrigger(seconds=30),
        id="arp_scan",
        replace_existing=True,
    )

    # Latency / slowdown check (Phase 4)
    _scheduler.add_job(
        _latency_check,
        trigger=IntervalTrigger(seconds=60),
        id="latency_check",
        replace_existing=True,
    )

    # Speed test every N hours
    _scheduler.add_job(
        _run_speed_test,
        trigger=IntervalTrigger(hours=6),
        id="speed_test",
        replace_existing=True,
        next_run_time=None,   # don't run immediately on startup
    )

    # Expire vouchers every hour
    _scheduler.add_job(
        _expire_vouchers,
        trigger=IntervalTrigger(hours=1),
        id="expire_vouchers",
        replace_existing=True,
    )

    # Rebuild baselines at 03:00 UTC
    _scheduler.add_job(
        _rebuild_baselines,
        trigger=CronTrigger(hour=3, minute=0),
        id="rebuild_baselines",
        replace_existing=True,
    )

    # Enforce time rules every 60 s
    _scheduler.add_job(
        _enforce_time_rules,
        trigger=IntervalTrigger(seconds=60),
        id="enforce_rules",
        replace_existing=True,
    )

    # Expire approved priority grants
    _scheduler.add_job(
        _expire_priority_grants,
        trigger=IntervalTrigger(minutes=5),
        id="expire_priority",
        replace_existing=True,
    )

    # Poll nftables counters → UsageRecord every 60 s
    _scheduler.add_job(
        _poll_traffic,
        trigger=IntervalTrigger(seconds=60),
        id="poll_traffic",
        replace_existing=True,
    )

    # DNS latency check every 5 minutes
    _scheduler.add_job(
        _dns_measure,
        trigger=IntervalTrigger(minutes=5),
        id="dns_measure",
        replace_existing=True,
    )

    # Daily usage summary at 00:05 UTC
    _scheduler.add_job(
        _daily_summary,
        trigger=CronTrigger(hour=0, minute=5),
        id="daily_summary",
        replace_existing=True,
    )

    _scheduler.start()
    log.info("APScheduler started with %d jobs", len(_scheduler.get_jobs()))


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        log.info("APScheduler stopped")


# Job implementations

def _arp_scan() -> None:
    """ARP scan — discovers devices and creates NEW entries + WebSocket alerts."""
    try:
        from clarinet.database import SessionLocal
        from clarinet.models import Settings as AppSettings
        with SessionLocal() as db:
            iface_row = db.get(AppSettings, "network_interface")
            iface = iface_row.value if iface_row and iface_row.value else None

        if not iface:
            log.debug("ARP scan skipped: no network_interface configured")
            return

        from clarinet.collector.arp_scanner import run_scan_loop
        run_scan_loop(iface)
    except Exception as e:
        log.debug("ARP scan failed (Linux only?): %s", e)


def _latency_check() -> None:
    try:
        from clarinet.collector.pinger import measure_and_store
        measure_and_store()
    except Exception as e:
        log.debug("Latency check failed: %s", e)


def _run_speed_test() -> None:
    log.info("Scheduled speed test starting")
    try:
        from clarinet.collector.speed_test import run_speed_test
        run_speed_test()
    except Exception as e:
        log.error("Speed test failed: %s", e)


def _expire_vouchers() -> None:
    from clarinet.database import SessionLocal
    from clarinet.models import Voucher
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        expired = (
            db.query(Voucher)
            .filter(Voucher.status == "UNUSED", Voucher.expires_at < now)
            .all()
        )
        for v in expired:
            v.status = "EXPIRED"
        if expired:
            db.commit()
            log.info("Expired %d voucher(s)", len(expired))


def _rebuild_baselines() -> None:
    log.info("Rebuilding baselines")
    try:
        from clarinet.analytics.baseline import rebuild_all
        rebuild_all()
    except Exception as e:
        log.error("Baseline rebuild failed: %s", e)


def _enforce_time_rules() -> None:
    try:
        from clarinet.enforcer.nft_wrapper import apply_time_rules
        apply_time_rules()
    except Exception as e:
        log.debug("Rule enforcement skipped (Linux only?): %s", e)


def _expire_priority_grants() -> None:
    """Revoke approved priority grants whose window has expired."""
    from clarinet.database import SessionLocal
    from clarinet.models import PriorityGrant
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        expired = (
            db.query(PriorityGrant)
            .filter(
                PriorityGrant.decision == "APPROVED",
                PriorityGrant.expires_at != None,
                PriorityGrant.expires_at < now,
            )
            .all()
        )
        for g in expired:
            g.decision = "EXPIRED"
            # Remove tc priority if enforcer is available
            try:
                from clarinet.enforcer.tc_wrapper import remove_priority
                from clarinet.models import Settings as AppSettings
                iface_row = db.get(AppSettings, "network_interface")
                if iface_row and g.device:
                    remove_priority(iface_row.value, g.device.mac_address)
            except Exception:
                pass
        if expired:
            db.commit()
            log.info("Expired %d priority grant(s)", len(expired))


def _poll_traffic() -> None:
    """Poll nftables byte counters and write them to UsageRecord."""
    try:
        from clarinet.database import SessionLocal
        from clarinet.models import Settings as AppSettings
        with SessionLocal() as db:
            iface_row = db.get(AppSettings, "network_interface")
            iface = iface_row.value if iface_row and iface_row.value else None
        if not iface:
            return
        from clarinet.collector.traffic_counter import poll_nft_counters
        poll_nft_counters(iface)
    except Exception as e:
        log.debug("Traffic poll skipped (Linux only?): %s", e)


def _dns_measure() -> None:
    """Measure DNS resolution time — feeds SLOW_DNS diagnosis."""
    try:
        from clarinet.collector.dns_timer import measure_dns, average_dns_ms
        results = measure_dns()
        avg = average_dns_ms(results)
        if avg is not None:
            log.debug("DNS avg: %.1f ms", avg)
    except Exception as e:
        log.debug("DNS measure failed: %s", e)


def _daily_summary() -> None:
    log.info("Running daily tasks (baseline rebuild + summary)")
    _rebuild_baselines()
