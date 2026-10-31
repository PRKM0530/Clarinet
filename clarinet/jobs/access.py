"""Access jobs: speed tests, guest vouchers, priority grants and time rules."""

import logging
from datetime import datetime, timezone

from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger("clarinet.jobs.access")


def register(scheduler) -> None:
    # Speed test every N hours
    scheduler.add_job(
        run_speed_test,
        trigger=IntervalTrigger(hours=6),
        id="speed_test",
        replace_existing=True,
        next_run_time=None,   # don't run immediately on startup
    )

    # Expire vouchers every hour
    scheduler.add_job(
        expire_vouchers,
        trigger=IntervalTrigger(hours=1),
        id="expire_vouchers",
        replace_existing=True,
    )

    # Enforce time rules every 60 s
    scheduler.add_job(
        enforce_time_rules,
        trigger=IntervalTrigger(seconds=60),
        id="enforce_rules",
        replace_existing=True,
    )

    # Expire approved priority grants
    scheduler.add_job(
        expire_priority_grants,
        trigger=IntervalTrigger(minutes=5),
        id="expire_priority",
        replace_existing=True,
    )


def run_speed_test() -> None:
    log.info("Scheduled speed test starting")
    try:
        from clarinet.collector.speed_test import run_speed_test as run
        run()
    except Exception as e:
        log.error("Speed test failed: %s", e)


def expire_vouchers() -> None:
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


def enforce_time_rules() -> None:
    try:
        from clarinet.enforcer.nft_wrapper import apply_time_rules
        apply_time_rules()
    except Exception as e:
        log.debug("Rule enforcement skipped (Linux only?): %s", e)


def expire_priority_grants() -> None:
    """Revoke approved priority grants whose window has expired."""
    from clarinet.app_settings import get_setting
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
                iface = get_setting(db, "network_interface")
                if iface and g.device:
                    remove_priority(iface, g.device.mac_address)
            except Exception:
                pass
        if expired:
            db.commit()
            log.info("Expired %d priority grant(s)", len(expired))
