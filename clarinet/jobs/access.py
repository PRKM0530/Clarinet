"""
clarinet/jobs/access.py  (M2 rewrite)
Background jobs: speed tests, guest vouchers, priority grants, time rules.

Fixes (F-02, F-03):
- next_run_time=None removed (was pausing the job)
- Speed test interval reads 'speed_test_interval_hours' setting
- expire_vouchers handles ACTIVE vouchers and closes nft access
- Priority grant expiry applies tc removal properly
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger("clarinet.jobs.access")


def register(scheduler) -> None:
    # Speed test: run immediately at startup, then every N hours
    scheduler.add_job(
        run_speed_test,
        trigger=IntervalTrigger(hours=6),   # overridden at runtime by _get_interval()
        id="speed_test",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        # next_run_time defaults to now → runs immediately on startup (F-02 fix)
        next_run_time=datetime.now(timezone.utc),
    )

    # Expire vouchers every minute so a guest's access ends close to the time on the voucher
    scheduler.add_job(
        expire_vouchers,
        trigger=IntervalTrigger(seconds=60),
        id="expire_vouchers",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        next_run_time=datetime.now(timezone.utc),
    )

    # Enforce time rules every 60 s
    scheduler.add_job(
        enforce_time_rules,
        trigger=IntervalTrigger(seconds=60),
        id="enforce_rules",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        next_run_time=datetime.now(timezone.utc),
    )

    # Expire approved priority grants every 60 s (was 5 min, too coarse)
    scheduler.add_job(
        expire_priority_grants,
        trigger=IntervalTrigger(seconds=60),
        id="expire_priority",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        next_run_time=datetime.now(timezone.utc),
    )

    # Full reconcile every minute: re-applies blocks, guests and counters after IP changes or a reboot
    scheduler.add_job(
        reconcile_full,
        trigger=IntervalTrigger(seconds=60),
        id="reconcile_full",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        next_run_time=datetime.now(timezone.utc),
    )

    # Handle pending reconcile requests (block/unblock immediately after state change)
    scheduler.add_job(
        reconcile_if_requested,
        trigger=IntervalTrigger(seconds=15),
        id="reconcile",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        next_run_time=datetime.now(timezone.utc),
    )


# ──────────────────────────────────────────────
# Speed test
# ──────────────────────────────────────────────

def run_speed_test() -> None:
    """Run speed test using interval from 'speed_test_interval_hours' setting."""
    log.info("Scheduled speed test starting")
    try:
        # Re-read interval and reschedule if it changed (F-02)
        _reschedule_speed_test_if_needed()

        from clarinet.collector.speed_test import run_speed_test as run
        run()
    except Exception as e:
        log.error("Speed test failed: %s", e)


def _reschedule_speed_test_if_needed() -> None:
    """Reschedule the speed test job if the interval setting changed."""
    try:
        from clarinet.database import SessionLocal
        from clarinet.app_settings import get_setting
        from clarinet.scheduler import scheduler as _sched

        with SessionLocal() as db:
            hours = int(float(get_setting(db, "speed_test_interval_hours", "6")))
            hours = max(1, min(hours, 168))  # 1h – 1 week

        job = _sched.get_job("speed_test")
        if job:
            current = getattr(job.trigger, "interval", None)
            if current and current.total_seconds() != hours * 3600:
                job.reschedule(IntervalTrigger(hours=hours))
                log.info("Speed test rescheduled to every %d hour(s)", hours)
    except Exception as exc:
        log.debug("Could not reschedule speed test: %s", exc)


# ──────────────────────────────────────────────
# Voucher expiry  (F-03 fix)
# ──────────────────────────────────────────────

def expire_vouchers() -> None:
    """
    Expire vouchers whose time is up (both UNUSED and ACTIVE).
    For ACTIVE vouchers: close nft guest access and delete EnforcementStatus.
    """
    from clarinet.database import SessionLocal
    from clarinet.models import Voucher

    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        # Expire UNUSED vouchers whose time window has passed
        unused_expired = (
            db.query(Voucher)
            .filter(Voucher.status == "UNUSED", Voucher.expires_at < now)
            .all()
        )
        for v in unused_expired:
            v.status = "EXPIRED"

        # Expire ACTIVE vouchers (close network access)
        active_expired = (
            db.query(Voucher)
            .filter(Voucher.status == "ACTIVE", Voucher.expires_at < now)
            .all()
        )
        for v in active_expired:
            v.status = "EXPIRED"
            _close_guest_access_for_voucher(db, v)

        # Also check data-cap exceeded
        _check_data_cap_exceeded(db, now)

        total = len(unused_expired) + len(active_expired)
        db.commit()                                   # also saves vouchers expired by their data cap
        if total:
            log.info("Expired %d voucher(s) (%d active)", total, len(active_expired))


def _close_guest_access_for_voucher(db, voucher) -> None:
    """Close nft access and remove EnforcementStatus for a voucher."""
    try:
        from clarinet.models.guest import EnforcementStatus
        from clarinet.enforcer.nft_wrapper import close_guest_access
        from clarinet.models import Device

        records = (
            db.query(EnforcementStatus)
            .filter(EnforcementStatus.voucher_id == voucher.voucher_id)
            .all()
        )
        for record in records:
            close_guest_access(record.mac)
            try:
                from clarinet.app_settings import get_setting
                from clarinet.enforcer.tc_wrapper import remove_rate_limit
                iface = get_setting(db, "guest.interface", get_setting(db, "network_interface", ""))
                if iface:
                    remove_rate_limit(iface, record.mac)
            except Exception:
                pass
            # Update device state back (set to FORGOTTEN if it was a guest device)
            device = db.query(Device).filter(Device.mac_address == record.mac).first()
            if device and device.state == "GUEST":
                db.delete(device)
            db.delete(record)
        log.info("Closed guest access for voucher %d (%d device(s))", voucher.voucher_id, len(records))
    except Exception as exc:
        log.error("_close_guest_access_for_voucher error: %s", exc)


def _check_data_cap_exceeded(db, now) -> None:
    """Expire ACTIVE vouchers that have exceeded their data cap."""
    try:
        from clarinet.models.guest import EnforcementStatus
        from clarinet.models import Voucher

        records = db.query(EnforcementStatus).all()
        for record in records:
            voucher = db.get(Voucher, record.voucher_id)
            if not voucher or voucher.status != "ACTIVE":
                continue
            if voucher.data_cap_mb and record.bytes_used > voucher.data_cap_mb * 1024 * 1024:
                voucher.status = "EXPIRED"
                _close_guest_access_for_voucher(db, voucher)
                log.info("Voucher %d expired: data cap exceeded", voucher.voucher_id)
    except Exception as exc:
        log.debug("_check_data_cap_exceeded: %s", exc)


# ──────────────────────────────────────────────
# Time rules
# ──────────────────────────────────────────────

def enforce_time_rules() -> None:
    try:
        from clarinet.enforcer.nft_wrapper import apply_time_rules
        apply_time_rules()
    except Exception as e:
        log.debug("Rule enforcement skipped: %s", e)


# ──────────────────────────────────────────────
# Priority grants
# ──────────────────────────────────────────────

def expire_priority_grants() -> None:
    """Revoke approved priority grants whose window has expired."""
    from clarinet.database import SessionLocal
    from clarinet.models import PriorityGrant
    from clarinet.app_settings import get_setting

    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        expired = (
            db.query(PriorityGrant)
            .filter(
                PriorityGrant.decision == "APPROVED",
                PriorityGrant.expires_at.isnot(None),
                PriorityGrant.expires_at < now,
            )
            .all()
        )
        iface = get_setting(db, "network_interface", "")
        for g in expired:
            g.decision = "EXPIRED"
            if iface and g.device:
                try:
                    from clarinet.enforcer.tc_wrapper import remove_priority
                    remove_priority(iface, g.device.mac_address)
                except Exception:
                    pass
            # Update fairness credit
            if g.duration_min:
                _record_fairness_used(db, g.member_id, g.duration_min)

        if expired:
            db.commit()
            log.info("Expired %d priority grant(s)", len(expired))


def _record_fairness_used(db, member_id: int, minutes: int) -> None:
    """Update fairness credit for the day."""
    try:
        from clarinet.models.guest import FairnessCredit
        from clarinet.app_settings import get_setting
        from zoneinfo import ZoneInfo
        from datetime import datetime

        tz_name = get_setting(db, "timezone", "Asia/Kolkata")
        tz = ZoneInfo(tz_name)
        today = datetime.now(tz).strftime("%Y-%m-%d")

        credit = (
            db.query(FairnessCredit)
            .filter(FairnessCredit.member_id == member_id, FairnessCredit.day == today)
            .first()
        )
        if credit:
            credit.minutes_used += minutes
        else:
            db.add(FairnessCredit(member_id=member_id, day=today, minutes_used=minutes))
    except Exception as exc:
        log.debug("_record_fairness_used: %s", exc)


# ──────────────────────────────────────────────
# Reconcile
# ──────────────────────────────────────────────

def reconcile_full() -> None:
    from clarinet.enforcer.reconcile import reconcile_now
    reconcile_now()


def reconcile_if_requested() -> None:
    """Apply nft rules if a reconcile was requested (e.g. after device block/unblock)."""
    try:
        from clarinet.enforcer.reconcile import consume_reconcile, reconcile_now
        if consume_reconcile():
            reconcile_now()
    except Exception as exc:
        log.debug("reconcile_if_requested: %s", exc)
