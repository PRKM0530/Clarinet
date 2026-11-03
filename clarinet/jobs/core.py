"""
clarinet/jobs/core.py
M1 core APScheduler job registrations.

Jobs:
  scan_cycle        — ARP device discovery (every 15 s)
  traffic_cycle     — Traffic counter poll (every 60 s)
  aggregate_hourly  — Roll UsageRecord into UsageDaily (every hour)
  limit_check       — Data limit thresholds (every 5 min)
  daily_summary     — Build DailySummary (daily at 00:05)
  weekly_summary    — Build WeeklySummary (Mondays at 00:10)
  retention         — Purge old data (daily at 03:00)
  heartbeat_watchdog — Check collector heartbeats (every 2 min)
"""

import logging

from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger("clarinet.jobs.core")


def register(scheduler) -> None:
    """Register all M1 jobs with the APScheduler instance."""

    # Usage comes from the nftables accounting counters (the rules are installed by the reconcile job)
    import platform
    from clarinet.collector.traffic_counter import HostTrafficSource, NftAccountingSource, set_source
    set_source(HostTrafficSource() if platform.system() == "Windows" else NftAccountingSource())

    scheduler.add_job(
        scan_cycle,
        trigger=IntervalTrigger(seconds=15),
        id="scan_cycle",
        replace_existing=True,
    )

    scheduler.add_job(
        traffic_cycle,
        trigger=IntervalTrigger(seconds=60),
        id="traffic_cycle",
        replace_existing=True,
    )

    scheduler.add_job(
        aggregate_hourly,
        trigger=CronTrigger(minute=2),   # 2 minutes past each hour
        id="aggregate_hourly",
        replace_existing=True,
    )

    scheduler.add_job(
        limit_check,
        trigger=IntervalTrigger(minutes=5),
        id="limit_check",
        replace_existing=True,
    )

    scheduler.add_job(
        daily_summary,
        trigger=CronTrigger(hour=0, minute=5),
        id="daily_summary",
        replace_existing=True,
    )

    scheduler.add_job(
        weekly_summary,
        trigger=CronTrigger(day_of_week="mon", hour=0, minute=10),
        id="weekly_summary",
        replace_existing=True,
    )

    scheduler.add_job(
        retention,
        trigger=CronTrigger(hour=3, minute=0),
        id="retention",
        replace_existing=True,
    )

    scheduler.add_job(
        heartbeat_watchdog,
        trigger=IntervalTrigger(minutes=2),
        id="heartbeat_watchdog",
        replace_existing=True,
    )


# ─── Job implementations ──────────────────────────────────────────────────────

def scan_cycle() -> None:
    """ARP device discovery cycle."""
    try:
        from clarinet.app_settings import get_setting
        from clarinet.database import SessionLocal
        from clarinet.collector.arp_scanner import scan_once

        with SessionLocal() as db:
            iface = get_setting(db, "network_interface") or ""
            import platform
            if not iface and platform.system() != "Windows":      # Windows reads `arp -a` and needs no interface name
                log.debug("scan_cycle: no network_interface configured — skipping")
                return
            scan_once(db, iface)
            from clarinet.core_svc.presence import record_presence_changes
            record_presence_changes(db)
        from clarinet.core_svc.heartbeat import beat
        beat("arp_scanner", 15)
    except Exception as exc:
        log.debug("scan_cycle failed (Linux only?): %s", exc)


def traffic_cycle() -> None:
    """Traffic counter poll and DB write."""
    try:
        from clarinet.collector.traffic_counter import poll_and_record
        deltas = poll_and_record()
        if deltas:
            log.debug("traffic_cycle: %d devices updated", len(deltas))
        from clarinet.core_svc.heartbeat import beat
        beat("traffic_counter", 60)
    except Exception as exc:
        log.debug("traffic_cycle failed: %s", exc)


def aggregate_hourly() -> None:
    """Roll per-hour UsageRecord rows into daily totals in UsageDaily."""
    try:
        from datetime import date, timedelta
        from sqlalchemy import func
        from clarinet.database import SessionLocal
        from clarinet.models import UsageRecord
        from clarinet.models.traffic import UsageDaily

        yesterday = (date.today() - timedelta(days=1)).isoformat()

        with SessionLocal() as db:
            rows = (
                db.query(
                    UsageRecord.device_id,
                    func.sum(UsageRecord.bytes_in).label("bi"),
                    func.sum(UsageRecord.bytes_out).label("bo"),
                )
                .filter(UsageRecord.date == yesterday)
                .group_by(UsageRecord.device_id)
                .all()
            )
            for row in rows:
                existing = (
                    db.query(UsageDaily)
                    .filter(UsageDaily.device_id == row.device_id, UsageDaily.date == yesterday)
                    .first()
                )
                if existing is None:
                    db.add(UsageDaily(
                        device_id=row.device_id,
                        date=yesterday,
                        bytes_in=row.bi or 0,
                        bytes_out=row.bo or 0,
                    ))
                else:
                    existing.bytes_in = row.bi or 0
                    existing.bytes_out = row.bo or 0
            db.commit()
            log.debug("aggregate_hourly: %d device rows rolled up", len(rows))
    except Exception as exc:
        log.warning("aggregate_hourly failed: %s", exc)


def limit_check() -> None:
    """Check data limit and raise/resolve alerts."""
    try:
        from clarinet.database import SessionLocal
        from clarinet.core_svc.limit_service import check_and_alert

        with SessionLocal() as db:
            check_and_alert(db)
    except Exception as exc:
        log.debug("limit_check failed: %s", exc)


def daily_summary() -> None:
    """Build and persist daily summary."""
    try:
        from datetime import date, timedelta
        from clarinet.database import SessionLocal
        from clarinet.core_svc.summaries import build_daily_summary

        yesterday = date.today() - timedelta(days=1)
        with SessionLocal() as db:
            summary = build_daily_summary(db, yesterday)
            log.info(
                "daily_summary: %s total_bytes=%d open_alerts=%d",
                summary.date, summary.total_bytes, summary.open_alerts,
            )
    except Exception as exc:
        log.warning("daily_summary failed: %s", exc)


def weekly_summary() -> None:
    """Build and persist weekly summary (Mondays)."""
    try:
        from datetime import date, timedelta
        from clarinet.database import SessionLocal
        from clarinet.core_svc.summaries import build_weekly_summary

        last_sunday = date.today() - timedelta(days=1)
        with SessionLocal() as db:
            summary = build_weekly_summary(db, last_sunday)
            log.info(
                "weekly_summary: %s–%s total_bytes=%d",
                summary.week_start, summary.week_end, summary.total_bytes,
            )
    except Exception as exc:
        log.warning("weekly_summary failed: %s", exc)


def retention() -> None:
    """Purge old data according to retention settings."""
    try:
        from clarinet.database import SessionLocal
        from clarinet.core_svc import purge
        from clarinet.core_svc.settings_m1 import (
            retention_traffic_days,
            retention_samples_hours,
            retention_login_attempts_days,
            retention_domain_days,
        )

        with SessionLocal() as db:
            d_days = retention_domain_days(db)
            s_hours = retention_samples_hours(db)
            t_days = retention_traffic_days(db)
            la_days = retention_login_attempts_days(db)

        with SessionLocal() as db:
            n1 = purge.purge_old_samples(db, hours=s_hours)
            n2 = purge.purge_old_usage(db, days=t_days)
            n3 = purge.purge_old_login_attempts(db, days=la_days)
            n4 = purge.purge_old_domains(db, days=d_days)
            log.info("retention: samples=%d usage=%d logins=%d domains=%d purged", n1, n2, n3, n4)
    except Exception as exc:
        log.warning("retention job failed: %s", exc)


def heartbeat_watchdog() -> None:
    """Alert if any collector thread has gone silent."""
    try:
        from datetime import datetime
        from clarinet.database import SessionLocal
        from clarinet.models.traffic import CollectorHeartbeat
        from clarinet.core_svc.alerts import raise_alert

        with SessionLocal() as db:
            from clarinet.core_svc.capabilities import COLLECTOR_FEATURE, unavailable
            from clarinet.models import Alert
            cannot = unavailable()
            now = datetime.utcnow()
            rows = db.query(CollectorHeartbeat).all()
            for hb in rows:
                if COLLECTOR_FEATURE.get(hb.collector) in cannot:
                    # not a fault: this computer cannot run it, and the pages say so. Close any old alert.
                    db.query(Alert).filter(Alert.type == "COLLECTOR_SILENT", Alert.status == "OPEN",
                                           Alert.title == f"Collector '{hb.collector}' has stopped").update({"status": "RESOLVED"})
                    db.commit()
                    continue
                lag = (now - hb.last_seen).total_seconds()
                threshold = hb.interval_s * 2
                if lag > threshold:
                    raise_alert(
                        db,
                        level="WARNING",
                        type="COLLECTOR_SILENT",
                        title=f"Collector '{hb.collector}' has stopped",
                        message=f"No heartbeat from '{hb.collector}' for {int(lag)}s (expected ≤{threshold}s).",
                        cooldown_s=600,
                    )
    except Exception as exc:
        log.debug("heartbeat_watchdog failed: %s", exc)
