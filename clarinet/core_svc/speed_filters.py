"""
clarinet/core_svc/speed_filters.py
A speed test that could not run (no tool installed, tool crashed) is stored as a row with
server_host == "failed" so the history page can show it. It carries no speed information, so
anything that reasons about speed must leave it out.
"""
from sqlalchemy import or_

from clarinet.models import SpeedTestResult

FAILED_SERVER = "failed"


MAX_BELIEVABLE_LATENCY_MS = 60_000


def valid_only(query):
    """Restrict a SpeedTestResult query to tests that actually measured something."""
    return query.filter(or_(SpeedTestResult.server_host.is_(None), SpeedTestResult.server_host != FAILED_SERVER),
                        SpeedTestResult.download_mbps > 0)


def known_latency(value) -> float | None:
    """The delay if it was really measured. speedtest-cli reports 1800000 ms when it could not measure one, and a
    test with no delay is stored as 0: neither is a number to show or to reason about."""
    return value if value and 0 < value < MAX_BELIEVABLE_LATENCY_MS else None


def real_latency(db, reported) -> float | None:
    """The delay the speed test tool reported, or else Clarinet's own latest ping to the internet (at most ten
    minutes old). None when neither exists: the delay is then unknown, not zero."""
    from datetime import datetime, timedelta, timezone
    from clarinet.models import PingRecord
    if known_latency(reported) is not None:
        return reported
    since = datetime.now(timezone.utc) - timedelta(minutes=10)
    row = (db.query(PingRecord)
           .filter(PingRecord.target.in_(("cloudflare", "google_dns")), PingRecord.reachable.is_(True),
                   PingRecord.avg_ms.isnot(None), PingRecord.measured_at >= since)
           .order_by(PingRecord.measured_at.desc()).first())
    return row.avg_ms if row else None
