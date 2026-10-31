"""
clarinet/collector/pinger.py
ICMP latency and packet-loss measurements.

Uses icmplib (needs root on Linux, works on Windows with admin).
Results feed the baseline and slowdown detection systems.
"""

import logging
import time
from dataclasses import dataclass

log = logging.getLogger("clarinet.collector.pinger")

# Targets to ping for latency measurement
PING_TARGETS = {
    "router": None,       # filled at runtime from settings
    "google_dns": "8.8.8.8",
    "cloudflare": "1.1.1.1",
}

PING_COUNT = 4
PING_INTERVAL = 0.2      # seconds between pings
PING_TIMEOUT = 2.0


@dataclass
class PingResult:
    target: str
    host: str
    avg_ms: float | None
    min_ms: float | None
    max_ms: float | None
    packet_loss: float    # 0.0 – 1.0
    reachable: bool


def ping_host(host: str, count: int = PING_COUNT) -> PingResult:
    """
    Ping a single host and return a PingResult.
    Falls back to a stub on non-Linux or missing icmplib.
    """
    try:
        from icmplib import ping as icmp_ping
        result = icmp_ping(host, count=count, interval=PING_INTERVAL, timeout=PING_TIMEOUT, privileged=True)
        return PingResult(
            target=host,
            host=host,
            avg_ms=round(result.avg_rtt, 2) if result.is_alive else None,
            min_ms=round(result.min_rtt, 2) if result.is_alive else None,
            max_ms=round(result.max_rtt, 2) if result.is_alive else None,
            packet_loss=result.packet_loss,
            reachable=result.is_alive,
        )
    except Exception as e:
        log.debug("Ping to %s failed: %s", host, e)
        return PingResult(
            target=host, host=host,
            avg_ms=None, min_ms=None, max_ms=None,
            packet_loss=1.0, reachable=False,
        )


def measure_latency() -> dict[str, PingResult]:
    """Ping all configured targets and return results keyed by name."""
    from clarinet.database import SessionLocal
    from clarinet.models import Settings as AppSettings

    results: dict[str, PingResult] = {}

    with SessionLocal() as db:
        # Get router IP from settings if configured
        router_row = db.get(AppSettings, "router_ip")
        if router_row:
            PING_TARGETS["router"] = router_row.value

    for name, host in PING_TARGETS.items():
        if host is None:
            continue
        results[name] = ping_host(host)
        log.debug("Ping %s (%s): avg=%.1fms loss=%.0f%%",
                  name, host,
                  results[name].avg_ms or 0,
                  (results[name].packet_loss or 0) * 100)

    return results


def measure_and_store() -> dict[str, PingResult]:
    """
    Measure latency, persist results to PingRecord, then feed the slowdown detector.
    Called every 60 seconds by APScheduler.
    """
    results = measure_latency()

    # Persist to PingRecord for latency history charts
    try:
        from clarinet.database import SessionLocal
        from clarinet.models import PingRecord
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        with SessionLocal() as db:
            for name, r in results.items():
                db.add(PingRecord(
                    measured_at=now,
                    target=name,
                    host=r.host,
                    avg_ms=r.avg_ms,
                    min_ms=r.min_ms,
                    max_ms=r.max_ms,
                    packet_loss=r.packet_loss,
                    reachable=r.reachable,
                ))
            db.commit()
    except Exception as e:
        log.debug("PingRecord write failed: %s", e)

    try:
        from clarinet.analytics.diagnosis import check_slowdown
        check_slowdown(results)
    except Exception as e:
        log.error("Slowdown check error: %s", e)
    return results

