"""
clarinet/collector/pinger.py  (M3 fix)
ICMP latency collector — stores PingRecord rows, feeds slowdown detector.

Fixes (F-13):
- PING_TARGETS is not mutated globally; router IP read fresh each call
- Non-privileged fallback (no root crash on Windows)
- Cadence 60 s is enforced by the scheduler, not by sleeping here
- Each call is isolated (no global state mutation)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger("clarinet.collector.pinger")

PING_COUNT = 4
PING_INTERVAL = 0.25
PING_TIMEOUT = 2.0

# Fixed public targets (never mutated)
_PUBLIC_TARGETS: dict[str, str] = {
    "google_dns": "8.8.8.8",
    "cloudflare": "1.1.1.1",
}


@dataclass
class PingResult:
    target: str
    host: str
    avg_ms: float | None
    min_ms: float | None
    max_ms: float | None
    packet_loss: float   # 0.0–1.0
    reachable: bool


def _get_router_ip(db=None) -> str | None:
    """Read router IP from settings without mutating any global."""
    try:
        if db is not None:
            from clarinet.app_settings import get_setting
            ip = get_setting(db, "router_ip", "")
            return ip if ip else None
        from clarinet.database import SessionLocal
        from clarinet.app_settings import get_setting
        with SessionLocal() as _db:
            ip = get_setting(_db, "router_ip", "")
            return ip if ip else None
    except Exception:
        return None


def ping_host(host: str, target_name: str = "") -> PingResult:
    """
    Ping a single host and return a PingResult.
    Tries privileged ICMP first; falls back to unprivileged on failure.
    Never crashes — returns an unreachable result on any exception.
    """
    target_name = target_name or host
    for privileged in (True, False):
        try:
            from icmplib import ping as icmp_ping
            result = icmp_ping(
                host,
                count=PING_COUNT,
                interval=PING_INTERVAL,
                timeout=PING_TIMEOUT,
                privileged=privileged,
            )
            return PingResult(
                target=target_name,
                host=host,
                avg_ms=round(result.avg_rtt, 2) if result.is_alive else None,
                min_ms=round(result.min_rtt, 2) if result.is_alive else None,
                max_ms=round(result.max_rtt, 2) if result.is_alive else None,
                packet_loss=result.packet_loss,
                reachable=result.is_alive,
            )
        except PermissionError:
            if not privileged:
                break
            continue  # retry unprivileged
        except Exception as exc:
            log.debug("Ping %s failed (privileged=%s): %s", host, privileged, exc)
            break

    return PingResult(
        target=target_name, host=host,
        avg_ms=None, min_ms=None, max_ms=None,
        packet_loss=1.0, reachable=False,
    )


def measure_latency(db=None) -> dict[str, PingResult]:
    """
    Ping all configured targets and return results keyed by name.
    Router IP is read fresh from settings each call (F-13 fix).
    """
    targets = dict(_PUBLIC_TARGETS)   # copy, never mutate the original

    router_ip = _get_router_ip(db)
    if router_ip:
        targets["router"] = router_ip

    results: dict[str, PingResult] = {}
    for name, host in targets.items():
        results[name] = ping_host(host, target_name=name)
        log.debug(
            "Ping %s (%s): avg=%s ms loss=%.0f%%",
            name, host,
            f"{results[name].avg_ms:.1f}" if results[name].avg_ms is not None else "—",
            (results[name].packet_loss or 0) * 100,
        )

    return results


def measure_and_store() -> dict[str, PingResult]:
    """
    Measure latency, persist to PingRecord, feed the slowdown detector.
    Called every 60 seconds by APScheduler.
    """
    from clarinet.database import SessionLocal
    from clarinet.models import PingRecord

    with SessionLocal() as db:
        results = measure_latency(db)
        now = datetime.now(timezone.utc)
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

    try:
        from clarinet.analytics.diagnosis import check_slowdown
        check_slowdown(results)
    except Exception as exc:
        log.error("Slowdown check error: %s", exc)

    return results
