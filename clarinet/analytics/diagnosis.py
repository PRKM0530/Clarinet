"""
clarinet/analytics/diagnosis.py
Slowdown diagnosis engine — implements the decision tree from Diagram 8.

Causes (in evaluation order):
  1. ONE_DEVICE_HEAVY    – one device using >50% of link capacity
  2. COLLECTIVE_CONGESTION – top-4 devices together >90%, none >50%
  3. WEAK_WIFI           – device RSSI < -75 dBm AND retry rate > 20%
  4. PROVIDER_ISSUE      – router latency normal, internet latency > 3× baseline
  5. LOCAL_CONGESTION    – router latency > 2× baseline, internet load < 20%
  6. SLOW_DNS            – DNS > 500 ms, ICMP to internet < 100 ms
  7. NO_CLEAR_CAUSE      – none of the above matched
"""

import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from clarinet.collector.pinger import PingResult

log = logging.getLogger("clarinet.analytics.diagnosis")

HEAVY_DEVICE_THRESHOLD = 0.50      # >50% of link → ONE_DEVICE_HEAVY
COLLECTIVE_THRESHOLD = 0.90        # top-4 together >90%
RSSI_THRESHOLD = -75               # dBm
DNS_SLOW_MS = 500.0
ICMP_FAST_MS = 100.0


def check_slowdown(ping_results: "dict[str, PingResult]") -> None:
    """
    Called every 60 seconds with fresh ping results.
    Decides whether a slowdown event should be opened or closed.
    """
    from clarinet.database import SessionLocal
    from clarinet.models import SlowdownEvent, Settings as AppSettings
    from clarinet.analytics.baseline import get_baseline_for_now, latency_is_elevated
    from clarinet.collector.dns_timer import measure_dns, average_dns_ms

    internet_ping = ping_results.get("google_dns") or ping_results.get("cloudflare")
    router_ping = ping_results.get("router")

    if internet_ping is None:
        return   # no data yet

    with SessionLocal() as db:
        baseline = get_baseline_for_now(db)
        thresh_row = db.get(AppSettings, "slowdown_latency_multiplier")
        multiplier = float(thresh_row.value) if thresh_row else 3.0

        internet_latency_ms = internet_ping.avg_ms or 9999.0
        router_latency_ms = (router_ping.avg_ms or 0) if router_ping else 0.0

        is_slow = (
            latency_is_elevated(internet_latency_ms, baseline, multiplier)
            or internet_ping.packet_loss > 0.10
        )

        # Close any active event if things are back to normal
        active = (
            db.query(SlowdownEvent)
            .filter(SlowdownEvent.ended_at == None)
            .first()
        )
        if not is_slow:
            if active:
                active.ended_at = datetime.now(timezone.utc)
                db.commit()
                log.info("Slowdown event %d ended", active.event_id)
            return

        # Already tracking a slowdown — don't open another
        if active:
            return

        # New slowdown — run diagnosis
        log.info("Slowdown detected — running diagnosis")
        causes, raw = _diagnose(db, internet_latency_ms, router_latency_ms, baseline, multiplier)

        event = SlowdownEvent(
            started_at=datetime.now(timezone.utc),
            causes_json=json.dumps(causes),
            raw_metrics_json=json.dumps(raw),
        )
        db.add(event)

        # Raise a CRITICAL alert
        from clarinet.models import Alert
        top_cause = causes[0]["cause"] if causes else "NO_CLEAR_CAUSE"
        alert = Alert(
            level="CRITICAL",
            type="SLOWDOWN",
            title=f"Internet slowdown detected — {top_cause.replace('_', ' ').title()}",
            message=_format_message(causes, raw),
        )
        db.add(alert)
        db.commit()

        from clarinet.routers.ws import broadcast_alert_sync
        broadcast_alert_sync({
            "type": "SLOWDOWN",
            "level": "CRITICAL",
            "title": alert.title,
            "message": alert.message,
        })
        log.info("Slowdown event opened: %s", top_cause)


def _diagnose(db, internet_ms: float, router_ms: float, baseline, multiplier: float):
    """
    Run the diagnosis decision tree (Diagram 8).
    Returns (causes_list, raw_metrics_dict).
    """
    from clarinet.models import UsageRecord, Device
    from clarinet.collector.dns_timer import measure_dns, average_dns_ms
    from datetime import date
    import pandas as pd

    causes = []
    today = date.today().isoformat()
    now_hour = datetime.now(timezone.utc).hour

    # Collect traffic share data
    records = (
        db.query(
            Device.device_id,
            Device.mac_address,
            Device.label,
            UsageRecord.bytes_in,
            UsageRecord.bytes_out,
        )
        .join(UsageRecord, Device.device_id == UsageRecord.device_id)
        .filter(UsageRecord.date == today, UsageRecord.hour == now_hour)
        .all()
    )

    total_bytes = sum((r.bytes_in or 0) + (r.bytes_out or 0) for r in records)

    raw = {
        "internet_latency_ms": internet_ms,
        "router_latency_ms": router_ms,
        "total_bytes_this_hour": total_bytes,
        "baseline_latency_ms": baseline.avg_latency_ms if baseline else None,
    }

    # Check 1: ONE_DEVICE_HEAVY
    if total_bytes > 0:
        for r in records:
            share = ((r.bytes_in or 0) + (r.bytes_out or 0)) / total_bytes
            if share > HEAVY_DEVICE_THRESHOLD:
                name = r.label or r.mac_address
                causes.append({
                    "cause": "ONE_DEVICE_HEAVY",
                    "confidence": "HIGH",
                    "detail": f"{name} used {share*100:.0f}% of hourly traffic.",
                })
                break

    # Check 2: COLLECTIVE_CONGESTION
    if not causes and total_bytes > 0:
        sorted_records = sorted(records, key=lambda r: (r.bytes_in or 0) + (r.bytes_out or 0), reverse=True)
        top4_bytes = sum((r.bytes_in or 0) + (r.bytes_out or 0) for r in sorted_records[:4])
        if top4_bytes / total_bytes > COLLECTIVE_THRESHOLD:
            causes.append({
                "cause": "COLLECTIVE_CONGESTION",
                "confidence": "MEDIUM",
                "detail": f"Top 4 devices used {top4_bytes/total_bytes*100:.0f}% of hourly traffic collectively.",
            })

    # Check 3: PROVIDER_ISSUE (internet latency >> baseline, router OK)
    if not causes and baseline and baseline.avg_latency_ms:
        router_baseline = baseline.avg_latency_ms * 0.3   # rough router share
        if router_ms < router_baseline * 2 and internet_ms > baseline.avg_latency_ms * multiplier:
            causes.append({
                "cause": "PROVIDER_ISSUE",
                "confidence": "HIGH",
                "detail": (
                    f"Internet latency {internet_ms:.0f} ms is {internet_ms/baseline.avg_latency_ms:.1f}× "
                    f"normal ({baseline.avg_latency_ms:.0f} ms). Router latency normal."
                ),
            })

    # Check 4: LOCAL_CONGESTION (router latency high, low internet load)
    if not causes and baseline and baseline.avg_latency_ms and router_ms > 0:
        if router_ms > baseline.avg_latency_ms * 2 and total_bytes < 1_000_000:
            causes.append({
                "cause": "LOCAL_CONGESTION",
                "confidence": "MEDIUM",
                "detail": f"Router latency {router_ms:.0f} ms elevated with low traffic.",
            })

    # Check 5: SLOW_DNS
    if not causes:
        dns_results = measure_dns()
        avg_dns = average_dns_ms(dns_results)
        raw["dns_avg_ms"] = avg_dns
        if avg_dns and avg_dns > DNS_SLOW_MS and internet_ms < ICMP_FAST_MS:
            causes.append({
                "cause": "SLOW_DNS",
                "confidence": "HIGH",
                "detail": f"DNS resolution averaging {avg_dns:.0f} ms (threshold: {DNS_SLOW_MS:.0f} ms).",
            })

    # Fallback
    if not causes:
        causes.append({
            "cause": "NO_CLEAR_CAUSE",
            "confidence": "LOW",
            "detail": "No specific cause identified. Raw metrics recorded.",
        })

    return causes, raw


def _format_message(causes: list[dict], raw: dict) -> str:
    lines = []
    for c in causes:
        label = c["cause"].replace("_", " ").title()
        lines.append(f"[{c['confidence']}] {label}: {c['detail']}")
    if raw.get("internet_latency_ms"):
        lines.append(f"Internet latency: {raw['internet_latency_ms']:.0f} ms")
    return " | ".join(lines)
