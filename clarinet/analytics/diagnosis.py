"""
clarinet/analytics/diagnosis.py  (M3 rewrite)
Slowdown diagnosis engine.

Fixes (F-09):
(a) Event opens only after 2+ consecutive bad samples (≥ 2 min hold)
(b) Thresholds per SRS: latency > 2× baseline, loss > 3%, speed < 50% plan
(c) Outage (packet_loss=100%, latency≫) classified as OUTAGE (CRITICAL),
    slowdown stays WARNING — not CRITICAL
(d) Per-device share from device_load.py (M2/M1 adapter, not one UsageRecord hour)
(e) DNS stored async via dns_timer (never blocks the 60 s check)
(f) Causes labelled "likely"/"possible" with evidence and suggestions
(g) "Several devices" collective-congestion rule correctly evaluated
(h) check_slowdown() returns early gracefully if no ping data yet
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from clarinet.collector.pinger import PingResult

log = logging.getLogger("clarinet.analytics.diagnosis")

# SRS thresholds
LATENCY_MULTIPLIER_DEFAULT = 2.0      # > 2× baseline avg (SRS, F-09b)
LOSS_THRESHOLD = 0.03                  # > 3% packet loss (SRS, F-09b)
SPEED_THRESHOLD = 0.50                 # < 50% of plan = likely cause (SRS, F-09b)
HEAVY_DEVICE_SHARE = 0.50             # one device > 50% of total
COLLECTIVE_SHARE = 0.90               # top-4 devices > 90% collectively
RSSI_THRESHOLD_DBM = -75              # weak Wi-Fi
DNS_SLOW_MS = 500.0

# Minimum consecutive bad samples before opening an event (F-09a)
MIN_BAD_SAMPLES = 2

# Module-level counter of consecutive bad samples (reset on "good" sample)
_consecutive_bad: int = 0


def check_slowdown(ping_results: "dict[str, PingResult]") -> None:
    """
    Called every 60 seconds with fresh ping results.
    Opens / extends / closes SlowdownEvent rows.
    Never raises; catches all exceptions internally.
    """
    global _consecutive_bad

    try:
        _check_slowdown_inner(ping_results)
    except Exception as exc:
        log.error("check_slowdown error: %s", exc)


def _best_internet_ping(ping_results):
    """
    The internet measurement to judge. Two public targets are pinged; losing only one of them says
    nothing about the connection (that one server may be down), so use the better of the two and treat
    the connection as down only when neither answers.
    """
    candidates = [ping_results.get(k) for k in ("google_dns", "cloudflare") if ping_results.get(k) is not None]
    if not candidates:
        return None
    alive = [p for p in candidates if p.reachable and p.packet_loss < 0.98]
    if not alive:
        return candidates[0]
    return min(alive, key=lambda p: (p.packet_loss, p.avg_ms if p.avg_ms is not None else 9999.0))


def _check_slowdown_inner(ping_results: "dict[str, PingResult]") -> None:
    global _consecutive_bad

    from clarinet.database import SessionLocal
    from clarinet.models import SlowdownEvent
    from clarinet.app_settings import get_setting
    from clarinet.analytics.baseline import (
        get_baseline_for_now, latency_is_elevated, is_baseline_ready
    )

    internet_ping = _best_internet_ping(ping_results)
    router_ping = ping_results.get("router")

    if internet_ping is None:
        log.debug("check_slowdown: no internet ping data yet")
        return

    with SessionLocal() as db:
        if not is_baseline_ready(db):
            log.debug("check_slowdown: baseline not ready yet")
            return

        baseline = get_baseline_for_now(db)
        multiplier = float(get_setting(db, "slowdown_latency_multiplier", str(LATENCY_MULTIPLIER_DEFAULT)))

        internet_ms = internet_ping.avg_ms or 9999.0
        internet_loss = internet_ping.packet_loss

        # Classify: outage vs slowdown
        is_outage = (
            not internet_ping.reachable
            or internet_loss >= 0.98
        )
        is_slow = is_outage or (
            latency_is_elevated(internet_ms, baseline, multiplier)
            or internet_loss > LOSS_THRESHOLD
            or _speed_below_plan_check(db)
        )

        # ── Close active event if now fine ──────────────────────────────
        active = (
            db.query(SlowdownEvent)
            .filter(SlowdownEvent.ended_at.is_(None))
            .first()
        )

        if not is_slow:
            _consecutive_bad = 0
            if active:
                active.ended_at = datetime.now(timezone.utc)
                db.commit()
                log.info("Slowdown/outage event %d ended", active.event_id)
            return

        # ── Bad sample counter (F-09a) ───────────────────────────────────
        _consecutive_bad += 1
        if _consecutive_bad < MIN_BAD_SAMPLES:
            log.debug(
                "check_slowdown: bad sample %d/%d — holding before opening event",
                _consecutive_bad, MIN_BAD_SAMPLES,
            )
            return

        # Already tracking this event
        if active:
            return

        # ── Open a new event ────────────────────────────────────────────
        log.info("Slowdown/outage detected — running diagnosis")
        causes, raw = _diagnose(db, internet_ms, router_ping, baseline, multiplier, is_outage)

        event_kind = "OUTAGE" if is_outage else "SLOWDOWN"
        level = "CRITICAL" if is_outage else "WARNING"   # F-09c fix

        event = SlowdownEvent(
            started_at=datetime.now(timezone.utc),
            causes_json=json.dumps(causes),
            raw_metrics_json=json.dumps(raw),
        )
        db.add(event)
        db.flush()

        # Alert text: plain language, no jargon
        top_cause = causes[0]["cause"] if causes else "NO_CLEAR_CAUSE"
        title, message = _format_alert(event_kind, causes, raw)

        _raise_alert(db, level, event_kind, title, message)
        db.commit()
        log.info("Event opened: %s (%s)", event_kind, top_cause)


def _speed_below_plan_check(db) -> bool:
    """Check if the latest speed test result is below 50% of plan."""
    try:
        from clarinet.models import SpeedTestResult
        from clarinet.app_settings import get_setting
        plan_dl = float(get_setting(db, "plan_download_mbps", "0") or 0)
        if plan_dl <= 0:
            return False
        from clarinet.core_svc.speed_filters import valid_only
        latest = (
            valid_only(db.query(SpeedTestResult))
            .order_by(SpeedTestResult.tested_at.desc())
            .first()
        )
        try:
            threshold = float(get_setting(db, "slowdown_speed_threshold", str(SPEED_THRESHOLD)))
        except ValueError:
            threshold = SPEED_THRESHOLD
        threshold = min(max(threshold, 0.05), 1.0)
        if latest and not latest.busy:
            return latest.download_mbps < plan_dl * threshold
    except Exception:
        pass
    return False


def _diagnose(
    db, internet_ms: float, router_ping, baseline, multiplier: float, is_outage: bool
) -> tuple[list[dict], dict]:
    """
    Run the diagnosis decision tree.
    Returns (causes_list, raw_metrics_dict).
    Each cause: {cause, confidence: likely|possible, evidence, suggestion}
    """
    from clarinet.analytics.device_load import get_device_bytes, total_bytes
    from clarinet.analytics.baseline import latency_is_elevated

    router_ms = (router_ping.avg_ms or 0) if router_ping else 0.0
    causes = []
    raw: dict = {
        "internet_ms": internet_ms,
        "router_ms": router_ms,
        "is_outage": is_outage,
    }

    # ── 1. Outage ──────────────────────────────────────────────────────
    if is_outage:
        causes.append({
            "cause": "INTERNET_OUTAGE",
            "confidence": "likely",
            "evidence": "Your internet connection is not responding to pings.",
            "suggestion": "Check if your router is online. Try restarting it.",
        })
        return causes, raw

    # ── 2. One device using > 50% of bandwidth ──────────────────────────
    device_bytes = get_device_bytes(window_s=60)
    total = sum(i + o for i, o in device_bytes.values())
    raw["total_bytes_60s"] = total
    raw["device_count"] = len(device_bytes)

    if total > 0:
        sorted_devices = sorted(device_bytes.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True)
        top_mac, (top_in, top_out) = sorted_devices[0]
        top_share = (top_in + top_out) / total

        if top_share > HEAVY_DEVICE_SHARE:
            device_name = _device_name(db, top_mac)
            causes.append({
                "cause": "ONE_DEVICE_HEAVY",
                "confidence": "likely",
                "evidence": f"{device_name} is using {top_share*100:.0f}% of your network.",
                "suggestion": f"Pause downloads or streaming on {device_name}.",
                "device_mac": top_mac,
            })

        # ── 3. Collective congestion (top-4 devices > 90%) ──────────────
        elif len(sorted_devices) >= 2:
            top4 = sorted_devices[:4]
            collective = sum(i + o for _, (i, o) in top4) / total
            if collective > COLLECTIVE_SHARE:
                names = ", ".join(_device_name(db, m) for m, _ in top4[:3])
                causes.append({
                    "cause": "COLLECTIVE_CONGESTION",
                    "confidence": "likely",
                    "evidence": f"Several devices ({names}…) together use {collective*100:.0f}% of your network.",
                    "suggestion": "Reduce simultaneous heavy use across multiple devices.",
                })
            raw["top4_share"] = round(collective, 3)

    # ── 4. Provider issue: router OK, internet slow ──────────────────────
    router_elevated = (
        router_ping is not None
        and router_ping.reachable
        and latency_is_elevated(router_ms, baseline, multiplier)
    )
    internet_elevated = latency_is_elevated(internet_ms, baseline, multiplier)

    if internet_elevated and not router_elevated:
        causes.append({
            "cause": "PROVIDER_ISSUE",
            "confidence": "likely" if not causes else "possible",
            "evidence": (
                f"Your router responds in {router_ms:.0f} ms (normal), "
                f"but the internet takes {internet_ms:.0f} ms (high)."
            ),
            "suggestion": "This is likely your internet provider. Wait and check again in 30 minutes.",
        })

    # ── 5. Local congestion: router slow, internet load low ─────────────
    elif router_elevated and total < 5_000_000:   # < 5 MB/min = low load
        causes.append({
            "cause": "LOCAL_CONGESTION",
            "confidence": "possible",
            "evidence": f"Your router is slow ({router_ms:.0f} ms). Internet load is low.",
            "suggestion": "Restart your router. Check for devices doing background updates.",
        })

    # ── 6. Slow DNS ─────────────────────────────────────────────────────
    dns_ms = _get_last_dns_ms(db)
    raw["dns_ms"] = dns_ms
    if dns_ms and dns_ms > DNS_SLOW_MS and internet_ms < 100:
        causes.append({
            "cause": "SLOW_DNS",
            "confidence": "possible",
            "evidence": f"DNS lookups are taking {dns_ms:.0f} ms (should be under 100 ms).",
            "suggestion": "Try changing your DNS to 1.1.1.1 or 8.8.8.8 in your router settings.",
        })

    # ── 7. No clear cause ───────────────────────────────────────────────
    if not causes:
        causes.append({
            "cause": "NO_CLEAR_CAUSE",
            "confidence": "possible",
            "evidence": "The network is slow but no single cause was found.",
            "suggestion": "Restart your router and wait a few minutes.",
        })

    return causes, raw


def _device_name(db, mac: str) -> str:
    """Look up a device's label or vendor for human-readable output."""
    try:
        from clarinet.models import Device
        dev = db.query(Device).filter(Device.mac_address == mac).first()
        if dev:
            return dev.label or dev.vendor or mac
    except Exception:
        pass
    return mac


def _get_last_dns_ms(db) -> float | None:
    """Return the last stored DNS latency measurement."""
    try:
        from clarinet.collector.dns_timer import average_dns_ms, measure_dns
        # Use cached results if available (dns_timer stores them)
        from clarinet.collector import dns_timer as _dt
        if hasattr(_dt, "_last_results") and _dt._last_results:
            return average_dns_ms(_dt._last_results)
    except Exception:
        pass
    return None


def _format_alert(event_kind: str, causes: list[dict], raw: dict) -> tuple[str, str]:
    """Format plain-language alert title and message (DASH-4)."""
    top = causes[0] if causes else {}
    cause_name = top.get("cause", "NO_CLEAR_CAUSE")
    evidence = top.get("evidence", "")
    suggestion = top.get("suggestion", "")

    if event_kind in ("OUTAGE", "INTERNET_OUTAGE") or cause_name == "INTERNET_OUTAGE":
        title = "Your internet connection seems to be down"
    elif cause_name == "ONE_DEVICE_HEAVY":
        title = "One device is slowing down the network"
    elif cause_name == "COLLECTIVE_CONGESTION":
        title = "Several devices are slowing down the network"
    elif cause_name == "PROVIDER_ISSUE":
        title = "Your internet provider may be having issues"
    elif cause_name == "LOCAL_CONGESTION":
        title = "Your router seems congested"
    elif cause_name == "SLOW_DNS":
        title = "Website lookups are unusually slow"
    else:
        title = "Your internet is slower than usual"

    message = evidence
    if suggestion:
        message += f" {suggestion}"
    if len(causes) > 1:
        others = ", ".join(c["cause"].replace("_", " ").title() for c in causes[1:3])
        message += f" (Other possible factors: {others}.)"

    return title, message


def _raise_alert(db, level: str, alert_type: str, title: str, message: str) -> None:
    """Create a slowdown/outage alert, using M1's helper if available."""
    try:
        from clarinet.core_svc.alerts import raise_alert
        raise_alert(db, level, alert_type, title, message, cooldown_s=300)
        return
    except ImportError:
        pass
    except Exception as exc:
        log.error("raise_alert failed: %s", exc)

    # Fallback
    try:
        from clarinet.models import Alert
        existing = db.query(Alert).filter(Alert.type == alert_type, Alert.status == "OPEN").first()
        if not existing:
            db.add(Alert(level=level, type=alert_type, title=title, message=message))
    except Exception as exc:
        log.error("Alert fallback failed: %s", exc)
