"""
clarinet/analytics/device_load.py
Per-device traffic load adapter — contract C-03, C-11.

Source priority (D-06 / PLAN_PATCHES_M2_M3 patch 12):
  1. clarinet.enforcer.accounting.read_counters()  (M2 nft counters, lazy import)
  2. clarinet.collector.traffic_counter.get_recent_device_bytes(window_s)  (M1, lazy import)
  3. Hourly UsageRecord from core DB (coarse fallback)

Returns {mac: (bytes_in, bytes_out)} for the requested window.
Used by analytics/diagnosis.py to compute per-device share of traffic.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

log = logging.getLogger("clarinet.analytics.device_load")


def get_device_bytes(window_s: int = 60) -> dict[str, tuple[int, int]]:
    """
    Return {mac: (bytes_in, bytes_out)} over the last `window_s` seconds.
    Falls back gracefully through three sources.
    """
    # Source 1: M2 nft accounting counters
    try:
        from clarinet.enforcer.accounting import read_counters
        counters = read_counters()
        if counters:
            log.debug("device_load: using nft accounting (%d entries)", len(counters))
            return counters
    except ImportError:
        pass
    except Exception as exc:
        log.debug("device_load: nft accounting failed: %s", exc)

    # Source 2: M1 traffic_counter
    try:
        from clarinet.collector.traffic_counter import get_recent_device_bytes
        result = get_recent_device_bytes(window_s)
        if result:
            log.debug("device_load: using M1 traffic_counter (%d entries)", len(result))
            return result
    except ImportError:
        pass
    except Exception as exc:
        log.debug("device_load: traffic_counter failed: %s", exc)

    # Source 3: Hourly UsageRecord (coarse)
    return _from_usage_records(window_s)


def _from_usage_records(window_s: int) -> dict[str, tuple[int, int]]:
    """Fallback: read the last hour's UsageRecord rows."""
    try:
        from clarinet.database import SessionLocal
        from clarinet.models import UsageRecord, Device
        from datetime import date

        now = datetime.now(timezone.utc)
        hour_start = now.replace(minute=0, second=0, microsecond=0)

        with SessionLocal() as db:
            rows = (
                db.query(Device.mac_address, UsageRecord.bytes_in, UsageRecord.bytes_out)
                .join(UsageRecord, Device.device_id == UsageRecord.device_id)
                .filter(UsageRecord.hour == hour_start)
                .all()
            )
            result = {mac: (b_in, b_out) for mac, b_in, b_out in rows}
            log.debug("device_load: using UsageRecord fallback (%d entries)", len(result))
            return result
    except Exception as exc:
        log.debug("device_load: UsageRecord fallback failed: %s", exc)
        return {}


def total_bytes(window_s: int = 60) -> int:
    """Return total bytes across all devices in the window (for busy detection)."""
    counters = get_device_bytes(window_s)
    return sum(i + o for i, o in counters.values())

