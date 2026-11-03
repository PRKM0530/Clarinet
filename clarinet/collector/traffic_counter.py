"""
clarinet/collector/traffic_counter.py
Per-device traffic byte accounting for M1. (C-03 contract)

Architecture:
  TrafficSource (abstract)
    ├── NftAccountingSource  — reads nftables counters (lazy import of enforcer)
    ├── PacketSniffSource    — passive packet sniffing (Linux + root only)
    └── NullSource           — no-op (dev/test)

Public API (C-03):
  get_recent_device_bytes(window_s) -> dict[mac, (bytes_in, bytes_out)]

Thread-safe: all DB writes use _lock.
"""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from datetime import date, datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from clarinet.core_svc.runner import Runner

log = logging.getLogger("clarinet.collector.traffic")

_lock = threading.Lock()

# In-memory rolling window: mac -> list of (timestamp, bytes_in, bytes_out)
_samples: dict[str, list[tuple[float, int, int]]] = {}
_WINDOW_S = 300  # 5-minute rolling window for get_recent_device_bytes


# ─── Abstract source ──────────────────────────────────────────────────────────

class TrafficSource(ABC):
    """Abstract traffic counter source."""

    @abstractmethod
    def read(self) -> dict[str, tuple[int, int]]:
        """
        Read current cumulative byte counters.
        Returns dict: mac_address -> (bytes_up, bytes_down)
        """
        ...


class NullSource(TrafficSource):
    """No-op source for development / testing."""

    def read(self) -> dict[str, tuple[int, int]]:
        return {}


class NftAccountingSource(TrafficSource):
    """
    Reads per-MAC byte counters from the M2 nftables accounting module.
    Lazy-imports clarinet.enforcer.accounting so M1 compiles on Windows.
    (C-08: M1 calls M2 via lazy import)
    """

    def read(self) -> dict[str, tuple[int, int]]:
        try:
            from clarinet.enforcer import accounting  # M2 module — lazy
            return accounting.read_counters()
        except Exception as exc:
            log.debug("NftAccountingSource.read failed (Linux only?): %s", exc)
            return {}


class PacketSniffSource(TrafficSource):
    """
    Passive packet sniffer source (Linux + raw socket only).
    Uses scapy if available; falls back silently.
    """

    def __init__(self, interface: str) -> None:
        self.interface = interface

    def read(self) -> dict[str, tuple[int, int]]:
        # PacketSniff gives realtime deltas, not cumulative — return empty here
        # (actual capture happens in a background thread, feeding _samples directly)
        return {}


# ─── Module-level source (injectable) ────────────────────────────────────────

_source: TrafficSource = NullSource()
_prev_counters: dict[str, tuple[int, int]] = {}  # for reset-safe delta computation


def set_source(source: TrafficSource) -> None:
    """Inject a traffic source (e.g. NftAccountingSource in production)."""
    global _source
    _source = source


def _compute_deltas(
    current: dict[str, tuple[int, int]],
    previous: dict[str, tuple[int, int]],
) -> dict[str, tuple[int, int]]:
    """
    Compute byte deltas between two counter snapshots.
    Reset-safe: if current < previous for a MAC, treat it as a full counter reset
    and use `current` as the delta.
    """
    deltas: dict[str, tuple[int, int]] = {}
    for mac, (cur_in, cur_out) in current.items():
        prev_in, prev_out = previous.get(mac, (0, 0))
        # Reset detection
        d_in = cur_in - prev_in if cur_in >= prev_in else cur_in
        d_out = cur_out - prev_out if cur_out >= prev_out else cur_out
        if d_in > 0 or d_out > 0:
            deltas[mac] = (d_in, d_out)
    return deltas


def poll_and_record() -> dict[str, tuple[int, int]]:
    """
    Read the traffic source, compute deltas, write to DB, update rolling window.
    Returns the delta dict. Called every 60 s by the traffic_cycle job.
    """
    global _prev_counters

    current = _source.read()
    deltas = _compute_deltas(current, _prev_counters)
    _prev_counters = current

    if deltas:
        _write_deltas(deltas)
        _update_rolling_window(deltas)

    return deltas


def _write_deltas(deltas: dict[str, tuple[int, int]]) -> None:
    """Persist byte deltas to the UsageRecord table."""
    from clarinet.database import SessionLocal
    from clarinet.models import Device, UsageRecord

    with _lock:
        with SessionLocal() as db:
            now = datetime.now(timezone.utc)
            today = now.date().isoformat()
            hour = now.hour

            for mac, (bytes_in, bytes_out) in deltas.items():
                device = db.query(Device).filter(Device.mac_address == mac.upper()).first()
                if device is None:
                    # A merged address: its traffic belongs to the device it was merged into.
                    from clarinet.models.merging import MergedMac
                    alias = db.get(MergedMac, mac.upper())
                    device = db.get(Device, alias.primary_device_id) if alias else None
                if device is None:
                    continue

                rec = (
                    db.query(UsageRecord)
                    .filter(
                        UsageRecord.device_id == device.device_id,
                        UsageRecord.date == today,
                        UsageRecord.hour == hour,
                    )
                    .first()
                )
                if rec is None:
                    rec = UsageRecord(
                        device_id=device.device_id,
                        date=today,
                        hour=hour,
                        activity="OTHER",
                        bytes_in=0,
                        bytes_out=0,
                    )
                    db.add(rec)
                    db.flush()

                rec.bytes_in += bytes_in
                rec.bytes_out += bytes_out

            db.commit()


def _update_rolling_window(deltas: dict[str, tuple[int, int]]) -> None:
    """Update the in-memory rolling window for get_recent_device_bytes."""
    import time
    now = time.time()
    for mac, (bi, bo) in deltas.items():
        if mac not in _samples:
            _samples[mac] = []
        _samples[mac].append((now, bi, bo))


def get_recent_device_bytes(window_s: int = _WINDOW_S) -> dict[str, tuple[int, int]]:
    """
    Return per-device byte totals for the last `window_s` seconds.
    Uses the in-memory rolling window (not DB) for low-latency reads.

    Returns: dict[mac_address, (bytes_in, bytes_out)]

    (C-03 contract)
    """
    import time
    cutoff = time.time() - window_s
    result: dict[str, tuple[int, int]] = {}

    for mac, entries in list(_samples.items()):
        # Prune old entries
        fresh = [(ts, bi, bo) for ts, bi, bo in entries if ts >= cutoff]
        _samples[mac] = fresh
        if fresh:
            total_in = sum(bi for _, bi, _ in fresh)
            total_out = sum(bo for _, _, bo in fresh)
            result[mac] = (total_in, total_out)

    return result


# ─── Legacy compatibility ─────────────────────────────────────────────────────

def record_traffic(mac: str, bytes_in: int, bytes_out: int) -> None:
    """Legacy direct-write API — kept for backward compatibility with existing callers."""
    _write_deltas({mac.upper(): (bytes_in, bytes_out)})
    _update_rolling_window({mac.upper(): (bytes_in, bytes_out)})


def poll_nft_counters(interface: str) -> None:
    """Legacy poll entry-point — delegates to poll_and_record()."""
    poll_and_record()
