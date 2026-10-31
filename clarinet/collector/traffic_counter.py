"""
clarinet/collector/traffic_counter.py
Maintains per-device per-hour traffic counters in SQLite.

On Linux with Scapy installed, a passive sniffer thread can call
record_traffic() directly. On any platform, you can also call it from
iptables/nftables accounting rules via a cron job that reads nft counters.

Thread-safe: uses a threading.Lock so multiple callers don't race on
the SQLite single-writer queue.
"""

import logging
import threading
from datetime import date, datetime, timezone

log = logging.getLogger("clarinet.collector.traffic")

_lock = threading.Lock()


def record_traffic(mac: str, bytes_in: int, bytes_out: int) -> None:
    """
    Add bytes_in / bytes_out to the UsageRecord for `mac` in the current hour.
    Creates the record if it doesn't exist yet.
    Called from the sniffer thread or from nft counter polling.
    """
    from clarinet.database import SessionLocal
    from clarinet.models import Device, UsageRecord

    with _lock:
        with SessionLocal() as db:
            device = db.query(Device).filter(Device.mac_address == mac.upper()).first()
            if device is None:
                return   # unknown device — ignore until discovered

            now = datetime.now(timezone.utc)
            today = now.date().isoformat()
            hour  = now.hour

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

            rec.bytes_in  += bytes_in
            rec.bytes_out += bytes_out
            db.commit()


def poll_nft_counters(interface: str) -> None:
    """
    (Linux / nftables) Read per-MAC byte counters from nftables and flush them
    into UsageRecord. Call this every 60 seconds from APScheduler.

    nftables must have counter rules per MAC set up by tc_wrapper.
    Falls back silently on non-Linux systems.
    """
    try:
        import subprocess, json
        out = subprocess.check_output(
            ["nft", "-j", "list", "table", "inet", "clarinet"],
            timeout=5, stderr=subprocess.DEVNULL
        )
        data = json.loads(out)
        for item in data.get("nftables", []):
            rule = item.get("rule", {})
            # Look for rules with a counter expression and a MAC match
            exprs = rule.get("expr", [])
            mac = None
            bytes_total = 0
            for expr in exprs:
                if "match" in expr:
                    left = expr["match"].get("left", {})
                    if left.get("payload", {}).get("field") == "saddr":
                        mac = expr["match"].get("right", "").upper()
                if "counter" in expr:
                    bytes_total = expr["counter"].get("bytes", 0)
            if mac and bytes_total:
                # Assume split 50/50 in/out as a rough estimate
                record_traffic(mac, bytes_total // 2, bytes_total // 2)
    except Exception as e:
        log.debug("nft counter poll failed (Linux only?): %s", e)
