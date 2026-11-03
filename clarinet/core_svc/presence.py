"""
clarinet/core_svc/presence.py
What "online" means: a device the ARP scan has seen recently. The scanner runs every 15 seconds,
so a device missing for five minutes has really left (or is asleep).
"""
from datetime import datetime, timedelta, timezone

ONLINE_WINDOW_SECONDS = 300


def online_cutoff() -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=ONLINE_WINDOW_SECONDS)


def record_presence_changes(db) -> int:
    """
    Write a JOIN when a device comes online and a LEAVE when it has not been seen for five minutes.
    Returns how many events were written. The scan creates the very first JOIN for a brand-new device.
    """
    from clarinet.models import Device, DeviceHistory
    cutoff = online_cutoff()
    written = 0
    for device in db.query(Device).all():
        seen = device.last_seen
        if seen is not None and seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        online = seen is not None and seen >= cutoff
        last = (db.query(DeviceHistory).filter(DeviceHistory.device_id == device.device_id)
                .order_by(DeviceHistory.timestamp.desc(), DeviceHistory.history_id.desc()).first())
        if online and (last is None or last.event != "JOIN"):
            db.add(DeviceHistory(device_id=device.device_id, event="JOIN", ip_address=device.ip_address))
            written += 1
        elif not online and last is not None and last.event == "JOIN":
            db.add(DeviceHistory(device_id=device.device_id, event="LEAVE", ip_address=device.ip_address))
            written += 1
    if written:
        db.commit()
    return written
