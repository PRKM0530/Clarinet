"""
clarinet/core_svc/presence.py
What "online" means: a device the ARP scan has seen recently. The scanner runs every 15 seconds,
so a device missing for five minutes has really left (or is asleep).
"""
from datetime import datetime, timedelta, timezone

ONLINE_WINDOW_SECONDS = 300


def online_cutoff() -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=ONLINE_WINDOW_SECONDS)
