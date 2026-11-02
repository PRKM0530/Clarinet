"""
clarinet/collector/arp_spoof.py
ARP spoofing detection (same IP answering with two different MACs).

arp_scanner calls check() for every device it sees. Add any further
per-device security checks inside check().

The last MAC seen for each IP is stored in the database, so detection survives
restarts. A change only counts as spoofing when the previous MAC was seen
recently: a DHCP lease that simply moved to another device hours later is
normal and must not raise a critical alert.
"""

import logging
from datetime import datetime, timedelta, timezone

log = logging.getLogger("clarinet.collector.arp_spoof")

# Previous binding must be at least this fresh for a change to be suspicious.
RECENT_MINUTES = 10


def check(ip: str, mac: str) -> None:
    """Entry point used by the ARP scanner for every sighting."""
    detect_arp_spoof(ip, mac)


def detect_arp_spoof(ip: str, mac: str, db=None) -> bool:
    """
    Record this IP -> MAC sighting. If the IP was answered by a different MAC
    within the last few minutes, raise a CRITICAL ARP_SPOOF alert.
    Returns True when spoofing is suspected.
    """
    from clarinet.database import SessionLocal
    from clarinet.models.security import ArpBinding

    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        mac = mac.upper()
        now = datetime.now(timezone.utc)
        binding = db.get(ArpBinding, ip)

        if binding is None:
            db.add(ArpBinding(ip_address=ip, mac_address=mac, first_seen=now, last_seen=now))
            db.commit()
            return False

        if binding.mac_address == mac:
            binding.last_seen = now
            db.commit()
            return False

        prev_mac = binding.mac_address
        last_seen = binding.last_seen
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        recent = now - last_seen <= timedelta(minutes=RECENT_MINUTES)

        binding.mac_address = mac
        binding.last_seen = now
        db.commit()

        if not recent:
            log.info("IP %s moved from %s to %s after a long gap; treating as a new lease", ip, prev_mac, mac)
            return False

        from clarinet.collector.security_alerts import raise_alert
        log.warning("ARP SPOOF DETECTED: IP %s changed MAC %s -> %s", ip, prev_mac, mac)
        raise_alert(
            "ARP_SPOOF",
            "CRITICAL",
            f"ARP spoofing detected on {ip}",
            (
                f"IP {ip} previously answered ARP as {prev_mac} but now "
                f"responds as {mac}. Possible ARP poisoning / MITM attack."
            ),
            extra={"ip": ip, "old_mac": prev_mac, "new_mac": mac},
            db=db,
        )
        return True
    finally:
        if own_session:
            db.close()
