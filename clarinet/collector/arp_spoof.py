"""
clarinet/collector/arp_spoof.py
ARP spoofing detection (same IP answering with two different MACs).

arp_scanner calls check() for every device it sees. Add any further
per-device security checks inside check().
"""

import logging

log = logging.getLogger("clarinet.collector.arp_spoof")

# In-memory IP -> MAC cache
# Format: { "192.168.1.5": "AA:BB:CC:DD:EE:FF" }
_ip_mac_cache: dict[str, str] = {}


def check(ip: str, mac: str) -> None:
    """Entry point used by the ARP scanner for every sighting."""
    detect_arp_spoof(ip, mac)


def detect_arp_spoof(ip: str, mac: str) -> bool:
    """
    Check if this IP was previously seen with a different MAC.
    If so, it's likely ARP spoofing / poisoning.
    Returns True and raises a CRITICAL alert if spoofing detected.
    """
    prev_mac = _ip_mac_cache.get(ip)
    _ip_mac_cache[ip] = mac

    if prev_mac and prev_mac != mac:
        log.warning("ARP SPOOF DETECTED: IP %s changed MAC %s → %s", ip, prev_mac, mac)
        try:
            from clarinet.database import SessionLocal
            from clarinet.models import Alert
            from clarinet.routers.ws import broadcast_alert_sync
            with SessionLocal() as db:
                alert = Alert(
                    level="CRITICAL",
                    type="ARP_SPOOF",
                    title=f"ARP spoofing detected on {ip}",
                    message=(
                        f"IP {ip} previously answered ARP as {prev_mac} but now "
                        f"responds as {mac}. Possible ARP poisoning / MITM attack."
                    ),
                )
                db.add(alert)
                db.commit()
                broadcast_alert_sync({
                    "type": "ARP_SPOOF",
                    "level": "CRITICAL",
                    "title": alert.title,
                    "message": alert.message,
                    "ip": ip,
                    "old_mac": prev_mac,
                    "new_mac": mac,
                })
        except Exception as e:
            log.error("Failed to raise ARP spoof alert: %s", e)
        return True
    return False
