"""
clarinet/collector/arp_scanner.py
Periodic ARP scan to discover devices on the local network.

Requires: scapy (Linux, needs root / CAP_NET_RAW)
On Windows / dev machines, this module is gracefully skipped.

Phase 2 will add:
  - Passive ARP sniffing (scapy.sniff)
  - ARP spoofing detection (same IP, two different MACs)
  - OUI vendor lookup for is_random_mac detection
  - mDNS hostname resolution via python-zeroconf
"""

import logging
import socket
from datetime import datetime, timezone

log = logging.getLogger("clarinet.collector.arp")

# In-memory IP → MAC cache for ARP spoof detection
# Format: { "192.168.1.5": "AA:BB:CC:DD:EE:FF" }
_ip_mac_cache: dict[str, str] = {}


def get_vendor_from_mac(mac: str) -> str | None:
    """
    OUI lookup: first 3 octets → vendor name.
    Uses the local manuf file bundled with Scapy when available.
    Falls back to None if Scapy isn't installed.
    """
    try:
        from scapy.layers.l2 import conf
        return conf.manufdb._get_manuf(mac)
    except Exception:
        return None


def is_random_mac(mac: str) -> bool:
    """
    Locally-administered MACs have bit 1 of the first octet set.
    This flags Android / iOS devices using MAC randomisation.
    """
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False


def scan_network(interface: str, subnet: str = None) -> list[dict]:
    """
    Send ARP who-has to the entire subnet and collect replies.
    Returns list of dicts: [{"ip": ..., "mac": ..., "vendor": ...}]

    Only works on Linux with root privileges.
    """
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
    except ImportError:
        log.warning("Scapy not installed — ARP scan skipped (Windows/dev?)")
        return []

    if subnet is None:
        # Derive subnet from interface IP (simple /24 assumption)
        import netifaces
        addrs = netifaces.ifaddresses(interface)
        ip = addrs[netifaces.AF_INET][0]["addr"]
        subnet = ip.rsplit(".", 1)[0] + ".0/24"

    log.debug("ARP scanning %s on %s", subnet, interface)
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=2,
            iface=interface,
            verbose=False,
        )
        results = []
        for _, rcv in ans:
            mac = rcv.hwsrc.upper()
            ip = rcv.psrc
            vendor = get_vendor_from_mac(mac)
            results.append({"ip": ip, "mac": mac, "vendor": vendor})
        return results
    except Exception as e:
        log.error("ARP scan failed: %s", e)
        return []


def upsert_devices(scan_results: list[dict]) -> None:
    """
    Compare scan results against DB; create NEW entries for unknowns,
    update last_seen for known ones, create DeviceHistory JOIN events.
    Raises alerts for new devices.
    """
    from clarinet.database import SessionLocal
    from clarinet.models import Device, DeviceHistory, Alert
    from clarinet.routers.ws import broadcast_alert_sync

    with SessionLocal() as db:
        for result in scan_results:
            mac = result["mac"]
            ip = result.get("ip")
            vendor = result.get("vendor")

            # Check for ARP spoofing before upserting
            if ip:
                detect_arp_spoof(ip, mac)

            existing = db.query(Device).filter(Device.mac_address == mac).first()
            now = datetime.now(timezone.utc)

            if existing is None:
                # New device discovered
                device = Device(
                    mac_address=mac,
                    ip_address=ip,
                    vendor=vendor,
                    state="NEW",
                    is_random_mac=is_random_mac(mac),
                    first_seen=now,
                    last_seen=now,
                )
                db.add(device)
                db.flush()

                # History event
                db.add(DeviceHistory(device_id=device.device_id, event="JOIN", ip_address=ip))

                # Alert
                alert = Alert(
                    level="WARNING",
                    type="NEW_DEVICE",
                    title="New device detected",
                    message=f"Unknown device with MAC {mac} ({vendor or 'unknown vendor'}) joined from {ip}.",
                    device_id=device.device_id,
                )
                db.add(alert)
                db.flush()

                # Push WebSocket notification
                broadcast_alert_sync({
                    "type": "NEW_DEVICE",
                    "level": "WARNING",
                    "title": alert.title,
                    "message": alert.message,
                    "mac": mac,
                    "ip": ip,
                })
                log.info("New device: %s (%s)", mac, ip)
            else:
                # Known device — just refresh
                if existing.ip_address != ip:
                    existing.ip_address = ip
                existing.last_seen = now
                if vendor and not existing.vendor:
                    existing.vendor = vendor

        db.commit()


def detect_arp_spoof(ip: str, mac: str) -> bool:
    """
    Check if this IP was previously seen with a different MAC.
    If so, it's likely ARP spoofing / poisoning.
    Returns True and raises a CRITICAL alert if spoofing detected.
    """
    global _ip_mac_cache
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


def run_scan_loop(interface: str) -> None:
    """Called by APScheduler or a dedicated thread every 30–60 seconds."""
    results = scan_network(interface)
    if results:
        upsert_devices(results)
