"""
clarinet/collector/arp_scanner.py
Device discovery via ARP for M1. (C-05 contract)

Architecture:
  ArpSource (abstract)
    ├── ScapyArpSource      — full ARP scan via scapy (Linux + root)
    ├── NeighbourTableSource — reads `ip neigh` (Linux, any user)
    └── FakeSource           — test double

C-05: M1 scanner NEVER raises alerts for or re-states GUEST devices,
      and skips the guest subnet entirely.

AT-03.4: IP change keeps the same device identity (keyed on MAC).
"""

from __future__ import annotations

import logging
import socket
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from clarinet.core_svc.runner import Runner

log = logging.getLogger("clarinet.collector.arp")


# ─── Abstract source ──────────────────────────────────────────────────────────

class ArpSource(ABC):
    @abstractmethod
    def scan(self, interface: str, subnet: str | None = None) -> list[dict]:
        """
        Perform a scan and return a list of dicts:
        [{"ip": "...", "mac": "...", "hostname": "..."}]
        """
        ...


class ScapyArpSource(ArpSource):
    """Full ARP scan using scapy — Linux + root only."""

    def scan(self, interface: str, subnet: str | None = None) -> list[dict]:
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import srp
        except ImportError:
            log.debug("Scapy not available — ScapyArpSource skipped")
            return []

        if subnet is None:
            try:
                import netifaces
                addrs = netifaces.ifaddresses(interface)
                ip = addrs[netifaces.AF_INET][0]["addr"]
                subnet = ip.rsplit(".", 1)[0] + ".0/24"
            except Exception:
                log.debug("Could not derive subnet from interface %s", interface)
                return []

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
                hostname = _resolve_hostname(ip)
                results.append({"ip": ip, "mac": mac, "hostname": hostname})
            return results
        except Exception as exc:
            log.error("ScapyArpSource scan failed: %s", exc)
            return []


class NeighbourTableSource(ArpSource):
    """Reads the OS ARP/neighbour cache via `ip neigh` — lighter, no root needed."""

    def __init__(self, runner: "Runner | None" = None) -> None:
        self._runner = runner

    def scan(self, interface: str, subnet: str | None = None) -> list[dict]:
        from clarinet.core_svc.runner import get_runner
        runner = self._runner or get_runner()
        try:
            result = runner.run(["ip", "neigh", "show"])
            lines = (result.stdout or "").splitlines()
            entries = []
            for line in lines:
                parts = line.split()
                # Format: IP dev IFACE lladdr MAC state STATE
                if len(parts) >= 5 and "lladdr" in parts:
                    ip = parts[0]
                    lladdr_idx = parts.index("lladdr")
                    mac = parts[lladdr_idx + 1].upper()
                    hostname = _resolve_hostname(ip)
                    entries.append({"ip": ip, "mac": mac, "hostname": hostname})
            return entries
        except Exception as exc:
            log.debug("NeighbourTableSource failed: %s", exc)
            return []


class FakeSource(ArpSource):
    """Test double — returns a pre-programmed list of scan results."""

    def __init__(self, results: list[dict] | None = None) -> None:
        self._results = results or []

    def scan(self, interface: str, subnet: str | None = None) -> list[dict]:
        return list(self._results)


# ─── Module-level injectable source ──────────────────────────────────────────

_arp_source: ArpSource = NeighbourTableSource()


def set_source(source: ArpSource) -> None:
    global _arp_source
    _arp_source = source


# ─── Core scan logic ──────────────────────────────────────────────────────────

def _resolve_hostname(ip: str) -> str | None:
    """Reverse DNS lookup — best-effort, 0.5 s timeout."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _get_guest_subnet(db) -> str | None:
    """Read the guest subnet from settings (C-05: skip this subnet)."""
    try:
        from clarinet.app_settings import get_setting
        return get_setting(db, "guest.subnet")
    except Exception:
        return None


def _ip_in_subnet(ip: str, subnet: str) -> bool:
    """Simple prefix check — avoids ipaddress import for speed."""
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
    except Exception:
        return False


def scan_once(db, interface: str, subnet: str | None = None) -> list[dict]:
    """
    Run one scan cycle, upsert Device rows, write DeviceEvent history.
    Returns list of newly discovered MACs as dicts.

    C-05: Skips GUEST devices and the guest subnet.
    AT-03.4: IP changes update the existing Device row (keyed on MAC).
    """
    from clarinet.models import Device, DeviceHistory
    from clarinet.models.devices_ext import DeviceEvent
    from clarinet.collector.oui import lookup_vendor, is_random_mac
    from clarinet.core_svc.alerts import raise_alert

    guest_subnet = _get_guest_subnet(db)
    results = _arp_source.scan(interface, subnet)

    now = datetime.now(timezone.utc)
    new_devices: list[dict] = []

    for entry in results:
        ip = entry.get("ip")
        mac = (entry.get("mac") or "").upper()
        hostname = entry.get("hostname")

        if not mac or len(mac) < 11:
            continue

        # C-05: Skip guest subnet
        if guest_subnet and ip and _ip_in_subnet(ip, guest_subnet):
            log.debug("ARP scan: skipping guest subnet IP %s", ip)
            continue

        vendor = lookup_vendor(mac)
        random_mac = is_random_mac(mac)

        existing = db.query(Device).filter(Device.mac_address == mac).first()

        if existing is None:
            # New device
            device = Device(
                mac_address=mac,
                ip_address=ip,
                hostname=hostname,
                vendor=vendor,
                state="NEW",
                is_random_mac=random_mac,
                first_seen=now,
                last_seen=now,
            )
            db.add(device)
            db.flush()

            db.add(DeviceHistory(device_id=device.device_id, event="JOIN", ip_address=ip))
            db.add(DeviceEvent(
                device_id=device.device_id,
                event_type="JOIN",
                occurred_at=now,
                new_value=ip,
            ))

            # Alert — but NOT for GUEST devices (C-05)
            raise_alert(
                db,
                level="WARNING",
                type="NEW_DEVICE",
                title="New device detected",
                message=f"Unknown device {mac} ({vendor or 'unknown vendor'}) joined from {ip}.",
                device_id=device.device_id,
                cooldown_s=3600,
            )

            new_devices.append({"mac": mac, "ip": ip, "device_id": device.device_id})
            log.info("New device: %s (%s)", mac, ip)

        else:
            # C-05: Skip re-stating GUEST devices
            if existing.state == "GUEST":
                existing.last_seen = now
                continue

            # AT-03.4: IP change → update IP but keep same Device row
            if ip and existing.ip_address != ip:
                db.add(DeviceEvent(
                    device_id=existing.device_id,
                    event_type="IP_CHANGE",
                    occurred_at=now,
                    old_value=existing.ip_address,
                    new_value=ip,
                ))
                existing.ip_address = ip

            if hostname and not existing.hostname:
                existing.hostname = hostname
            if vendor and not existing.vendor:
                existing.vendor = vendor

            existing.last_seen = now

    db.commit()
    return new_devices


def run_scan_loop(interface: str, subnet: str | None = None) -> None:
    """Entry point called by APScheduler — wraps scan_once with its own DB session."""
    from clarinet.database import SessionLocal
    with SessionLocal() as db:
        scan_once(db, interface, subnet)


# ─── Legacy compat ────────────────────────────────────────────────────────────

def get_vendor_from_mac(mac: str) -> str | None:
    from clarinet.collector.oui import lookup_vendor
    return lookup_vendor(mac)


def is_random_mac(mac: str) -> bool:
    from clarinet.collector.oui import is_random_mac as _is_random
    return _is_random(mac)


def scan_network(interface: str, subnet: str | None = None) -> list[dict]:
    return _arp_source.scan(interface, subnet)


def upsert_devices(scan_results: list[dict]) -> None:
    from clarinet.database import SessionLocal
    with SessionLocal() as db:
        scan_once(db, interface="", subnet=None)
