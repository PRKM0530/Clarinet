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

import ipaddress
import logging
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from clarinet.collector import arp_spoof

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
            subnet = _subnet_of(interface)
            if subnet is None:
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
        if platform.system() == "Windows":
            return _windows_neighbours(runner)
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
                    entries.append({"ip": ip, "mac": parts[lladdr_idx + 1].upper(), "hostname": None})
            names = _resolve_many([e["ip"] for e in entries])
            for e in entries:
                e["hostname"] = names.get(e["ip"])
            return entries
        except Exception as exc:
            log.debug("NeighbourTableSource failed: %s", exc)
            return []


# ─── Windows: the ARP cache is read with `arp -a` ─────────────────────────────

_ARP_ROW = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)")
_last_sweep = 0.0
SWEEP_EVERY_SECONDS = 120


def parse_windows_arp(text: str) -> list[dict]:
    """Devices from `arp -a`: private unicast addresses only (no multicast, broadcast or router-less entries)."""
    found, seen = [], set()
    for line in text.splitlines():
        m = _ARP_ROW.match(line)
        if not m:
            continue
        ip, mac, kind = m.group(1), m.group(2).replace("-", ":").upper(), m.group(3).lower()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if kind != "dynamic" or not addr.is_private or addr.is_multicast or addr.is_loopback or mac.startswith("FF:FF") or mac in seen:
            continue
        seen.add(mac)
        found.append({"ip": ip, "mac": mac, "hostname": None})
    return found


def _local_ip() -> str | None:
    """The address this computer uses on the local network (nothing is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))
            return sock.getsockname()[0]
    except OSError:
        return None


def _poke(ip: str) -> None:
    """One quick ping, so the device appears in the ARP cache."""
    try:
        subprocess.run(["ping", "-n", "1", "-w", "300", ip], capture_output=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        pass


def _sweep_local_network() -> None:
    """Ping the computer's own /24 now and then, so devices that have been quiet still show in `arp -a`."""
    global _last_sweep
    if time.monotonic() - _last_sweep < SWEEP_EVERY_SECONDS:
        return
    _last_sweep = time.monotonic()
    me = _local_ip()
    if not me:
        return
    net = ipaddress.ip_network(f"{me}/24", strict=False)
    with ThreadPoolExecutor(max_workers=64) as pool:
        list(pool.map(_poke, [str(h) for h in net.hosts() if str(h) != me]))


def parse_adapter_mac(ipconfig_all: str, ip: str) -> str | None:
    """The physical address of the adapter that has `ip`, from `ipconfig /all`."""
    block_mac = None
    for line in ipconfig_all.splitlines():
        if line and not line[0].isspace():
            block_mac = None                       # a new adapter starts
        m = re.search(r"Physical Address[ .]*:\s*([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", line)
        if m:
            block_mac = m.group(1).replace("-", ":").upper()
        elif ip in line and "IPv4" in line and block_mac:
            return block_mac
    return None


_host_cache: dict = {}


def host_identity() -> dict | None:
    """This computer as a device: {"ip", "mac", "hostname"}. Windows only; Linux sees itself in the neighbour table."""
    if platform.system() != "Windows":
        return None
    if "me" in _host_cache:
        return _host_cache["me"]
    me = _local_ip()
    identity = None
    if me:
        try:
            out = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=10, errors="replace").stdout
        except (OSError, subprocess.SubprocessError):
            out = ""
        mac = parse_adapter_mac(out, me)
        if mac:
            identity = {"ip": me, "mac": mac, "hostname": socket.gethostname()}
    if identity:
        _host_cache["me"] = identity
    return identity


def _windows_neighbours(runner) -> list[dict]:
    try:
        _sweep_local_network()
        out = runner.run(["arp", "-a"], timeout=10).stdout or ""
    except Exception as exc:
        log.debug("arp -a failed: %s", exc)
        return []
    found = parse_windows_arp(out)
    me = host_identity()
    if me and all(f["mac"] != me["mac"] for f in found):
        found.append(dict(me))
    return found


class FakeSource(ArpSource):
    """Test double — returns a pre-programmed list of scan results."""

    def __init__(self, results: list[dict] | None = None) -> None:
        self._results = results or []

    def scan(self, interface: str, subnet: str | None = None) -> list[dict]:
        return list(self._results)


# ─── Module-level injectable source ──────────────────────────────────────────

_arp_source: ArpSource = NeighbourTableSource()
_default_source = _arp_source          # tests replace the source; only the default one gets the active scan added


def active_discovery_on(db) -> bool:
    """Should the active ARP scan run as well? Needs root and scapy. Setting active_discovery:
    "on", "off", or "auto" (default): on only in Full Control mode, where this machine is the router."""
    import os
    try:
        if os.geteuid() != 0:
            return False
        import importlib.util
        if importlib.util.find_spec("scapy") is None:
            return False
        from clarinet.app_settings import get_setting
        choice = (get_setting(db, "active_discovery", "auto") or "auto").lower()
        if choice == "on":
            return True
        if choice == "off":
            return False
        return (get_setting(db, "network_mode", "MONITOR") or "").upper() == "FULL"
    except Exception:
        return False


def _subnet_of(interface: str) -> str | None:
    """The IPv4 network of an interface, from `ip`."""
    import subprocess
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", interface],
                             capture_output=True, text=True, timeout=5).stdout
        for part in out.split():
            if "/" in part and part[0].isdigit():
                import ipaddress
                iface_addr = ipaddress.ip_interface(part)
                if iface_addr.network.prefixlen < 24:
                    # A big network (for example a /16) would mean tens of thousands of probes: scan our own /24 only
                    return str(ipaddress.ip_network(f"{iface_addr.ip}/24", strict=False))
                return str(iface_addr.network)
    except Exception:
        pass
    return None


def set_source(source: ArpSource) -> None:
    global _arp_source
    _arp_source = source


# ─── Core scan logic ──────────────────────────────────────────────────────────

_name_cache: dict[str, tuple[float, str | None]] = {}
NAME_CACHE_SECONDS = 1800


def _resolve_hostname(ip: str) -> str | None:
    """Reverse DNS lookup, best effort. Remembered for a while, so every scan does not ask again."""
    hit = _name_cache.get(ip)
    if hit and time.monotonic() - hit[0] < NAME_CACHE_SECONDS:
        return hit[1]
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = None
    _name_cache[ip] = (time.monotonic(), name)
    return name


def _resolve_many(ips: list[str]) -> dict[str, str | None]:
    """Look up many names at once: one slow answer must not hold up the others."""
    with ThreadPoolExecutor(max_workers=16) as pool:
        return dict(zip(ips, pool.map(_resolve_hostname, ips)))


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
    if _arp_source is _default_source and active_discovery_on(db):
        known = {(r.get("mac") or "").upper() for r in results}
        for r in ScapyArpSource().scan(interface, subnet):
            if (r.get("mac") or "").upper() not in known:
                results.append(r)

    now = datetime.now(timezone.utc)
    new_devices: list[dict] = []
    first_scan = db.query(Device.device_id).first() is None        # nothing known yet: everything is "new"

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

        # Security: same IP answering with a different MAC (ARP spoofing).
        # Uses this scan's session so two writers never fight over SQLite, and
        # must never be able to break device discovery.
        if ip:
            try:
                arp_spoof.check(ip, mac, db=db)
            except Exception as e:
                log.warning("ARP spoof check failed for %s: %s", ip, e)

        vendor = lookup_vendor(mac)
        random_mac = is_random_mac(mac)

        existing = db.query(Device).filter(Device.mac_address == mac).first()
        if existing is None:
            # An address the admin merged into another device is that device, not a new one
            from clarinet.models.merging import MergedMac
            alias = db.get(MergedMac, mac)
            if alias is not None:
                existing = db.get(Device, alias.primary_device_id)

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

            # Alert, except for the very first scan, which gets one summary below (C-05: never for guests)
            if not first_scan:
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

    if first_scan and new_devices:
        raise_alert(
            db,
            level="INFO",
            type="NEW_DEVICE",
            title=f"{len(new_devices)} device{'s' if len(new_devices) != 1 else ''} found on your network",
            message="These are the devices Clarinet found on its first scan. Open Devices to approve the ones you know. "
                    "From now on you are alerted whenever a new one joins.",
            cooldown_s=3600,
        )

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
