"""
clarinet/core_svc/capabilities.py
What works on THIS computer, and why not when something does not.

Several features read the network the way only Linux allows (neighbour table, firewall counters, packet
sniffing). On another system, or without administrator rights, they cannot work. Every page that depends on
one shows the reason from here, so nobody mistakes "not possible here" for "nothing happening".
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Feature:
    key: str
    name: str            # what the person sees it called
    what: str            # what it gives them
    reason: str | None   # why it does not work here, or None when it works
    partial: str | None = None   # what is limited when it works only in part

    @property
    def works(self) -> bool:
        return self.reason is None


def _linux() -> bool:
    return platform.system() == "Linux"


_probe_cache: dict[str, tuple[float, bool]] = {}


def _probe(name: str, check, seconds: int = 30) -> bool:
    """Run a real test of an ability, and remember the answer briefly (pages ask on every load)."""
    now = time.monotonic()
    hit = _probe_cache.get(name)
    if hit and now - hit[0] < seconds:
        return hit[1]
    try:
        ok = bool(check())
    except Exception:
        ok = False
    _probe_cache[name] = (now, ok)
    return ok


def _can_read_firewall_counters() -> bool:
    """Clarinet counts traffic with nftables. Root is not needed, only the right to use it: the service runs as its
    own user with the network capabilities, so the reliable test is to ask nftables."""
    if not shutil.which("nft"):
        return False
    return subprocess.run(["nft", "list", "tables"], capture_output=True, timeout=3).returncode == 0


def _can_sniff_packets() -> bool:
    """Watching packets (website lookups, port scans) needs the raw-socket right and scapy."""
    import importlib.util
    import socket
    if importlib.util.find_spec("scapy") is None:
        return False
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW):        # AF_PACKET exists on Linux only
        return True


def features() -> dict[str, Feature]:
    from clarinet.core_svc import netinfo

    on_linux = _linux()
    needs_linux = "This computer does not run Linux"

    system = platform.system()
    if system == "Linux":
        discovery = None if shutil.which("ip") else "The ip command is missing"
    elif system == "Windows":
        discovery = None if shutil.which("arp") else "The arp command is missing"
    else:
        discovery = "This computer's system cannot list network devices"
    # counting reads the nftables counters; watching packets is a separate right
    if system == "Windows":
        counting = None                                  # this computer's own traffic only (see `partial` below)
    elif not on_linux:
        counting = needs_linux
    elif not shutil.which("nft"):
        counting = "nftables is not installed"
    else:
        counting = None if _probe("nft", _can_read_firewall_counters) else "Clarinet is not allowed to use nftables (it needs root or the network capabilities)"
    if not on_linux:
        sniffing = needs_linux
    else:
        sniffing = None if _probe("sniff", _can_sniff_packets) else "Clarinet cannot watch packets (it needs scapy and the raw-socket right)"
    # nearby Wi-Fi is read with netsh on Windows and nmcli on Linux
    if system == "Windows":
        wifi = None if shutil.which("netsh") else "The netsh command is missing"
    elif system == "Linux":
        wifi = None if shutil.which("nmcli") else "NetworkManager (nmcli) is missing"
    else:
        wifi = "This computer's system cannot scan Wi-Fi"

    items = [
        Feature("discovery", "Finding devices", "the list of connected devices", discovery),
        Feature("usage", "Counting data usage", "how much data each device uses", counting,
                "Only this computer's own traffic is counted. Other devices need Clarinet to run on Linux, on the router."),
        Feature("lookups", "Sorting usage by activity", "streaming, browsing and so on", sniffing),
        Feature("arpspoof", "ARP spoofing detection", "a device pretending to be another", discovery),
        Feature("portscan", "Port scan detection", "a device probing many ports", sniffing),
        Feature("wifi", "Nearby Wi-Fi checks", "spotting fake access points", wifi),
        Feature("control", "Blocking, limits and time rules", "Full Control mode", None if netinfo.can_control_cached() else (needs_linux if not on_linux else "Full Control is not allowed to change the firewall here")),
    ]
    return {f.key: f for f in items}


def limited() -> dict[str, Feature]:
    """Features that work, but only in part on this computer."""
    return {k: f for k, f in features().items() if f.works and f.partial}


def unavailable() -> dict[str, Feature]:
    return {k: f for k, f in features().items() if not f.works}


# collectors whose silence only means the feature cannot run on this computer
COLLECTOR_FEATURE = {"arp_scanner": "discovery", "traffic_counter": "usage"}
