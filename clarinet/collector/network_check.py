"""
clarinet/collector/network_check.py
Unfamiliar network detection.

A network is recognised by its gateway (router) MAC address. The first network
Clarinet runs on is remembered as trusted. If the gateway later has a MAC it has
never seen, either the server moved to a different network or something is
pretending to be the router, and an alert is raised.
"""

import logging
import platform
import re
import socket
import subprocess
from datetime import datetime, timezone

log = logging.getLogger("clarinet.collector.network_check")


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return out.stdout or ""
    except (OSError, subprocess.SubprocessError) as e:
        log.debug("Command %s failed: %s", cmd[0], e)
        return ""


# Parsers (pure functions)

def parse_default_gateway_windows(route_print: str) -> str | None:
    """Pick the lowest-metric default route from `route print -4`."""
    best: tuple[int, str] | None = None
    for line in route_print.splitlines():
        m = re.match(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(\d+)\s*$", line)
        if m:
            metric = int(m.group(2))
            if best is None or metric < best[0]:
                best = (metric, m.group(1))
    return best[1] if best else None


def parse_default_gateway_linux(ip_route: str) -> str | None:
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", ip_route)
    return m.group(1) if m else None


def parse_mac_from_arp(text: str, ip: str) -> str | None:
    """Find the MAC for `ip` in `arp -a` (Windows) or `ip neigh` (Linux) output."""
    for line in text.splitlines():
        if ip not in line.split():
            continue
        m = re.search(r"([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})", line)
        if m:
            return m.group(1).replace("-", ":").upper()
    return None


# Facts about the current network

def get_gateway_ip() -> str | None:
    if platform.system() == "Windows":
        return parse_default_gateway_windows(_run(["route", "print", "-4"]))
    return parse_default_gateway_linux(_run(["ip", "route", "show", "default"]))


def get_gateway_mac(gateway_ip: str) -> str | None:
    if platform.system() == "Windows":
        _run(["ping", "-n", "1", "-w", "500", gateway_ip], timeout=5)    # fills the ARP table
        return parse_mac_from_arp(_run(["arp", "-a", gateway_ip]), gateway_ip)
    _run(["ping", "-c", "1", "-W", "1", gateway_ip], timeout=5)
    return parse_mac_from_arp(_run(["ip", "neigh", "show", gateway_ip]), gateway_ip)


def get_local_subnet() -> str | None:
    """Local address of the default route, as a /24 (same assumption as the ARP scanner)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))      # no packet is sent for UDP connect
            ip = s.getsockname()[0]
        return ip.rsplit(".", 1)[0] + ".0/24"
    except OSError:
        return None


def current_network() -> dict | None:
    gateway_ip = get_gateway_ip()
    if not gateway_ip:
        return None
    gateway_mac = get_gateway_mac(gateway_ip)
    if not gateway_mac:
        return None

    from clarinet.collector.wifi_scan import current_connection
    wifi = current_connection()
    return {
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac,
        "subnet": get_local_subnet(),
        "ssid": wifi.ssid if wifi else None,
    }


# Evaluation

def evaluate(db, info: dict) -> str:
    """
    Compare the current network with the known ones.
    Returns one of: LEARNED, KNOWN, UNTRUSTED, CHANGED, UNFAMILIAR.
    """
    from clarinet.collector.security_alerts import raise_alert
    from clarinet.models.security import KnownNetwork

    mac = info["gateway_mac"].upper()
    now = datetime.now(timezone.utc)
    known = db.query(KnownNetwork).filter(KnownNetwork.gateway_mac == mac).first()

    if known is not None:
        known.last_seen = now
        known.gateway_ip = info["gateway_ip"]
        db.commit()
        if known.trusted:
            return "KNOWN"
        raise_alert(
            "UNFAMILIAR_NETWORK", "WARNING",
            f"Unfamiliar network: {known.ssid or known.gateway_ip}",
            f"Connected to a network you have not trusted (gateway {mac}). "
            "Trust it on the Security page if it is yours.",
            db=db,
        )
        return "UNTRUSTED"

    # Very first run: remember this network as the trusted home network.
    if db.query(KnownNetwork).count() == 0:
        db.add(KnownNetwork(
            gateway_mac=mac, gateway_ip=info["gateway_ip"], subnet=info.get("subnet"),
            ssid=info.get("ssid"), label="Learned on first run", trusted=True,
        ))
        db.commit()
        log.info("Learned home network, gateway %s", mac)
        return "LEARNED"

    db.add(KnownNetwork(
        gateway_mac=mac, gateway_ip=info["gateway_ip"], subnet=info.get("subnet"),
        ssid=info.get("ssid"), label=None, trusted=False,
    ))
    db.commit()

    # Same address or Wi-Fi name as a trusted network, but a different router MAC.
    lookalike = (
        db.query(KnownNetwork)
        .filter(KnownNetwork.trusted == True, KnownNetwork.gateway_mac != mac)  # noqa: E712
        .all()
    )
    for k in lookalike:
        same_ip = k.gateway_ip == info["gateway_ip"]
        same_ssid = bool(info.get("ssid")) and k.ssid == info.get("ssid")
        if same_ip or same_ssid:
            raise_alert(
                "UNFAMILIAR_NETWORK", "CRITICAL",
                f"Gateway changed on {info.get('ssid') or info['gateway_ip']}",
                f"The router at {info['gateway_ip']} now answers as {mac}; it used to be {k.gateway_mac}. "
                "Either the router was replaced or something is impersonating it.",
                extra={"old_mac": k.gateway_mac, "new_mac": mac},
                db=db,
            )
            return "CHANGED"

    raise_alert(
        "UNFAMILIAR_NETWORK", "WARNING",
        f"Unfamiliar network: {info.get('ssid') or info['gateway_ip']}",
        f"This machine is on a network it has not seen before (gateway {mac}, subnet {info.get('subnet') or 'unknown'}). "
        "Trust it on the Security page if it is yours.",
        extra={"gateway_mac": mac},
        db=db,
    )
    return "UNFAMILIAR"


def check_and_evaluate(db) -> str | None:
    info = current_network()
    if info is None:
        log.debug("Network check skipped: no gateway found")
        return None
    return evaluate(db, info)
