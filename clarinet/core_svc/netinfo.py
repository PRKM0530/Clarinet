"""
clarinet/core_svc/netinfo.py
Network interface and capability detection for M1 setup wizard.

All shell calls go through the injectable Runner so tests don't need
real network adapters or root privileges.
"""

from __future__ import annotations

import logging
import platform
import re
import socket

from clarinet.core_svc.runner import Runner, get_runner

log = logging.getLogger("clarinet.core_svc.netinfo")

_IS_LINUX = platform.system() == "Linux"


def detect_gateway(runner: Runner | None = None) -> str | None:
    """
    Return the default gateway IP address, or None if not detectable.
    Uses `ip route` on Linux, `ipconfig` heuristic on Windows.
    """
    if runner is None:
        runner = get_runner()
    try:
        if _IS_LINUX:
            result = runner.run(["ip", "route", "show", "default"])
            # "default via 192.168.1.1 dev eth0 ..."
            m = re.search(r"default via (\S+)", result.stdout or "")
            if m:
                return m.group(1)
        else:
            # Windows / dev — try socket trick
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]  # our IP, not gateway, but useful for dev
    except Exception as exc:
        log.debug("detect_gateway failed: %s", exc)
    return None


def detect_interface(runner: Runner | None = None) -> str | None:
    """
    Return the name of the default network interface, or None.
    """
    if runner is None:
        runner = get_runner()
    try:
        if _IS_LINUX:
            result = runner.run(["ip", "route", "show", "default"])
            m = re.search(r"dev (\S+)", result.stdout or "")
            if m:
                return m.group(1)
    except Exception as exc:
        log.debug("detect_interface failed: %s", exc)
    return None


def detect_subnet(interface: str, runner: Runner | None = None) -> str | None:
    """
    Return the subnet CIDR for the given interface (e.g. "192.168.1.0/24"), or None.
    """
    if runner is None:
        runner = get_runner()
    try:
        if _IS_LINUX:
            result = runner.run(["ip", "addr", "show", interface])
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", result.stdout or "")
            if m:
                return m.group(1)
    except Exception as exc:
        log.debug("detect_subnet failed: %s", exc)
    return None


def probe_capabilities(runner: Runner | None = None) -> dict[str, bool]:
    """
    Check which system capabilities are available.
    Returns a dict of feature flags used to choose the network_mode default.

    Keys:
      has_nft         — nftables available
      has_tc          — traffic control (tc) available
      has_root        — running as root / CAP_NET_ADMIN
      has_raw_socket  — can open a raw socket (for packet capture)
      has_monitor_adapter — has a WiFi adapter in monitor mode
      is_linux        — platform is Linux
    """
    if runner is None:
        runner = get_runner()

    caps: dict[str, bool] = {
        "is_linux": _IS_LINUX,
        "has_nft": False,
        "has_tc": False,
        "has_root": False,
        "has_raw_socket": False,
        "has_monitor_adapter": False,
    }

    if not _IS_LINUX:
        return caps  # all False on Windows/macOS

    # Root check
    try:
        import os
        caps["has_root"] = os.geteuid() == 0
    except AttributeError:
        pass

    # nftables
    try:
        result = runner.run(["nft", "--version"])
        caps["has_nft"] = result.returncode == 0
    except Exception:
        pass

    # tc
    try:
        result = runner.run(["tc", "-help"])
        caps["has_tc"] = True
    except Exception:
        pass

    # Raw socket capability
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0800)
        s.close()
        caps["has_raw_socket"] = True
    except (AttributeError, PermissionError, OSError):
        pass

    return caps


def recommend_mode(caps: dict[str, bool]) -> str:
    """
    Given capability dict from probe_capabilities(), return the recommended
    network_mode: "FULL" if enforcement is possible, "MONITOR" otherwise.
    """
    if caps.get("has_nft") and caps.get("has_root"):
        return "FULL"
    return "MONITOR"
