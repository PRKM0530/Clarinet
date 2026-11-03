"""
clarinet/core_svc/autoconfig.py
Settings Clarinet works out for itself, so nobody has to know what a "network
interface" or a "gateway" is.

The network connection (interface) and the router's address are looked up from
the operating system when they are not set. A value set on purpose in
Settings > Advanced always wins, unless it names something that does not exist
on this computer (an interface called eth0 on a machine that has none), in
which case the detected one is used instead.

Detection runs system commands, so results are kept for a minute.
"""

from __future__ import annotations

import os
import time

AUTO_KEYS = ("network_interface", "router_ip")
CACHE_SECONDS = 60

_cache: dict[str, tuple[float, str | None]] = {}


def _disabled() -> bool:
    # The test-suite sets this so results do not depend on the computer running it.
    return os.environ.get("CLARINET_NO_AUTODETECT") == "1"


def _cached(name: str, find) -> str | None:
    now = time.monotonic()
    hit = _cache.get(name)
    if hit is not None and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    try:
        value = find()
    except Exception:
        value = None
    _cache[name] = (now, value)
    return value


def forget() -> None:
    """Drop what was detected (used after the admin changes the connection, and by tests)."""
    _cache.clear()


def detected_interface() -> str | None:
    """The network connection that carries traffic to the internet, if it can be found."""
    if _disabled():
        return None
    from clarinet.core_svc import netinfo
    return _cached("interface", netinfo.detect_interface)


def detected_router() -> str | None:
    """The router's address (the default gateway), if it can be found."""
    if _disabled():
        return None
    from clarinet.collector.network_check import get_gateway_ip
    return _cached("router", get_gateway_ip)


def interfaces_here() -> list[str]:
    from clarinet.core_svc import netinfo
    try:
        return netinfo.list_interfaces()
    except Exception:
        return []


def resolve(key: str, stored: str | None, default: str | None) -> str | None:
    """
    The value to use for `key`: what the admin set, or else what was detected,
    or else `default`.
    """
    stored = (stored or "").strip()
    if key == "network_interface":
        if stored and (stored in interfaces_here() or _disabled()):
            return stored
        return detected_interface() or (stored or default)
    if key == "router_ip":
        return stored or detected_router() or default
    return stored or default
