"""
clarinet/enforcer/mode.py
Small helper: read `network_mode` from the DB and classify it.
"""
from __future__ import annotations


def get_mode(db) -> str:
    """Return 'FULL', 'MONITOR', or 'PUBLIC' (default MONITOR for unknown values)."""
    from clarinet.app_settings import get_setting
    raw = get_setting(db, "network_mode", "MONITOR")
    val = (raw or "MONITOR").strip().upper()
    if val in ("FULL", "MONITOR", "PUBLIC"):
        return val
    return "MONITOR"


def is_full(db) -> bool:
    return get_mode(db) == "FULL"


def is_monitor(db) -> bool:
    return get_mode(db) in ("FULL", "MONITOR")

