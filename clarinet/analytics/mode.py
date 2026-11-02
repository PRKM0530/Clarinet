"""
clarinet/analytics/mode.py
Mode helper for M3 (duplicated on purpose from enforcer/mode.py — independent branches).
"""
from __future__ import annotations


def get_mode(db) -> str:
    from clarinet.app_settings import get_setting
    raw = get_setting(db, "network_mode", "MONITOR")
    val = (raw or "MONITOR").strip().upper()
    return val if val in ("FULL", "MONITOR", "PUBLIC") else "MONITOR"


def is_full_or_monitor(db) -> bool:
    return get_mode(db) in ("FULL", "MONITOR")

