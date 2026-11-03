"""
clarinet/enforcer/mode.py
The mode helpers other modules import. The definition lives in core_svc/mode.py.
"""
from __future__ import annotations

from clarinet.core_svc.mode import get_mode, hold_new_devices  # noqa: F401


def is_full(db) -> bool:
    return get_mode(db) == "FULL"


def is_monitor(db) -> bool:
    return get_mode(db) in ("FULL", "MONITOR")
