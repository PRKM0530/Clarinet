"""
clarinet/analytics/mode.py
The mode helper the analytics code imports. The definition lives in core_svc/mode.py.
"""
from __future__ import annotations

from clarinet.core_svc.mode import get_mode  # noqa: F401


def is_full_or_monitor(db) -> bool:
    return get_mode(db) in ("FULL", "MONITOR")
