"""
clarinet/core_svc/mode.py
Network mode parsing and helpers.

The 'network_mode' setting drives whether Clarinet can block/limit devices:
  FULL    — has nftables, tc, root; can block and rate-limit
  MONITOR — can see traffic but cannot enforce rules
  PUBLIC  — open network (no per-device auth required by router)
"""

from __future__ import annotations

import enum


class NetworkMode(enum.Enum):
    FULL = "FULL"
    MONITOR = "MONITOR"
    PUBLIC = "PUBLIC"


_MODE_WORDS: dict[str, str] = {
    "FULL": "Full Control",
    "MONITOR": "Monitor Only",
    "PUBLIC": "Public Network",
}

_NETWORK_WORDS: dict[str, str] = {
    "FULL": "Private",
    "MONITOR": "Private",
    "PUBLIC": "Public",
}


def parse_mode(raw: str | None) -> NetworkMode:
    """Return a NetworkMode from a settings string; default MONITOR."""
    if raw and raw.upper() in NetworkMode.__members__:
        return NetworkMode[raw.upper()]
    return NetworkMode.MONITOR


def mode_word(mode: NetworkMode) -> str:
    """Human-readable mode label, e.g. 'Full Control'."""
    return _MODE_WORDS.get(mode.value, mode.value.title())


def network_word(mode: NetworkMode) -> str:
    """Human-readable network type, e.g. 'Private'."""
    return _NETWORK_WORDS.get(mode.value, "Unknown")


def can_enforce(mode: NetworkMode) -> bool:
    """True if the mode allows blocking / rate-limiting devices."""
    return mode == NetworkMode.FULL
