"""
clarinet/core_svc/mode.py
The network mode, in one place.

  MONITOR - Clarinet only watches. It never changes the network.
  FULL    - Clarinet can also block devices, limit speed, apply time rules and
            give guests access. Optionally it keeps new devices offline until
            an administrator approves them (the "hold_new_devices" setting).

Older installs may still hold the value PUBLIC from when guest networks were a
separate mode. It is read as Full Control with new devices held back.
"""

from __future__ import annotations

import enum


class NetworkMode(enum.Enum):
    FULL = "FULL"
    MONITOR = "MONITOR"


_MODE_WORDS: dict[str, str] = {
    "FULL": "Full Control",
    "MONITOR": "Monitor only",
}


def parse_mode(raw: str | None) -> NetworkMode:
    """Return a NetworkMode from a settings string; unknown values mean MONITOR."""
    value = (raw or "").strip().upper()
    if value in ("FULL", "PUBLIC"):          # PUBLIC: the old guest-network mode
        return NetworkMode.FULL
    return NetworkMode.MONITOR


def mode_word(mode: NetworkMode) -> str:
    """Human-readable mode label, e.g. 'Full Control'."""
    return _MODE_WORDS.get(mode.value, mode.value.title())


def network_word(mode: NetworkMode) -> str:
    """Kept for the status page: Clarinet always describes the network it runs on as private."""
    return "Private"


def can_enforce(mode: NetworkMode) -> bool:
    """True if the mode allows blocking / rate-limiting devices."""
    return mode == NetworkMode.FULL


def get_mode(db) -> str:
    """The saved mode as 'FULL' or 'MONITOR'."""
    from clarinet.app_settings import get_setting
    return parse_mode(get_setting(db, "network_mode", "MONITOR")).value


def hold_new_devices(db) -> bool:
    """
    True when devices nobody has approved yet must stay offline until an
    administrator approves them or they use a voucher. Only meaningful in Full Control.
    """
    from clarinet.app_settings import get_setting
    if get_mode(db) != "FULL":
        return False
    if (get_setting(db, "network_mode", "") or "").strip().upper() == "PUBLIC":
        return True
    return (get_setting(db, "hold_new_devices", "false") or "").strip().lower() == "true"
