"""
clarinet/collector/oui.py
OUI vendor lookup and random MAC detection for M1.

OUI data is loaded from clarinet/data/oui.csv (format: OUI,VendorName).
Falls back gracefully if the file is absent.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path

log = logging.getLogger("clarinet.collector.oui")

_DATA_PATH = Path(__file__).parent.parent / "data" / "oui.csv"

# Cached OUI table: "AA:BB:CC" -> "Vendor Name"
_oui_table: dict[str, str] | None = None


def _load_oui_table() -> dict[str, str]:
    global _oui_table
    if _oui_table is not None:
        return _oui_table

    table: dict[str, str] = {}
    if not _DATA_PATH.exists():
        log.debug("OUI file not found at %s — vendor lookup disabled", _DATA_PATH)
        _oui_table = table
        return table

    try:
        with open(_DATA_PATH, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    oui = row[0].strip().upper()
                    vendor = row[1].strip()
                    # Normalise OUI to AA:BB:CC format
                    oui_clean = oui.replace("-", ":").replace(".", ":")
                    if len(oui_clean) == 8:
                        table[oui_clean] = vendor
        log.debug("Loaded %d OUI entries from %s", len(table), _DATA_PATH)
    except Exception as exc:
        log.warning("Failed to load OUI file: %s", exc)

    _oui_table = table
    return table


def lookup_vendor(mac: str) -> str | None:
    """
    Return vendor name for a MAC address, or None if not found.
    mac: any of "AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF", "AABBCCDDEEFF"
    """
    try:
        clean = mac.upper().replace("-", ":").replace(".", ":")
        # Normalise to colon-separated
        if ":" not in clean:
            # Hex string without separators
            clean = ":".join(clean[i:i+2] for i in range(0, 12, 2))
        oui = ":".join(clean.split(":")[:3])
        table = _load_oui_table()
        return table.get(oui)
    except Exception:
        return None


def is_random_mac(mac: str) -> bool:
    """
    Locally-administered bit check (bit 1 of first octet).
    Devices using MAC randomisation (Android, iOS) set this bit.
    """
    try:
        first_byte = int(mac.replace(":", "").replace("-", "")[:2], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False


def invalidate_cache() -> None:
    """Force reload of OUI table on next lookup (e.g. after update_oui.py run)."""
    global _oui_table
    _oui_table = None

