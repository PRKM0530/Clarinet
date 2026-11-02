"""
clarinet/core_svc/exporter.py
CSV export utilities for M1 (formula-injection safe).

All string values exported to CSV are sanitised so that values starting
with =, +, -, @ are prefixed with a tab to prevent spreadsheet formula injection.
"""

from __future__ import annotations

import csv
import io
import logging
from typing import Any

log = logging.getLogger("clarinet.core_svc.exporter")

_INJECTION_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _sanitise(value: Any) -> str:
    """Prefix potentially dangerous cell values with a tab character."""
    s = str(value) if value is not None else ""
    if s and s[0] in _INJECTION_CHARS:
        return "\t" + s
    return s


def rows_to_csv(headers: list[str], rows: list[list[Any]]) -> str:
    """
    Convert a list of rows to a CSV string with formula-injection protection.
    Returns a UTF-8 string (write to response with media_type="text/csv").
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([_sanitise(h) for h in headers])
    for row in rows:
        writer.writerow([_sanitise(v) for v in row])
    return buf.getvalue()


def devices_to_csv(devices: list[Any]) -> str:
    """Export a list of Device ORM objects to CSV."""
    headers = [
        "device_id", "mac_address", "ip_address", "hostname", "vendor",
        "label", "state", "owner_member_id", "first_seen", "last_seen",
        "is_random_mac",
    ]
    rows = []
    for d in devices:
        rows.append([
            d.device_id, d.mac_address, d.ip_address or "", d.hostname or "",
            d.vendor or "", d.label or "", d.state, d.owner_member_id or "",
            d.first_seen.isoformat() if d.first_seen else "",
            d.last_seen.isoformat() if d.last_seen else "",
            "yes" if d.is_random_mac else "no",
        ])
    return rows_to_csv(headers, rows)


def usage_to_csv(records: list[Any]) -> str:
    """Export UsageRecord ORM objects to CSV."""
    headers = ["device_id", "date", "hour", "activity", "bytes_in", "bytes_out", "total_bytes"]
    rows = []
    for r in records:
        rows.append([
            r.device_id, r.date, r.hour, r.activity,
            r.bytes_in, r.bytes_out, r.bytes_in + r.bytes_out,
        ])
    return rows_to_csv(headers, rows)

