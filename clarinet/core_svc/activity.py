"""
clarinet/core_svc/activity.py
Activity types (streaming, browsing, gaming, ...) for each device's traffic.

Clarinet never looks inside traffic. It only sees which domain names a device
looks up, and how many bytes the device moved in each hour. From those two
facts it works out what the hour was mostly spent on:

  1. classify_name()   maps a domain name to an activity type
  2. split_bytes()     shares an hour's bytes between the types, in proportion
                       to how many lookups each type had that hour
  3. classify_recent() writes the result to UsageActivity

Hours with no lookups are counted as OTHER.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

from sqlalchemy.orm import Session

log = logging.getLogger("clarinet.core_svc.activity")

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "domain_categories.json"

# Order is the order they are shown in.
CATEGORIES = ["STREAMING", "BROWSING", "CALLS", "GAMING", "DOWNLOAD", "UPDATES", "OTHER"]

LABELS = {
    "STREAMING": "Streaming",
    "BROWSING": "Browsing and social",
    "CALLS": "Calls and messaging",
    "GAMING": "Gaming",
    "DOWNLOAD": "Downloads",
    "UPDATES": "Software updates",
    "OTHER": "Other",
}

# Public suffixes with two parts, so "bbc.co.uk" is the registrable name and not "co.uk".
_TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "ac.in", "gov.in", "edu.in",
    "co.jp", "ne.jp", "or.jp", "co.kr", "co.nz", "co.za", "com.au", "net.au", "org.au", "edu.au",
    "com.br", "com.cn", "com.hk", "com.sg", "com.my", "com.tr", "com.mx", "com.ar", "com.pk",
}


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    try:
        return {k.lower(): v.upper() for k, v in json.loads(DATA_FILE.read_text(encoding="utf-8")).items()}
    except (OSError, ValueError) as exc:
        log.warning("Could not read %s: %s", DATA_FILE, exc)
        return {}


def clean_name(name: str) -> str | None:
    """Lower-case a DNS name and drop names that say nothing about activity."""
    name = (name or "").strip().rstrip(".").lower()
    if not name or "." not in name:
        return None
    if name.endswith((".arpa", ".local", ".lan", ".home", ".internal", ".localdomain")):
        return None
    return name


def registrable_domain(name: str) -> str | None:
    """'rr3---sn-abc.googlevideo.com' -> 'googlevideo.com'; 'www.bbc.co.uk' -> 'bbc.co.uk'."""
    name = clean_name(name)
    if name is None:
        return None
    labels = name.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def classify_name(name: str) -> str:
    """Activity type of a DNS name. Tries the full name first, then each parent domain."""
    name = clean_name(name)
    if name is None:
        return "OTHER"
    table = _table()
    labels = name.split(".")
    for start in range(len(labels) - 1):
        hit = table.get(".".join(labels[start:]))
        if hit:
            return hit
    return "OTHER"


def split_bytes(bytes_in: int, bytes_out: int, weights: dict[str, int]) -> dict[str, tuple[int, int]]:
    """
    Share an hour's bytes between activity types in proportion to `weights`.
    The shares always add up to exactly the original totals.
    """
    weights = {k: w for k, w in weights.items() if w > 0}
    if not weights:
        return {"OTHER": (bytes_in, bytes_out)}
    total = sum(weights.values())
    # Largest first, so rounding leftovers go to the dominant type
    order = sorted(weights, key=lambda k: (-weights[k], k))
    shares: dict[str, tuple[int, int]] = {}
    left_in, left_out = bytes_in, bytes_out
    for cat in order[:-1]:
        part_in = bytes_in * weights[cat] // total
        part_out = bytes_out * weights[cat] // total
        shares[cat] = (part_in, part_out)
        left_in -= part_in
        left_out -= part_out
    shares[order[-1]] = (left_in, left_out)
    return shares


def classify_recent(db: Session, hours: int = 48) -> int:
    """
    (Re)build the UsageActivity rows for the last `hours` hours of usage.
    Safe to run repeatedly. Returns the number of hour buckets written.
    """
    from clarinet.models import UsageRecord
    from clarinet.models.traffic import DomainObservation, UsageActivity

    now = datetime.now(timezone.utc)
    first_day = (now - timedelta(hours=hours)).date().isoformat()
    written = 0

    for rec in db.query(UsageRecord).filter(UsageRecord.date >= first_day).all():
        hour_start = datetime.fromisoformat(rec.date).replace(hour=rec.hour, tzinfo=timezone.utc)
        if hour_start < now - timedelta(hours=hours):
            continue

        weights: dict[str, int] = {}
        for obs in (
            db.query(DomainObservation)
            .filter(
                DomainObservation.device_id == rec.device_id,
                DomainObservation.observed_at >= hour_start.replace(tzinfo=None),
                DomainObservation.observed_at < (hour_start + timedelta(hours=1)).replace(tzinfo=None),
            )
            .all()
        ):
            if obs.category and obs.category not in ("UNKNOWN", "OTHER"):
                weights[obs.category] = weights.get(obs.category, 0) + (obs.hit_count or 1)

        db.query(UsageActivity).filter(
            UsageActivity.device_id == rec.device_id,
            UsageActivity.date == rec.date,
            UsageActivity.hour == rec.hour,
        ).delete()
        for category, (b_in, b_out) in split_bytes(rec.bytes_in, rec.bytes_out, weights).items():
            db.add(UsageActivity(
                device_id=rec.device_id, date=rec.date, hour=rec.hour,
                category=category, bytes_in=b_in, bytes_out=b_out,
            ))
        written += 1

    db.commit()
    return written
