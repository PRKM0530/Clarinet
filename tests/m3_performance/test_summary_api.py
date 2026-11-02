"""
tests/m3_performance/test_summary_api.py
Contract tests for clarinet.analytics.summary_api

C-09 pin  /api/slowdowns/summary returns required JSON shape
C-10 pin  slowdowns_between() returns correct list[dict]
          build_status() returns correct network word
"""
from __future__ import annotations

import json
import pytest
from datetime import datetime, timedelta, timezone

from clarinet.analytics.summary_api import (
    build_status,
    build_summary,
    slowdowns_between,
)
from clarinet.models import Alert, SlowdownEvent


# ── helpers ───────────────────────────────────────────────────────────────────

def _event(db, started_offset_min: int = 30, ended_offset_min: int | None = 10,
           cause: str = "SLOWDOWN"):
    """Insert a SlowdownEvent. offsets are minutes-ago values."""
    now = datetime.now(timezone.utc)
    started = now - timedelta(minutes=started_offset_min)
    ended = (now - timedelta(minutes=ended_offset_min)) if ended_offset_min is not None else None
    e = SlowdownEvent(
        started_at=started,
        ended_at=ended,
        causes_json=json.dumps([{"cause": cause, "description": "test event"}]),
        raw_metrics_json="{}",
    )
    db.add(e)
    db.flush()
    return e


# ── C-10: slowdowns_between ───────────────────────────────────────────────────

def test_slowdowns_between_returns_events_in_range(db):
    """slowdowns_between returns events whose started_at falls in [start, end]."""
    now = datetime.now(timezone.utc)
    e = _event(db, started_offset_min=60, ended_offset_min=30)
    db.commit()

    result = slowdowns_between(db, now - timedelta(hours=2), now)
    assert len(result) >= 1
    ids = [r["event_id"] for r in result]
    assert e.event_id in ids


def test_slowdowns_between_excludes_out_of_range(db):
    """slowdowns_between does NOT return events outside the window."""
    now = datetime.now(timezone.utc)
    _event(db, started_offset_min=120, ended_offset_min=90)  # 2 hours ago
    db.commit()

    # Only look at last 30 minutes
    result = slowdowns_between(db, now - timedelta(minutes=30), now)
    assert result == []


def test_slowdowns_between_dict_shape(db):
    """slowdowns_between returns dicts with required contract keys."""
    now = datetime.now(timezone.utc)
    _event(db, started_offset_min=30, ended_offset_min=10)
    db.commit()

    result = slowdowns_between(db, now - timedelta(hours=1), now)
    assert len(result) >= 1
    required = {"event_id", "started_at", "ended_at", "duration_s", "top_cause", "causes"}
    for item in result:
        missing = required - item.keys()
        assert not missing, f"slowdowns_between dict missing keys: {missing}"


# ── C-09: build_summary ───────────────────────────────────────────────────────

def test_build_summary_shape_no_active_event(db):
    """build_summary returns correct JSON shape when no active event."""
    result = build_summary(db)
    required = {"available", "status", "active_event", "events_last_7d",
                "last_event_at", "open_alerts", "diagnose_url"}
    missing = required - result.keys()
    assert not missing, f"build_summary missing keys: {missing}"
    assert result["available"] is True
    assert result["active_event"] is None
    assert result["status"] == "good"


def test_build_summary_status_slow_when_active_slowdown(db):
    """build_summary returns status='slow' when there is an open SLOWDOWN event."""
    e = _event(db, started_offset_min=5, ended_offset_min=None, cause="SLOWDOWN")
    db.commit()

    result = build_summary(db)
    assert result["status"] == "slow"
    assert result["active_event"] is not None
    assert result["active_event"]["event_id"] == e.event_id


def test_build_summary_status_problem_when_active_outage(db):
    """build_summary returns status='problem' when there is an open INTERNET_OUTAGE event."""
    _event(db, started_offset_min=5, ended_offset_min=None, cause="INTERNET_OUTAGE")
    db.commit()

    result = build_summary(db)
    assert result["status"] == "problem"


def test_build_summary_events_last_7d_count(db):
    """build_summary.events_last_7d counts correctly."""
    for _ in range(3):
        _event(db, started_offset_min=60, ended_offset_min=30)
    db.commit()

    result = build_summary(db)
    assert result["events_last_7d"] >= 3


# ── build_status ──────────────────────────────────────────────────────────────

def test_build_status_good_when_no_active(db):
    """build_status returns 'good' when no active event."""
    result = build_status(db)
    assert result["network"] == "good"
    assert "network_word" in result


def test_build_status_slow_when_active_slowdown(db):
    """build_status returns 'slow' for active SLOWDOWN event."""
    _event(db, started_offset_min=5, ended_offset_min=None, cause="SLOWDOWN")
    db.commit()

    result = build_status(db)
    assert result["network"] == "slow"
    assert result["network_word"]  # non-empty


def test_build_status_problem_when_outage(db):
    """build_status returns 'problem' for active INTERNET_OUTAGE event."""
    _event(db, started_offset_min=5, ended_offset_min=None, cause="INTERNET_OUTAGE")
    db.commit()

    result = build_status(db)
    assert result["network"] == "problem"
    assert "down" in result["network_word"].lower() or "problem" in result["network_word"].lower()
