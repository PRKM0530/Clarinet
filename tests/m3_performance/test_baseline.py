"""
tests/m3_performance/test_baseline.py
Unit tests for clarinet.analytics.baseline

AT-10.1  rebuild_all populates Baseline rows from PingRecord
AT-10.2  rebuild_all skips outage samples (packet_loss >= 0.5)
AT-10.3  outlier rejection (_reject_outliers) removes IQR extremes
AT-10.4  latency_is_elevated returns True when current > 2× baseline avg
AT-10.5  latency_is_elevated returns False when baseline is None
AT-10.6  speed_is_below_plan uses 80% threshold (SRS, not 70%)
AT-10.7  is_baseline_ready returns False when sample count < 20
"""
from __future__ import annotations

import pytest
from datetime import timedelta, timezone, datetime

from clarinet.analytics.baseline import (
    _reject_outliers,
    is_baseline_ready,
    latency_is_elevated,
    rebuild_all,
    speed_is_below_plan,
)
from clarinet.models import Baseline, PingRecord


def _ping(db, target="google_dns", avg_ms=20.0, packet_loss=0.0,
          measured_at=None, reachable=True):
    """Helper: insert a PingRecord row."""
    if measured_at is None:
        measured_at = datetime.now(timezone.utc)
    r = PingRecord(
        target=target,
        host="8.8.8.8",
        avg_ms=avg_ms,
        min_ms=avg_ms * 0.9,
        max_ms=avg_ms * 1.1,
        packet_loss=packet_loss,
        reachable=reachable,
        measured_at=measured_at,
    )
    db.add(r)
    db.flush()
    return r


# ── AT-10.1 ───────────────────────────────────────────────────────────────────

def test_rebuild_all_populates_baseline(db):
    """rebuild_all creates Baseline rows from PingRecord data."""
    now = datetime.now(timezone.utc)
    # Insert several pings at the same hour/weekday
    for i in range(5):
        _ping(db, avg_ms=25.0 + i, measured_at=now)
    db.commit()

    count = rebuild_all(db=db)
    assert count >= 1

    bl = db.query(Baseline).filter(
        Baseline.hour == now.hour,
        Baseline.day_of_week == now.weekday(),
    ).first()
    assert bl is not None
    assert bl.avg_latency_ms is not None
    assert bl.sample_count >= 5


# ── AT-10.2 ───────────────────────────────────────────────────────────────────

def test_rebuild_all_skips_outage_samples(db):
    """rebuild_all excludes rows with packet_loss >= 0.5."""
    now = datetime.now(timezone.utc)
    # Good pings
    for _ in range(5):
        _ping(db, avg_ms=20.0, packet_loss=0.0, measured_at=now)
    # Outage pings — should NOT be included
    for _ in range(3):
        _ping(db, avg_ms=500.0, packet_loss=0.8, measured_at=now)
    db.commit()

    rebuild_all(db=db)
    bl = db.query(Baseline).filter(
        Baseline.hour == now.hour,
        Baseline.day_of_week == now.weekday(),
    ).first()
    assert bl is not None
    # avg should be near 20, not influenced by 500ms outage pings
    assert bl.avg_latency_ms < 50


# ── AT-10.3 ───────────────────────────────────────────────────────────────────

def test_reject_outliers_removes_extremes():
    """_reject_outliers removes IQR-based outliers from a list."""
    # Normal cluster 20-30, one extreme outlier
    values = [20.0, 21.0, 22.0, 23.0, 24.0, 25.0, 200.0]
    cleaned = _reject_outliers(values)
    assert 200.0 not in cleaned
    assert len(cleaned) < len(values)


def test_reject_outliers_small_list_unchanged():
    """_reject_outliers leaves lists with <4 elements unchanged."""
    short = [10.0, 20.0, 30.0]
    assert _reject_outliers(short) == short


# ── AT-10.4 ───────────────────────────────────────────────────────────────────

def test_latency_is_elevated_true():
    """latency_is_elevated returns True when current > 2× baseline average."""
    bl = Baseline(hour=12, day_of_week=0, avg_latency_ms=30.0, std_latency_ms=5.0, sample_count=20)
    assert latency_is_elevated(70.0, bl) is True   # 70 > 30*2 = 60


def test_latency_is_elevated_false_within_range():
    """latency_is_elevated returns False when current is within normal range."""
    bl = Baseline(hour=12, day_of_week=0, avg_latency_ms=30.0, std_latency_ms=5.0, sample_count=20)
    assert latency_is_elevated(44.0, bl) is False   # 44 < 60 and 44 < 30+3*5=45


# ── AT-10.5 ───────────────────────────────────────────────────────────────────

def test_latency_is_elevated_none_baseline():
    """latency_is_elevated returns False when baseline is None."""
    assert latency_is_elevated(9999.0, None) is False


# ── AT-10.6 ───────────────────────────────────────────────────────────────────

def test_speed_is_below_plan_uses_80_percent():
    """speed_is_below_plan flags when current < 80% of plan (SRS fix, not 70%)."""
    # 75 Mbps vs 100 Mbps plan → 75% → below 80% threshold
    assert speed_is_below_plan(75.0, 100.0) is True
    # 85 Mbps → 85% → above threshold
    assert speed_is_below_plan(85.0, 100.0) is False


def test_speed_is_below_plan_zero_plan():
    """speed_is_below_plan returns False when plan is 0 (unconfigured)."""
    assert speed_is_below_plan(0.0, 0.0) is False


# ── AT-10.7 ───────────────────────────────────────────────────────────────────

def test_is_baseline_ready_false_when_few_samples(db):
    """is_baseline_ready returns False when fewer than 20 PingRecord rows exist."""
    # Insert only 5 pings
    now = datetime.now(timezone.utc)
    for _ in range(5):
        _ping(db, measured_at=now)
    db.commit()

    assert is_baseline_ready(db) is False


def test_is_baseline_ready_true_when_enough_samples(db):
    """is_baseline_ready returns True with >= 20 recent PingRecord rows that span at least a day."""
    now = datetime.now(timezone.utc)
    for i in range(25):
        _ping(db, measured_at=now - timedelta(hours=i * 1.2))      # 29 hours of history
    db.commit()

    assert is_baseline_ready(db) is True

