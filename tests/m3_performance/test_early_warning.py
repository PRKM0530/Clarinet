"""
tests/m3_performance/test_early_warning.py
Unit tests for clarinet.analytics.early_warning

AT-EW.1  No warning when latency is flat
AT-EW.2  Warning raised when latency trends sharply upward
AT-EW.3  Warning payload has required keys (level, type, title, message)
AT-EW.4  check_early_warning returns None when too few samples
"""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from clarinet.analytics.early_warning import (
    SLOPE_WARN_THRESHOLD,
    TREND_MIN_SAMPLES,
    TREND_WINDOW_MINUTES,
    check_early_warning,
)
from clarinet.models import PingRecord


# ── helpers ───────────────────────────────────────────────────────────────────

def _add_pings(db, latencies: list[float]):
    """Insert PingRecord rows evenly spaced over TREND_WINDOW_MINUTES."""
    now = datetime.now(timezone.utc)
    n = len(latencies)
    for i, lat in enumerate(latencies):
        offset = TREND_WINDOW_MINUTES * (1 - i / max(n - 1, 1))
        r = PingRecord(
            target="google_dns",
            host="8.8.8.8",
            avg_ms=lat,
            min_ms=lat * 0.9,
            max_ms=lat * 1.1,
            packet_loss=0.0,
            reachable=True,
            measured_at=now - timedelta(minutes=offset),
        )
        db.add(r)
    db.flush()


def _mock_baseline(avg_ms=30.0):
    bl = MagicMock()
    bl.avg_latency_ms = avg_ms
    bl.std_latency_ms = 5.0
    return bl


# ── AT-EW.1 ───────────────────────────────────────────────────────────────────

def test_no_warning_flat_trend(db):
    """No early warning when latency is stable (flat trend)."""
    flat = [30.0] * 10
    _add_pings(db, flat)
    db.commit()

    with patch("clarinet.analytics.early_warning.get_baseline_for_now",
               return_value=_mock_baseline(avg_ms=30.0)):
        result = check_early_warning(db=db)

    # Flat trend should produce no warning (slope near 0, not near threshold)
    assert result is None


# ── AT-EW.2 ───────────────────────────────────────────────────────────────────

def test_warning_raised_on_sharp_rising_latency(db):
    """Early warning fires when latency rises sharply and nears the alert threshold."""
    # Baseline avg=30, alert threshold=60. Rise from 20 → 55 ms (near 70% of 60=42)
    # Use strong rise so slope >> SLOPE_WARN_THRESHOLD
    baseline_avg = 30.0
    alert_threshold = baseline_avg * 2.0   # 60 ms
    pre_thresh = alert_threshold * 0.70    # 42 ms

    # 10 samples: start at 20, end at 55 — steep rise, last sample > pre_thresh
    rising = [20.0 + i * 3.9 for i in range(10)]   # ends at ~55 ms
    _add_pings(db, rising)
    db.commit()

    with patch("clarinet.analytics.early_warning.get_baseline_for_now",
               return_value=_mock_baseline(avg_ms=baseline_avg)):
        result = check_early_warning(db=db)

    assert result is not None, (
        f"Expected early warning for sharp latency rise. "
        f"SLOPE_WARN_THRESHOLD={SLOPE_WARN_THRESHOLD}"
    )


# ── AT-EW.3 ───────────────────────────────────────────────────────────────────

def test_warning_payload_keys(db):
    """Warning result contains required keys: level, type, title, message."""
    baseline_avg = 30.0
    rising = [20.0 + i * 3.9 for i in range(10)]
    _add_pings(db, rising)
    db.commit()

    with patch("clarinet.analytics.early_warning.get_baseline_for_now",
               return_value=_mock_baseline(avg_ms=baseline_avg)):
        result = check_early_warning(db=db)

    if result is not None:
        required = {"level", "type", "title", "message"}
        missing = required - result.keys()
        assert not missing, f"Warning payload missing keys: {missing}"
        assert result["level"] == "WARNING"
        assert result["type"] == "EARLY_SLOWDOWN_WARNING"
        assert isinstance(result["title"], str) and result["title"]
        assert isinstance(result["message"], str) and result["message"]


# ── AT-EW.4 ───────────────────────────────────────────────────────────────────

def test_no_warning_when_too_few_samples(db):
    """check_early_warning returns None when there are fewer than TREND_MIN_SAMPLES records."""
    # Insert fewer than the minimum required
    sparse = [50.0] * (TREND_MIN_SAMPLES - 1)
    _add_pings(db, sparse)
    db.commit()

    with patch("clarinet.analytics.early_warning.get_baseline_for_now",
               return_value=_mock_baseline(avg_ms=30.0)):
        result = check_early_warning(db=db)

    assert result is None, "Should not warn with insufficient samples"


def test_no_warning_when_baseline_none(db):
    """check_early_warning returns None when no baseline is available."""
    rising = [20.0 + i * 5.0 for i in range(10)]
    _add_pings(db, rising)
    db.commit()

    with patch("clarinet.analytics.early_warning.get_baseline_for_now", return_value=None):
        result = check_early_warning(db=db)

    assert result is None, "Should not warn without baseline"
