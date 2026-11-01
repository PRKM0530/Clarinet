"""
tests/m3_performance/test_diagnosis.py
Unit tests for clarinet.analytics.diagnosis

AT-09.1  No slowdown event when latency is normal
AT-09.2  2-minute hold-down: single spike does NOT open an event (MIN_BAD_SAMPLES=2)
AT-09.3  INTERNET_OUTAGE cause when router is unreachable (packet_loss=1.0)
AT-09.4  Diagnosis classify helpers: _build_causes returns INTERNET_OUTAGE / SLOWDOWN
AT-09.5  Plain-language text has no technical jargon
AT-09.6  Open event gets ended_at when network recovers
"""
from __future__ import annotations

import json
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, call

from clarinet.analytics.diagnosis import (
    MIN_BAD_SAMPLES,
    _format_alert,
    check_slowdown,
)
from clarinet.models import SlowdownEvent


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_ping(avg_ms=20.0, packet_loss=0.0, reachable=True):
    """Return a mock PingResult-like object."""
    m = MagicMock()
    m.avg_ms = avg_ms
    m.packet_loss = packet_loss
    m.reachable = reachable
    return m


def _ping_results(internet_ms=20.0, internet_loss=0.0, internet_up=True,
                  router_ms=5.0, router_up=True):
    return {
        "google_dns": _make_ping(internet_ms, internet_loss, internet_up),
        "router": _make_ping(router_ms, 0.0, router_up),
    }


def _make_session_context(mock_db):
    """Return a context manager mock that yields mock_db."""
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=mock_db)
    cm.__exit__ = MagicMock(return_value=False)
    return cm


# ── AT-09.1 ───────────────────────────────────────────────────────────────────

def test_no_event_when_latency_normal():
    """No SlowdownEvent is created when latency is within baseline."""
    import clarinet.analytics.diagnosis as diag_mod
    diag_mod._consecutive_bad = 0

    mock_baseline = MagicMock()
    mock_baseline.avg_latency_ms = 30.0
    mock_baseline.std_latency_ms = 5.0

    pings = _ping_results(internet_ms=35.0, internet_loss=0.0)

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    with patch("clarinet.database.SessionLocal", return_value=_make_session_context(mock_db)), \
         patch("clarinet.analytics.baseline.is_baseline_ready", return_value=True), \
         patch("clarinet.analytics.baseline.get_baseline_for_now", return_value=mock_baseline), \
         patch("clarinet.analytics.baseline.latency_is_elevated", return_value=False), \
         patch("clarinet.analytics.diagnosis._speed_below_plan_check", return_value=False):

        check_slowdown(pings)
        mock_db.add.assert_not_called()

    diag_mod._consecutive_bad = 0


# ── AT-09.2 ───────────────────────────────────────────────────────────────────

def test_hold_constant_is_at_least_2():
    """MIN_BAD_SAMPLES must be >= 2 (SRS: 2-minute hold-down, F-09a)."""
    assert MIN_BAD_SAMPLES >= 2, (
        f"MIN_BAD_SAMPLES={MIN_BAD_SAMPLES} — must be >= 2 for 2-min hold (SRS F-09a)"
    )


def test_single_bad_sample_does_not_open_event():
    """A single elevated reading should NOT open a SlowdownEvent (hold-down)."""
    import clarinet.analytics.diagnosis as diag_mod
    diag_mod._consecutive_bad = 0

    mock_baseline = MagicMock()
    mock_baseline.avg_latency_ms = 30.0
    mock_baseline.std_latency_ms = 5.0

    pings = _ping_results(internet_ms=100.0, internet_loss=0.0)

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    with patch("clarinet.database.SessionLocal", return_value=_make_session_context(mock_db)), \
         patch("clarinet.analytics.baseline.is_baseline_ready", return_value=True), \
         patch("clarinet.analytics.baseline.get_baseline_for_now", return_value=mock_baseline), \
         patch("clarinet.analytics.baseline.latency_is_elevated", return_value=True), \
         patch("clarinet.analytics.diagnosis._speed_below_plan_check", return_value=False):

        # First call — _consecutive_bad goes 0→1 (below MIN_BAD_SAMPLES=2)
        check_slowdown(pings)
        mock_db.add.assert_not_called()

    diag_mod._consecutive_bad = 0


# ── AT-09.3 ───────────────────────────────────────────────────────────────────

def test_outage_detected_when_internet_unreachable():
    """When internet is unreachable (packet_loss=1.0), an event is opened."""
    import clarinet.analytics.diagnosis as diag_mod
    diag_mod._consecutive_bad = MIN_BAD_SAMPLES  # hold satisfied

    mock_baseline = MagicMock()
    mock_baseline.avg_latency_ms = 30.0
    mock_baseline.std_latency_ms = 5.0

    pings = _ping_results(internet_ms=9999.0, internet_loss=1.0, internet_up=False)

    added_events = []

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None
    mock_db.add.side_effect = lambda obj: added_events.append(obj)

    with patch("clarinet.database.SessionLocal", return_value=_make_session_context(mock_db)), \
         patch("clarinet.analytics.baseline.is_baseline_ready", return_value=True), \
         patch("clarinet.analytics.baseline.get_baseline_for_now", return_value=mock_baseline), \
         patch("clarinet.analytics.baseline.latency_is_elevated", return_value=True), \
         patch("clarinet.analytics.diagnosis._speed_below_plan_check", return_value=False), \
         patch("clarinet.analytics.diagnosis._raise_alert"):

        check_slowdown(pings)

    assert len(added_events) >= 1, "Expected at least one SlowdownEvent to be added"
    diag_mod._consecutive_bad = 0


# ── AT-09.5 ───────────────────────────────────────────────────────────────────

def test_format_alert_no_jargon():
    """_format_alert returns human-readable title and message."""
    jargon = ["ICMP", "TCP", "traceroute", "RTT", "AI-powered", "algorithm"]

    causes_by_type = [
        ("INTERNET_OUTAGE", [{"cause": "INTERNET_OUTAGE", "confidence": "likely",
                               "evidence": "Internet is unreachable.",
                               "suggestion": "Contact your ISP."}]),
        ("SLOWDOWN", [{"cause": "ONE_DEVICE_HEAVY", "confidence": "likely",
                        "evidence": "One device is using most of the bandwidth.",
                        "suggestion": "Pause downloads on that device."}]),
        ("SLOWDOWN", [{"cause": "NO_CLEAR_CAUSE", "confidence": "possible",
                        "evidence": "Network is slow.",
                        "suggestion": "Restart your router."}]),
    ]

    for kind, causes in causes_by_type:
        title, message = _format_alert(kind, causes, {})
        full_text = f"{title} {message}"
        for word in jargon:
            assert word.lower() not in full_text.lower(), (
                f"Jargon '{word}' in alert text for {kind}: {full_text!r}"
            )


# ── AT-09.6 ───────────────────────────────────────────────────────────────────

def test_active_event_closed_when_network_ok():
    """Open SlowdownEvent gets ended_at set when network returns to normal."""
    import clarinet.analytics.diagnosis as diag_mod
    diag_mod._consecutive_bad = 0

    mock_baseline = MagicMock()
    mock_baseline.avg_latency_ms = 30.0
    mock_baseline.std_latency_ms = 5.0

    pings = _ping_results(internet_ms=25.0, internet_loss=0.0)  # back to normal

    # Fake open event
    fake_event = MagicMock()
    fake_event.ended_at = None
    fake_event.event_id = 42

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = fake_event

    with patch("clarinet.database.SessionLocal", return_value=_make_session_context(mock_db)), \
         patch("clarinet.analytics.baseline.is_baseline_ready", return_value=True), \
         patch("clarinet.analytics.baseline.get_baseline_for_now", return_value=mock_baseline), \
         patch("clarinet.analytics.baseline.latency_is_elevated", return_value=False), \
         patch("clarinet.analytics.diagnosis._speed_below_plan_check", return_value=False):

        check_slowdown(pings)

    assert fake_event.ended_at is not None, "Event should be closed when network recovers"
