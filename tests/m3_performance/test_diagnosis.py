"""
tests/m3_performance/test_diagnosis.py
Tests for clarinet.analytics.diagnosis, run against a real (in-memory) database.

AT-09.1  No slowdown event when latency is normal
AT-09.2  2-minute hold-down: a single bad sample does NOT open an event
AT-09.3  A real slowdown opens a WARNING event; a full outage opens a CRITICAL one
AT-09.5  Plain-language alert text has no technical jargon, and an outage says so
AT-09.6  An open event gets ended_at when the network recovers
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import clarinet.analytics.diagnosis as diag
from clarinet.analytics.diagnosis import MIN_BAD_SAMPLES, _format_alert, check_slowdown
from clarinet.models import Alert, SlowdownEvent


def ping(avg_ms=20.0, packet_loss=0.0, reachable=True):
    return SimpleNamespace(avg_ms=avg_ms, packet_loss=packet_loss, reachable=reachable)


def pings(internet_ms=20.0, internet_loss=0.0, internet_up=True, router_ms=5.0):
    return {
        "google_dns": ping(internet_ms, internet_loss, internet_up),
        "router": ping(router_ms),
    }


BASELINE = SimpleNamespace(avg_latency_ms=30.0, std_latency_ms=5.0)


@pytest.fixture()
def run(db):
    """
    check_slowdown(pings) wired to the test database, with the baseline fixed at
    30 ms. Anything above 2x that counts as elevated.
    """
    diag._consecutive_bad = 0
    session_factory = MagicMock()
    session_factory.return_value.__enter__ = MagicMock(return_value=db)
    session_factory.return_value.__exit__ = MagicMock(return_value=False)

    with patch("clarinet.database.SessionLocal", session_factory), \
         patch("clarinet.analytics.baseline.is_baseline_ready", return_value=True), \
         patch("clarinet.analytics.baseline.get_baseline_for_now", return_value=BASELINE), \
         patch("clarinet.analytics.baseline.latency_is_elevated",
               side_effect=lambda ms, baseline, multiplier=2.0: ms > baseline.avg_latency_ms * multiplier), \
         patch("clarinet.analytics.diagnosis._speed_below_plan_check", return_value=False):
        yield check_slowdown
    diag._consecutive_bad = 0


def events(db):
    return db.query(SlowdownEvent).all()


def alerts(db):
    return db.query(Alert).all()


# AT-09.1

def test_no_event_when_latency_normal(run, db):
    for _ in range(MIN_BAD_SAMPLES + 2):
        run(pings(internet_ms=35.0))
    assert events(db) == []
    assert alerts(db) == []


# AT-09.2

def test_hold_constant_is_at_least_2():
    """MIN_BAD_SAMPLES must be >= 2 (SRS: 2-minute hold-down, F-09a)."""
    assert MIN_BAD_SAMPLES >= 2


def test_single_bad_sample_does_not_open_event(run, db):
    run(pings(internet_ms=100.0))
    assert events(db) == []


def test_event_opens_after_the_hold_down(run, db):
    for _ in range(MIN_BAD_SAMPLES):
        run(pings(internet_ms=100.0))
    [event] = events(db)
    assert event.ended_at is None
    assert event.causes, "an event must record at least one cause"


def test_a_good_sample_resets_the_hold_down(run, db):
    run(pings(internet_ms=100.0))
    run(pings(internet_ms=25.0))           # recovered, counter resets
    run(pings(internet_ms=100.0))
    assert events(db) == []


# AT-09.3

def test_slowdown_is_a_warning_not_critical(run, db):
    for _ in range(MIN_BAD_SAMPLES):
        run(pings(internet_ms=100.0))
    [alert] = alerts(db)
    assert alert.type == "SLOWDOWN"
    assert alert.level == "WARNING"


def test_outage_is_critical_and_says_the_internet_is_down(run, db):
    for _ in range(MIN_BAD_SAMPLES):
        run(pings(internet_ms=9999.0, internet_loss=1.0, internet_up=False))
    [event] = events(db)
    assert event.causes[0]["cause"] == "INTERNET_OUTAGE"
    [alert] = alerts(db)
    assert alert.type == "OUTAGE"
    assert alert.level == "CRITICAL"
    assert "down" in alert.title.lower(), f"outage alert said: {alert.title!r}"


def test_a_continuing_slowdown_does_not_open_a_second_event(run, db):
    for _ in range(MIN_BAD_SAMPLES + 3):
        run(pings(internet_ms=100.0))
    assert len(events(db)) == 1


# AT-09.5

def test_format_alert_no_jargon():
    jargon = ["ICMP", "TCP", "traceroute", "RTT", "AI-powered", "algorithm"]
    cases = [
        ("OUTAGE", [{"cause": "INTERNET_OUTAGE", "confidence": "likely",
                     "evidence": "Your internet connection is not responding.",
                     "suggestion": "Try restarting your router."}]),
        ("SLOWDOWN", [{"cause": "ONE_DEVICE_HEAVY", "confidence": "likely",
                       "evidence": "One device is using most of the bandwidth.",
                       "suggestion": "Pause downloads on that device."}]),
        ("SLOWDOWN", [{"cause": "NO_CLEAR_CAUSE", "confidence": "possible",
                       "evidence": "Network is slow.", "suggestion": "Restart your router."}]),
    ]
    for kind, causes in cases:
        title, message = _format_alert(kind, causes, {})
        text = f"{title} {message}".lower()
        for word in jargon:
            assert word.lower() not in text, f"jargon {word!r} in {text!r}"


@pytest.mark.parametrize("kind", ["OUTAGE", "INTERNET_OUTAGE"])
def test_outage_title_is_not_the_generic_slowdown_title(kind):
    title, _ = _format_alert(kind, [{"cause": "INTERNET_OUTAGE", "evidence": "x", "suggestion": "y"}], {})
    assert "slower than usual" not in title.lower()
    assert "down" in title.lower()


# AT-09.6

def test_active_event_closed_when_network_ok(run, db):
    for _ in range(MIN_BAD_SAMPLES):
        run(pings(internet_ms=100.0))
    [event] = events(db)
    assert event.ended_at is None

    run(pings(internet_ms=25.0))           # back to normal
    db.refresh(event)
    assert event.ended_at is not None, "event should be closed when the network recovers"
