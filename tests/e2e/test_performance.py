"""
PRF-02/03: slowdown detection against a real database. Only the ping RESULTS are supplied
(the outer edge); the baseline, hold rule, event open/close and alert code all run for real.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tests._support import seed_world


@pytest.fixture(autouse=True)
def world():
    seed_world()
    from clarinet.database import SessionLocal
    from clarinet.models import Alert
    with SessionLocal() as db:           # the shared world has open SLOWDOWN alerts; they would trigger the cooldown
        db.query(Alert).delete()
        db.commit()
    from clarinet.analytics import diagnosis
    diagnosis._consecutive_bad = 0
    yield
    diagnosis._consecutive_bad = 0


def seed_pings(count=40, ms=20.0, spread_hours=12):
    from clarinet.database import SessionLocal
    from clarinet.models import PingRecord
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        for i in range(count):
            t = now - timedelta(minutes=i * spread_hours * 60 // count)
            db.add(PingRecord(measured_at=t, target="google_dns", host="8.8.8.8", avg_ms=ms + (i % 3),
                              min_ms=ms, max_ms=ms + 3, packet_loss=0.0, reachable=True))
        db.commit()


def ping(target, ms=20.0, loss=0.0, reachable=True):
    from clarinet.collector.pinger import PingResult
    host = {"google_dns": "8.8.8.8", "cloudflare": "1.1.1.1", "router": "192.168.1.1"}[target]
    return PingResult(target, host, ms if reachable else None, ms if reachable else None,
                      ms if reachable else None, loss, reachable)


def sample(google=None, cloudflare=None):
    from clarinet.analytics.diagnosis import _check_slowdown_inner
    _check_slowdown_inner({"google_dns": google or ping("google_dns"), "cloudflare": cloudflare or ping("cloudflare")})


def events_and_alerts():
    from clarinet.database import SessionLocal
    from clarinet.models import Alert, SlowdownEvent
    with SessionLocal() as db:
        return (db.query(SlowdownEvent).all(), [a.type for a in db.query(Alert).filter(Alert.type.in_(["SLOWDOWN", "OUTAGE"]))])


def ready_baseline():
    from clarinet.analytics.baseline import rebuild_all
    seed_pings()
    rebuild_all()


def test_prf03_slow_latency_needs_two_samples_then_opens_one_event_and_closes():
    ready_baseline()
    slow = ping("google_dns", ms=400.0)
    sample(google=slow)
    assert events_and_alerts() == ([], [])                     # one bad sample is only held
    sample(google=slow)
    events, alerts = events_and_alerts()
    assert len(events) == 1 and alerts == ["SLOWDOWN"]
    sample(google=slow)
    assert len(events_and_alerts()[0]) == 1                   # not reopened while it continues
    sample()                                                  # back to normal
    events, _ = events_and_alerts()
    assert events[0].ended_at is not None


def test_prf03_total_outage_is_critical_and_labelled_outage():
    from clarinet.database import SessionLocal
    from clarinet.models import Alert
    ready_baseline()
    down = lambda t: ping(t, reachable=False, loss=1.0)
    sample(google=down("google_dns"), cloudflare=down("cloudflare"))
    sample(google=down("google_dns"), cloudflare=down("cloudflare"))
    with SessionLocal() as db:
        alert = db.query(Alert).filter(Alert.type == "OUTAGE").one()
        assert alert.level == "CRITICAL"


def test_prf03_packet_loss_alone_opens_a_slowdown():
    ready_baseline()
    lossy = ping("google_dns", loss=0.2)
    sample(google=lossy)
    sample(google=lossy)
    assert events_and_alerts()[1] == ["SLOWDOWN"]


@pytest.mark.xfail(strict=True, reason="S-16: losing only 8.8.8.8 is reported as a full outage although 1.1.1.1 works")
def test_s16_one_dead_ping_target_is_not_an_outage():
    ready_baseline()
    down = ping("google_dns", reachable=False, loss=1.0)
    sample(google=down)
    sample(google=down)
    assert "OUTAGE" not in events_and_alerts()[1]


@pytest.mark.xfail(strict=True, reason="S-17: 20 recent pings count as a 'ready' baseline; the design asks for 7 days of history")
def test_s17_baseline_is_not_ready_after_one_hour_of_samples():
    from clarinet.analytics.baseline import is_baseline_ready
    from clarinet.database import SessionLocal
    seed_pings(count=40, spread_hours=1)
    with SessionLocal() as db:
        assert is_baseline_ready(db) is False


@pytest.mark.xfail(strict=True, reason="S-17: no baseline rows exist before the 03:00 rebuild, so a slow line is never flagged until then")
def test_s17_slowdown_is_detected_before_the_first_nightly_rebuild():
    seed_pings()            # enough samples, but rebuild_all() has not run yet
    slow = ping("google_dns", ms=400.0)
    sample(google=slow)
    sample(google=slow)
    assert events_and_alerts()[1] == ["SLOWDOWN"]
