"""
Phase 3: the features the system documentation promises on the dashboard, device, usage and alert pages.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from tests._support import ADMIN, ALICE, BOB, new_client, seed_world


@pytest.fixture(autouse=True)
def network_ready(monkeypatch):
    monkeypatch.setattr("clarinet.core_svc.enforcement_status.problem", lambda: None)


def ping_history(router=True):
    from clarinet.database import SessionLocal
    from clarinet.models import PingRecord
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        for i in range(30):
            t = now - timedelta(minutes=i * 5)
            for target, host in (("google_dns", "8.8.8.8"), ("cloudflare", "1.1.1.1")) + ((("router", "192.168.1.1"),) if router else ()):
                db.add(PingRecord(measured_at=t, target=target, host=host, avg_ms=20.0, min_ms=18.0, max_ms=25.0, packet_loss=0, reachable=True))
        db.commit()


# ---- dashboard
def test_dashboard_shows_the_health_badge():
    seed_world("FULL")
    assert "Healthy" in new_client(ADMIN).get("/dashboard").text


@pytest.mark.parametrize("cause,badge", [("ONE_DEVICE_HEAVY", "Degraded"), ("INTERNET_OUTAGE", "Critical slowdown")])
def test_health_badge_follows_the_active_slowdown(cause, badge):
    import json
    from clarinet.database import SessionLocal
    from clarinet.models import SlowdownEvent
    seed_world("FULL")
    with SessionLocal() as db:
        db.add(SlowdownEvent(started_at=datetime.now(timezone.utc), causes_json=json.dumps([{"cause": cause}])))
        db.commit()
    for who in (ADMIN, ALICE):
        assert badge in new_client(who).get("/dashboard").text


def test_dashboard_has_the_three_target_latency_chart():
    seed_world("FULL")
    ping_history()
    page = new_client(ALICE).get("/dashboard").text
    assert 'id="latency-chart"' in page and "Cloudflare" in page and "Google" in page
    assert '"router"' in page and '"cloudflare"' in page and '"google_dns"' in page


def test_dashboard_without_pings_explains_instead_of_an_empty_chart():
    seed_world("FULL")
    page = new_client(ADMIN).get("/dashboard").text
    assert "No latency measurements yet" in page and 'id="latency-chart"' not in page


def test_admin_is_told_how_to_get_the_router_line():
    seed_world("FULL")
    ping_history(router=False)
    assert "enter the router address" in new_client(ADMIN).get("/dashboard").text
    assert "enter the router address" not in new_client(ALICE).get("/dashboard").text


def test_dashboard_top_devices_have_usage_bars_scaled_to_the_busiest():
    seed_world("FULL")
    page = new_client(ADMIN).get("/dashboard").text
    assert "width:100%" in page                                    # the busiest device fills its bar


def test_empty_usage_is_explained_on_a_monitor_only_install():
    from clarinet.database import SessionLocal
    from clarinet.models import UsageRecord
    seed_world("MONITOR")
    with SessionLocal() as db:
        db.query(UsageRecord).delete()
        db.commit()
    for path in ("/dashboard", "/usage"):
        assert "needs Clarinet to run on the router" in new_client(ADMIN).get(path).text, path


def test_usage_is_not_explained_away_when_there_is_data():
    seed_world("FULL")
    assert "needs Clarinet to run on the router" not in new_client(ADMIN).get("/usage").text


# ---- activity stream
def test_leaving_and_rejoining_are_recorded_as_events():
    from clarinet.core_svc.presence import record_presence_changes
    from clarinet.database import SessionLocal
    from clarinet.models import Device, DeviceHistory
    world = seed_world("FULL")
    with SessionLocal() as db:
        assert record_presence_changes(db) >= 1                    # devices seen just now: JOIN
        assert record_presence_changes(db) == 0                    # nothing changed
        db.get(Device, world["d_alice"]).last_seen = datetime.now(timezone.utc) - timedelta(minutes=30)
        db.commit()
        assert record_presence_changes(db) == 1                    # alice's laptop has gone quiet: LEAVE
        db.get(Device, world["d_alice"]).last_seen = datetime.now(timezone.utc)
        db.commit()
        assert record_presence_changes(db) == 1                    # and is back: JOIN
        events = [h.event for h in db.query(DeviceHistory).filter_by(device_id=world["d_alice"]).order_by(DeviceHistory.history_id)]
    assert events == ["JOIN", "LEAVE", "JOIN"]


def test_dashboard_activity_lists_joins_and_leaves_of_own_devices_only():
    from clarinet.core_svc.presence import record_presence_changes
    from clarinet.database import SessionLocal
    seed_world("FULL")
    with SessionLocal() as db:
        record_presence_changes(db)
    mine = new_client(ALICE).get("/dashboard").text
    assert "alice-laptop" in mine and "bob-phone" not in mine
    assert "bob-phone" in new_client(ADMIN).get("/dashboard").text


def test_dashboard_page_hands_live_alerts_to_the_activity_list():
    seed_world("FULL")
    assert "clarinet:alert" in new_client(ALICE).get("/dashboard").text
    assert "clarinet:alert" in open("clarinet/static/js/clarinet.js").read()


# ---- device page
def test_device_page_has_a_seven_day_usage_chart():
    world = seed_world("FULL")
    page = new_client(ALICE).get(f"/devices/{world['d_alice']}").text
    assert 'id="week-chart"' in page and "Usage, last 7 days" in page


def test_device_page_without_usage_says_so():
    from clarinet.database import SessionLocal
    from clarinet.models import UsageRecord
    world = seed_world("FULL")
    with SessionLocal() as db:
        db.query(UsageRecord).delete()
        db.commit()
    assert "No usage recorded for this device yet" in new_client(ALICE).get(f"/devices/{world['d_alice']}").text


def test_member_sees_the_time_rules_on_their_own_device_but_cannot_change_them():
    from clarinet.database import SessionLocal
    from clarinet.models import TimeRule
    world = seed_world("FULL")
    with SessionLocal() as db:
        db.add(TimeRule(device_id=world["d_alice"], days_json='["Mon","Tue"]', start_time="21:00", end_time="06:30",
                        action="BLOCK", created_by=world["boss"], active=True))
        db.commit()
    page = new_client(ALICE).get(f"/devices/{world['d_alice']}").text
    assert "Time rules on this device" in page and "21:00" in page and "Blocked" in page
    assert "/rules/" not in page and "Manage" not in page


# ---- usage fairness
def test_fairness_index_values():
    from clarinet.analytics.fairness import fairness_words, jain_index
    assert jain_index([5, 5, 5]) == pytest.approx(1.0)
    assert jain_index([100, 1]) < 0.55
    assert jain_index([10]) is None and jain_index([]) is None and jain_index([0, 0]) is None
    assert "fairly" in fairness_words(1.0) and "most of the bandwidth" in fairness_words(0.5) and "Not enough" in fairness_words(None)


def test_usage_page_shows_a_fairness_score_without_naming_devices():
    seed_world("FULL")
    for who in (ADMIN, ALICE):
        page = new_client(who).get("/usage?period=today").text
        assert "Fairness" in page
    assert "bob-phone" not in new_client(ALICE).get("/usage?period=today").text


# ---- alerts
def test_alert_filters_by_type_level_and_status():
    seed_world("FULL")
    admin = new_client(ADMIN)
    page = admin.get("/alerts?status=ALL").text
    assert "ARP_SPOOF" in page and "SLOWDOWN" in page
    only = admin.get("/alerts?status=ALL&type=ARP_SPOOF").text
    assert "SECRET-SECURITY-ALERT" in only and "ALICE-ALERT" not in only
    assert "SECRET-SECURITY-ALERT" not in admin.get("/alerts?status=ALL&level=WARNING").text
    assert 'name="type"' in page and "Arp Spoof" in page          # the type list is offered


def test_alert_type_choices_do_not_reveal_types_a_member_cannot_see():
    seed_world("FULL")
    page = new_client(ALICE).get("/alerts?status=ALL").text
    assert "Arp Spoof" not in page and "ARP_SPOOF" not in page


def test_alerts_are_paged_with_links():
    from clarinet.database import SessionLocal
    from clarinet.models import Alert
    seed_world("FULL")
    with SessionLocal() as db:
        for i in range(45):
            db.add(Alert(level="INFO", type="TEST", title=f"bulk-{i}", message="x"))
        db.commit()
    admin = new_client(ADMIN)
    first = admin.get("/alerts?status=ALL&type=TEST").text
    assert "Page 1 of 3" in first and "page=2" in first
    assert "Page 2 of 3" in admin.get("/alerts?status=ALL&type=TEST&page=2").text


def test_a_lockout_raises_an_alert_for_administrators_only():
    seed_world("FULL")
    admin_client, bob_client = new_client(ADMIN), new_client(BOB)        # signed in before the address gets locked
    for _ in range(5):
        new_client().post("/login", data={"username": "alice", "password": "wrong"})
    admin = admin_client.get("/alerts?type=LOCKOUT").text
    assert "alice was locked out" in admin
    assert "alice was locked out" not in bob_client.get("/alerts?status=ALL").text


# ---- priority
def test_a_member_can_cancel_their_own_priority_request_from_the_page():
    world = seed_world("FULL")
    alice = new_client(ALICE)
    alice.post("/priority/request", data={"device_id": str(world["d_alice"]), "duration_min": "30"})
    assert "/cancel" in alice.get("/priority").text
    assert "/cancel" not in new_client(BOB).get("/priority").text


def test_the_priority_table_lists_requests_and_admins_can_decide_pending_ones():
    from clarinet.database import SessionLocal
    from clarinet.models import PriorityGrant
    world = seed_world("FULL")
    with SessionLocal() as db:
        db.add(PriorityGrant(member_id=world["alice"], device_id=world["d_alice"], decision="PENDING", duration_min=30, reason="video call"))
        db.commit()
    admin = new_client(ADMIN).get("/priority").text
    assert "video call" in admin and "/approve" in admin and "/deny" in admin
    assert "video call" in new_client(ALICE).get("/priority").text
    assert "video call" not in new_client(BOB).get("/priority").text
