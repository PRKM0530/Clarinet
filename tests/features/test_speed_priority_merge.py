"""
The provider speed report (UC-08), the admin-editable priority rules (FAIR-6),
and merging and splitting device entries (DEV-5).
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from clarinet import app
from clarinet.auth import hash_password
from clarinet.database import Base, SessionLocal, engine
from clarinet.models import (
    Alert, AuditLog, Device, DeviceHistory, Member, Settings, SpeedTestResult, UsageRecord,
)
from clarinet.models.merging import MergedMac


@pytest.fixture()
def db():
    assert "clarinet_test_" in str(engine.url), "refusing to touch a non-test database"
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        session.add(Settings(key="setup_complete", value="true"))
        session.add(Settings(key="plan_download_mbps", value="100"))
        session.add(Settings(key="plan_upload_mbps", value="20"))
        session.add(Member(username="alice", password_hash=hash_password("pw-alice-1"), role="MEMBER"))
        session.add(Member(username="boss", password_hash=hash_password("pw-boss-1"), role="ADMIN"))
        session.commit()
        yield session


def login(user, password):
    client = TestClient(app, follow_redirects=False, raise_server_exceptions=False)
    assert client.post("/login", data={"username": user, "password": password}).status_code == 302
    return client


def admin():
    return login("boss", "pw-boss-1")


def member():
    return login("alice", "pw-alice-1")


# the provider speed report

def add_tests(db, speeds, busy=False, days_ago=1):
    for i, down in enumerate(speeds):
        db.add(SpeedTestResult(
            tested_at=datetime.now(timezone.utc) - timedelta(days=days_ago, hours=i),
            download_mbps=down, upload_mbps=18.0, latency_ms=20.0, busy=busy,
        ))
    db.commit()


def test_report_counts_tests_under_the_threshold_and_says_often_below(db):
    from clarinet.core_svc.speed_report import build_speed_report
    add_tests(db, [95, 60, 50, 90])                       # 2 of 4 are under 80 Mbps
    report = build_speed_report(db, 30)
    assert len(report.tests) == 4 and report.below_count == 2
    assert report.avg_download == 73.8 and report.min_download == 50.0 and report.max_download == 95.0
    assert report.often_below is True
    assert "often slower" in report.verdict() and "2 of 4" in report.verdict()


def test_report_says_the_plan_was_met_when_only_a_few_tests_were_low(db):
    from clarinet.core_svc.speed_report import build_speed_report
    add_tests(db, [95, 92, 98, 91, 70])                   # 1 of 5 = 20%, not "often"
    report = build_speed_report(db, 30)
    assert report.below_count == 1 and report.often_below is False
    assert "mostly delivered" in report.verdict()


def test_tests_taken_while_the_network_was_busy_are_left_out(db):
    from clarinet.core_svc.speed_report import build_speed_report
    add_tests(db, [95, 96])
    add_tests(db, [5, 5, 5], busy=True)
    report = build_speed_report(db, 30)
    assert len(report.tests) == 2 and report.busy_excluded == 3 and report.below_count == 0


def test_tests_outside_the_period_are_ignored(db):
    from clarinet.core_svc.speed_report import build_speed_report
    add_tests(db, [10], days_ago=40)
    assert build_speed_report(db, 30).tests == []
    assert len(build_speed_report(db, 90).tests) == 1


def test_report_with_no_tests_or_no_plan_does_not_claim_anything(db):
    from clarinet.core_svc.speed_report import build_speed_report
    assert "no valid speed tests" in build_speed_report(db, 30).verdict()
    db.get(Settings, "plan_download_mbps").value = "0"
    add_tests(db, [50])
    db.commit()
    assert "No plan speed is set" in build_speed_report(db, 30).verdict()


def test_threshold_follows_the_setting(db):
    from clarinet.core_svc.speed_report import build_speed_report
    add_tests(db, [85, 85, 85, 85])
    assert build_speed_report(db, 30).below_count == 0
    db.add(Settings(key="speed_report_threshold_pct", value="90"))
    db.commit()
    assert build_speed_report(db, 30).below_count == 4


def test_speed_report_page_is_for_admins_and_shows_the_numbers(db):
    add_tests(db, [95, 60, 50, 90])
    page = admin().get("/speed/report")
    assert page.status_code == 200
    for text in ("Internet speed report", "100 / 20 Mbps", "often slower", "Print"):
        assert text in page.text, text
    refused = member().get("/speed/report")
    assert refused.status_code == 302 and "forbidden" in refused.headers["location"]
    assert TestClient(app, follow_redirects=False).get("/speed/report").status_code == 302


@pytest.mark.parametrize("days", ["7", "30", "90", "5", "abc", "-1", ""])
def test_speed_report_page_survives_any_period(db, days):
    assert admin().get(f"/speed/report?days={days}").status_code == 200


@pytest.mark.parametrize("bad", ["5", "101", "abc", "-3", "7.5"])
def test_a_bad_speed_threshold_is_rejected(db, bad):
    r = admin().post("/settings/update", data={"speed_report_threshold_pct": bad})
    assert "bad_threshold" in r.headers["location"]
    assert db.get(Settings, "speed_report_threshold_pct") is None


def test_admin_can_change_the_speed_threshold(db):
    admin().post("/settings/update", data={"speed_report_threshold_pct": "70"})
    db.expire_all()
    assert db.get(Settings, "speed_report_threshold_pct").value == "70"


# priority rules the admin can change

def test_priority_rules_start_at_the_defaults(db):
    from clarinet.routers.priority import get_policy
    assert get_policy(db) == {"default_duration_min": 60, "max_duration_min": 120, "daily_limit_min": 180}


def test_admin_can_change_the_priority_rules(db):
    r = admin().post("/priority/policy", data={"default_duration_min": "30", "max_duration_min": "60", "daily_limit_min": "90"})
    assert "policy_saved" in r.headers["location"]
    from clarinet.routers.priority import get_policy
    db.expire_all()
    assert get_policy(db) == {"default_duration_min": 30, "max_duration_min": 60, "daily_limit_min": 90}
    assert "UPDATE_PRIORITY_POLICY" in [a.action for a in db.query(AuditLog)]


@pytest.mark.parametrize("values, error", [
    (("0", "60", "90"), "bad_policy"),
    (("30", "abc", "90"), "bad_policy"),
    (("30", "60", "99999"), "bad_policy"),
    (("30", "", "90"), "bad_policy"),
    (("90", "60", "120"), "bad_policy_order"),        # default longer than the maximum
    (("30", "120", "60"), "bad_policy_order"),        # maximum longer than the daily total
])
def test_nonsense_priority_rules_are_refused_and_nothing_is_saved(db, values, error):
    r = admin().post("/priority/policy", data=dict(zip(("default_duration_min", "max_duration_min", "daily_limit_min"), values)))
    assert error in r.headers["location"]
    assert db.get(Settings, "priority.max_duration_min") is None


def test_a_member_cannot_change_the_priority_rules(db):
    r = member().post("/priority/policy", data={"default_duration_min": "1", "max_duration_min": "1", "daily_limit_min": "1"})
    assert r.status_code == 302
    assert db.get(Settings, "priority.daily_limit_min") is None


def test_the_daily_limit_the_admin_sets_is_the_one_that_decides_requests(db):
    from clarinet.routers.priority import _auto_decide
    admin().post("/priority/policy", data={"default_duration_min": "10", "max_duration_min": "30", "daily_limit_min": "30"})
    boss = db.query(Member).filter(Member.username == "boss").one()
    device = Device(mac_address="AA:00:00:00:00:01", state="APPROVED")
    db.add(device)
    db.commit()
    assert _auto_decide(db, boss.member_id, device.device_id, 30)[0] == "APPROVED"
    decision, reason = _auto_decide(db, boss.member_id, device.device_id, 45)
    assert decision == "DENIED" and "30 minutes" in reason


def test_the_priority_page_offers_only_lengths_the_rules_allow(db):
    db.add(Settings(key="network_mode", value="FULL"))          # priority only exists in Full Control mode
    db.commit()
    admin().post("/priority/policy", data={"default_duration_min": "15", "max_duration_min": "30", "daily_limit_min": "60"})
    page = admin().get("/priority").text
    assert 'name="default_duration_min"' in page and 'value="60"' in page
    assert member().get("/priority").text.count('name="default_duration_min"') == 0


# merging and splitting devices

def two_devices(db):
    now = datetime.now(timezone.utc)
    alice = db.query(Member).filter(Member.username == "alice").one()
    main = Device(mac_address="AA:00:00:00:00:01", ip_address="192.168.1.10", label="Alice phone", state="APPROVED",
                  owner_member_id=alice.member_id, first_seen=now, last_seen=now)
    extra = Device(mac_address="CC:00:00:00:00:03", ip_address="192.168.1.20", hostname="android-123", state="NEW",
                   first_seen=now - timedelta(days=2), last_seen=now)
    db.add_all([main, extra])
    db.commit()
    return main, extra


def test_merging_moves_usage_history_and_alerts_and_adds_up_shared_hours(db):
    from clarinet.core_svc.device_merge import merge_devices
    main, extra = two_devices(db)
    today = date.today().isoformat()
    db.add_all([
        UsageRecord(device_id=main.device_id, date=today, hour=9, bytes_in=100, bytes_out=10),
        UsageRecord(device_id=extra.device_id, date=today, hour=9, bytes_in=50, bytes_out=5),     # same hour: added up
        UsageRecord(device_id=extra.device_id, date=today, hour=10, bytes_in=70, bytes_out=7),    # different hour: moved
        DeviceHistory(device_id=extra.device_id, event="JOIN", ip_address="192.168.1.20"),
        Alert(level="INFO", type="NEW_DEVICE", title="new", message="x", device_id=extra.device_id),
    ])
    db.commit()
    main_id, extra_id = main.device_id, extra.device_id

    merge_devices(db, main_id, extra_id)

    assert db.get(Device, extra_id) is None
    usage = {r.hour: (r.bytes_in, r.bytes_out) for r in db.query(UsageRecord).filter(UsageRecord.device_id == main_id)}
    assert usage == {9: (150, 15), 10: (70, 7)}
    assert db.query(UsageRecord).filter(UsageRecord.device_id == extra_id).count() == 0
    assert db.query(DeviceHistory).filter(DeviceHistory.device_id == main_id).count() == 1
    assert db.query(Alert).filter(Alert.device_id == main_id).count() == 1
    alias = db.get(MergedMac, "CC:00:00:00:00:03")
    assert alias.primary_device_id == main_id and alias.former_label == "android-123"


def test_the_main_device_keeps_its_label_and_owner(db):
    from clarinet.core_svc.device_merge import merge_devices
    main, extra = two_devices(db)
    owner = main.owner_member_id
    merge_devices(db, main.device_id, extra.device_id)
    db.refresh(main)
    assert main.label == "Alice phone" and main.owner_member_id == owner


def test_a_main_device_without_an_owner_takes_the_absorbed_ones(db):
    from clarinet.core_svc.device_merge import merge_devices
    main, extra = two_devices(db)
    boss = db.query(Member).filter(Member.username == "boss").one()
    main.owner_member_id, extra.owner_member_id = None, boss.member_id
    db.commit()
    merge_devices(db, main.device_id, extra.device_id)
    db.refresh(main)
    assert main.owner_member_id == boss.member_id


def test_a_device_cannot_be_merged_into_itself_or_a_missing_one(db):
    from clarinet.core_svc.device_merge import MergeError, merge_devices
    main, _ = two_devices(db)
    for other in (main.device_id, 9999):
        with pytest.raises(MergeError):
            merge_devices(db, main.device_id, other)
    assert db.query(Device).count() == 2


def test_chained_merges_keep_every_address_with_the_final_device(db):
    from clarinet.core_svc.device_merge import merge_devices
    main, extra = two_devices(db)
    third = Device(mac_address="DD:00:00:00:00:04", state="NEW")
    db.add(third)
    db.commit()
    merge_devices(db, extra.device_id, third.device_id)     # third into extra
    merge_devices(db, main.device_id, extra.device_id)      # then extra (with third) into main
    owners = {a.mac_address: a.primary_device_id for a in db.query(MergedMac)}
    assert owners == {"CC:00:00:00:00:03": main.device_id, "DD:00:00:00:00:04": main.device_id}


def test_splitting_makes_the_address_its_own_device_and_forgets_the_alias(db):
    from clarinet.core_svc.device_merge import merge_devices, split_address
    main, extra = two_devices(db)
    merge_devices(db, main.device_id, extra.device_id)
    new_id = split_address(db, "cc:00:00:00:00:03")
    device = db.get(Device, new_id)
    assert device.mac_address == "CC:00:00:00:00:03" and device.state == "NEW"
    assert db.get(MergedMac, "CC:00:00:00:00:03") is None


def test_splitting_an_address_that_was_never_merged_is_refused(db):
    from clarinet.core_svc.device_merge import MergeError, split_address
    with pytest.raises(MergeError):
        split_address(db, "EE:00:00:00:00:05")


def test_the_scanner_treats_a_merged_address_as_the_main_device(db):
    from clarinet.collector import arp_scanner
    from clarinet.core_svc.device_merge import merge_devices
    main, extra = two_devices(db)
    merge_devices(db, main.device_id, extra.device_id)
    devices_before = db.query(Device).count()

    class Fake(arp_scanner.ArpSource):
        def scan(self, interface, subnet=None):
            return [{"ip": "192.168.1.77", "mac": "CC:00:00:00:00:03"}]

    arp_scanner.set_source(Fake())
    new_devices = arp_scanner.scan_once(db, "eth0")
    assert new_devices == []                                   # not announced as new
    assert db.query(Device).count() == devices_before
    db.expire_all()
    assert db.get(Device, main.device_id).ip_address == "192.168.1.77"


def test_merge_split_and_guest_buttons_are_for_admins_only(db):
    main, extra = two_devices(db)
    r = member().post(f"/devices/{main.device_id}/merge", data={"other_id": str(extra.device_id)})
    assert r.status_code == 302 and db.get(Device, extra.device_id) is not None
    member().post(f"/devices/{main.device_id}/guest")
    db.expire_all()
    assert db.get(Device, main.device_id).state == "APPROVED"


def test_admin_can_merge_split_and_mark_a_guest_from_the_device_page(db):
    main, extra = two_devices(db)
    client = admin()
    assert "Same device, more than one entry?" in client.get(f"/devices/{main.device_id}").text

    r = client.post(f"/devices/{main.device_id}/merge", data={"other_id": str(extra.device_id)})
    assert "merged" in r.headers["location"]
    assert "CC:00:00:00:00:03" in client.get(f"/devices/{main.device_id}").text

    r = client.post(f"/devices/{main.device_id}/split", data={"mac": "CC:00:00:00:00:03"})
    assert "split" in r.headers["location"]
    db.expire_all()
    assert db.query(MergedMac).count() == 0
    assert db.query(Device).filter(Device.mac_address == "CC:00:00:00:00:03").count() == 1

    client.post(f"/devices/{main.device_id}/guest")
    db.expire_all()
    assert db.get(Device, main.device_id).state == "GUEST"
    actions = [a.action for a in db.query(AuditLog)]
    assert {"MERGE_DEVICES", "SPLIT_DEVICE", "MARK_GUEST_DEVICE"} <= set(actions)


@pytest.mark.parametrize("bad", ["", "abc", "999999", "-1"])
def test_a_bad_merge_choice_changes_nothing(db, bad):
    main, extra = two_devices(db)
    r = admin().post(f"/devices/{main.device_id}/merge", data={"other_id": bad})
    assert "bad_merge" in r.headers["location"]
    assert db.query(Device).count() == 2


def test_an_address_cannot_be_split_from_the_wrong_device(db):
    from clarinet.core_svc.device_merge import merge_devices
    main, extra = two_devices(db)
    other = Device(mac_address="FF:00:00:00:00:06", state="APPROVED")
    db.add(other)
    db.commit()
    merge_devices(db, main.device_id, extra.device_id)
    r = admin().post(f"/devices/{other.device_id}/split", data={"mac": "CC:00:00:00:00:03"})
    assert "bad_merge" in r.headers["location"]
    assert db.get(MergedMac, "CC:00:00:00:00:03") is not None
