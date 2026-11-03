"""
Per-device speed, the one side panel for both roles, the member Security page,
Linux notes, and the System status page.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from clarinet.core_svc import device_speed
from clarinet.core_svc.device_names import device_mono, device_name
from clarinet.database import SessionLocal
from clarinet.models import Device
from clarinet.models.devspeed import DeviceSpeedResult
from tests._support import ADMIN, ALICE, new_client, seed_world


class Dev:
    def __init__(self, **kw):
        self.label = self.hostname = self.vendor = None
        self.mac_address = "AA:BB:CC:DD:EE:FF"
        self.__dict__.update(kw)


def test_device_name_order_and_monogram():
    assert device_name(Dev(label="Kitchen TV", hostname="x")) == "Kitchen TV"
    assert device_name(Dev(hostname="alice-laptop")) == "alice-laptop"
    assert device_name(Dev(vendor="Apple")) == "Apple EE:FF"
    assert device_name(Dev()) == "AA:BB:CC:DD:EE:FF"
    assert device_mono(Dev(hostname="alice-laptop")) == "AL"
    assert device_mono(Dev(label="  ")) == "A"


def _add(db, device_id, mbps, minutes_ago, latency=20):
    db.add(DeviceSpeedResult(device_id=device_id, download_mbps=mbps, upload_mbps=5, latency_ms=latency,
                             tested_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)))
    db.commit()


def test_slowdown_is_judged_against_the_device_itself_and_needs_two_readings():
    ids = seed_world()
    with SessionLocal() as db:
        dev = db.get(Device, ids["d_alice"])
        assert device_speed.summary(db, dev).status == "none"
        for minutes in (400, 390, 380, 370, 360):
            _add(db, dev.device_id, 100, minutes)
        assert device_speed.summary(db, dev).status == "ok"
        _add(db, dev.device_id, 40, 20)                       # one low reading: only a possible slowdown
        assert device_speed.summary(db, dev).status == "possible"
        _add(db, dev.device_id, 38, 1)                        # a second one soon after: confirmed
        s = device_speed.summary(db, dev)
        assert s.status == "much_slower" and s.reason == "speed" and s.slowdown_pct == 60
        _add(db, dev.device_id, 98, 0.5)                      # back to normal
        assert device_speed.summary(db, dev).status == "ok"


def test_small_changes_and_a_long_delay():
    ids = seed_world()
    with SessionLocal() as db:
        dev = db.get(Device, ids["d_bob"])
        for minutes in (400, 390, 380, 370, 360):
            _add(db, dev.device_id, 1.5, minutes, latency=20)
        _add(db, dev.device_id, 0.9, 20, latency=20)          # 40% lower, but under 2 Mbps of change: noise
        assert device_speed.summary(db, dev).status == "ok"
        _add(db, dev.device_id, 1.5, 10, latency=400)
        _add(db, dev.device_id, 1.5, 1, latency=420)          # delay 20 times the usual, twice in a row
        s = device_speed.summary(db, dev)
        assert s.status == "slower" and s.reason == "delay"

def test_record_rejects_bad_numbers_and_rapid_repeats():
    ids = seed_world()
    with SessionLocal() as db:
        dev = db.get(Device, ids["d_alice"])
        for bad in (("x", 1, 1), (float("nan"), 1, 1), (-1, 1, 1), (0, 1, 1), (1e9, 1, 1)):
            with pytest.raises(device_speed.Refused):
                device_speed.record(db, dev, None, *bad)
        device_speed.record(db, dev, None, 50, 10, 12)
        with pytest.raises(device_speed.Refused):
            device_speed.record(db, dev, None, 50, 10, 12)


def test_result_only_for_own_device(monkeypatch):
    ids = seed_world()
    from clarinet.routers import devicespeed
    body = {"download_mbps": 40, "upload_mbps": 8, "latency_ms": 15}

    def pretend(device_key):
        def detect(db, ip):
            return db.get(Device, ids[device_key])
        monkeypatch.setattr(devicespeed, "detect_device", detect)

    alice = new_client(ALICE)
    pretend("d_bob")
    assert alice.post("/speed/device/result", json=body).status_code == 403
    pretend("d_alice")
    assert alice.post("/speed/device/result", json=body).status_code == 200
    with SessionLocal() as db:
        assert db.query(DeviceSpeedResult).count() == 1
    assert new_client().post("/speed/device/result", json=body).status_code == 401


def test_probe_download_is_capped_and_needs_sign_in():
    seed_world()
    assert new_client().get("/speed/device/probe/down").status_code == 401
    r = new_client(ALICE).get("/speed/device/probe/down?bytes=999999999")
    assert r.status_code == 200 and len(r.content) == 8 * 1024 * 1024


def test_same_side_panel_for_both_roles_and_members_lack_admin_items():
    seed_world()
    admin = new_client(ADMIN).get("/dashboard").text
    member = new_client(ALICE).get("/dashboard").text
    for label in ("Dashboard", "Devices", "Usage", "Speed", "Alerts", "My account"):
        assert f"<span>{label}</span>" in admin and f"<span>{label}</span>" in member
    for label in ("Security", "Settings"):                       # Manage: administrators only
        assert f"<span>{label}</span>" in admin and f"<span>{label}</span>" not in member
    assert 'href="/security"' not in member and 'href="/settings"' not in member


def test_members_never_see_mode_or_time_zone():
    seed_world()
    admin = new_client(ADMIN).get("/dashboard").text
    member = new_client(ALICE).get("/dashboard").text
    assert 'id="mode-label"' in admin and 'id="mode-label"' not in member
    assert "topbar-meta" not in member
    assert "Monitor only" not in member and "UTC" not in member


def test_members_have_no_security_page_of_their_own():
    seed_world()
    r = new_client(ALICE).get("/security")
    assert r.status_code == 302 and r.headers["location"] == "/account"
    page = new_client(ALICE).get("/account").text
    assert "Sign-ins" in page and "BOB-ALERT" not in page and "SECRET-SECURITY-ALERT" not in page


def test_sign_out_others_keeps_this_session():
    seed_world()
    c = new_client(ALICE)
    new_client(ALICE)
    r = c.post("/account/sign-out-others")
    assert r.status_code == 302 and "signed_out_others" in r.headers["location"]
    assert c.get("/dashboard").status_code == 200


def test_speed_views_per_role():
    seed_world()
    member = new_client(ALICE).get("/speed")
    assert member.status_code == 200 and "alice-laptop" in member.text and "bob-phone" not in member.text
    admin = new_client(ADMIN).get("/speed")
    assert admin.status_code == 200
    assert "printer" not in admin.text and "alice-laptop" not in admin.text and "bob-phone" not in admin.text


def test_linux_pill_shown_when_control_is_unavailable(monkeypatch):
    seed_world()
    from clarinet.core_svc import netinfo
    monkeypatch.setattr(netinfo, "can_control_cached", lambda *a, **k: False)
    assert "Linux required" in new_client(ADMIN).get("/rules").text
    monkeypatch.setattr(netinfo, "can_control_cached", lambda *a, **k: True)
    assert "Linux required" not in new_client(ADMIN).get("/rules").text


def test_system_status_is_admin_only_and_complete():
    seed_world()
    assert new_client(ALICE).get("/status").status_code in (302, 303, 403)
    page = new_client(ADMIN).get("/status")
    assert page.status_code == 200
    for text in ("Running for", "Router", "Internet", "Memory in use", "Disk free", "Database", "Background collectors"):
        assert text in page.text


def test_a_members_speed_and_slowdowns_are_private_to_them(monkeypatch):
    ids = seed_world()
    from clarinet.core_svc import device_speed
    from clarinet.core_svc.permissions import visible_alerts
    from clarinet.models import Alert, Member
    with SessionLocal() as db:
        boss, alice = db.get(Member, ids["boss"]), db.get(Member, ids["alice"])
        shown = {d.device_id for d in device_speed.devices_for(db, boss)}
        assert ids["d_alice"] not in shown and ids["d_bob"] not in shown      # members' devices are theirs
        assert ids["d_free"] not in shown                                       # nobody's device: nobody's list
        assert {d.device_id for d in device_speed.devices_for(db, alice)} == {ids["d_alice"]}
        assert not device_speed.may_measure(boss, db.get(Device, ids["d_alice"]))
        assert not device_speed.may_measure(boss, db.get(Device, ids["d_free"]))
        titles_admin = {a.title for a in visible_alerts(db, boss)}
        assert "ALICE-ALERT" not in titles_admin and "BOB-ALERT" not in titles_admin   # SLOWDOWN alerts of members
        assert "SECRET-SECURITY-ALERT" in titles_admin                                  # network alerts stay with the admin
        assert "ALICE-ALERT" in {a.title for a in visible_alerts(db, alice)}


def test_the_admin_cannot_store_a_speed_result_for_a_members_device(monkeypatch):
    ids = seed_world()
    from clarinet.routers import devicespeed
    monkeypatch.setattr(devicespeed, "detect_device", lambda db, ip: db.get(Device, ids["d_alice"]))
    body = {"download_mbps": 40, "upload_mbps": 8, "latency_ms": 15}
    assert new_client(ADMIN).post("/speed/device/result", json=body).status_code == 403
