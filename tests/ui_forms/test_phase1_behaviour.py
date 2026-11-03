"""
What each repaired form actually does for the person using it (phase 1 of CLARINET_USABILITY_GAP_PLAN.md).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests._support import ADMIN, ALICE, BOB, new_client, seed_world


@pytest.fixture()
def world():
    return seed_world("FULL")


def db_value(model, key, **where):
    from clarinet.database import SessionLocal
    with SessionLocal() as db:
        return getattr(db.query(model).filter_by(**where).one(), key)


# A1 / A2 / A8: vouchers
def test_a1_voucher_with_blank_caps_is_created(world):
    from clarinet.database import SessionLocal
    from clarinet.models import Voucher
    r = new_client(ADMIN).post("/vouchers/create", data={"expires_hours": "4", "data_cap_mb": "", "speed_cap_mbps": ""})
    assert r.status_code == 302 and "error" not in r.headers["location"]
    with SessionLocal() as db:
        v = db.query(Voucher).one()
        assert v.data_cap_mb is None and v.speed_cap_mbps is None


@pytest.mark.parametrize("hours,minutes", [("1", 60), ("4", 240), ("24", 1440), ("72", 4320)])
def test_a2_voucher_lasts_as_long_as_the_hours_chosen(world, hours, minutes):
    from clarinet.database import SessionLocal
    from clarinet.models import Voucher
    new_client(ADMIN).post("/vouchers/create", data={"expires_hours": hours})
    with SessionLocal() as db:
        v = db.query(Voucher).one()
        got = (v.expires_at.replace(tzinfo=None) - datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds() / 60
        assert abs(got - minutes) < 2, f"{hours} h voucher lasts {got:.0f} minutes"


def test_a1_bad_voucher_numbers_get_a_message_not_raw_json(world):
    r = new_client(ADMIN).post("/vouchers/create", data={"expires_hours": "24", "data_cap_mb": "abc"})
    assert r.status_code == 302 and "error=bad_voucher" in r.headers["location"]


def test_a8_voucher_page_shows_the_message_after_creating(world):
    c = new_client(ADMIN)
    c.post("/vouchers/create", data={"expires_hours": "1"})
    page = c.get("/vouchers?info=Voucher+created").text
    assert "Voucher created" in page


# A3: time rules
def test_a3_rule_with_a_blank_speed_box_is_created(world):
    from clarinet.database import SessionLocal
    from clarinet.models import TimeRule
    r = new_client(ADMIN).post("/rules/create", data={"device_id": str(world["d_alice"]), "days": ["Mon"],
                                                      "start_time": "22:00", "end_time": "23:00", "action": "BLOCK", "rate_kbps": ""})
    assert r.status_code == 302 and "error" not in r.headers["location"]
    with SessionLocal() as db:
        assert db.query(TimeRule).one().rate_kbps is None


def test_a3_rule_without_a_day_gets_a_message(world):
    r = new_client(ADMIN).post("/rules/create", data={"device_id": str(world["d_alice"]), "start_time": "22:00",
                                                      "end_time": "23:00", "action": "BLOCK", "rate_kbps": ""})
    assert r.status_code == 302 and "at+least+one+day" in r.headers["location"].lower()


# A4: renaming
def test_a4_admin_renames_from_the_device_page(world):
    from clarinet.models import Device
    new_client(ADMIN).post(f"/devices/{world['d_new']}/rename", data={"label": "Printer"})
    assert db_value(Device, "label", device_id=world["d_new"]) == "Printer"


def test_a4_member_renames_their_own_device_only(world):
    from clarinet.models import Device
    alice = new_client(ALICE)
    assert "info=" in alice.post(f"/devices/{world['d_alice']}/rename", data={"label": "My laptop"}).headers["location"]
    assert db_value(Device, "label", device_id=world["d_alice"]) == "My laptop"
    other = alice.post(f"/devices/{world['d_bob']}/rename", data={"label": "hacked"})
    assert "error=forbidden" in other.headers["location"]
    assert db_value(Device, "label", device_id=world["d_bob"]) != "hacked"


def test_a4_device_page_form_points_at_the_rename_route(world):
    page = new_client(ALICE).get(f"/devices/{world['d_alice']}").text
    assert f'action="/devices/{world["d_alice"]}/rename"' in page


# A5 / B3: own password
def test_a5_member_changes_their_own_password_and_signs_in_with_it(world):
    alice = new_client(ALICE)
    r = alice.post("/account/password", data={"current_password": ALICE[1], "new_password": "brand-new-pass-1",
                                              "confirm_password": "brand-new-pass-1"})
    assert "info=password_changed" in r.headers["location"]
    assert alice.get("/dashboard").status_code == 200                       # this session stays signed in
    assert new_client().post("/login", data={"username": "alice", "password": "brand-new-pass-1"}).status_code == 302
    assert new_client().post("/login", data={"username": "alice", "password": ALICE[1]}).status_code == 401


@pytest.mark.parametrize("data,code", [
    ({"current_password": "wrong", "new_password": "brand-new-pass-1", "confirm_password": "brand-new-pass-1"}, "password_wrong"),
    ({"current_password": ALICE[1], "new_password": "brand-new-pass-1", "confirm_password": "different-pass-1"}, "password_mismatch"),
    ({"current_password": ALICE[1], "new_password": "short", "confirm_password": "short"}, "password_short"),
    ({"current_password": ALICE[1], "new_password": ALICE[1], "confirm_password": ALICE[1]}, "password_same")])
def test_a5_bad_password_changes_are_explained(world, data, code):
    r = new_client(ALICE).post("/account/password", data=data)
    assert f"error={code}" in r.headers["location"]
    assert new_client().post("/login", data={"username": "alice", "password": ALICE[1]}).status_code == 302


def test_a5_changing_a_password_signs_out_other_devices(world):
    first, second = new_client(ALICE), new_client(ALICE)
    first.post("/account/password", data={"current_password": ALICE[1], "new_password": "brand-new-pass-1",
                                          "confirm_password": "brand-new-pass-1"})
    assert first.get("/dashboard").status_code == 200
    assert second.get("/dashboard").status_code == 302


def test_account_page_is_in_every_users_menu(world):
    for who in (ADMIN, ALICE):
        assert 'href="/account"' in new_client(who).get("/dashboard").text


# A6: unblock
def test_a6_blocked_device_offers_unblock_not_block(world):
    from clarinet.database import SessionLocal
    from clarinet.models import Device
    with SessionLocal() as db:
        db.get(Device, world["d_bob"]).state = "BLOCKED"
        db.commit()
    admin = new_client(ADMIN)
    for path in (f"/devices/{world['d_bob']}", "/devices"):
        page = admin.get(path).text
        assert f"/devices/{world['d_bob']}/unblock" in page and f"/devices/{world['d_bob']}/block\"" not in page, path
    admin.post(f"/devices/{world['d_bob']}/unblock")
    from clarinet.models import Device as D
    assert db_value(D, "state", device_id=world["d_bob"]) == "APPROVED"


# A7: reset a member's password
def test_a7_the_settings_page_no_longer_offers_to_reset_a_members_password(world):
    page = new_client(ADMIN).get("/settings").text
    assert "reset-password" not in page and "Reset password" not in page


def test_a7_a_member_can_reset_their_own_password_from_the_sign_in_page(world):
    assert 'href="/forgot"' in new_client().get("/login").text
    assert "Recovery code" in new_client(ALICE).get("/account").text


# A9: the login page explains why you were signed out
@pytest.mark.parametrize("reason,words", [("session", "expired")])
def test_a9_login_page_explains_why_you_were_signed_out(world, reason, words):
    assert words in new_client().get(f"/login?reason={reason}").text


# A10: people get a page, programs get JSON
def test_a10_people_get_an_error_page_with_a_way_back(world):
    c = new_client(ALICE)
    for path, status in (("/no-such-page", 404), ("/export/usage.csv/extra", 404)):
        r = c.get(path, headers={"Accept": "text/html"})
        assert r.status_code == status and "Go back" in r.text and "{" not in r.text.split("<body>")[1][:40]
    r = c.post(f"/devices/{world['d_alice']}/rename", data={}, headers={"Accept": "text/html"})
    assert r.status_code == 422 and "Go back" in r.text


def test_a10_programs_still_get_json(world):
    r = new_client(ALICE).get("/no-such-page", headers={"Accept": "application/json"})
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"}
    assert new_client().get("/api/v1/status").status_code == 401


# Blank "trust access point" form
def test_security_trust_with_nothing_ticked_says_so(world):
    r = new_client(ADMIN).post("/security/access-points/trust", data={})
    assert r.status_code == 303 and "msg=ap_none" in r.headers["location"]


# Members are not offered what they cannot do (B5, part)
def test_b5_member_pages_do_not_show_admin_only_buttons(world):
    alice = new_client(ALICE)
    detail = alice.get(f"/devices/{world['d_alice']}").text
    for word in ("Block Device", "Approve Device", "Add Time Rule", "Merge into this device", "Mark as guest"):
        assert word not in detail, word
    assert "/resolve" not in alice.get("/alerts?status=OPEN").text           # no Resolve button for members
    assert "approve-modal" not in alice.get("/devices").text
