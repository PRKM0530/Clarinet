"""
ADM-01, 05, 06, 08, 09: setup wizard, settings, members, purge and the audit log.
"""
from __future__ import annotations

import pytest

from tests._support import ADMIN, ALICE, BOB, new_client, reset_db, seed_world


def setting(key):
    from clarinet.database import SessionLocal
    from clarinet.models import Settings
    with SessionLocal() as db:
        row = db.get(Settings, key)
        return row.value if row else None


def audit_actions():
    from clarinet.database import SessionLocal
    from clarinet.models import AuditLog
    with SessionLocal() as db:
        return [a.action for a in db.query(AuditLog).order_by(AuditLog.log_id)] if hasattr(AuditLog, "log_id") \
            else [a.action for a in db.query(AuditLog)]


GOOD = {"username": "owner", "password": "pw-12345678", "password_confirm": "pw-12345678",
        "network_mode": "MONITOR", "plan_download": "100", "plan_upload": "20", "billing_day": "1", "consent": "yes"}


@pytest.fixture()
def fresh():
    reset_db()


# Setup wizard
def test_adm01_first_run_sends_visitors_to_setup(fresh):
    r = new_client().get("/dashboard")
    assert r.status_code == 302 and r.headers["location"].startswith(("/setup", "/login"))
    assert new_client().get("/setup").status_code == 200


@pytest.mark.parametrize("change", [
    {"username": "ab"}, {"password": "short", "password_confirm": "short"}, {"password_confirm": "different-pw"},
    {"network_mode": "NOPE"}, {"billing_day": "0"}, {"billing_day": "29"}, {"consent": ""},
    {"monthly_limit_gb": "-5"}, {"monthly_limit_gb": "abc"},
], ids=lambda c: next(iter(c.items())).__repr__())
def test_adm01_invalid_setup_is_refused_and_creates_nothing(fresh, change):
    from clarinet.database import SessionLocal
    from clarinet.models import Member
    r = new_client().post("/setup/admin", data=GOOD | change)
    assert r.status_code == 422
    with SessionLocal() as db:
        assert db.query(Member).count() == 0


@pytest.mark.parametrize("day", ["1", "28"])
def test_adm01_valid_setup_saves_values_and_closes_the_wizard(fresh, day):
    c = new_client()
    r = c.post("/setup/admin", data=GOOD | {"billing_day": day, "network_mode": "FULL", "monthly_limit_gb": "50"})
    assert r.status_code in (302, 200), r.text[:200]
    assert setting("setup_complete") == "true" and setting("network_mode") == "FULL"
    assert setting("billing_day") == day and setting("limit.bytes") == str(50 * 1_073_741_824)
    assert "SETUP_COMPLETE" in audit_actions()
    again = new_client().post("/setup/admin", data=GOOD | {"username": "second-admin"})
    assert again.status_code == 302 and again.headers["location"] == "/login"
    assert new_client().post("/login", data={"username": "owner", "password": "pw-12345678"}).status_code == 302


@pytest.mark.parametrize("bad", ["0", "-10"])
def test_adm01_plan_speed_must_be_positive(fresh, bad):
    assert new_client().post("/setup/admin", data=GOOD | {"plan_download": bad}).status_code == 422


# Settings
def test_adm06_valid_settings_are_saved_and_audited():
    seed_world()
    r = new_client(ADMIN).post("/settings/update", data={
        "plan_download_mbps": "250", "plan_upload_mbps": "40", "billing_day": "15", "network_mode": "MONITOR",
        "slowdown_latency_multiplier": "2.5", "speed_test_interval_hours": "12"})
    assert r.headers["location"] == "/settings?info=saved"
    assert (setting("plan_download_mbps"), setting("billing_day"), setting("network_mode")) == ("250", "15", "MONITOR")
    assert "UPDATE_SETTINGS" in audit_actions()


@pytest.mark.parametrize("field,value", [("monthly_limit_gb", "abc"), ("monthly_limit_gb", "-1"),
                                         ("speed_report_threshold_pct", "5"), ("speed_report_threshold_pct", "x")])
def test_adm06_validated_fields_refuse_bad_values(field, value):
    seed_world()
    r = new_client(ADMIN).post("/settings/update", data={field: value})
    assert "error=" in r.headers["location"]


@pytest.mark.parametrize("field,value", [("network_mode", "BANANA"), ("billing_day", "29"), ("billing_day", "0"),
                                         ("billing_day", "abc"), ("plan_download_mbps", "-5"),
                                         ("plan_upload_mbps", "abc"), ("slowdown_latency_multiplier", "abc")])
def test_adm06_unvalidated_fields_should_refuse_bad_values(field, value):
    seed_world()
    r = new_client(ADMIN).post("/settings/update", data={field: value})
    assert "error=" in r.headers["location"]


# Members
def test_adm05_create_member_and_log_in_as_them():
    seed_world()
    admin = new_client(ADMIN)
    assert admin.post("/settings/members/create", data={"username": "carol", "password": "pw-carol-1234"}
                      ).headers["location"] == "/settings?info=member_created"
    assert new_client(("carol", "pw-carol-1234")).get("/dashboard").status_code == 200
    assert "CREATE_MEMBER" in audit_actions()


@pytest.mark.parametrize("data,err", [
    ({"username": "alice", "password": "pw-12345678"}, "username_taken"),
    ({"username": "dave", "password": "short"}, "password_too_short")])
def test_adm05_create_member_refusals(data, err):
    seed_world()
    assert err in new_client(ADMIN).post("/settings/members/create", data=data).headers["location"]


def test_adm05_unknown_role_becomes_member():
    from clarinet.database import SessionLocal
    from clarinet.models import Member
    seed_world()
    new_client(ADMIN).post("/settings/members/create", data={"username": "eve", "password": "pw-12345678", "role": "ROOT"})
    with SessionLocal() as db:
        assert db.query(Member).filter_by(username="eve").one().role == "MEMBER"


@pytest.mark.parametrize("name", ["", "   "])
def test_adm05_blank_username_is_refused(name):
    from clarinet.database import SessionLocal
    from clarinet.models import Member
    seed_world()
    r = new_client(ADMIN).post("/settings/members/create", data={"username": name, "password": "pw-12345678"})
    with SessionLocal() as db:
        assert not db.query(Member).filter(Member.username == "").count() and "error=" in r.headers.get("location", "error=")


def test_adm05_name_with_trailing_space_cannot_duplicate_a_member():
    seed_world()
    r = new_client(ADMIN).post("/settings/members/create", data={"username": "alice ", "password": "pw-12345678"})
    assert r.status_code < 500 and "username_taken" in r.headers["location"]


def test_adm05_admin_cannot_disable_self_and_can_disable_others():
    from clarinet.database import SessionLocal
    from clarinet.models import Member
    ids = seed_world()
    admin = new_client(ADMIN)
    assert "cannot_disable_self" in admin.post(f"/settings/members/{ids['boss']}/toggle").headers["location"]
    admin.post(f"/settings/members/{ids['bob']}/toggle")
    with SessionLocal() as db:
        assert db.get(Member, ids["bob"]).is_active is False
    assert new_client().post("/login", data={"username": BOB[0], "password": BOB[1]}).status_code == 401


def test_adm05_reset_password_changes_login_and_clears_lockout():
    ids = seed_world()
    for _ in range(5):
        new_client().post("/login", data={"username": ALICE[0], "password": "bad"}, headers={"X-Forwarded-For": "4.4.4.4"})
    new_client(ADMIN).post(f"/settings/members/{ids['alice']}/reset-password", data={"new_password": "brand-new-pw-1"})
    ok = new_client().post("/login", data={"username": ALICE[0], "password": "brand-new-pw-1"}, headers={"X-Forwarded-For": "6.6.6.6"})
    old = new_client().post("/login", data={"username": ALICE[0], "password": ALICE[1]}, headers={"X-Forwarded-For": "6.6.6.7"})
    assert ok.status_code == 302 and old.status_code == 401
    assert "RESET_PASSWORD" in audit_actions()


# Purge
def test_adm08_purge_needs_the_word_delete_and_keeps_accounts():
    from clarinet.database import SessionLocal
    from clarinet.models import Alert, Device, Member, Settings, UsageRecord
    seed_world()
    admin = new_client(ADMIN)
    assert "error=confirm_delete" in admin.post("/settings/purge", data={"confirm": "delete"}).headers["location"]
    with SessionLocal() as db:
        assert db.query(Device).count() == 4
    assert admin.post("/settings/purge", data={"confirm": "DELETE"}).headers["location"] == "/settings?info=data_deleted"
    with SessionLocal() as db:
        assert (db.query(Device).count(), db.query(Alert).count(), db.query(UsageRecord).count()) == (0, 0, 0)
        assert db.query(Member).count() == 3 and db.get(Settings, "setup_complete").value == "true"
    assert "PURGE_ALL_DATA" in audit_actions()
    assert new_client(ALICE).get("/dashboard").status_code == 200


def test_adm08_pages_still_work_after_a_purge():
    seed_world()
    admin = new_client(ADMIN)
    admin.post("/settings/purge", data={"confirm": "DELETE"})
    for page in ("/dashboard", "/devices", "/alerts", "/usage", "/reports", "/speed", "/slowdowns", "/security", "/vouchers"):
        assert admin.get(page).status_code == 200, page


# Privacy page
def test_adm07_privacy_page_is_public_and_states_retention():
    seed_world()
    r = new_client().get("/privacy")
    assert r.status_code == 200 and ("days" in r.text.lower() or "hours" in r.text.lower())
