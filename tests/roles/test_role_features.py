"""
tests/roles/test_role_features.py
Checks, against the real application, that each role gets the features it needs
(and only those). Roles come from the requirements: administrator, member, and
guest (a visitor who redeems a voucher and has no dashboard login).
"""
from __future__ import annotations

from datetime import date, datetime, timezone

import pytest
from fastapi.testclient import TestClient

from clarinet import app
from clarinet.auth import hash_password
from clarinet.database import Base, SessionLocal, engine
from clarinet.models import (
    Alert, AuditLog, Device, Member, PriorityGrant, Settings, TimeRule, UsageRecord,
)
from clarinet.models.security import KnownNetwork, TrustedAccessPoint

GB = 1_073_741_824


@pytest.fixture()
def world():
    assert "clarinet_test_" in str(engine.url), "refusing to touch a non-test database"
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.add(Settings(key="setup_complete", value="true"))
        db.add(Settings(key="network_mode", value="FULL"))
        alice = Member(username="alice", password_hash=hash_password("pw-alice-1"), role="MEMBER")
        boss = Member(username="boss", password_hash=hash_password("pw-boss-1"), role="ADMIN")
        gone = Member(username="gone", password_hash=hash_password("pw-gone-1"), role="MEMBER", is_active=False)
        db.add_all([alice, boss, gone])
        db.flush()
        new_device = Device(mac_address="AA:00:00:00:00:09", state="NEW", first_seen=now, last_seen=now)
        db.add(new_device)
        db.commit()
        return {"alice": alice.member_id, "boss": boss.member_id, "gone": gone.member_id, "device": new_device.device_id}


def login(username=None, password=None) -> TestClient:
    client = TestClient(app, follow_redirects=False, raise_server_exceptions=False)
    if username:
        assert client.post("/login", data={"username": username, "password": password}).status_code == 302
    return client


def admin():
    return login("boss", "pw-boss-1")


def member():
    return login("alice", "pw-alice-1")


def setting(key):
    with SessionLocal() as db:
        row = db.get(Settings, key)
        return row.value if row else None


# The role matrix

ADMIN_ONLY = ["/rules", "/vouchers", "/settings", "/status"]
# Speed results and slowdown explanations are read-only for members (Clarinet_System_Documentation.pdf role matrix)
MEMBER_AND_ADMIN = ["/dashboard", "/devices", "/usage", "/alerts", "/priority", "/speed", "/slowdowns", "/security"]
PUBLIC = ["/login", "/guest", "/api/status/health", "/privacy"]


@pytest.mark.parametrize("path", PUBLIC)
def test_anyone_can_open_the_public_pages(world, path):
    assert login().get(path).status_code == 200


@pytest.mark.parametrize("path", MEMBER_AND_ADMIN + ADMIN_ONLY)
def test_a_visitor_who_is_not_logged_in_is_sent_to_login(world, path):
    r = login().get(path)
    assert r.status_code == 302 and "/login" in r.headers["location"]


@pytest.mark.parametrize("path", MEMBER_AND_ADMIN)
def test_member_pages(world, path):
    assert member().get(path).status_code == 200


@pytest.mark.parametrize("path", ADMIN_ONLY)
def test_admin_pages_are_refused_to_a_member_with_an_explanation(world, path):
    client = member()
    r = client.get(path)
    assert r.status_code == 302 and "forbidden" in r.headers["location"]
    page = client.get(r.headers["location"])
    assert "only for administrators" in page.text, "the refusal must be explained in plain words"


@pytest.mark.parametrize("path", MEMBER_AND_ADMIN + ADMIN_ONLY)
def test_admin_can_open_every_page(world, path):
    assert admin().get(path).status_code == 200


def test_the_sidebar_hides_admin_pages_from_members(world):
    page = member().get("/dashboard").text
    for hidden in ("/rules", "/vouchers", "/settings", "/status"):
        assert f'href="{hidden}"' not in page, f"member sidebar links to {hidden}"
    assert 'href="/priority"' in page and 'href="/usage"' in page
    assert 'href="/speed"' in page and 'href="/slowdowns"' in page and 'href="/account"' in page
    assert 'href="/security"' in page and 'href="/security"' in admin().get("/dashboard").text   # same item, a member-sized page


def test_a_guest_has_no_dashboard_access_after_redeeming(world):
    guest = login()
    r = guest.post("/guest/redeem", data={"code": "NOT-A-REAL-CODE"})
    assert r.status_code < 500
    assert guest.get("/dashboard").status_code == 302       # still not logged in


# DEV-4: the admin assigns a device to a member

def test_approving_a_device_saves_its_label_and_owner(world):
    ids = world
    r = admin().post(f"/devices/{ids['device']}/approve", data={"label": "Alice's phone", "owner_id": str(ids["alice"])})
    assert r.status_code == 302
    with SessionLocal() as db:
        device = db.get(Device, ids["device"])
        assert (device.state, device.label, device.owner_member_id) == ("APPROVED", "Alice's phone", ids["alice"])


def test_the_owner_makes_the_device_visible_to_that_member_only(world):
    ids = world
    assert "AA:00:00:00:00:09" not in member().get("/devices").text      # nobody owns it yet
    admin().post(f"/devices/{ids['device']}/approve", data={"owner_id": str(ids["alice"])})
    assert "AA:00:00:00:00:09" in member().get("/devices").text


def test_approving_without_an_owner_keeps_the_existing_owner(world):
    ids = world
    admin().post(f"/devices/{ids['device']}/owner", data={"owner_id": str(ids["alice"])})
    admin().post(f"/devices/{ids['device']}/approve", data={"label": "", "owner_id": ""})
    with SessionLocal() as db:
        assert db.get(Device, ids["device"]).owner_member_id == ids["alice"]


def test_owner_can_be_changed_and_cleared(world):
    ids = world
    client = admin()
    client.post(f"/devices/{ids['device']}/owner", data={"owner_id": str(ids["alice"])})
    client.post(f"/devices/{ids['device']}/owner", data={"owner_id": ""})
    with SessionLocal() as db:
        assert db.get(Device, ids["device"]).owner_member_id is None
        assert "SET_DEVICE_OWNER" in [a.action for a in db.query(AuditLog)]


@pytest.mark.parametrize("bad", ["999", "abc", "-1"])
def test_a_device_cannot_be_given_to_a_member_who_does_not_exist(world, bad):
    ids = world
    admin().post(f"/devices/{ids['device']}/owner", data={"owner_id": bad})
    with SessionLocal() as db:
        assert db.get(Device, ids["device"]).owner_member_id is None


def test_a_device_cannot_be_given_to_a_disabled_member(world):
    ids = world
    admin().post(f"/devices/{ids['device']}/owner", data={"owner_id": str(ids["gone"])})
    with SessionLocal() as db:
        assert db.get(Device, ids["device"]).owner_member_id is None


def test_a_member_cannot_assign_owners(world):
    ids = world
    member().post(f"/devices/{ids['device']}/owner", data={"owner_id": str(ids["alice"])})
    member().post(f"/devices/{ids['device']}/approve", data={"owner_id": str(ids["alice"])})
    with SessionLocal() as db:
        device = db.get(Device, ids["device"])
        assert device.owner_member_id is None and device.state == "NEW"


def test_the_device_page_lets_an_admin_pick_the_owner(world):
    ids = world
    assert 'name="owner_id"' in admin().get(f"/devices/{ids['device']}").text
    admin().post(f"/devices/{ids['device']}/owner", data={"owner_id": str(ids["alice"])})
    assert "alice" in admin().get(f"/devices/{ids['device']}").text


# ACC-4: monthly data limit

def test_admin_can_set_and_clear_the_monthly_limit(world):
    client = admin()
    client.post("/settings/update", data={"monthly_limit_gb": "100"})
    assert setting("limit.bytes") == str(100 * GB)
    assert 'value="100"' in client.get("/settings").text
    client.post("/settings/update", data={"monthly_limit_gb": ""})
    assert setting("limit.bytes") == ""


@pytest.mark.parametrize("bad", ["abc", "-5", "0", "99999999999"])
def test_a_bad_monthly_limit_is_rejected(world, bad):
    r = admin().post("/settings/update", data={"monthly_limit_gb": bad})
    assert "bad_limit" in r.headers["location"]
    assert setting("limit.bytes") is None


def test_a_member_cannot_change_the_limit(world):
    member().post("/settings/update", data={"monthly_limit_gb": "5"})
    assert setting("limit.bytes") is None


def _use(db, device_id, nbytes):
    db.add(UsageRecord(device_id=device_id, date=date.today().isoformat(), hour=1, bytes_in=nbytes, bytes_out=0))
    db.commit()


@pytest.mark.parametrize("used_pct, expected", [
    (50, None),
    (70, "DATA_LIMIT_WARN"),
    (90, "DATA_LIMIT_CRITICAL"),
    (100, "DATA_LIMIT_EXCEEDED"),
    (120, "DATA_LIMIT_EXCEEDED"),
])
def test_limit_warnings_follow_the_spec_at_70_90_and_100_percent(world, used_pct, expected):
    from clarinet.core_svc.limit_service import check_and_alert
    with SessionLocal() as db:
        db.add(Settings(key="limit.bytes", value="1000"))
        db.commit()
        _use(db, world["device"], used_pct * 10)
        check_and_alert(db)
        types = [a.type for a in db.query(Alert).filter(Alert.type.like("DATA_LIMIT%"))]
        assert types == ([expected] if expected else [])


def test_dashboard_shows_the_limit_to_the_admin_only(world):
    with SessionLocal() as db:
        db.add(Settings(key="limit.bytes", value=str(100 * GB)))
        db.commit()
    assert "Monthly data" in admin().get("/dashboard").text
    assert "Monthly data" not in member().get("/dashboard").text


def test_dashboard_has_no_limit_card_when_no_limit_is_set(world):
    assert "Monthly data" not in admin().get("/dashboard").text


# SYS-4 / SYS-5: export and delete

def _seed_everything(ids):
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.add_all([
            UsageRecord(device_id=ids["device"], date=date.today().isoformat(), hour=2, bytes_in=5, bytes_out=5),
            Alert(level="WARNING", type="SLOWDOWN", title="=cmd|' /C calc'!A0", message="x", device_id=ids["device"]),
            Alert(level="CRITICAL", type="ARP_SPOOF", title="network-wide", message="x"),
            PriorityGrant(device_id=ids["device"], member_id=ids["alice"], decision="PENDING", requested_at=now),
            TrustedAccessPoint(ssid="Home", bssid="AA:AA:AA:AA:AA:AA"),
            KnownNetwork(gateway_mac="BB:BB:BB:BB:BB:BB", trusted=True),
        ])
        db.commit()


def test_admin_can_export_every_alert_and_a_member_only_their_own(world):
    _seed_everything(world)
    admin().post(f"/devices/{world['device']}/owner", data={"owner_id": str(world["alice"])})
    everything = admin().get("/export/alerts.csv")
    assert everything.status_code == 200 and "text/csv" in everything.headers["content-type"]
    assert "network-wide" in everything.text
    mine = member().get("/export/alerts.csv").text
    assert "network-wide" not in mine


def test_alert_export_cannot_run_formulas_in_a_spreadsheet(world):
    _seed_everything(world)
    body = admin().get("/export/alerts.csv").text
    assert "'=cmd" in body and ",=cmd" not in body


def test_a_logged_out_visitor_cannot_export(world):
    r = login().get("/export/alerts.csv")
    assert r.status_code == 302 and "/login" in r.headers["location"]


def test_delete_all_data_needs_the_word_delete(world):
    _seed_everything(world)
    r = admin().post("/settings/purge", data={"confirm": "yes please"})
    assert "confirm_delete" in r.headers["location"]
    with SessionLocal() as db:
        assert db.query(Device).count() == 1 and db.query(Alert).count() > 0


def test_delete_all_data_removes_network_data_and_keeps_accounts_and_settings(world):
    _seed_everything(world)
    r = admin().post("/settings/purge", data={"confirm": "DELETE"})
    assert "data_deleted" in r.headers["location"]
    with SessionLocal() as db:
        assert db.query(Device).count() == 0
        assert db.query(Alert).count() == 0
        assert db.query(UsageRecord).count() == 0
        assert db.query(PriorityGrant).count() == 0
        # kept
        assert db.query(Member).count() == 3
        assert db.get(Settings, "setup_complete").value == "true"
        assert db.query(TrustedAccessPoint).count() == 1
        assert db.query(KnownNetwork).count() == 1
        assert "PURGE_ALL_DATA" in [a.action for a in db.query(AuditLog)]
    assert admin().get("/dashboard").status_code == 200       # the app still works afterwards


def test_a_member_cannot_delete_data(world):
    _seed_everything(world)
    member().post("/settings/purge", data={"confirm": "DELETE"})
    with SessionLocal() as db:
        assert db.query(Device).count() == 1


# DASH-4: friendly messages

@pytest.mark.parametrize("code, words", [
    ("not_found", "could not be found"),
    ("bad_owner", "does not exist or is disabled"),
    ("bad_limit", "positive number"),
])
def test_codes_in_the_address_are_shown_as_plain_sentences(world, code, words):
    assert words in admin().get(f"/dashboard?error={code}").text


def test_the_slowdown_banner_does_not_send_members_to_an_admin_page(world):
    from clarinet.models import SlowdownEvent
    with SessionLocal() as db:
        db.add(SlowdownEvent(started_at=datetime.now(timezone.utc), causes_json='[{"cause": "NO_CLEAR_CAUSE"}]'))
        db.commit()
    assert 'href="/slowdowns"' not in member().get("/dashboard").text.split("slowdown-banner", 1)[-1][:900]
    assert 'href="/slowdowns"' in admin().get("/dashboard").text


# First-run wizard

@pytest.fixture()
def fresh_install():
    assert "clarinet_test_" in str(engine.url), "refusing to touch a non-test database"
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


WIZARD = {"username": "owner", "password": "Owner-pass-123", "password_confirm": "Owner-pass-123",
          "network_mode": "MONITOR", "plan_download": "100", "plan_upload": "20", "billing_day": "1",
          "consent": "yes"}


def test_wizard_saves_an_optional_monthly_limit(fresh_install):
    r = login().post("/setup/admin", data={**WIZARD, "monthly_limit_gb": "250"})
    assert r.status_code == 200
    assert setting("limit.bytes") == str(250 * GB)


def test_wizard_works_without_a_limit(fresh_install):
    r = login().post("/setup/admin", data={**WIZARD, "monthly_limit_gb": ""})
    assert r.status_code == 200
    assert setting("limit.bytes") is None
    assert setting("setup_complete") == "true"


@pytest.mark.parametrize("bad", ["abc", "-1", "0"])
def test_wizard_rejects_a_bad_limit_and_creates_nothing(fresh_install, bad):
    r = login().post("/setup/admin", data={**WIZARD, "monthly_limit_gb": bad})
    assert r.status_code == 422
    with SessionLocal() as db:
        assert db.query(Member).count() == 0


def test_wizard_requires_confirming_permission_to_monitor(fresh_install):
    without = {k: v for k, v in WIZARD.items() if k != "consent"}
    r = login().post("/setup/admin", data=without)
    assert r.status_code == 422
    assert "allowed to monitor" in r.text
    with SessionLocal() as db:
        assert db.query(Member).count() == 0
    assert setting("setup_complete") is None


def test_wizard_shows_the_permission_checkbox_and_links_to_the_privacy_page(fresh_install):
    page = login().get("/setup").text
    assert 'name="consent"' in page and 'href="/privacy"' in page


# SYS-8: the privacy page

def test_privacy_page_is_public_and_tells_the_truth(world):
    page = login().get("/privacy")
    assert page.status_code == 200
    for expected in ("What Clarinet collects", "Nothing leaves your network", "90 days", "does not record"):
        assert expected in page.text, expected


def test_privacy_page_follows_the_configured_retention(world):
    with SessionLocal() as db:
        db.add(Settings(key="retention.traffic_days", value="30"))
        db.commit()
    assert "30 days" in login().get("/privacy").text


def test_the_login_page_and_sidebar_link_to_the_privacy_page(world):
    assert 'href="/privacy"' in login().get("/login").text
    assert 'href="/privacy"' in member().get("/dashboard").text
