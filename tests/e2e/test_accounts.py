"""
Phase 2: sign-up, administrator-access requests, device claims and password recovery.
"""
from __future__ import annotations

import pytest

from tests._support import ADMIN, ALICE, BOB, new_client, reset_db, seed_world


@pytest.fixture()
def world():
    return seed_world("FULL")


SIGNUP = {"username": "newbie", "password": "newbie-pass-1", "password_confirm": "newbie-pass-1"}


def member(username):
    from clarinet.database import SessionLocal
    from clarinet.models import Member
    with SessionLocal() as db:
        return db.query(Member).filter(Member.username == username).first()


def alerts(kind):
    from clarinet.database import SessionLocal
    from clarinet.models import Alert
    with SessionLocal() as db:
        return [(a.title, a.status) for a in db.query(Alert).filter(Alert.type == kind)]


# ---- sign-up
def test_signup_creates_a_member_and_signs_them_in(world):
    c = new_client()
    r = c.post("/signup", data=SIGNUP)
    assert r.status_code == 302 and r.headers["location"].startswith("/dashboard")
    assert member("newbie").role == "MEMBER"
    assert c.get("/dashboard").status_code == 200
    assert "Welcome to Clarinet" in c.get("/dashboard?info=welcome").text
    assert new_client(("newbie", "newbie-pass-1")).get("/dashboard").status_code == 200       # and can sign in later


def test_signup_cannot_be_used_to_become_an_admin_directly(world):
    new_client().post("/signup", data={**SIGNUP, "role": "ADMIN", "is_admin": "true"})
    assert member("newbie").role == "MEMBER"


@pytest.mark.parametrize("change,words", [
    ({"username": "ab"}, "at least 3"), ({"password": "short", "password_confirm": "short"}, "at least 8"),
    ({"password_confirm": "different-one"}, "do not match"), ({"username": "ALICE"}, "taken"), ({"username": " alice "}, "taken")])
def test_signup_refuses_bad_input_with_a_message(world, change, words):
    r = new_client().post("/signup", data={**SIGNUP, **change})
    assert r.status_code == 422 and words in r.text
    assert member(SIGNUP["username"]) is None or change.get("username") in ("ab",) is False


def test_signup_before_setup_goes_to_the_wizard():
    reset_db()
    assert new_client().get("/signup").headers["location"] == "/setup"
    assert new_client().post("/signup", data=SIGNUP).headers["location"] == "/setup"


def test_signup_is_limited_per_address(world):
    c = new_client()
    codes = [c.post("/signup", data={**SIGNUP, "username": "ab"}).status_code for _ in range(11)]
    assert codes[:10] == [422] * 10 and codes[10] == 429


def test_login_page_links_to_signup_and_explains_recovery(world):
    page = new_client().get("/login").text
    assert 'href="/signup"' in page and "Ask an administrator" in page


def test_admin_can_switch_sign_up_off_and_on(world):
    admin = new_client(ADMIN)
    assert "info=signup_off" in admin.post("/settings/signup", data={"enabled": "no"}).headers["location"]
    assert 'href="/signup"' not in new_client().get("/login").text
    r = new_client().post("/signup", data=SIGNUP)
    assert r.status_code == 403 and member("newbie") is None
    admin.post("/settings/signup", data={"enabled": "yes"})
    assert new_client().post("/signup", data=SIGNUP).status_code == 302


def test_a_member_cannot_switch_sign_up(world):
    r = new_client(ALICE).post("/settings/signup", data={"enabled": "no"})
    assert r.headers["location"].startswith("/dashboard?error=forbidden")


# ---- administrator access requests
def ask_at_signup():
    c = new_client()
    c.post("/signup", data={**SIGNUP, "want_admin": "yes"})
    return c


def test_asking_for_admin_at_signup_stays_a_member_until_approved(world):
    c = ask_at_signup()
    assert member("newbie").role == "MEMBER"
    assert c.get("/settings").headers["location"].startswith("/dashboard?error=forbidden")


def test_admin_sees_the_request_in_settings_and_as_an_alert(world):
    ask_at_signup()
    admin = new_client(ADMIN)
    page = admin.get("/settings").text
    assert "Administrator access requested" in page and "newbie" in page and "/approve" in page
    assert alerts("ADMIN_REQUEST") == [("newbie asked for administrator access", "OPEN")]
    assert "newbie asked for administrator access" in admin.get("/alerts").text


def test_members_do_not_see_the_request_alert(world):
    ask_at_signup()
    assert "asked for administrator access" not in new_client(ALICE).get("/alerts").text


def test_approving_makes_them_an_admin_and_closes_the_alert(world):
    c = ask_at_signup()
    admin = new_client(ADMIN)
    r = admin.post(f"/settings/admin-requests/{member('newbie').member_id}/approve")
    assert "info=admin_approved" in r.headers["location"]
    assert member("newbie").role == "ADMIN"
    assert c.get("/settings").status_code == 200                       # the session they already have now has the access
    assert alerts("ADMIN_REQUEST") == [("newbie asked for administrator access", "RESOLVED")]
    assert "Administrator access requested" not in admin.get("/settings").text


def test_declining_keeps_them_a_member_and_they_can_ask_again(world):
    c = ask_at_signup()
    new_client(ADMIN).post(f"/settings/admin-requests/{member('newbie').member_id}/decline")
    assert member("newbie").role == "MEMBER"
    assert "declined" in c.get("/account").text.lower()
    assert "info=admin_asked" in c.post("/account/admin-request").headers["location"]
    assert "Administrator access requested" in new_client(ADMIN).get("/settings").text


def test_asking_twice_does_not_pile_up_requests_or_alerts(world):
    c = ask_at_signup()
    assert "info=admin_already" in c.post("/account/admin-request").headers["location"]
    assert len(alerts("ADMIN_REQUEST")) == 1


def test_a_member_can_ask_from_their_account_page(world):
    alice = new_client(ALICE)
    assert "Ask for administrator access" in alice.get("/account").text
    assert "info=admin_asked" in alice.post("/account/admin-request").headers["location"]
    assert "waiting" in alice.get("/account").text.lower()
    assert "Ask for administrator access" not in new_client(ADMIN).get("/account").text


def test_a_member_cannot_approve_their_own_request(world):
    c = ask_at_signup()
    r = c.post(f"/settings/admin-requests/{member('newbie').member_id}/approve")
    assert r.headers["location"].startswith("/dashboard?error=forbidden") and member("newbie").role == "MEMBER"


def test_requests_survive_a_data_purge(world):
    ask_at_signup()
    new_client(ADMIN).post("/settings/purge", data={"confirm": "DELETE"})
    assert "newbie" in new_client(ADMIN).get("/settings").text


# ---- "This is my device"
FREE_IP = {"X-Forwarded-For": "192.168.1.14"}            # the unowned approved device in the shared world


def devices_owner(device_id):
    from clarinet.database import SessionLocal
    from clarinet.models import Device
    with SessionLocal() as db:
        return db.get(Device, device_id).owner_member_id


def test_member_claims_the_device_they_are_using_and_admin_confirms(world, trusted_proxy):
    alice = new_client(ALICE)
    assert "This is my device" in alice.get("/devices", headers=FREE_IP).text
    assert "info=claim_sent" in alice.post("/devices/claim", headers=FREE_IP).headers["location"]
    assert devices_owner(world["d_free"]) is None                         # not theirs until an admin confirms
    assert "waiting for an administrator" in alice.get("/devices", headers=FREE_IP).text
    admin = new_client(ADMIN)
    assert "alice says a device is theirs" in admin.get("/alerts").text
    page = admin.get("/devices").text
    assert "Devices people say are theirs" in page and "/approve" in page
    from clarinet.database import SessionLocal
    from clarinet.models.accounts import DeviceClaim
    with SessionLocal() as db:
        claim_id = db.query(DeviceClaim).one().claim_id
    assert "info=claim_approved" in admin.post(f"/devices/claims/{claim_id}/approve").headers["location"]
    assert devices_owner(world["d_free"]) == world["alice"]
    assert "printer" in alice.get("/devices").text


def test_declined_claim_leaves_the_device_unowned(world, trusted_proxy):
    new_client(ALICE).post("/devices/claim", headers=FREE_IP)
    from clarinet.database import SessionLocal
    from clarinet.models.accounts import DeviceClaim
    with SessionLocal() as db:
        claim_id = db.query(DeviceClaim).one().claim_id
    new_client(ADMIN).post(f"/devices/claims/{claim_id}/decline")
    assert devices_owner(world["d_free"]) is None


def test_a_device_someone_else_owns_cannot_be_claimed(world, trusted_proxy):
    r = new_client(ALICE).post("/devices/claim", headers={"X-Forwarded-For": "192.168.1.12"})      # bob's phone
    assert "error=claim_taken" in r.headers["location"] and devices_owner(world["d_bob"]) == world["bob"]


def test_two_members_cannot_claim_the_same_device(world, trusted_proxy):
    new_client(ALICE).post("/devices/claim", headers=FREE_IP)
    assert "error=claim_taken" in new_client(BOB).post("/devices/claim", headers=FREE_IP).headers["location"]


def test_an_unrecognised_address_gets_an_explanation(world, trusted_proxy):
    r = new_client(ALICE).post("/devices/claim", headers={"X-Forwarded-For": "203.0.113.7"})
    assert "error=claim_no_device" in r.headers["location"]
    assert "could not recognise" in new_client(ALICE).get("/devices?error=claim_no_device").text


def test_an_admin_claim_needs_no_confirmation(world, trusted_proxy):
    assert "info=claim_done" in new_client(ADMIN).post("/devices/claim", headers=FREE_IP).headers["location"]
    assert devices_owner(world["d_free"]) == world["boss"]


def test_a_member_cannot_confirm_claims(world, trusted_proxy):
    new_client(ALICE).post("/devices/claim", headers=FREE_IP)
    from clarinet.database import SessionLocal
    from clarinet.models.accounts import DeviceClaim
    with SessionLocal() as db:
        claim_id = db.query(DeviceClaim).one().claim_id
    r = new_client(BOB).post(f"/devices/claims/{claim_id}/approve")
    assert r.headers["location"].startswith("/dashboard?error=forbidden") and devices_owner(world["d_free"]) is None


def test_a_new_member_is_told_how_to_get_a_device(world):
    c = new_client()
    c.post("/signup", data=SIGNUP)
    page = c.get("/devices").text
    assert "You have no devices yet" in page


# ---- recovery from the machine
def test_cli_resets_the_only_admins_password(world):
    from clarinet import cli
    assert cli.main(["reset-password", "boss", "--password", "recovered-pass-1"]) == 0
    assert new_client().post("/login", data={"username": "boss", "password": "recovered-pass-1"}).status_code == 302
    assert new_client().post("/login", data={"username": "boss", "password": ADMIN[1]}).status_code == 401


def test_cli_clears_a_lockout_and_signs_out_old_sessions(world):
    from clarinet import cli
    old = new_client(ADMIN)
    for _ in range(5):
        new_client().post("/login", data={"username": "boss", "password": "wrong"})
    cli.main(["reset-password", "boss", "--password", "recovered-pass-1"])
    assert old.get("/dashboard").status_code == 302
    assert new_client().post("/login", data={"username": "boss", "password": "recovered-pass-1"}).status_code == 302


def test_cli_refuses_unknown_users_and_short_passwords(world, capsys):
    from clarinet import cli
    assert cli.main(["reset-password", "nobody", "--password", "long-enough-1"]) == 1
    assert cli.main(["reset-password", "boss", "--password", "short"]) == 1
    assert new_client().post("/login", data={"username": "boss", "password": ADMIN[1]}).status_code == 302
