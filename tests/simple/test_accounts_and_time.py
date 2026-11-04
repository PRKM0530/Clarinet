"""
Password recovery by members, sign-up that is always open, sign-in that ignores
capital letters, and a time zone that is found automatically.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from clarinet import app
from clarinet.auth import hash_password
from clarinet.core_svc import recovery
from clarinet.database import Base, SessionLocal, engine
from clarinet.models import Member, Settings
from clarinet.models.recovery import RecoveryAttempt, RecoveryCode

CODE_SHAPE = re.compile(r"\b[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){3}\b")


@pytest.fixture()
def db():
    assert "clarinet_test_" in str(engine.url), "refusing to touch a non-test database"
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        session.add(Settings(key="setup_complete", value="true"))
        session.add(Member(username="Praveen", password_hash=hash_password("12345678"), role="ADMIN"))
        session.add(Member(username="alice", password_hash=hash_password("alice-pass-1"), role="MEMBER"))
        session.add(Member(username="bob", password_hash=hash_password("bob-pass-123"), role="MEMBER"))
        session.commit()
        yield session


def client(user=None, password=None) -> TestClient:
    c = TestClient(app, follow_redirects=False, raise_server_exceptions=False)
    if user:
        assert c.post("/login", data={"username": user, "password": password}).status_code == 302
    return c


def member(db, name):
    return db.query(Member).filter(Member.username == name).one()


def forgot(code, user="alice", new="a-brand-new-pw", confirm=None, c=None):
    return (c or client()).post("/forgot", data={
        "username": user, "recovery_code": code, "new_password": new, "confirm_password": new if confirm is None else confirm})


# the code itself

def test_codes_are_long_random_and_free_of_look_alike_characters():
    codes = {recovery.new_code() for _ in range(300)}
    assert len(codes) == 300
    for code in codes:
        assert CODE_SHAPE.fullmatch(code), code
        assert not set(code) & set("IO01")


def test_typing_a_code_loosely_still_works():
    assert recovery.normalise(" abcd-efgh  jklm-npqr ") == "ABCDEFGHJKLMNPQR"
    assert recovery.normalise(None) == ""


def test_only_a_hash_is_stored_and_a_new_code_replaces_the_old_one(db):
    alice = member(db, "alice")
    first = recovery.issue(db, alice)
    row = db.get(RecoveryCode, alice.member_id)
    assert recovery.normalise(first) not in row.code_hash and first not in row.code_hash
    first_hash = row.code_hash
    second = recovery.issue(db, alice)
    db.expire_all()
    assert second != first and db.get(RecoveryCode, alice.member_id).code_hash != first_hash
    assert db.query(RecoveryCode).filter_by(member_id=alice.member_id).count() == 1


# resetting a forgotten password

def test_a_member_resets_their_password_with_the_code_and_gets_a_new_code(db):
    code = recovery.issue(db, member(db, "alice"))
    r = forgot(code.lower().replace("-", " "))                      # typed carelessly
    assert r.status_code == 200 and "Your password was changed" in r.text
    fresh = CODE_SHAPE.search(r.text).group(0)
    assert fresh != code
    assert client().post("/login", data={"username": "alice", "password": "a-brand-new-pw"}).status_code == 302
    assert client().post("/login", data={"username": "alice", "password": "alice-pass-1"}).status_code == 401
    assert forgot(code, new="another-new-pw-1").status_code == 422        # the old code is spent
    assert forgot(fresh, new="another-new-pw-1").status_code == 200       # the new one works


def test_resetting_signs_the_member_out_everywhere(db, trusted_proxy):
    alice_session = client("alice", "alice-pass-1")
    assert alice_session.get("/dashboard").status_code == 200
    code = recovery.issue(db, member(db, "alice"))
    assert forgot(code).status_code == 200
    assert alice_session.get("/dashboard").status_code == 302
    ok = client().post("/login", data={"username": "alice", "password": "a-brand-new-pw"}, headers={"X-Forwarded-For": "6.6.6.6"})
    assert ok.status_code == 302


@pytest.mark.parametrize("who, why", [
    ("nobody", "no such member"),
    ("Praveen", "administrators recover another way"),
    ("bob", "a member who never made a code"),
])
def test_every_failure_says_the_same_thing(db, who, why):
    alice_code = recovery.issue(db, member(db, "alice"))
    r = forgot(alice_code, user=who)
    assert r.status_code == 422 and recovery.WRONG in r.text, why
    assert client().post("/login", data={"username": "alice", "password": "alice-pass-1"}).status_code == 302


def test_a_wrong_code_and_a_disabled_member_are_refused(db):
    bob = member(db, "bob")
    code = recovery.issue(db, bob)
    assert forgot("AAAA-AAAA-AAAA-AAAA", user="bob").status_code == 422
    bob.is_active = False
    db.commit()
    assert forgot(code, user="bob").status_code == 422
    assert client().post("/login", data={"username": "bob", "password": "bob-pass-123"}).status_code == 401


def test_a_code_belongs_to_one_member(db):
    alice_code = recovery.issue(db, member(db, "alice"))
    recovery.issue(db, member(db, "bob"))
    assert forgot(alice_code, user="bob").status_code == 422
    assert client().post("/login", data={"username": "bob", "password": "bob-pass-123"}).status_code == 302


@pytest.mark.parametrize("new, confirm, words", [
    ("short", "short", "at least 8"),
    ("long-enough-pw", "different-pw-1", "do not match"),
])
def test_a_bad_new_password_is_refused_and_the_code_survives(db, new, confirm, words):
    code = recovery.issue(db, member(db, "alice"))
    r = forgot(code, new=new, confirm=confirm)
    assert r.status_code == 422 and words in r.text
    assert forgot(code).status_code == 200


def test_unknown_and_known_names_take_the_same_work(db, monkeypatch):
    """A wrong username must still cost one password check, so timing does not reveal who exists."""
    import clarinet.auth as auth
    calls = []
    real = auth.verify_password
    monkeypatch.setattr(auth, "verify_password", lambda *a, **k: calls.append(1) or real(*a, **k))
    code = recovery.issue(db, member(db, "alice"))
    for user in ("nobody", "Praveen", "bob", "alice"):
        calls.clear()
        forgot(code if user == "alice" else "AAAA-AAAA-AAAA-AAAA", user=user)
        assert len(calls) == 1, user


def test_guessing_is_slowed_down_per_name_and_per_address(db):
    code = recovery.issue(db, member(db, "alice"))
    for _ in range(recovery.MAX_PER_USERNAME_PER_HOUR):
        assert forgot("AAAA-AAAA-AAAA-AAAA").status_code == 422
    blocked = forgot(code)                                          # even the right code is refused now
    assert blocked.status_code == 429 and recovery.TOO_MANY in blocked.text
    assert client().post("/login", data={"username": "alice", "password": "alice-pass-1"}).status_code == 302


def test_one_address_cannot_try_many_names(db):
    for i in range(recovery.MAX_PER_IP_PER_HOUR):
        forgot("AAAA-AAAA-AAAA-AAAA", user=f"name{i}")
    assert forgot("AAAA-AAAA-AAAA-AAAA", user="another").status_code == 429
    assert db.query(RecoveryAttempt).count() == recovery.MAX_PER_IP_PER_HOUR


def test_the_forgot_page_is_public_and_signed_in_people_go_to_their_account(db):
    page = client().get("/forgot")
    assert page.status_code == 200 and 'name="recovery_code"' in page.text and "Forgot your password?" in page.text
    assert 'type="password"' in page.text and "/static/js/clarinet.js" in page.text          # so it gets the eye too
    assert client("alice", "alice-pass-1").get("/forgot").headers["location"] == "/account"


def test_the_forgot_page_waits_for_setup(db):
    db.get(Settings, "setup_complete").value = "false"
    db.commit()
    assert client().get("/forgot").headers["location"] == "/setup"


# sign-up hands out the code

def test_sign_up_shows_the_code_once_and_it_works_straight_away(db):
    c = client()
    r = c.post("/signup", data={"username": "newbie", "password": "newbie-pass-1", "password_confirm": "newbie-pass-1"})
    assert r.status_code == 200 and "Your account is ready" in r.text and "only this once" in r.text
    code = CODE_SHAPE.search(r.text).group(0)
    assert c.get("/dashboard").status_code == 200                    # already signed in
    assert code not in c.get("/account").text                        # never shown again
    assert forgot(code, user="newbie").status_code == 200


# the account page

def test_a_member_without_a_code_is_told_and_can_make_one(db):
    c = client("alice", "alice-pass-1")
    page = c.get("/account").text
    assert "You do not have a recovery code yet" in page and "Make my recovery code" in page
    r = c.post("/account/recovery-code", data={"current_password": "alice-pass-1"})
    code = CODE_SHAPE.search(r.text).group(0)
    assert "Your new recovery code" in r.text and forgot(code).status_code == 200


def test_making_a_new_code_needs_the_password_and_replaces_the_old_one(db):
    c = client("alice", "alice-pass-1")
    old = recovery.issue(db, member(db, "alice"))
    assert "/account?error=password_wrong" in c.post("/account/recovery-code", data={"current_password": "nope-nope"}).headers["location"]
    assert forgot(old, new="x-a-valid-pw-1").status_code == 200        # still valid after the refused attempt
    c = client("alice", "x-a-valid-pw-1")
    old2 = CODE_SHAPE.search(forgot(recovery.issue(db, member(db, "alice")), user="alice", new="y-a-valid-pw-1").text).group(0)
    c = client("alice", "y-a-valid-pw-1")
    new = CODE_SHAPE.search(c.post("/account/recovery-code", data={"current_password": "y-a-valid-pw-1"}).text).group(0)
    assert forgot(old2, new="z-a-valid-pw-1").status_code == 422
    assert forgot(new, new="z-a-valid-pw-1").status_code == 200


def test_administrators_have_no_recovery_code_section(db):
    c = client("Praveen", "12345678")
    assert "Recovery code" not in c.get("/account").text
    r = c.post("/account/recovery-code", data={"current_password": "12345678"})
    assert "admin_no_recovery" in r.headers["location"]
    assert db.query(RecoveryCode).count() == 0


def test_an_administrator_has_no_way_to_set_a_members_password(db):
    admin = client("Praveen", "12345678")
    page = admin.get("/settings").text
    assert "reset-password" not in page and "Reset password" not in page
    assert admin.post(f"/settings/members/{member(db, 'alice').member_id}/reset-password",
                      data={"new_password": "admin-chosen-1"}).status_code in (404, 405)
    assert client().post("/login", data={"username": "alice", "password": "admin-chosen-1"}).status_code == 401


# sign-up is always open, and the link stays

def test_the_sign_up_toggle_is_gone_and_sign_up_works_whatever_an_old_setting_says(db):
    db.add(Settings(key="signup_enabled", value="false"))
    db.commit()
    assert "People can create their own accounts" not in client("Praveen", "12345678").get("/settings").text
    assert client().post("/signup", data={"username": "late", "password": "late-pass-123", "password_confirm": "late-pass-123"}).status_code == 200


@pytest.mark.parametrize("attempt", [("nobody", "x"), ("alice", "wrong-password"), ("Praveen", "wrong-password")])
def test_the_create_account_link_survives_a_failed_sign_in(db, attempt):
    r = client().post("/login", data={"username": attempt[0], "password": attempt[1]})
    assert r.status_code == 401
    assert 'href="/signup"' in r.text and 'href="/forgot"' in r.text


# capital letters do not matter in a username

@pytest.mark.parametrize("typed", ["Praveen", "praveen", "PRAVEEN", " praveen "])
def test_sign_in_ignores_capital_letters_like_sign_up_does(db, typed):
    assert client().post("/login", data={"username": typed, "password": "12345678"}).status_code == 302


# the time zone is found automatically

WIZARD = {"username": "owner", "password": "Owner-pass-123", "password_confirm": "Owner-pass-123", "network_mode": "MONITOR",
          "plan_download": "100", "plan_upload": "20", "billing_day": "1", "consent": "yes"}


@pytest.fixture()
def fresh():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def stored(key):
    with SessionLocal() as s:
        row = s.get(Settings, key)
        return row.value if row else None


def test_the_setup_page_does_not_ask_for_a_time_zone(fresh):
    html = client().get("/setup").text
    assert "<select" not in html                                   # the list of zones is gone
    field = re.search(r'<input[^>]*name="timezone"[^>]*>', html).group(0)
    assert 'type="hidden"' in field
    assert "Found automatically" in html and "Intl.DateTimeFormat" in html


def test_the_browsers_zone_is_used_when_it_sends_one(fresh):
    assert client().post("/setup/admin", data={**WIZARD, "timezone": "Asia/Kolkata"}).status_code == 200
    assert stored("timezone") == "Asia/Kolkata"


@pytest.mark.parametrize("sent", [None, "", "Not/AZone", "../../etc/passwd"])
def test_a_missing_or_unknown_zone_falls_back_to_the_computers_instead_of_an_error(fresh, sent):
    from clarinet.core_svc.localtime import machine_zone, valid_zone
    data = dict(WIZARD) if sent is None else {**WIZARD, "timezone": sent}
    r = client().post("/setup/admin", data=data)
    assert r.status_code == 200 and stored("setup_complete") == "true"
    assert stored("timezone") == machine_zone() and valid_zone(stored("timezone"))


def test_settings_still_lets_an_administrator_override_it_under_advanced(db):
    page = client("Praveen", "12345678").get("/settings").text
    advanced = page.split('<details class="advanced">')[1].split("</details>")[0]
    assert 'name="timezone"' in advanced and "Found automatically" in advanced
    client("Praveen", "12345678").post("/settings/update", data={"timezone": "Europe/London"})
    assert stored("timezone") == "Europe/London"
    assert client("Praveen", "12345678").post("/settings/update", data={"timezone": "Nowhere/Land"}).headers["location"].endswith("error=bad_timezone")
