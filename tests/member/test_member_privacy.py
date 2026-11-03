"""
tests/member/test_member_privacy.py
Member-role audit against the real application.

Logs in as an ordinary member and requests the real pages and APIs. Nothing
that belongs to another member, nothing from the audit log, and no network-wide
security alert may ever show up, and no page may crash.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

import pytest
from fastapi.testclient import TestClient

from clarinet import app
from clarinet.auth import hash_password
from clarinet.database import Base, SessionLocal, engine
from clarinet.models import (
    Alert, AuditLog, Device, Member, PriorityGrant, Settings, UsageRecord,
)

# Strings that must never reach Alice's screen
BOB_NAME = "bobby-secret-name"
BOB_DEVICE = "BOB-PHONE-SECRET"
BOB_MAC = "BB:00:00:00:00:02"
BOB_BYTES = "987654321"
AUDIT_NOTE = "AUDIT-SECRET-NOTE"
SECURITY_ALERT = "SECURITY-ALERT-SECRET"
BOB_ALERT = "BOB-DEVICE-ALERT"
FORBIDDEN = [BOB_NAME, BOB_DEVICE, BOB_MAC, BOB_BYTES, AUDIT_NOTE, SECURITY_ALERT, BOB_ALERT]

SKIP_PREFIXES = ("/static", "/ws", "/api/docs", "/openapi", "/docs", "/redoc",
                 "/logout", "/login", "/setup", "/guest", "/portal")


@pytest.fixture()
def world():
    assert "clarinet_test_" in str(engine.url), "refusing to touch a non-test database"
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.add(Settings(key="setup_complete", value="true"))
        alice = Member(username="alice", password_hash=hash_password("pw-alice-1"), role="MEMBER")
        bob = Member(username=BOB_NAME, password_hash=hash_password("pw-bob-1"), role="MEMBER")
        boss = Member(username="boss", password_hash=hash_password("pw-boss-1"), role="ADMIN")
        db.add_all([alice, bob, boss])
        db.flush()
        d_alice = Device(mac_address="AA:00:00:00:00:01", label="ALICE-LAPTOP", state="APPROVED",
                         owner_member_id=alice.member_id, first_seen=now, last_seen=now)
        d_bob = Device(mac_address=BOB_MAC, label=BOB_DEVICE, state="APPROVED",
                       owner_member_id=bob.member_id, first_seen=now, last_seen=now)
        db.add_all([d_alice, d_bob])
        db.flush()
        today = datetime.now(timezone.utc).date().isoformat()
        db.add_all([
            UsageRecord(device_id=d_alice.device_id, date=today, hour=datetime.now(timezone.utc).hour, bytes_in=5_000_000, bytes_out=1_000_000),
            UsageRecord(device_id=d_bob.device_id, date=today, hour=datetime.now(timezone.utc).hour, bytes_in=int(BOB_BYTES), bytes_out=1),
            PriorityGrant(device_id=d_bob.device_id, member_id=bob.member_id, decision="PENDING", requested_at=now),
            AuditLog(actor_id=boss.member_id, action="BLOCK_DEVICE", detail_json=f'{{"note": "{AUDIT_NOTE}"}}'),
            Alert(level="CRITICAL", type="ARP_SPOOF", title=SECURITY_ALERT, message="router impersonated"),
            Alert(level="WARNING", type="SLOWDOWN", title=BOB_ALERT, message="x", device_id=d_bob.device_id),
            Alert(level="WARNING", type="SLOWDOWN", title="ALICE-DEVICE-ALERT", message="x", device_id=d_alice.device_id),
        ])
        db.commit()
        ids = {"alice_device": d_alice.device_id, "bob_device": d_bob.device_id}
    return ids


def login(username: str, password: str) -> TestClient:
    client = TestClient(app, follow_redirects=False, raise_server_exceptions=False)
    assert client.post("/login", data={"username": username, "password": password}).status_code == 302
    return client


def get_routes() -> list[str]:
    return sorted({
        r.path for r in app.routes
        if hasattr(r, "methods") and "GET" in r.methods and "{" not in r.path
        and not r.path.startswith(SKIP_PREFIXES)
    })


def test_no_page_leaks_other_peoples_data_to_a_member(world):
    client = login("alice", "pw-alice-1")
    leaks = []
    for path in get_routes():
        r = client.get(path)
        if r.status_code == 200:
            leaks += [(path, bad) for bad in FORBIDDEN if bad in r.text]
    assert leaks == [], f"a member can read other people's data: {leaks}"


@pytest.mark.parametrize("who", [("alice", "pw-alice-1"), ("boss", "pw-boss-1")])
def test_no_page_crashes(world, who):
    client = login(*who)
    crashed = [p for p in get_routes() if client.get(p).status_code >= 500]
    assert crashed == [], f"{who[0]} gets a server error on: {crashed}"


def test_dashboard_only_counts_the_members_own_devices(world):
    body = login("alice", "pw-alice-1").get("/dashboard").text
    assert "ALICE-LAPTOP" in body
    assert BOB_DEVICE not in body and BOB_MAC not in body
    assert "ALICE-DEVICE-ALERT" not in body or BOB_ALERT not in body   # never Bob's
    assert SECURITY_ALERT not in body


def test_admin_device_list_sees_the_whole_network(world):
    body = login("boss", "pw-boss-1").get("/devices").text
    assert "ALICE-LAPTOP" in body and BOB_DEVICE in body


def test_device_pages_are_scoped(world):
    client = login("alice", "pw-alice-1")
    listing = client.get("/devices").text
    assert "ALICE-LAPTOP" in listing and BOB_DEVICE not in listing
    other = client.get(f"/devices/{world['bob_device']}")
    assert other.status_code in (302, 403, 404)
    assert BOB_DEVICE not in other.text


def test_usage_page_works_and_is_scoped(world):
    client = login("alice", "pw-alice-1")
    r = client.get("/usage")
    assert r.status_code == 200, "the usage page must render"
    assert BOB_BYTES not in r.text and BOB_DEVICE not in r.text
    assert "ALICE-LAPTOP" in r.text

    summary = client.get("/api/usage/summary?period=today").json()
    assert summary["bytes_in"] == 5_000_000          # only Alice's traffic

    boss = login("boss", "pw-boss-1").get("/api/usage/summary?period=today").json()
    assert boss["bytes_in"] == 5_000_000 + int(BOB_BYTES)


@pytest.mark.parametrize("period", ["today", "week", "month", "billing", "2020-01-01",
                                    "garbage", "abcde-fghi", "9999-99-99", ""])
def test_usage_page_survives_any_period_value(world, period):
    assert login("alice", "pw-alice-1").get(f"/usage?period={period}").status_code == 200


def test_member_cannot_open_another_members_usage_detail(world):
    r = login("alice", "pw-alice-1").get(f"/usage/device/{world['bob_device']}")
    assert r.status_code in (302, 403, 404)
    assert BOB_BYTES not in r.text


def test_alerts_page_is_scoped(world):
    body = login("alice", "pw-alice-1").get("/alerts").text
    assert "ALICE-DEVICE-ALERT" in body
    assert BOB_ALERT not in body and SECURITY_ALERT not in body


def test_priority_page_hides_other_members_requests(world):
    body = login("alice", "pw-alice-1").get("/priority").text
    assert BOB_NAME not in body and BOB_DEVICE not in body


def test_audit_log_is_admin_only(world):
    client = login("alice", "pw-alice-1")
    assert client.get("/security/summary").status_code in (302, 403)
    r = client.get("/security")                      # members have no Security page: they are sent to their account
    assert r.status_code == 302 and r.headers["location"] == "/account"
    assert AUDIT_NOTE in login("boss", "pw-boss-1").get("/security").text


