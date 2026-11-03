"""
tests/_support.py
Helpers shared by the new tests/access and tests/e2e folders.

* no_real_network: autouse guard so a test can never probe the real gateway,
  run a real speed test, call nmcli or ping. Tests that need a "network edge"
  install their own fake on top of it.
* seed_world: one throw-away database with an admin, two members, devices,
  alerts and security rows. Safe to call before every test.
"""
from __future__ import annotations

import socket
import subprocess
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

ADMIN = ("boss", "pw-boss-12345")
ALICE = ("alice", "pw-alice-12345")
BOB = ("bob", "pw-bob-12345")


class NetworkBlocked(OSError):   # OSError, so the app sees it like a missing command or refused connection
    pass


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Fail closed: any real socket connection or subprocess is refused."""
    def blocked(*a, **k):
        raise NetworkBlocked("tests must not touch the real network or run host commands")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(subprocess, "check_output", blocked)
    # POST /speed/run starts a background thread; it must not outlive the test and race with the next reset
    monkeypatch.setattr("clarinet.collector.speed_test.run_speed_test_async", lambda: None)
    yield


def reset_db():
    from clarinet.database import Base, engine
    import clarinet.models  # noqa: F401
    assert "clarinet_test_" in str(engine.url), "refusing to touch a non-test database"
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


_HASH_CACHE: dict[str, str] = {}


def _hash(pw: str) -> str:
    from clarinet.auth import hash_password
    if pw not in _HASH_CACHE:
        _HASH_CACHE[pw] = hash_password(pw)
    return _HASH_CACHE[pw]


def seed_world(mode: str = "FULL") -> dict:
    """Admin id 1, alice id 2, bob id 3. Devices: 1 alice, 2 bob, 3 NEW, 4 ownerless approved."""
    from clarinet.database import SessionLocal
    from clarinet.models import Alert, Device, Member, Settings, UsageRecord
    from clarinet.models.security import KnownNetwork, SeenAccessPoint

    reset_db()
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    with SessionLocal() as db:
        db.add_all([Settings(key="setup_complete", value="true"), Settings(key="network_mode", value=mode)])
        boss = Member(username=ADMIN[0], password_hash=_hash(ADMIN[1]), role="ADMIN")
        alice = Member(username=ALICE[0], password_hash=_hash(ALICE[1]), role="MEMBER")
        bob = Member(username=BOB[0], password_hash=_hash(BOB[1]), role="MEMBER")
        db.add_all([boss, alice, bob])
        db.flush()
        d1 = Device(mac_address="AA:00:00:00:00:01", ip_address="192.168.1.11", hostname="alice-laptop",
                    state="APPROVED", owner_member_id=alice.member_id, first_seen=now, last_seen=now)
        d2 = Device(mac_address="AA:00:00:00:00:02", ip_address="192.168.1.12", hostname="bob-phone",
                    state="APPROVED", owner_member_id=bob.member_id, first_seen=now, last_seen=now)
        d3 = Device(mac_address="AA:00:00:00:00:03", ip_address="192.168.1.13", state="NEW",
                    first_seen=now, last_seen=now)
        d4 = Device(mac_address="AA:00:00:00:00:04", ip_address="192.168.1.14", hostname="printer",
                    state="APPROVED", first_seen=now, last_seen=now)
        db.add_all([d1, d2, d3, d4])
        db.flush()
        db.add_all([
            UsageRecord(device_id=d1.device_id, date=today, hour=9, bytes_in=5_000_000, bytes_out=1_000_000),
            UsageRecord(device_id=d2.device_id, date=today, hour=10, bytes_in=7_777_000, bytes_out=1),
            Alert(level="WARNING", type="SLOWDOWN", title="ALICE-ALERT", message="x", device_id=d1.device_id),
            Alert(level="WARNING", type="SLOWDOWN", title="BOB-ALERT", message="x", device_id=d2.device_id),
            Alert(level="CRITICAL", type="ARP_SPOOF", title="SECRET-SECURITY-ALERT", message="x"),
            KnownNetwork(gateway_mac="BB:00:00:00:00:01", trusted=False),
            SeenAccessPoint(bssid="CC:00:00:00:00:01", ssid="Cafe", verdict="UNKNOWN",
                            first_seen=now, last_seen=now),
        ])
        db.commit()
        return {"boss": boss.member_id, "alice": alice.member_id, "bob": bob.member_id,
                "d_alice": d1.device_id, "d_bob": d2.device_id, "d_new": d3.device_id, "d_free": d4.device_id}


def new_client(identity: tuple[str, str] | None = None, **kw) -> TestClient:
    from clarinet import app
    c = TestClient(app, follow_redirects=False, raise_server_exceptions=False, **kw)
    if identity:
        r = c.post("/login", data={"username": identity[0], "password": identity[1]})
        assert r.status_code == 302, (identity, r.status_code, r.text[:200])
    return c
