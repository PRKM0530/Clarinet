"""
Suspects S-05, S-09, S-14, S-23, S-25 against the real routes and job functions.
Only the clock (S-14) and the websocket client objects (S-25) are faked.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from tests._support import ADMIN, ALICE, new_client, seed_world


@pytest.fixture()
def world():
    return seed_world()


# S-09: cancelling a priority grant must still charge the minutes that were used
@pytest.mark.xfail(strict=True, reason="S-09: only the expiry job charges fairness minutes; cancel skips it")
def test_s09_cancelled_priority_counts_against_the_daily_limit(world):
    from clarinet.database import SessionLocal
    from clarinet.models import PriorityGrant
    from clarinet.models.guest import FairnessCredit
    alice = new_client(ALICE)
    r = alice.post("/priority/request", data={"device_id": str(world["d_alice"]), "duration_min": "30"})
    with SessionLocal() as db:
        grant = db.query(PriorityGrant).one()
        assert grant.decision == "APPROVED", (r.headers.get("location"), grant.decision)
        grant.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)     # 25 of 30 minutes already used
        gid = grant.grant_id
        db.commit()
    assert "cancelled" in alice.post(f"/priority/{gid}/cancel").headers["location"].lower()
    with SessionLocal() as db:
        used = sum(c.minutes_used for c in db.query(FairnessCredit).filter_by(member_id=world["alice"]))
    assert used >= 20, f"only {used} minutes charged for a grant that ran about 25"


def test_s09_expired_priority_is_charged(world):
    from clarinet.database import SessionLocal
    from clarinet.jobs.access import expire_priority_grants
    from clarinet.models import PriorityGrant
    from clarinet.models.guest import FairnessCredit
    new_client(ALICE).post("/priority/request", data={"device_id": str(world["d_alice"]), "duration_min": "30"})
    with SessionLocal() as db:
        db.query(PriorityGrant).one().expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    expire_priority_grants()
    with SessionLocal() as db:
        assert sum(c.minutes_used for c in db.query(FairnessCredit)) > 0


# S-05: a voucher over its data cap must be expired AND saved
def _active_voucher_over_cap(world):
    from clarinet.database import SessionLocal
    from clarinet.models import Voucher
    from clarinet.models.guest import EnforcementStatus
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        v = Voucher(code="CAPPED-0001", created_by=world["boss"], expires_at=now + timedelta(hours=2),
                    status="ACTIVE", data_cap_mb=10, used_by_mac="AA:00:00:00:00:77")
        db.add(v)
        db.flush()
        db.add(EnforcementStatus(mac="AA:00:00:00:00:77", voucher_id=v.voucher_id, expires_at=v.expires_at,
                                 data_cap_mb=10, bytes_used=50 * 1024 * 1024))
        db.commit()
        return v.voucher_id


@pytest.mark.xfail(strict=True, reason="S-05: cap expiry is never committed when no voucher has timed out")
def test_s05_voucher_over_its_data_cap_is_expired_and_saved(world):
    from clarinet.database import SessionLocal
    from clarinet.jobs.access import expire_vouchers
    from clarinet.models import Voucher
    vid = _active_voucher_over_cap(world)
    expire_vouchers()
    with SessionLocal() as db:
        assert db.get(Voucher, vid).status == "EXPIRED"


@pytest.mark.xfail(strict=True, reason="S-05: nothing writes EnforcementStatus.bytes_used")
def test_s05_something_in_the_app_updates_bytes_used():
    """S-05 root cause: bytes_used must be written somewhere under clarinet/ (static check)."""
    import pathlib, re
    root = pathlib.Path(__file__).resolve().parents[2] / "clarinet"
    writers = [str(p.relative_to(root)) for p in root.rglob("*.py")
               if re.search(r"bytes_used\s*(\+=|=[^=])", p.read_text()) and "models" not in p.parts
               and p.name != "limit_service.py"]
    assert writers, "no code ever updates EnforcementStatus.bytes_used, so data caps cannot trigger"


# S-14: background polling must not keep an idle session alive
@pytest.mark.xfail(strict=True, reason="S-14: the 60-second status poll resets the idle clock, so the timeout never fires")
def test_s14_polling_does_not_extend_the_session(world, monkeypatch):
    from clarinet import auth
    from clarinet.config import settings
    clock = {"t": 1_000_000.0}
    monkeypatch.setattr(auth, "time", SimpleNamespace(time=lambda: clock["t"]))
    monkeypatch.setattr(settings, "SESSION_IDLE_MINUTES", 1)
    c = new_client(ALICE)
    clock["t"] += 50
    assert c.get("/api/status/topbar").status_code == 200          # what the open tab does every 60 s
    clock["t"] += 50                                                # 100 s after login, user did nothing
    assert c.get("/dashboard").status_code == 302


def test_s14_a_truly_idle_session_does_time_out(world, monkeypatch):
    from clarinet import auth
    from clarinet.config import settings
    clock = {"t": 1_000_000.0}
    monkeypatch.setattr(auth, "time", SimpleNamespace(time=lambda: clock["t"]))
    monkeypatch.setattr(settings, "SESSION_IDLE_MINUTES", 1)
    c = new_client(ALICE)
    clock["t"] += 100
    r = c.get("/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["location"]


# S-23: contract paths documented in the team brief
@pytest.mark.xfail(strict=True, reason="S-23: /api/slowdowns/summary is documented but only /slowdowns/api/slowdowns/summary exists")
def test_s23_documented_slowdown_summary_path_is_served(world):
    assert new_client(ADMIN).get("/api/slowdowns/summary").status_code == 200


# S-25: members must not get push notices of security alerts
class FakeSocket:
    def __init__(self):
        self.sent = []

    async def send_text(self, text):
        self.sent.append(text)


@pytest.mark.xfail(strict=True, reason="S-25: every connected member is sent the type and level of every alert, including security ones")
def test_s25_security_alert_is_not_pushed_to_members():
    from clarinet.routers import ws
    member, admin = FakeSocket(), FakeSocket()
    ws._clients.clear()
    ws._clients[member], ws._clients[admin] = "MEMBER", "ADMIN"
    try:
        asyncio.run(ws.broadcast_alert({"type": "ARP_SPOOF", "level": "CRITICAL", "title": "t", "message": "m"}))
    finally:
        ws._clients.clear()
    assert admin.sent, "the admin must still receive it"
    assert member.sent == []


def test_s25_member_payload_is_only_type_and_level():
    import json
    from clarinet.routers import ws
    member = FakeSocket()
    ws._clients.clear()
    ws._clients[member] = "MEMBER"
    try:
        asyncio.run(ws.broadcast_alert({"type": "SLOWDOWN", "level": "WARNING", "title": "secret", "message": "secret"}))
    finally:
        ws._clients.clear()
    assert json.loads(member.sent[0]) == {"type": "SLOWDOWN", "level": "WARNING"}
