"""
ACC-04..07 and ADM-04: web security checks against the real app.
"""
from __future__ import annotations

import pytest

from tests._support import ADMIN, ALICE, BOB, new_client, seed_world

XSS = "<script>alert(1)</script>"
PAGES = ["/devices", "/dashboard", "/usage", "/vouchers", "/priority", "/rules", "/alerts", "/slowdowns", "/security"]


@pytest.fixture()
def world():
    return seed_world()


def test_acc04_stored_xss_in_labels_is_escaped_on_every_page(world):
    from clarinet.database import SessionLocal
    from clarinet.models import Alert, Device
    from clarinet.models.security import SeenAccessPoint
    with SessionLocal() as db:
        d = db.get(Device, world["d_free"])
        d.label = XSS
        d.hostname = XSS
        db.add(Alert(level="INFO", type="X", title=XSS, message=XSS, device_id=d.device_id))
        db.add(SeenAccessPoint(bssid="CC:00:00:00:00:77", ssid=XSS, verdict="UNKNOWN"))
        db.commit()
    admin = new_client(ADMIN)
    admin.post("/vouchers/create", data={"expires_minutes": "60", "label": XSS})
    for page in PAGES + [f"/devices/{world['d_free']}"]:
        r = admin.get(page)
        assert r.status_code == 200, page
        assert XSS not in r.text, f"{page} renders the payload unescaped"


def test_acc04_usage_script_block_cannot_be_closed_by_data(world):
    from clarinet.database import SessionLocal
    from clarinet.models import UsageRecord
    from datetime import datetime, timezone
    with SessionLocal() as db:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        db.add(UsageRecord(device_id=world["d_alice"], date=today + "</script><script>alert(1)</script>",
                           hour=1, bytes_in=5, bytes_out=5))
        db.commit()
    body = new_client(ADMIN).get("/usage?period=all").text
    assert "</script><script>alert(1)" not in body


def test_acc06_session_cookie_flags(world):
    r = new_client().post("/login", data={"username": ADMIN[0], "password": ADMIN[1]})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie


@pytest.mark.xfail(strict=True, reason="N-01: logout only clears the client's cookie; the signed cookie still works if replayed")
def test_acc06_cookie_is_dead_after_logout(world):
    c = new_client(ADMIN)
    saved = dict(c.cookies)
    c.get("/logout")
    replay = new_client()
    replay.cookies.update(saved)
    assert replay.get("/dashboard").status_code in (302, 401, 403)


def test_acc06_disabled_user_session_ends(world):
    from clarinet.database import SessionLocal
    from clarinet.models import Member
    alice = new_client(ALICE)
    assert alice.get("/dashboard").status_code == 200
    with SessionLocal() as db:
        db.get(Member, world["alice"]).is_active = False
        db.commit()
    assert alice.get("/dashboard").status_code == 302


def test_acc07_csv_exports_neutralise_formulas(world):
    from clarinet.database import SessionLocal
    from clarinet.models import Device
    with SessionLocal() as db:
        d = db.get(Device, world["d_free"])
        d.label, d.hostname = '=HYPERLINK("http://evil")', "+cmd|calc"
        db.commit()
    body = new_client(ADMIN).get("/export/devices.csv").text
    for line in body.splitlines():
        for cell in ("=HYPERLINK", "+cmd"):
            if cell in line:
                assert f',{cell}' not in line and f',"{cell}' not in line, f"unescaped formula cell: {line}"


def test_acc05_logout_is_a_get_request_documented(world):
    """GET /logout logs the user out. Low risk, recorded in the report (any page can log a user out)."""
    assert new_client(ADMIN).get("/logout").status_code == 302


def test_acc05_post_has_no_csrf_token_so_samesite_is_the_only_defence(world):
    """Documents the design: a POST carrying only the cookie and a foreign Origin is accepted."""
    r = new_client(ADMIN).post(f"/devices/{world['d_free']}/rename", data={"label": "x"},
                               headers={"Origin": "http://evil.example"})
    assert r.status_code == 302 and "info=" in r.headers["location"]


# S-13: login lockout
def _fail(username, xff=None):
    h = {"X-Forwarded-For": xff} if xff else {}
    return new_client().post("/login", data={"username": username, "password": "wrong"}, headers=h)


def test_adm04_ip_lockout_exists_for_a_single_address(world):
    for i in range(8):
        _fail(f"ghost{i}")
    assert new_client().post("/login", data={"username": BOB[0], "password": BOB[1]}).status_code == 401


@pytest.mark.xfail(strict=True, reason="S-13: X-Forwarded-For is trusted, so rotating it bypasses the IP lockout")
def test_s13_rotating_forwarded_for_cannot_bypass_ip_lockout(world):
    for i in range(8):
        _fail(f"ghost{i}", xff=f"1.1.1.{i}")
    # all 8 came from the same real client, so it should now be locked out
    assert new_client().post("/login", data={"username": BOB[0], "password": BOB[1]}).status_code == 401


@pytest.mark.xfail(strict=True, reason="S-13: locked message differs from the unknown-user message, revealing valid usernames")
def test_s13_locked_account_message_does_not_reveal_username(world):
    for _ in range(5):
        _fail(ALICE[0])
    # probe from a second address so the first address's own IP lockout does not mask the difference
    other = {"X-Forwarded-For": "8.8.4.4"}
    locked = new_client().post("/login", data={"username": ALICE[0], "password": "x"}, headers=other).text
    unknown = new_client().post("/login", data={"username": "nosuchuser", "password": "x"}, headers=other).text
    assert ("temporarily locked" in locked) == ("temporarily locked" in unknown)


@pytest.mark.xfail(strict=True, reason="S-13: ALERT_LOCKOUT_* settings are ignored; auth.py uses hard-coded constants")
def test_s13_lockout_settings_are_honoured(world, monkeypatch):
    from clarinet.config import settings
    monkeypatch.setattr(settings, "ALERT_LOCKOUT_ATTEMPTS", 2)
    for _ in range(2):
        _fail(ALICE[0])
    locked = new_client().post("/login", data={"username": ALICE[0], "password": ALICE[1]})
    assert locked.status_code == 401


@pytest.mark.xfail(strict=True, reason="S-19: 'online' counts approved devices, not recently seen ones")
def test_s19_online_count_uses_last_seen(world):
    from datetime import datetime, timedelta, timezone
    from clarinet.database import SessionLocal
    from clarinet.models import Device
    with SessionLocal() as db:
        for d in db.query(Device):
            d.last_seen = datetime.now(timezone.utc) - timedelta(days=30)
        db.commit()
    assert new_client(ADMIN).get("/api/v1/status").json()["online_devices"] == 0
