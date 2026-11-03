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


def test_acc06_cookie_is_dead_after_logout(world):
    c = new_client(ADMIN)
    saved = dict(c.cookies)
    c.post("/logout")
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


def test_acc05_a_plain_link_cannot_log_a_user_out(world):
    """Signing out is a POST, so another page cannot end someone's session with a link or image."""
    c = new_client(ADMIN)
    assert c.get("/logout").status_code == 302
    assert c.get("/dashboard").status_code == 200, "GET /logout ended the session"
    assert c.post("/logout").status_code == 302
    assert c.get("/dashboard").status_code == 302


def test_acc05_post_from_another_site_is_refused(world):
    admin = new_client(ADMIN)
    for headers in ({"Origin": "http://evil.example"}, {"Sec-Fetch-Site": "cross-site"}, {"Origin": "null"}):
        r = admin.post(f"/devices/{world['d_free']}/rename", data={"label": "hacked"}, headers=headers)
        assert r.status_code == 403, headers
    from clarinet.database import SessionLocal
    from clarinet.models import Device
    with SessionLocal() as db:
        assert db.get(Device, world["d_free"]).label != "hacked"


def test_acc05_post_from_the_same_site_still_works(world):
    r = new_client(ADMIN).post(f"/devices/{world['d_free']}/rename", data={"label": "mine"},
                               headers={"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 302 and "info=" in r.headers["location"]


# S-13: login lockout
def _fail(username, xff=None):
    h = {"X-Forwarded-For": xff} if xff else {}
    return new_client().post("/login", data={"username": username, "password": "wrong"}, headers=h)


def test_adm04_ip_lockout_exists_for_a_single_address(world):
    for i in range(8):
        _fail(f"ghost{i}")
    assert new_client().post("/login", data={"username": BOB[0], "password": BOB[1]}).status_code == 401


def test_s13_rotating_forwarded_for_cannot_bypass_ip_lockout(world):
    for i in range(8):
        _fail(f"ghost{i}", xff=f"1.1.1.{i}")
    # all 8 came from the same real client, so it should now be locked out
    assert new_client().post("/login", data={"username": BOB[0], "password": BOB[1]}).status_code == 401


def test_s13_locked_account_message_does_not_reveal_username(world):
    for _ in range(5):
        _fail(ALICE[0])
    # probe from a second address so the first address's own IP lockout does not mask the difference
    other = {"X-Forwarded-For": "8.8.4.4"}
    locked = new_client().post("/login", data={"username": ALICE[0], "password": "x"}, headers=other).text
    unknown = new_client().post("/login", data={"username": "nosuchuser", "password": "x"}, headers=other).text
    assert ("temporarily locked" in locked) == ("temporarily locked" in unknown)


def test_s13_lockout_settings_are_honoured(world, monkeypatch):
    from clarinet.config import settings
    monkeypatch.setattr(settings, "ALERT_LOCKOUT_ATTEMPTS", 2)
    for _ in range(2):
        _fail(ALICE[0])
    locked = new_client().post("/login", data={"username": ALICE[0], "password": ALICE[1]})
    assert locked.status_code == 401


def test_s19_online_count_uses_last_seen(world):
    from datetime import datetime, timedelta, timezone
    from clarinet.database import SessionLocal
    from clarinet.models import Device
    with SessionLocal() as db:
        for d in db.query(Device):
            d.last_seen = datetime.now(timezone.utc) - timedelta(days=30)
        db.commit()
    assert new_client(ADMIN).get("/api/v1/status").json()["online_devices"] == 0


# Trusted proxies and server-side sessions
def test_x_forwarded_for_is_only_believed_from_a_trusted_proxy(monkeypatch):
    from types import SimpleNamespace
    from clarinet.auth import client_ip
    from clarinet.config import settings

    def request(peer, forwarded):
        return SimpleNamespace(client=SimpleNamespace(host=peer), headers={"X-Forwarded-For": forwarded} if forwarded else {})

    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "127.0.0.1,::1")
    assert client_ip(request("203.0.113.9", "1.2.3.4")) == "203.0.113.9"                 # not a proxy: header ignored
    assert client_ip(request("127.0.0.1", "198.51.100.7")) == "198.51.100.7"            # Caddy on this machine
    assert client_ip(request("127.0.0.1", "6.6.6.6, 198.51.100.7")) == "198.51.100.7"   # client-supplied entries are ignored
    assert client_ip(request("127.0.0.1", None)) == "127.0.0.1"


def test_resetting_a_password_logs_the_member_out_everywhere(world):
    alice = new_client(ALICE)
    assert alice.get("/dashboard").status_code == 200
    new_client(ADMIN).post(f"/settings/members/{world['alice']}/reset-password", data={"new_password": "another-pw-12345"})
    assert alice.get("/dashboard").status_code == 302


def test_login_is_recorded_and_logout_removes_the_record(world):
    from clarinet.database import SessionLocal
    from clarinet.models.sessions import ActiveSession
    c = new_client(ALICE)
    with SessionLocal() as db:
        assert db.query(ActiveSession).filter_by(member_id=world["alice"]).count() == 1
    c.post("/logout")
    with SessionLocal() as db:
        assert db.query(ActiveSession).filter_by(member_id=world["alice"]).count() == 0
