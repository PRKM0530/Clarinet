"""
Admin-role audit.

Every admin-only page and action must refuse anonymous visitors and ordinary
members, and every admin action on the Security page must leave an audit entry.
"""

import pytest
from fastapi.testclient import TestClient

from clarinet import app
from clarinet.auth import hash_password
from clarinet.models import AuditLog, Member
from clarinet.models.security import KnownNetwork, SeenAccessPoint, TrustedAccessPoint


@pytest.fixture()
def accounts(db):
    from clarinet.models import Settings
    db.add(Settings(key="setup_complete", value="true"))
    db.add(Member(username="boss", password_hash=hash_password("pw-admin-1"), role="ADMIN"))
    db.add(Member(username="kid", password_hash=hash_password("pw-member-1"), role="MEMBER"))
    db.commit()


def client_for(username=None, password=None):
    client = TestClient(app, follow_redirects=False)
    if username:
        r = client.post("/login", data={"username": username, "password": password})
        assert r.status_code == 302, r.text
    return client


SECURITY_GETS = ["/security", "/security/summary"]
SECURITY_POSTS = [
    "/security/router-audit/run",
    "/security/wifi/scan",
    "/security/access-points/trust",
    "/security/access-points/1/untrust",
    "/security/networks/1/trust",
    "/security/networks/1/forget",
]


@pytest.mark.parametrize("path", SECURITY_GETS)
def test_anonymous_cannot_read_security_pages(accounts, path):
    r = client_for().get(path)
    assert r.status_code in (302, 403)
    assert r.status_code == 403 or "/login" in r.headers["location"]


@pytest.mark.parametrize("path", SECURITY_GETS)
def test_member_cannot_read_security_pages(accounts, path):
    r = client_for("kid", "pw-member-1").get(path)
    assert r.status_code in (302, 403)
    if r.status_code == 302:
        assert "forbidden" in r.headers["location"]


@pytest.mark.parametrize("path", SECURITY_POSTS)
def test_member_and_anonymous_cannot_run_security_actions(accounts, db, path):
    db.add(KnownNetwork(gateway_mac="AA:AA:AA:AA:AA:01", trusted=False))
    db.commit()
    for client in (client_for(), client_for("kid", "pw-member-1")):
        r = client.post(path, data={"bssid": "AA:AA:AA:AA:AA:01"})
        assert r.status_code == 302 and "/security" not in r.headers["location"]
    assert db.query(KnownNetwork).filter(KnownNetwork.trusted == True).count() == 0  # noqa: E712
    assert db.query(AuditLog).filter(AuditLog.action.in_(["TRUST_NETWORK", "FORGET_NETWORK"])).count() == 0


def test_admin_can_open_the_security_page(accounts):
    client = client_for("boss", "pw-admin-1")
    assert client.get("/security").status_code == 200
    body = client.get("/security/summary").json()
    assert body["open_total"] == 0


def test_admin_actions_are_written_to_the_audit_log(accounts, db):
    from datetime import datetime, timezone
    db.add(SeenAccessPoint(bssid="AA:AA:AA:AA:AA:02", ssid="Cafe", verdict="UNKNOWN",
                           first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc)))
    net = KnownNetwork(gateway_mac="AA:AA:AA:AA:AA:03", trusted=False)
    db.add(net)
    db.commit()
    network_id = net.network_id

    client = client_for("boss", "pw-admin-1")
    assert client.post("/security/access-points/trust", data={"bssid": "AA:AA:AA:AA:AA:02"}).status_code == 303
    assert client.post(f"/security/networks/{network_id}/trust").status_code == 303
    ap_id = db.query(TrustedAccessPoint).one().ap_id
    assert client.post(f"/security/access-points/{ap_id}/untrust").status_code == 303
    assert client.post(f"/security/networks/{network_id}/forget").status_code == 303

    actions = [a.action for a in db.query(AuditLog).order_by(AuditLog.log_id)]
    for expected in ("TRUST_AP", "TRUST_NETWORK", "UNTRUST_AP", "FORGET_NETWORK"):
        assert expected in actions
    actor = db.query(AuditLog).filter(AuditLog.action == "TRUST_AP").one().actor
    assert actor.username == "boss"


def test_only_the_ticked_access_points_are_trusted(accounts, db):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    for n in (1, 2, 3):
        db.add(SeenAccessPoint(bssid=f"AA:AA:AA:AA:AA:0{n}", ssid="Campus", verdict="SUSPECT",
                               first_seen=now, last_seen=now))
    db.commit()

    client = client_for("boss", "pw-admin-1")
    r = client.post("/security/access-points/trust",
                    data={"bssid": ["AA:AA:AA:AA:AA:01", "AA:AA:AA:AA:AA:03"]})
    assert r.status_code == 303

    assert sorted(t.bssid for t in db.query(TrustedAccessPoint)) == ["AA:AA:AA:AA:AA:01", "AA:AA:AA:AA:AA:03"]
    db.expire_all()
    assert db.get(SeenAccessPoint, "AA:AA:AA:AA:AA:02").verdict == "SUSPECT"      # not ticked, still suspect
    assert db.query(AuditLog).filter(AuditLog.action == "TRUST_AP").count() == 2


def test_trusting_an_access_point_nobody_saw_does_nothing(accounts, db):
    client = client_for("boss", "pw-admin-1")
    client.post("/security/access-points/trust", data={"bssid": "DE:AD:BE:EF:00:00"})
    assert db.query(TrustedAccessPoint).count() == 0


def test_every_admin_router_page_refuses_a_member(accounts):
    """Sweep: GET pages that use require_admin must not answer 200 to a member."""
    admin_pages = ["/devices", "/rules", "/vouchers", "/settings", "/security", "/alerts"]
    client = client_for("kid", "pw-member-1")
    leaked = [p for p in admin_pages if client.get(p).status_code == 200]
    assert leaked == [], f"members can open admin pages: {leaked}"
