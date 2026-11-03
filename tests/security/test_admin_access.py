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


SECURITY_GETS = ["/security/summary"]       # /security itself is open to members, as their own smaller page
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
    """
    Sweep: GET pages that use require_admin must not answer 200 to a member.
    /devices and /alerts are open to members on purpose (scoped to their own
    devices), so they are covered by the tests below instead.
    """
    admin_pages = ["/rules", "/vouchers", "/settings", "/status"]
    client = client_for("kid", "pw-member-1")
    leaked = [p for p in admin_pages if client.get(p).status_code == 200]
    assert leaked == [], f"members can open admin pages: {leaked}"


def _seed_alerts(db):
    from clarinet.models import Alert, Device
    kid = db.query(Member).filter(Member.username == "kid").one()
    mine = Device(mac_address="AA:AA:AA:AA:01:01", state="APPROVED", owner_member_id=kid.member_id)
    other = Device(mac_address="AA:AA:AA:AA:02:02", state="APPROVED")
    db.add_all([mine, other])
    db.flush()
    db.add_all([
        Alert(level="CRITICAL", type="ARP_SPOOF", title="SECRET-ARP-ALERT", message="router impersonated"),
        Alert(level="CRITICAL", type="ROUTER_AUDIT", title="SECRET-ROUTER-AUDIT", message="Telnet is open"),
        Alert(level="WARNING", type="FAKE_AP", title="SECRET-FAKE-AP", message="evil twin"),
        Alert(level="WARNING", type="SLOWDOWN", title="MINE-ALERT", message="x", device_id=mine.device_id),
        Alert(level="WARNING", type="SLOWDOWN", title="OTHERS-ALERT", message="x", device_id=other.device_id),
    ])
    db.commit()


def test_member_cannot_read_security_alerts_on_the_alerts_page(accounts, db):
    _seed_alerts(db)
    body = client_for("kid", "pw-member-1").get("/alerts").text
    assert "MINE-ALERT" in body
    for hidden in ("SECRET-ARP-ALERT", "SECRET-ROUTER-AUDIT", "SECRET-FAKE-AP", "OTHERS-ALERT"):
        assert hidden not in body, f"member can read {hidden}"


def test_admin_still_sees_every_alert(accounts, db):
    _seed_alerts(db)
    body = client_for("boss", "pw-admin-1").get("/alerts").text
    for shown in ("SECRET-ARP-ALERT", "SECRET-ROUTER-AUDIT", "SECRET-FAKE-AP", "MINE-ALERT", "OTHERS-ALERT"):
        assert shown in body


def test_member_cannot_acknowledge_someone_elses_or_security_alerts(accounts, db):
    from clarinet.models import Alert
    _seed_alerts(db)
    client = client_for("kid", "pw-member-1")
    for title in ("SECRET-ARP-ALERT", "OTHERS-ALERT"):
        alert_id = db.query(Alert).filter(Alert.title == title).one().alert_id
        r = client.post(f"/alerts/{alert_id}/ack")
        assert "not_found" in r.headers["location"]
    db.expire_all()
    assert db.query(Alert).filter(Alert.title.in_(["SECRET-ARP-ALERT", "OTHERS-ALERT"]), Alert.status != "OPEN").count() == 0
