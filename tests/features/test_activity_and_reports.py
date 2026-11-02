"""
Activity types (USE-2), daily and weekly reports (USE-3), and the retention
that goes with them (NFR-20).
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from clarinet import app
from clarinet.auth import hash_password
from clarinet.core_svc import activity
from clarinet.database import Base, SessionLocal, engine
from clarinet.models import Alert, Device, Member, Settings, SlowdownEvent, UsageRecord
from clarinet.models.traffic import DomainObservation, UsageActivity


@pytest.fixture()
def db():
    assert "clarinet_test_" in str(engine.url), "refusing to touch a non-test database"
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        session.add(Settings(key="setup_complete", value="true"))
        session.commit()
        yield session


def make_world(db):
    now = datetime.now(timezone.utc)
    alice = Member(username="alice", password_hash=hash_password("pw-alice-1"), role="MEMBER")
    boss = Member(username="boss", password_hash=hash_password("pw-boss-1"), role="ADMIN")
    db.add_all([alice, boss])
    db.flush()
    mine = Device(mac_address="AA:00:00:00:00:01", ip_address="192.168.1.10", label="ALICE-LAPTOP",
                  state="APPROVED", owner_member_id=alice.member_id, first_seen=now, last_seen=now)
    theirs = Device(mac_address="BB:00:00:00:00:02", ip_address="192.168.1.11", label="OTHER-PHONE",
                    state="APPROVED", first_seen=now, last_seen=now)
    db.add_all([mine, theirs])
    db.commit()
    return alice, boss, mine, theirs


def login(user, password):
    client = TestClient(app, follow_redirects=False, raise_server_exceptions=False)
    assert client.post("/login", data={"username": user, "password": password}).status_code == 302
    return client


# domain names to activity types

@pytest.mark.parametrize("name, expected", [
    ("www.youtube.com", "STREAMING"),
    ("rr3---sn-abc.googlevideo.com", "STREAMING"),
    ("meet.google.com", "CALLS"),            # the specific name wins over google.com
    ("mail.google.com", "BROWSING"),
    ("x.windowsupdate.com", "UPDATES"),
    ("store.steampowered.com", "GAMING"),
    ("dl.mega.nz", "DOWNLOAD"),
    ("some-unknown-site.xyz", "OTHER"),
    ("printer.local", "OTHER"),
    ("1.1.168.192.in-addr.arpa", "OTHER"),
    ("", "OTHER"),
])
def test_domain_names_are_sorted_into_activity_types(name, expected):
    assert activity.classify_name(name) == expected


@pytest.mark.parametrize("name, expected", [
    ("www.youtube.com", "youtube.com"),
    ("rr3---sn-abc.googlevideo.com", "googlevideo.com"),
    ("www.bbc.co.uk", "bbc.co.uk"),
    ("a.b.c.example.co.in", "example.co.in"),
    ("localhost", None),
    ("foo.local", None),
])
def test_only_the_registrable_domain_is_kept(name, expected):
    assert activity.registrable_domain(name) == expected


@pytest.mark.parametrize("b_in, b_out, weights", [
    (1000, 10, {"STREAMING": 3, "BROWSING": 1}),
    (999_999_937, 12_345_679, {"STREAMING": 7, "CALLS": 5, "GAMING": 3, "OTHER": 1}),
    (5, 5, {"STREAMING": 1, "BROWSING": 1, "CALLS": 1}),
    (0, 0, {"STREAMING": 1}),
    (7, 3, {}),
])
def test_splitting_an_hour_never_loses_or_invents_bytes(b_in, b_out, weights):
    shares = activity.split_bytes(b_in, b_out, weights)
    assert sum(i for i, _ in shares.values()) == b_in
    assert sum(o for _, o in shares.values()) == b_out
    assert all(i >= 0 and o >= 0 for i, o in shares.values())


def test_an_hour_with_no_lookups_counts_as_other():
    assert activity.split_bytes(100, 50, {}) == {"OTHER": (100, 50)}


# the DNS observer

def test_observer_counts_lookups_and_writes_them_for_known_devices_only(db):
    from clarinet.collector.dns_observer import DnsObserver, flush
    _, _, mine, _ = make_world(db)
    obs = DnsObserver()
    for _ in range(3):
        obs.observe("192.168.1.10", "www.youtube.com")
    obs.observe("192.168.1.10", "mail.google.com")
    obs.observe("192.168.1.99", "www.youtube.com")        # not one of our devices
    assert obs.observe("192.168.1.10", "printer.local") is False

    assert flush(db, obs) == 2
    rows = {(r.domain, r.category): r.hit_count for r in db.query(DomainObservation)}
    assert rows == {("youtube.com", "STREAMING"): 3, ("google.com", "BROWSING"): 1}
    assert {r.device_id for r in db.query(DomainObservation)} == {mine.device_id}
    assert flush(db, obs) == 0                              # nothing is written twice


def test_observer_stores_the_domain_only_never_the_full_name(db):
    from clarinet.collector.dns_observer import DnsObserver, flush
    make_world(db)
    obs = DnsObserver()
    obs.observe("192.168.1.10", "very-private-subdomain.account123.youtube.com")
    flush(db, obs)
    assert [r.domain for r in db.query(DomainObservation)] == ["youtube.com"]


# turning lookups and bytes into activity rows

def _usage_and_lookups(db, device, when, b_in, b_out, lookups):
    db.add(UsageRecord(device_id=device.device_id, date=when.date().isoformat(), hour=when.hour,
                       bytes_in=b_in, bytes_out=b_out))
    for category, hits in lookups.items():
        db.add(DomainObservation(device_id=device.device_id, domain=f"{category.lower()}.test", category=category,
                                 observed_at=when.replace(minute=30, second=0, microsecond=0, tzinfo=None),
                                 hit_count=hits))
    db.commit()


def test_an_hours_bytes_are_shared_in_proportion_to_the_lookups(db):
    _, _, mine, _ = make_world(db)
    when = datetime.now(timezone.utc) - timedelta(hours=3)
    _usage_and_lookups(db, mine, when, 1000, 100, {"STREAMING": 3, "BROWSING": 1})

    assert activity.classify_recent(db) == 1
    rows = {r.category: (r.bytes_in, r.bytes_out) for r in db.query(UsageActivity)}
    assert rows == {"STREAMING": (750, 75), "BROWSING": (250, 25)}


def test_an_hour_without_lookups_is_other_and_the_job_can_be_repeated(db):
    _, _, mine, _ = make_world(db)
    when = datetime.now(timezone.utc) - timedelta(hours=2)
    _usage_and_lookups(db, mine, when, 500, 50, {})
    activity.classify_recent(db)
    activity.classify_recent(db)
    rows = db.query(UsageActivity).all()
    assert [(r.category, r.bytes_in, r.bytes_out) for r in rows] == [("OTHER", 500, 50)]


def test_old_hours_are_left_alone(db):
    _, _, mine, _ = make_world(db)
    _usage_and_lookups(db, mine, datetime.now(timezone.utc) - timedelta(days=5), 500, 50, {"STREAMING": 1})
    assert activity.classify_recent(db, hours=48) == 0


def test_the_usage_page_breakdown_only_covers_what_the_viewer_may_see(db):
    alice, boss, mine, theirs = make_world(db)
    when = datetime.now(timezone.utc) - timedelta(hours=2)
    _usage_and_lookups(db, mine, when, 1000, 0, {"STREAMING": 1})
    _usage_and_lookups(db, theirs, when, 9000, 0, {"GAMING": 1})
    activity.classify_recent(db)

    member = login("alice", "pw-alice-1").get("/api/usage/summary?period=today").json()
    assert member["by_activity"] == {"STREAMING": 1000}
    everyone = login("boss", "pw-boss-1").get("/api/usage/summary?period=today").json()
    assert everyone["by_activity"] == {"GAMING": 9000, "STREAMING": 1000}
    page = login("alice", "pw-alice-1").get("/usage?period=today").text
    assert "Streaming" in page and "Gaming" not in page


def test_domain_detail_is_deleted_after_seven_days_but_the_totals_stay(db):
    from clarinet.core_svc.purge import purge_old_domains
    _, _, mine, _ = make_world(db)
    old = datetime.now(timezone.utc) - timedelta(days=9)
    _usage_and_lookups(db, mine, old, 100, 10, {"STREAMING": 2})
    db.add(UsageActivity(device_id=mine.device_id, date=old.date().isoformat(), hour=old.hour,
                         category="STREAMING", bytes_in=100, bytes_out=10))
    _usage_and_lookups(db, mine, datetime.now(timezone.utc) - timedelta(hours=1), 5, 5, {"BROWSING": 1})
    db.commit()

    assert purge_old_domains(db, days=7) == 1
    assert [r.category for r in db.query(DomainObservation)] == ["BROWSING"]
    assert db.query(UsageActivity).count() == 1


# daily and weekly reports

def _traffic(db, device, day, b_in, b_out, hour=12):
    db.add(UsageRecord(device_id=device.device_id, date=day.isoformat(), hour=hour, bytes_in=b_in, bytes_out=b_out))
    db.commit()


def test_a_daily_report_adds_up_the_day_and_compares_with_the_day_before(db):
    from clarinet.core_svc.reports import build_report
    alice, boss, mine, theirs = make_world(db)
    yesterday = date.today() - timedelta(days=1)
    _traffic(db, mine, yesterday, 3_000_000, 1_000_000, hour=20)
    _traffic(db, theirs, yesterday, 6_000_000, 0, hour=9)
    _traffic(db, mine, yesterday - timedelta(days=1), 5_000_000, 0)

    report = build_report(db, boss, "day", yesterday)
    assert (report.total_bytes, report.bytes_in, report.bytes_out) == (10_000_000, 9_000_000, 1_000_000)
    assert report.previous_total == 5_000_000 and report.change_pct == 100.0
    assert report.peak_hour in (9, 20)
    assert [t["device"].label for t in report.top_devices] == ["OTHER-PHONE", "ALICE-LAPTOP"]


def test_a_weekly_report_has_a_bar_for_every_day_including_quiet_ones(db):
    from clarinet.core_svc.reports import build_report
    _, boss, mine, _ = make_world(db)
    end = date.today() - timedelta(days=1)
    _traffic(db, mine, end, 1_000, 0)
    _traffic(db, mine, end - timedelta(days=3), 2_000, 0)
    report = build_report(db, boss, "week", end)
    assert len(report.by_day) == 7
    assert report.by_day[end.isoformat()] == 1_000
    assert sum(report.by_day.values()) == 3_000
    assert report.start == (end - timedelta(days=6)).isoformat()


def test_a_report_with_no_earlier_data_has_no_percentage(db):
    from clarinet.core_svc.reports import build_report
    _, boss, mine, _ = make_world(db)
    day = date.today() - timedelta(days=1)
    _traffic(db, mine, day, 100, 0)
    assert build_report(db, boss, "day", day).change_pct is None


def test_a_member_report_only_covers_their_own_devices_and_has_no_network_extras(db):
    from clarinet.core_svc.reports import build_report
    alice, boss, mine, theirs = make_world(db)
    day = date.today() - timedelta(days=1)
    _traffic(db, mine, day, 1_000, 0)
    _traffic(db, theirs, day, 9_000, 0)
    start = datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)
    db.add(SlowdownEvent(started_at=start + timedelta(hours=2), ended_at=start + timedelta(hours=2, minutes=30)))
    db.add(Alert(level="WARNING", type="SLOWDOWN", title="mine", message="x", device_id=mine.device_id,
                 raised_at=start + timedelta(hours=1)))
    db.add(Alert(level="CRITICAL", type="ARP_SPOOF", title="network", message="x", raised_at=start + timedelta(hours=1)))
    db.commit()

    mine_report = build_report(db, alice, "day", day)
    assert mine_report.total_bytes == 1_000
    assert mine_report.alerts == 1
    assert (mine_report.new_devices, mine_report.slowdown_minutes, mine_report.limit_pct) == (None, None, None)

    admin_report = build_report(db, boss, "day", day)
    assert admin_report.total_bytes == 10_000
    assert admin_report.alerts == 2
    assert admin_report.slowdown_minutes == 30


def test_the_reports_page_works_for_every_view_and_survives_bad_dates(db):
    make_world(db)
    for who in (("alice", "pw-alice-1"), ("boss", "pw-boss-1")):
        client = login(*who)
        for query in ("", "?view=day", "?view=week", "?view=day&date=2020-01-01", "?date=garbage",
                      "?view=week&date=9999-12-31", "?view=%27%3E%3Cscript%3E"):
            assert client.get("/reports" + query).status_code == 200, (who[0], query)


def test_the_reports_page_never_shows_a_member_other_peoples_devices(db):
    alice, _, mine, theirs = make_world(db)
    day = date.today() - timedelta(days=1)
    _traffic(db, mine, day, 1_000_000, 0)
    _traffic(db, theirs, day, 9_000_000, 0)
    page = login("alice", "pw-alice-1").get(f"/reports?view=day&date={day}").text
    assert "ALICE-LAPTOP" in page and "OTHER-PHONE" not in page


def test_the_reports_page_needs_a_login(db):
    client = TestClient(app, follow_redirects=False)
    r = client.get("/reports")
    assert r.status_code == 302 and "/login" in r.headers["location"]
