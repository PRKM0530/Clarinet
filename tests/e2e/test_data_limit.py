"""
USG-05: the monthly data limit - alerts at each level, billing period rollover, and the throttle contract.
"""
from __future__ import annotations

from datetime import date, timedelta

import pytest

from tests._support import seed_world

MB = 1_000_000


@pytest.fixture()
def world():
    from clarinet.database import SessionLocal
    from clarinet.models import Alert, Settings, UsageRecord
    ids = seed_world("FULL")
    with SessionLocal() as db:
        db.query(Alert).delete()
        db.query(UsageRecord).delete()
        db.add(Settings(key="limit.bytes", value=str(100 * MB)))
        db.add(Settings(key="billing_day", value="1"))
        db.commit()
    return ids


def use(world, megabytes, day=None):
    from clarinet.database import SessionLocal
    from clarinet.models import UsageRecord
    day = day or date.today()
    with SessionLocal() as db:
        db.add(UsageRecord(device_id=world["d_alice"], date=day.isoformat(), hour=3, bytes_in=megabytes * MB, bytes_out=0))
        db.commit()


def run_check():
    from clarinet.core_svc.limit_service import check_and_alert
    from clarinet.database import SessionLocal
    with SessionLocal() as db:
        check_and_alert(db)


def alert_types():
    from clarinet.database import SessionLocal
    from clarinet.models import Alert
    with SessionLocal() as db:
        return sorted(a.type for a in db.query(Alert) if a.type.startswith("DATA_LIMIT"))


def first_of_month_billing():
    # a billing day of 1 means the period starts on the 1st: today is always inside it
    return date.today().replace(day=1)


@pytest.mark.parametrize("mb,expected", [
    (10, []), (85, ["DATA_LIMIT_WARN"]), (97, ["DATA_LIMIT_CRITICAL"]), (100, ["DATA_LIMIT_EXCEEDED"]), (140, ["DATA_LIMIT_EXCEEDED"])])
def test_usg05_alert_level_matches_usage(world, mb, expected):
    use(world, mb)
    run_check()
    assert alert_types() == expected


def test_usg05_repeated_checks_do_not_duplicate_the_alert(world):
    use(world, 120)
    run_check()
    run_check()
    assert alert_types() == ["DATA_LIMIT_EXCEEDED"]


def test_usg05_unlimited_never_alerts(world):
    from clarinet.database import SessionLocal
    from clarinet.models import Settings
    with SessionLocal() as db:
        db.get(Settings, "limit.bytes").value = ""
        db.commit()
    use(world, 5000)
    run_check()
    assert alert_types() == []


def test_usg05_usage_before_the_billing_period_is_not_counted(world):
    from clarinet.core_svc.limit_service import get_limit_summary
    from clarinet.database import SessionLocal
    start = first_of_month_billing()
    use(world, 90, day=start - timedelta(days=1))      # last period
    use(world, 5, day=start)                           # this period
    with SessionLocal() as db:
        assert get_limit_summary(db).bytes_used == 5 * MB


@pytest.mark.parametrize("billing_day", [1, 28])
def test_usg05_period_boundaries_for_billing_days_1_and_28(world, billing_day):
    from clarinet.core_svc.timeutil import billing_period_end, billing_period_start
    today = date.today()
    start, end = billing_period_start(billing_day, today), billing_period_end(billing_day, today)
    assert start <= today <= end and start.day == billing_day


def test_s10_exceeding_the_limit_triggers_the_throttle(world, monkeypatch):
    called = []
    monkeypatch.setattr("clarinet.enforcer.limits.throttle_low_priority", lambda *a, **k: called.append(a))
    use(world, 150)
    run_check()
    assert called, "the data limit was exceeded but no throttle was requested"


def test_a_single_device_using_over_half_the_limit_raises_high_usage(world):
    from clarinet.database import SessionLocal
    from clarinet.models import Alert
    use(world, 60)                                                     # 60 MB of a 100 MB limit, all on one device
    run_check()
    with SessionLocal() as db:
        rows = db.query(Alert).filter(Alert.type == "HIGH_USAGE").all()
        assert len(rows) == 1 and rows[0].device_id == world["d_alice"] and "over half" in rows[0].title


def test_shared_usage_does_not_raise_high_usage(world):
    from clarinet.database import SessionLocal
    from clarinet.models import Alert, UsageRecord
    use(world, 40)
    with SessionLocal() as db:
        db.add(UsageRecord(device_id=world["d_bob"], date=date.today().isoformat(), hour=4, bytes_in=40 * MB, bytes_out=0))
        db.commit()
    run_check()
    with SessionLocal() as db:
        assert db.query(Alert).filter(Alert.type == "HIGH_USAGE").count() == 0


def test_the_owner_sees_their_high_usage_alert_but_others_do_not(world):
    from tests._support import ALICE, BOB, new_client
    use(world, 60)
    run_check()
    assert "over half of the monthly data" in new_client(ALICE).get("/alerts").text
    assert "over half of the monthly data" not in new_client(BOB).get("/alerts").text
