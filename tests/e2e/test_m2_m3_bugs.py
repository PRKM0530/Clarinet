"""
E2E confirmations for the guest, speed and analytics suspects (S-04, S-07, S-15, S-21, S-24).
Only the outer edge is faked: the speed tool (returns "no tool") and the host time zone.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

import pytest

from tests._support import ADMIN, new_client, seed_world


@pytest.fixture()
def world():
    return seed_world()


def _failed_speed_run(monkeypatch):
    """Run the real _do_run with no speed tool installed."""
    from clarinet.collector import speed_test
    monkeypatch.setattr(speed_test, "_run_speedtest_cli", lambda: None)
    speed_test._do_run()


def _set(key, value):
    from clarinet.database import SessionLocal
    from clarinet.models import Settings
    with SessionLocal() as db:
        row = db.get(Settings, key)
        if row:
            row.value = value
        else:
            db.add(Settings(key=key, value=value))
        db.commit()


def test_s04_failed_speed_run_does_not_look_like_a_slow_line(world, monkeypatch):
    from clarinet.analytics.diagnosis import _speed_below_plan_check
    from clarinet.database import SessionLocal
    _set("plan_download_mbps", "100")
    _failed_speed_run(monkeypatch)
    with SessionLocal() as db:
        assert _speed_below_plan_check(db) is False


def test_s04_failed_speed_run_is_not_in_the_speed_report(world, monkeypatch):
    from clarinet.core_svc.speed_report import build_speed_report
    from clarinet.database import SessionLocal
    _set("plan_download_mbps", "100")
    _failed_speed_run(monkeypatch)
    with SessionLocal() as db:
        report = build_speed_report(db, 7)
    assert report.tests == []


def test_s15_speed_threshold_setting_is_used(world):
    from clarinet.analytics.diagnosis import _speed_below_plan_check
    from clarinet.database import SessionLocal
    from clarinet.models import SpeedTestResult
    _set("plan_download_mbps", "100")
    _set("slowdown_speed_threshold", "0.9")
    with SessionLocal() as db:
        db.add(SpeedTestResult(tested_at=datetime.now(timezone.utc), download_mbps=80, upload_mbps=10,
                               latency_ms=10, busy=False, below_plan=False, server_host="x"))
        db.commit()
        assert _speed_below_plan_check(db) is True     # 80 Mbps is below 90% of a 100 Mbps plan


def test_s21_speed_csv_time_is_correct_on_a_non_utc_host(world):
    from clarinet.database import SessionLocal
    from clarinet.models import SpeedTestResult
    old_tz = os.environ.get("TZ")
    os.environ["TZ"] = "America/New_York"
    time.tzset()
    try:
        _set("timezone", "UTC")
        with SessionLocal() as db:
            db.add(SpeedTestResult(tested_at=datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc), download_mbps=50,
                                   upload_mbps=5, latency_ms=10, busy=False, below_plan=False, server_host="x"))
            db.commit()
        body = new_client(ADMIN).get("/speed/export.csv").text
        assert "2026-01-15 12:00" in body, body
    finally:
        if old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old_tz
        time.tzset()


def _voucher_code(minutes="60"):
    from clarinet.database import SessionLocal
    from clarinet.models import Voucher
    new_client(ADMIN).post("/vouchers/create", data={"expires_minutes": minutes})
    with SessionLocal() as db:
        return db.query(Voucher).order_by(Voucher.voucher_id.desc()).first().code


def test_s24_revoke_audit_records_the_previous_status(world):
    import json
    from clarinet.database import SessionLocal
    from clarinet.models import AuditLog, Voucher
    _voucher_code()
    with SessionLocal() as db:
        vid = db.query(Voucher).first().voucher_id
    new_client(ADMIN).post(f"/vouchers/{vid}/revoke")
    with SessionLocal() as db:
        row = db.query(AuditLog).filter(AuditLog.action == "REVOKE_VOUCHER").one()
        assert "UNUSED" in str(row.detail) and "REVOKED" not in str(row.detail), row.detail


@pytest.mark.xfail(strict=True, reason="S-07: redeeming on an approved device turns it into a guest")
def test_s07_redeeming_does_not_demote_an_approved_device(world):
    from clarinet.database import SessionLocal
    from clarinet.models import Device
    code = _voucher_code()
    r = new_client().post("/guest/redeem", data={"code": code}, headers={"X-Forwarded-For": "192.168.1.11"})
    assert r.status_code == 200
    with SessionLocal() as db:
        assert db.get(Device, world["d_alice"]).state == "APPROVED"


@pytest.mark.xfail(strict=True, reason="S-07: a voucher redeemed from an unknown IP is used up with no device behind it")
def test_s07_voucher_is_not_consumed_when_no_device_can_be_found(world):
    from clarinet.database import SessionLocal
    from clarinet.models import Voucher
    code = _voucher_code()
    new_client().post("/guest/redeem", data={"code": code}, headers={"X-Forwarded-For": "203.0.113.50"})
    with SessionLocal() as db:
        assert db.query(Voucher).filter(Voucher.code == code).one().status == "UNUSED"
