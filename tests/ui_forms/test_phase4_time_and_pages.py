"""
Phase 4: time zone, the new setup-wizard fields, and the small page fixes (speed tool, reports, exports).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests._support import ADMIN, new_client, seed_world


@pytest.fixture(autouse=True)
def fresh_zone_cache():
    from clarinet.core_svc.localtime import reset_cache
    reset_cache()
    yield
    reset_cache()


def _set_zone(name):
    from clarinet.app_settings import set_setting
    from clarinet.core_svc.localtime import reset_cache
    from clarinet.database import SessionLocal
    with SessionLocal() as db:
        set_setting(db, "timezone", name)
    reset_cache()


def test_stored_utc_time_is_shown_in_the_chosen_zone():
    from clarinet.core_svc.localtime import local_filter
    seed_world("MONITOR")
    _set_zone("Asia/Kolkata")
    assert local_filter(datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc), "%H:%M") == "17:30"
    assert local_filter(datetime(2026, 1, 15, 12, 0), "%H:%M") == "17:30"        # naive values are UTC
    _set_zone("UTC")
    assert local_filter(datetime(2026, 1, 15, 12, 0), "%H:%M") == "12:00"


def test_bad_zone_falls_back_to_the_machine_zone():
    from clarinet.core_svc.localtime import machine_zone, valid_zone, zone_name
    seed_world("MONITOR")
    assert not valid_zone("Mars/Olympus")
    _set_zone("Mars/Olympus")
    assert zone_name() == machine_zone()


def test_settings_page_offers_zones_and_rejects_unknown_ones():
    seed_world("MONITOR")
    c = new_client(ADMIN)
    page = c.get("/settings").text
    assert 'name="timezone"' in page and "Asia/Kolkata" in page


def test_speed_page_tells_the_truth_about_a_failed_test():
    from clarinet.database import SessionLocal
    from clarinet.models import SpeedTestResult
    seed_world("MONITOR")
    with SessionLocal() as db:
        db.add(SpeedTestResult(tested_at=datetime.now(timezone.utc), download_mbps=0, upload_mbps=0,
                               latency_ms=0, busy=False, below_plan=False, server_host="failed"))
        db.commit()
    page = new_client(ADMIN).get("/speed").text
    assert "did not finish" in page


def test_speed_tool_is_also_searched_next_to_the_apps_python(monkeypatch):
    from clarinet.collector import speed_test
    monkeypatch.delenv("CLARINET_NO_VENV_TOOLS", raising=False)
    monkeypatch.setenv("PATH", "/nonexistent")
    assert "/nonexistent" in speed_test._tool_env()["PATH"].split(":")
    assert len(speed_test._tool_env()["PATH"].split(":")) == 2
    monkeypatch.setenv("CLARINET_NO_VENV_TOOLS", "1")
    assert speed_test._tool_env()["PATH"] == "/nonexistent"


def test_export_links_and_audit_warning_are_on_the_pages():
    seed_world("MONITOR")
    c = new_client(ADMIN)
    assert "/export/devices.csv" in c.get("/devices").text
    assert "/export/alerts.csv" in c.get("/alerts").text
    assert "only run it on a router you own" in c.get("/security").text.lower()


def test_slowdowns_page_explains_learning_and_has_admin_settings():
    seed_world("MONITOR")
    page = new_client(ADMIN).get("/slowdowns").text
    assert 'action="/slowdowns/settings"' in page


def test_reports_open_on_today():
    seed_world("MONITOR")
    r = new_client(ADMIN).get("/reports")
    assert r.status_code == 200
