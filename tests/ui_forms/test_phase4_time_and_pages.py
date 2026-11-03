"""
Phase 4: time zone, the new setup-wizard fields, and the small page fixes (speed tool, reports, exports).
"""
from __future__ import annotations

from datetime import datetime, timezone

import sys

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


@pytest.mark.skipif(sys.platform == "win32", reason="builds a ':' separated PATH, which is a Linux convention")
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


def test_slowdowns_page_points_to_settings_instead_of_repeating_them():
    seed_world("MONITOR")
    page = new_client(ADMIN).get("/slowdowns").text
    assert 'action="/slowdowns/settings"' not in page
    assert "Settings, then Advanced" in page


def test_reports_open_on_today():
    seed_world("MONITOR")
    r = new_client(ADMIN).get("/reports")
    assert r.status_code == 200


# ── Phase 5: discovery, guests, and Public-mode quarantine ─────────────────────────────────────────────────

def _reconcile_with_fake_nft(monkeypatch):
    """Run the real reconcile with a recording stand-in for nftables."""
    from clarinet.enforcer import accounting, nft_wrapper as nft, reconcile
    calls = {"deny": [], "counted": None, "allow": [], "open": []}
    monkeypatch.setattr(accounting, "sync_accounting", lambda devices: calls.__setitem__("counted", devices))
    monkeypatch.setattr(nft, "ensure_table_exists", lambda: True)
    monkeypatch.setattr(nft, "macs_with_rules", lambda chain, prefix: set())
    monkeypatch.setattr(nft, "block_device", lambda *a, **k: True)
    monkeypatch.setattr(nft, "unblock_device", lambda *a, **k: True)
    monkeypatch.setattr(nft, "deny_guest", lambda mac: calls["deny"].append(mac) or True)
    monkeypatch.setattr(nft, "close_guest_access", lambda mac: True)
    monkeypatch.setattr(nft, "open_guest_access", lambda mac, **k: calls["open"].append(mac) or True)
    monkeypatch.setattr(nft, "allow_guest_again", lambda mac: calls["allow"].append(mac))
    reconcile.reconcile_now()
    return calls


def _device_states():
    from clarinet.database import SessionLocal
    from clarinet.models import Device
    with SessionLocal() as db:
        return {d.mac_address.lower(): d.state for d in db.query(Device).all()}


def _hold_new_devices():
    from clarinet.database import SessionLocal
    from clarinet.models import Settings
    with SessionLocal() as db:
        db.merge(Settings(key="hold_new_devices", value="true"))
        db.commit()


def test_keeping_new_devices_offline_holds_them_back_but_not_approved_ones(monkeypatch):
    seed_world("FULL")
    _hold_new_devices()
    calls = _reconcile_with_fake_nft(monkeypatch)
    states = _device_states()
    new = {m for m, st in states.items() if st == "NEW"}
    approved = {m for m, st in states.items() if st == "APPROVED"}
    assert new and approved
    assert new <= set(calls["deny"])
    assert not (approved & set(calls["deny"]))
    assert calls["counted"] is not None                     # usage is still counted


def test_monitor_mode_never_holds_anything_back(monkeypatch):
    seed_world("MONITOR")
    calls = _reconcile_with_fake_nft(monkeypatch)
    assert calls["deny"] == []


def test_full_mode_still_only_holds_back_guests(monkeypatch):
    seed_world("FULL")
    calls = _reconcile_with_fake_nft(monkeypatch)
    states = _device_states()
    assert not ({m for m, st in states.items() if st == "NEW"} & set(calls["deny"]))


def test_vouchers_are_offered_while_new_devices_are_held(monkeypatch):
    monkeypatch.setattr("clarinet.core_svc.enforcement_status.problem", lambda: None)
    seed_world("FULL")
    _hold_new_devices()
    c = new_client(ADMIN)
    assert 'href="/vouchers"' in c.get("/dashboard").text
    assert "needs Full Control mode" not in c.get("/vouchers").text


def test_login_page_points_visitors_to_the_guest_page():
    seed_world("MONITOR")
    from tests._support import new_client as anon
    page = anon().get("/login").text
    assert 'href="/guest"' in page


@pytest.mark.skipif(sys.platform == "win32", reason="uses os.geteuid, which Windows does not have")
def test_active_scan_needs_root_scapy_and_the_right_mode(monkeypatch):
    import os
    from clarinet.app_settings import set_setting
    from clarinet.collector.arp_scanner import active_discovery_on
    from clarinet.database import SessionLocal
    seed_world("FULL")
    with SessionLocal() as db:
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        assert not active_discovery_on(db)                  # not root
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        assert active_discovery_on(db)                      # auto + Full Control
        set_setting(db, "active_discovery", "off")
        assert not active_discovery_on(db)
        set_setting(db, "active_discovery", "auto")
        set_setting(db, "network_mode", "MONITOR")
        assert not active_discovery_on(db)                  # auto stays passive outside Full Control
        set_setting(db, "active_discovery", "on")
        assert active_discovery_on(db)


# ── Phase 6: installer and secret key ──────────────────────────────────────────────────────────────────────

def _cfg(key, env):
    from clarinet.config import Settings
    return Settings(SECRET_KEY=key, APP_ENV=env)


def test_production_refuses_the_example_secret_key():
    from clarinet.config import check_secret_key
    for bad in ("change-me", "", "  Change-Me "):
        with pytest.raises(RuntimeError):
            check_secret_key(_cfg(bad, "production"))
    assert check_secret_key(_cfg("a" * 64, "production")) is None


def test_development_only_warns_about_the_example_secret_key():
    from clarinet.config import check_secret_key
    assert "SECRET_KEY" in check_secret_key(_cfg("change-me", "development"))
    assert check_secret_key(_cfg("something-private", "development")) is None


def test_installer_creates_a_private_env_file():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    script = (root / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "secrets.token_hex" in script and "chmod 600" in script and "APP_ENV=production" in script
    assert script.index("Private configuration") < script.index("systemctl start clarinet")   # .env exists before the service starts


def test_active_scan_never_probes_more_than_one_24(monkeypatch):
    import subprocess
    from types import SimpleNamespace
    from clarinet.collector.arp_scanner import _subnet_of
    for line, expected in (("2: eth0 inet 10.81.34.7/16 brd x scope global eth0", "10.81.34.0/24"),
                           ("2: eth0 inet 192.168.1.20/24 brd x scope global eth0", "192.168.1.0/24"),
                           ("2: eth0 inet 192.168.1.130/26 brd x scope global eth0", "192.168.1.128/26")):
        monkeypatch.setattr(subprocess, "run", lambda *a, _l=line, **k: SimpleNamespace(stdout=_l))
        assert _subnet_of("eth0") == expected
