"""
E2E confirmations of suspected bugs from CLARINET_TEST_PLAN.md.

Each test states the CORRECT behaviour. Where the bug is confirmed it is marked
xfail(strict=True) with the issue id, so the suite stays green today and fails
loudly (XPASS) the moment the owner fixes the bug and the marker must be removed.
"""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from tests._support import ADMIN, ALICE, new_client, seed_world


@pytest.fixture()
def world():
    return seed_world()


# S-22: bad input must not cause 500s
def test_s22_alerts_non_numeric_page(world):
    assert new_client(ADMIN).get("/alerts?page=abc").status_code < 500


def test_s22_reports_year_one(world):
    assert new_client(ADMIN).get("/reports?date=0001-01-01").status_code < 500


def test_s22_latency_huge_hours(world):
    assert new_client(ADMIN).get("/api/v1/latency?hours=99999999999").status_code < 500


def test_s22_junk_plan_speed_does_not_break_pages(world):
    c = new_client(ADMIN)
    c.post("/settings/update", data={"plan_download_mbps": "abc"})
    assert c.get("/speed").status_code < 500


# S-12: a member must not see network-wide totals
@pytest.mark.xfail(strict=True, reason="S-12: /api/v1/status gives members network-wide counts and traffic")
def test_s12_member_status_is_scoped_to_own_devices(world):
    body = new_client(ALICE).get("/api/v1/status").json()
    assert body["total_devices"] == 1          # alice owns exactly one device
    assert body["critical_alerts"] == 0        # the only CRITICAL alert is a security alert
    assert body["today_traffic_mb"] < 6        # her own traffic is 6,000,000 bytes


# S-11: router IP saved in Settings must be stored and pinged
def test_s11_router_ip_is_saved(world):
    from clarinet.app_settings import get_setting
    from clarinet.database import SessionLocal
    assert new_client(ADMIN).post("/settings/update", data={"router_ip": "10.9.9.9"}).status_code == 302
    with SessionLocal() as db:
        assert get_setting(db, "router_ip", "") == "10.9.9.9"


# S-02: blocking a device must reach nftables
def _record_nft(monkeypatch):
    calls = []

    def fake_run(args, input=None, **kw):
        calls.append((list(args), input or ""))
        return SimpleNamespace(ok=True, stderr="", stdout="", returncode=0)

    monkeypatch.setattr("clarinet.enforcer.runner.run", fake_run)
    return calls


def test_s02_block_reaches_nftables(world, monkeypatch):
    calls = _record_nft(monkeypatch)
    r = new_client(ADMIN).post(f"/devices/{world['d_free']}/block")
    assert r.status_code == 302 and "info=blocke" in r.headers["location"]
    assert any("aa:00:00:00:00:04" in inp.lower() for _, inp in calls), \
        "no nft command mentioning the blocked MAC was issued"


# S-03: an alert raised from a worker thread must reach a connected websocket
def test_s03_alert_from_worker_thread_reaches_websocket(world, monkeypatch):
    from fastapi.testclient import TestClient
    from clarinet import app
    from clarinet.core_svc.alerts import raise_alert
    from clarinet.database import SessionLocal

    monkeypatch.setattr("clarinet.scheduler.start_scheduler", lambda: None)   # no real jobs; lifespan still runs
    monkeypatch.setattr("clarinet.scheduler.stop_scheduler", lambda: None)
    with TestClient(app) as client:
        client.post("/login", data={"username": ADMIN[0], "password": ADMIN[1]})
        with client.websocket_connect("/ws/alerts") as ws:
            def job():
                with SessionLocal() as db:
                    raise_alert(db, "WARNING", "LIVE_TEST", "LIVE-TEST", "from a scheduler thread")
            threading.Thread(target=job).start()
            time.sleep(0.6)
            ws.send_text("ping")
            seen = [ws.receive_text()]
            assert any("LIVE-TEST" in m for m in seen), f"live alert never arrived; got {seen}"
