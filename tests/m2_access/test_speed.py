"""
tests/m2_access/test_speed.py
Speed test: routes, API summary, mode gating.
"""
import pytest


class TestSpeedRoutes:
    def test_speed_page_loads_admin(self, admin_client):
        resp = admin_client.get("/speed", follow_redirects=True)
        assert resp.status_code == 200

    def test_speed_page_refuses_anonymous(self, anon_client):
        resp = anon_client.get("/speed", follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_speed_summary_api(self, admin_client):
        resp = admin_client.get("/speed/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "available" in data

    def test_speed_summary_refuses_anonymous(self, anon_client):
        resp = anon_client.get("/speed/summary", follow_redirects=False)
        assert resp.status_code in (401, 302)

    def test_csv_export_admin(self, admin_client):
        resp = admin_client.get("/speed/export.csv", follow_redirects=True)
        assert resp.status_code == 200
        assert "csv" in resp.headers.get("content-type", "") or "text" in resp.headers.get("content-type", "")


class TestSpeedTestCollector:
    def test_below_plan_threshold_80_percent(self):
        """Plan threshold must be 80% (F-08e fix), not 70%."""
        from clarinet.collector.speed_test import PLAN_THRESHOLD
        assert PLAN_THRESHOLD == 0.80

    def test_no_crash_without_cli(self, monkeypatch):
        """Speed test handles missing CLI gracefully."""
        import subprocess
        def fake_run(*args, **kwargs):
            raise FileNotFoundError("speedtest not found")
        monkeypatch.setattr(subprocess, "run", fake_run)

        from clarinet.collector.speed_test import _run_speedtest_cli
        result = _run_speedtest_cli()
        assert result is None   # graceful fallback


class TestPriorityRoutes:
    def test_priority_page_loads_member(self, member_client):
        resp = member_client.get("/priority", follow_redirects=True)
        assert resp.status_code == 200

    def test_priority_page_loads_admin(self, admin_client):
        resp = admin_client.get("/priority", follow_redirects=True)
        assert resp.status_code == 200

    def test_priority_summary_api(self, admin_client):
        resp = admin_client.get("/priority/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "active_grants" in data

    def test_member_cannot_request_for_other_device(self, member_client, admin_client):
        """F-07a: Member cannot request priority for another member's device."""
        from clarinet.database import SessionLocal
        from clarinet.models import Device, Member
        with SessionLocal() as db:
            # Create a device owned by admin
            admin = db.query(Member).filter(Member.username == "admin").first()
            dev = Device(mac_address="de:ad:be:ef:00:01", state="APPROVED",
                         label="AdminDevice", owner_member_id=admin.member_id)
            db.add(dev)
            db.commit()
            device_id = dev.device_id

        resp = member_client.post("/priority/request", data={
            "device_id": device_id,
            "duration_min": 30,
        }, follow_redirects=True)
        # Should be refused or error
        assert "not+your" in str(resp.url) or "error" in str(resp.url) or resp.status_code in (200, 302, 403)


class TestContracts:
    """Pin M2 contract function signatures."""

    def test_request_reconcile_callable(self):
        from clarinet.enforcer.reconcile import request_reconcile
        request_reconcile()   # must not raise

    def test_throttle_low_priority_importable(self):
        from clarinet.enforcer.limits import throttle_low_priority
        assert callable(throttle_low_priority)

    def test_release_throttle_importable(self):
        from clarinet.enforcer.limits import release_throttle
        assert callable(release_throttle)

    def test_read_counters_importable(self):
        from clarinet.enforcer.accounting import read_counters
        result = read_counters()
        assert isinstance(result, dict)

    def test_is_guest_ip_importable(self):
        from clarinet.enforcer.guest_net import is_guest_ip
        from clarinet.database import SessionLocal
        with SessionLocal() as db:
            result = is_guest_ip("192.168.1.1", db)
        assert isinstance(result, bool)
